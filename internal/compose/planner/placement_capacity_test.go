package planner

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Compose planning must place under the cluster's configured capacity policy —
// not the built-in defaults — or the plan targets hosts that admission
// (which uses the configured policy) then refuses at deploy time.
func TestBuildPlacementRequest_CarriesCapacityPolicy(t *testing.T) {
	pol := corrosion.CapacityPolicy{
		CPUOvercommit: 2.0, MemOvercommit: 1.0,
		CPUReserve: 2, MemReserveMiB: 8192, MemReservePct: 10, VMMemOverheadMiB: 256,
	}
	spec := &pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 2048}

	req := buildPlacementRequest(spec, pol)

	if req.Capacity != pol {
		t.Errorf("req.Capacity = %+v, want configured policy %+v", req.Capacity, pol)
	}
	if req.VMName != "vm1" || req.CPUNeeded != 2 || req.MemMiBNeeded != 2048 {
		t.Errorf("basic fields wrong: %+v", req)
	}
}

// Running containers in the snapshot must count against host memory during
// plan-time batch placement, exactly as they do at deploy-time admission —
// otherwise the plan succeeds and CreateVM then refuses.
func TestResolve_ContainerMemoryCountsAgainstHosts(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		// Default policy: allocatable = 4096 - max(1024, 5%) = 3072 MiB.
		// The 2800 MiB running container leaves 272 — this VM must not place.
		"web": {Image: "ubuntu", CPU: 1, Memory: 2048},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 8, 4096)},
		nil, nil,
	)
	state.Containers = []corrosion.ContainerRecord{
		{Name: "hog", HostName: "h1", State: "running", MemMiB: 2800},
	}

	if _, err := Resolve(context.Background(), f, state); err == nil {
		t.Fatal("expected placement failure: container memory must count against the host at plan time")
	}
}

// labUpdateState is the 3-host lab (4 vCPU / 2971 MiB each, 1947 MiB
// allocatable under the default policy) with stack hc's db running on node-2
// at 1 vCPU / 1 GiB.
func labUpdateState() *ClusterState {
	return makeState(
		[]corrosion.HostRecord{makeHost("node-1", 4, 2971), makeHost("node-2", 4, 2971), makeHost("node-3", 4, 2971)},
		[]corrosion.VMRecord{{
			Name: "db", StackName: "hc", HostName: "node-2",
			Spec:  `{"name":"db","image":"ubuntu","cpu":1,"memory_mib":1024,"placement":{"host":"node-2"}}`,
			State: "running", CPUActual: 1, MemActual: 1024,
		}},
		nil,
	)
}

// An update of a VM that fills most of its host is evaluated as replacing the
// VM's current allocation, not adding to it. The planner used to charge db's
// running 1024 MiB AND its new request on node-2, so neither a shrink to 768M
// nor a label-only change could be planned: "no eligible host for VM db".
func TestResolve_UpdateOfAVMFillingItsHostReplacesItsAllocation(t *testing.T) {
	for _, mem := range []int{768, 1024} {
		f := makeFile("hc", map[string]compose.VMDef{
			"db": {Image: "ubuntu", CPU: 1, Memory: compose.Memory(mem),
				Labels:    map[string]string{"tier": "data"},
				Placement: &compose.PlacementDef{Host: "node-2"}},
		})
		plan, err := Resolve(context.Background(), f, labUpdateState())
		if err != nil {
			t.Fatalf("memory %d: Resolve: %v", mem, err)
		}
		a := ctAction(plan, "db")
		if a == nil || a.Kind != OpUpdate || a.TargetHost != "node-2" {
			t.Fatalf("memory %d: db = %+v, want an update on node-2", mem, a)
		}
	}
}

// An update that genuinely no longer fits its pinned host is still refused,
// and the refusal names the resource and the numbers.
func TestResolve_UpdateBeyondItsHostNamesTheShortfall(t *testing.T) {
	f := makeFile("hc", map[string]compose.VMDef{
		"db": {Image: "ubuntu", CPU: 1, Memory: 4096, Placement: &compose.PlacementDef{Host: "node-2"}},
	})
	_, err := Resolve(context.Background(), f, labUpdateState())
	want := "db needs 4224 MiB of memory on node-2 (4096 MiB + 128 MiB qemu overhead), " +
		"which has 1947 MiB free after db's current 1024 MiB is released"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Resolve err = %v\nwant it to contain %q", err, want)
	}
}

// A container update is a replacement too: its running memory limit is not
// charged alongside the recreated one.
func TestResolve_ContainerUpdateReplacesItsAllocation(t *testing.T) {
	// 4096 − 1024 reserve = 3072 allocatable. The running container holds 2000;
	// its 2000 MiB replacement (+128) fits only once the old 2000 is released.
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.21", CPU: 2, Memory: 2000},
	})
	state := makeState([]corrosion.HostRecord{lxcHost("lxc1", 8, 4096)}, nil, nil)
	ct := stackContainer("lxc1")
	ct.MemMiB = 2000
	state.Containers = []corrosion.ContainerRecord{ct}

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if a := ctAction(plan, "web"); a == nil || a.Kind != OpUpdate || a.TargetHost != "lxc1" {
		t.Fatalf("container update = %+v, want an update on lxc1", a)
	}
}
