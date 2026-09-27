package planner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// storedFor is the spec a deploy of def stores for VM "web" of stack
// "mystack", edited by edit — what the planner reads back as the VM's spec.
func storedFor(t *testing.T, f *compose.File, edit func(*pb.VMSpec)) string {
	t.Helper()
	def := f.VMs["web"]
	spec, err := compose.BuildVMSpec("web", "web", &def, f)
	if err != nil {
		t.Fatal(err)
	}
	spec.Uuid = "u-1"
	if edit != nil {
		edit(spec)
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func resolveOne(t *testing.T, f *compose.File, vm corrosion.VMRecord) (*ResolvedPlan, VMAction) {
	t.Helper()
	state := makeState([]corrosion.HostRecord{makeHost("h1", 16, 32768)}, []corrosion.VMRecord{vm}, nil)
	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, a := range plan.VMs {
		if a.VMName == vm.Name {
			return plan, a
		}
	}
	t.Fatalf("no action for %s", vm.Name)
	return nil, VMAction{}
}

// An update the plan applies in place applies something: a VM whose plan says
// "applied in place, no restart" has a live change classified for it.
func assertNoEmptyUpdate(t *testing.T, a VMAction) {
	t.Helper()
	if a.Kind == OpUpdate && !a.Retry && a.Apply == compose.ActionLive && a.Plan.Max() == compose.ActionNoChange {
		t.Errorf("%s planned %q with nothing classified to apply", a.VMName, a.Detail)
	}
}

// The stored spec, not what the host reports the VM using now, is what a
// desired size is compared with. A ballooned or not-yet-grown guest used to
// plan "memory X→Y" as an in-place update that applied nothing, on every
// deploy.
func TestResolve_ActualsDriftIsNoChange(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 2, Memory: 1024, MaxMemory: 2048},
	})
	_, a := resolveOne(t, f, corrosion.VMRecord{
		Name: "web", StackName: "mystack", HostName: "h1", State: "running",
		Spec: storedFor(t, f, nil), CPUActual: 1, MemActual: 700,
	})
	assertNoEmptyUpdate(t, a)
	if a.Kind != OpNoChange {
		t.Errorf("planned %s (%s), want no-change", a.Kind, a.Detail)
	}
}

// A live memory change is planned once. Once it is applied the stored spec
// records the new size; re-applying the file then plans no change even while
// the guest's balloon has not reached it yet.
func TestResolve_ReapplyAfterLiveResizeIsNoChange(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 2, Memory: 1536, MaxMemory: 2048},
	})
	before := storedFor(t, f, func(s *pb.VMSpec) { s.MemoryMib = 1024 })
	_, a := resolveOne(t, f, corrosion.VMRecord{
		Name: "web", StackName: "mystack", HostName: "h1", State: "running",
		Spec: before, CPUActual: 2, MemActual: 1024,
	})
	if a.Kind != OpUpdate || a.Apply != compose.ActionLive || len(a.Plan.ResourceChanges) != 1 {
		t.Fatalf("planned %s apply=%v plan=%+v (%s), want one live memory change", a.Kind, a.Apply, a.Plan, a.Detail)
	}

	after := storedFor(t, f, nil) // the size the live resize recorded
	_, a = resolveOne(t, f, corrosion.VMRecord{
		Name: "web", StackName: "mystack", HostName: "h1", State: "running",
		Spec: after, CPUActual: 2, MemActual: 1024,
	})
	assertNoEmptyUpdate(t, a)
	if a.Kind != OpNoChange {
		t.Errorf("re-apply after the resize planned %s (%s), want no-change", a.Kind, a.Detail)
	}
}

// Removing cloud-init from the file of a running VM changes nothing about the
// VM: the plan says no change, and warns that the VM keeps the cloud-init it
// was created with. It is not an in-place update that applies nothing (and is
// planned again on every deploy), and not a recreate that replaces the disks.
func TestResolve_CloudInitRemovedIsNoChangeWithAWarning(t *testing.T) {
	with := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512,
			CloudInit: &compose.CloudInitDef{UserData: "#cloud-config\n{}\n"}},
	})
	stored := storedFor(t, with, nil)
	without := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	for i := 0; i < 2; i++ { // and again: nothing was applied, nothing is re-planned
		plan, a := resolveOne(t, without, corrosion.VMRecord{
			Name: "web", StackName: "mystack", HostName: "h1", State: "running",
			Spec: stored, CPUActual: 1, MemActual: 512,
		})
		assertNoEmptyUpdate(t, a)
		if a.Kind != OpNoChange {
			t.Fatalf("deploy %d: cloud-init removal planned %s (%s), want no-change", i+1, a.Kind, a.Detail)
		}
		found := false
		for _, w := range plan.Warnings {
			if strings.Contains(w, "web") && strings.Contains(w, "cloud-init") {
				found = true
			}
		}
		if !found {
			t.Errorf("deploy %d: no warning that web keeps its cloud-init; warnings=%q", i+1, plan.Warnings)
		}
	}
}
