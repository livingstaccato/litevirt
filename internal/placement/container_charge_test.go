package placement

import (
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A container holds host memory only — no vCPU reservation and no qemu
// overhead — by the same rule the snapshot counts existing containers with.
// Placement used to charge a container request like a VM: its cpu_limit as
// vCPUs and its memory plus a qemu overhead it does not have.

func TestContainerAllocation_MatchesTheSnapshotCountingRule(t *testing.T) {
	ct := corrosion.ContainerRecord{HostName: "node-2", Name: "c", State: "running", CPULimit: 4, MemMiB: 512}
	got := ContainerAllocation(ct)
	if got == nil || *got != (Allocation{Host: "node-2", MemMiB: 512}) {
		t.Fatalf("ContainerAllocation(running, capped) = %+v, want node-2 / 512 MiB, no CPU, not a VM", got)
	}
	for _, c := range []corrosion.ContainerRecord{
		{HostName: "node-2", Name: "c", State: "stopped", MemMiB: 512},
		{HostName: "node-2", Name: "c", State: "running", MemMiB: 0}, // uncapped: counted as nothing
	} {
		if got := ContainerAllocation(c); got != nil {
			t.Errorf("ContainerAllocation(%s, %d MiB) = %+v, want nil", c.State, c.MemMiB, got)
		}
		if n := corrosion.ContainerMemoryByHost([]corrosion.ContainerRecord{c})["node-2"]; n != 0 {
			t.Errorf("snapshot counts %d MiB for %s/%d MiB, want 0", n, c.State, c.MemMiB)
		}
	}
	if n := corrosion.ContainerMemoryByHost([]corrosion.ContainerRecord{ct})["node-2"]; n != got.MemMiB {
		t.Errorf("snapshot counts %d MiB, ContainerAllocation %d: the two rules disagree", n, got.MemMiB)
	}
}

// 1947 MiB allocatable: a 1900 MiB container fits (a VM would need 2028).
func TestSelectBatch_ContainerChargesNoQemuOverhead(t *testing.T) {
	results, err := SelectBatch(labHosts()[1:2], nil, nil, nil, nil, time.Time{}, []Request{{
		VMName: "c", Container: true, MemMiBNeeded: 1900,
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["c"].Host != "node-2" {
		t.Fatalf("1900 MiB container = %+v, want node-2 (no qemu overhead)", results["c"])
	}
}

// A container's cpu figure is not a vCPU reservation: 15 allocatable vCPU on
// node-2, a container asking for 64 still places.
func TestSelectBatch_ContainerChargesNoVCPU(t *testing.T) {
	results, err := SelectBatch(labHosts()[1:2], nil, nil, nil, nil, time.Time{}, []Request{{
		VMName: "c", Container: true, CPUNeeded: 64, MemMiBNeeded: 256,
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["c"].Host != "node-2" {
		t.Fatalf("container with cpu 64 = %+v, want node-2 (container CPU is not host-counted)", results["c"])
	}
}

// A container placed earlier in a batch holds its memory and nothing else: no
// VMCount slot (so no overhead charged to it) and no vCPU.
func TestSelectBatch_CommittedContainerHoldsMemoryOnly(t *testing.T) {
	hosts := labHosts()[1:2]
	hosts[0].CPUTotal = 1 // 4×1 − 1 = 3 allocatable vCPU
	results, err := SelectBatch(hosts, nil, nil, nil, nil, time.Time{}, []Request{
		{VMName: "c", Container: true, CPUNeeded: 3, MemMiBNeeded: 1000},
		// 1947 − 1000 = 947 free; 800+128 = 928 fits only if c took no overhead,
		// and 3 vCPU fits only if c took none.
		{VMName: "vm", CPUNeeded: 3, MemMiBNeeded: 800},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm"].Host != "node-2" {
		t.Fatalf("vm after container = %+v, want node-2", results["vm"])
	}
}

// A container update replaces what the container holds, by the same rule.
func TestSelectBatch_ContainerUpdateReplacesItsMemory(t *testing.T) {
	ct := corrosion.ContainerRecord{HostName: "node-2", Name: "c", State: "running", MemMiB: 1500}
	ctMem := corrosion.ContainerMemoryByHost([]corrosion.ContainerRecord{ct})
	results, err := SelectBatch(labHosts()[1:2], nil, nil, ctMem, nil, time.Time{}, []Request{{
		VMName: "c", Container: true, MemMiBNeeded: 1600, PinHost: "node-2", Replaces: ContainerAllocation(ct),
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["c"].Host != "node-2" {
		t.Fatalf("container update = %+v, want node-2", results["c"])
	}
}

// A container's memory shortfall is reported without an overhead it does not pay.
func TestSelectBatch_ContainerRejectionHasNoOverhead(t *testing.T) {
	results, err := SelectBatch(labHosts()[1:2], nil, nil, nil, nil, time.Time{}, []Request{{
		VMName: "c", Container: true, MemMiBNeeded: 2000,
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	want := "node-2: memory (needs 2000 MiB, 1947 free)"
	if e := results["c"].Err; e == nil || !strings.Contains(e.Error(), want) {
		t.Fatalf("Err = %v, want it to contain %q", e, want)
	}
}
