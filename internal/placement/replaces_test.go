package placement

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// labHosts reproduces the lab where the bug was found: 4 vCPU / 2971 MiB
// hosts. Under the default capacity policy that is 1947 MiB allocatable
// (2971 − the 1024 MiB reserve) and 15 vCPU (4×4 − 1).
func labHosts() []corrosion.HostRecord {
	return makeHostsWithResources([]struct {
		name string
		cpu  int
		mem  int
	}{{"node-1", 4, 2971}, {"node-2", 4, 2971}, {"node-3", 4, 2971}})
}

// labDB is VM db, 1 vCPU / 1 GiB, running on node-2.
func labDB() corrosion.VMRecord { return makeVM("db", "node-2", 1, 1024, "running") }

func TestVMAllocation_CountsOnlyWhatTheSnapshotCounts(t *testing.T) {
	got := VMAllocation(labDB())
	if got == nil || *got != (Allocation{Host: "node-2", CPU: 1, MemMiB: 1024, VM: true}) {
		t.Fatalf("VMAllocation(running db) = %+v, want node-2 / 1 vCPU / 1024 MiB / VM", got)
	}
	if got := VMAllocation(makeVM("db", "node-2", 1, 1024, "stopped")); got != nil {
		t.Fatalf("a stopped VM holds nothing, VMAllocation = %+v, want nil", got)
	}
}

// The lab failure: a pinned update of a VM that fills most of its host was
// charged on top of its own current allocation. 1947 − 1024 − 128 (db's
// overhead) = 795 MiB "free", and the update's 768+128 did not fit — nor did an
// unchanged 1024+128 with only a label added.
func TestSelectBatch_PinnedUpdateReplacesItsOwnAllocation(t *testing.T) {
	for _, mem := range []int{768, 1024} {
		db := labDB()
		results, err := SelectBatch(labHosts(), []corrosion.VMRecord{db}, nil, nil, nil, time.Time{}, []Request{{
			VMName: "db", CPUNeeded: 1, MemMiBNeeded: mem, PinHost: "node-2",
			Replaces: VMAllocation(db),
		}})
		if err != nil {
			t.Fatalf("mem %d: SelectBatch: %v", mem, err)
		}
		if got := results["db"]; got.Host != "node-2" {
			t.Fatalf("mem %d: pinned update of db = %+v, want node-2 (db's own 1024 MiB counted twice)", mem, got)
		}
	}
}

// A pinned update that genuinely no longer fits is still refused — and the
// refusal names the resource and the numbers, with db's released allocation.
func TestSelectBatch_PinnedUpdateThatDoesNotFitSaysWhy(t *testing.T) {
	db := labDB()
	results, err := SelectBatch(labHosts(), []corrosion.VMRecord{db}, nil, nil, nil, time.Time{}, []Request{{
		VMName: "db", CPUNeeded: 1, MemMiBNeeded: 4096, PinHost: "node-2",
		Replaces: VMAllocation(db),
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	got := results["db"]
	if got.Host != "" {
		t.Fatalf("a 4096 MiB db cannot fit a 1947 MiB host, got %q", got.Host)
	}
	if !errors.Is(got.Err, ErrNoEligibleHost) {
		t.Fatalf("Err = %v, want ErrNoEligibleHost", got.Err)
	}
	want := "db needs 4224 MiB of memory on node-2 (4096 MiB + 128 MiB qemu overhead), " +
		"which has 1947 MiB free after db's current 1024 MiB is released"
	if got.Err == nil || !strings.Contains(got.Err.Error(), want) {
		t.Fatalf("Err = %v\nwant it to contain %q", got.Err, want)
	}
}

// After a replaced VM is placed, the batch snapshot holds its NEW allocation
// exactly once: a following create sees db's 768 MiB (+overhead), not 1024+768.
func TestSelectBatch_ReplacedAllocationIsCommittedOnce(t *testing.T) {
	db := labDB()
	// 1947 − (768+128) = 1051 free after the update. A 900 MiB create needs
	// 1028: fits only if db's old 1024 was released rather than kept alongside.
	results, err := SelectBatch(labHosts()[1:2], []corrosion.VMRecord{db}, nil, nil, nil, time.Time{}, []Request{
		{VMName: "db", CPUNeeded: 1, MemMiBNeeded: 768, PinHost: "node-2", Replaces: VMAllocation(db)},
		{VMName: "cache", CPUNeeded: 1, MemMiBNeeded: 900},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["db"].Host != "node-2" || results["cache"].Host != "node-2" {
		t.Fatalf("results = %+v, want both on node-2", results)
	}
	// And one more byte than that no longer fits: the new allocation IS charged.
	results, err = SelectBatch(labHosts()[1:2], []corrosion.VMRecord{db}, nil, nil, nil, time.Time{}, []Request{
		{VMName: "db", CPUNeeded: 1, MemMiBNeeded: 768, PinHost: "node-2", Replaces: VMAllocation(db)},
		{VMName: "cache", CPUNeeded: 1, MemMiBNeeded: 924},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["cache"].Host != "" {
		t.Fatalf("cache 924+128 > 1051 free after db's new 768+128, got %q", results["cache"].Host)
	}
}

// A replica-limited VM does not count itself against its own max_per_node.
func TestSelectBatch_PinnedUpdateDoesNotCountItselfAsAReplica(t *testing.T) {
	web := makeVM("web-1", "node-2", 1, 512, "running")
	results, err := SelectBatch(labHosts(), []corrosion.VMRecord{web}, nil, nil, nil, time.Time{}, []Request{{
		VMName: "web-1", VMBaseName: "web", MaxPerNode: 1, CPUNeeded: 1, MemMiBNeeded: 512,
		PinHost: "node-2", Replaces: VMAllocation(web),
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["web-1"].Host != "node-2" {
		t.Fatalf("web-1 update = %+v, want node-2 (it is its own replica)", results["web-1"])
	}
}

// A replaced VM that finds no host keeps its OLD allocation in the batch: the
// snapshot must not leak its release to the requests that follow.
func TestSelectBatch_UnplacedReplacementRestoresItsAllocation(t *testing.T) {
	db := labDB()
	results, err := SelectBatch(labHosts()[1:2], []corrosion.VMRecord{db}, nil, nil, nil, time.Time{}, []Request{
		{VMName: "db", CPUNeeded: 1, MemMiBNeeded: 4096, PinHost: "node-2", Replaces: VMAllocation(db)},
		// 1000+128 fits in 1947 only if db's 1024+128 was wrongly left released.
		{VMName: "cache", CPUNeeded: 1, MemMiBNeeded: 1000},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["cache"].Host != "" {
		t.Fatalf("cache placed on %q: db's release leaked past its failed placement", results["cache"].Host)
	}
}

// Failover and migration place a VM on a host OTHER than the one its record
// names, so the destination never counts it: the VM's own allocation sits on
// the source. A destination with exactly enough room for it must accept it.
func TestSelectBatch_MoveDoesNotCountTheVMOnTheDestination(t *testing.T) {
	hosts := labHosts()
	hosts[1].State = "offline" // db's host has failed
	db := labDB()
	// 1947 allocatable: 1819+128 fills node-1 exactly.
	db.MemActual = 1819
	results, err := SelectBatch(hosts[:2], []corrosion.VMRecord{db}, nil, nil, nil, time.Time{}, []Request{{
		VMName: "db", CPUNeeded: 1, MemMiBNeeded: 1819,
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["db"].Host != "node-1" {
		t.Fatalf("failover of db = %+v, want node-1", results["db"])
	}
}

// When placement fails, the error says why per candidate host, not merely
// "no eligible host".
func TestSelectBatch_NoEligibleHostNamesEachRejection(t *testing.T) {
	hosts := labHosts()
	hosts[0].Labels = map[string]string{"tier": "web"}
	hosts[0].MemTotal = 8192 // room enough: only its label rejects it
	hosts[1].State = "draining"
	hosts[2].Labels = map[string]string{"tier": "data"}
	results, err := SelectBatch(hosts, nil, nil, nil, nil, time.Time{}, []Request{{
		VMName: "db", CPUNeeded: 1, MemMiBNeeded: 2048, RequireLabels: map[string]string{"tier": "data"},
	}})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	e := results["db"].Err
	var ne *NoEligibleHostError
	if !errors.As(e, &ne) {
		t.Fatalf("Err = %v, want *NoEligibleHostError", e)
	}
	for _, want := range []string{
		"node-1 lacks required label tier=data",
		"node-2 is not active (state: draining)",
		"db needs 2176 MiB of memory on node-3 (2048 MiB + 128 MiB qemu overhead), which has 1947 MiB free",
	} {
		if !strings.Contains(e.Error(), want) {
			t.Errorf("Err = %v\nwant it to contain %q", e, want)
		}
	}
	if len(ne.Rejections) != 3 {
		t.Errorf("Rejections = %+v, want one per host", ne.Rejections)
	}
}
