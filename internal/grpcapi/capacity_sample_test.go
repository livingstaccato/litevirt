package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// The union rules, pinned one by one. These are what make a rogue runtime
// COST something: without them placement admits against a database view the
// runtime has already outgrown.

func obsInv(complete bool, ws ...runtimeWorkload) runtimeInventory {
	return runtimeInventory{Host: "h1", Complete: complete, SampledAt: "2026-08-04T10:00:00Z", Workloads: ws}
}

func TestCapacityObservation_MatchingWorkloadChargesGreater(t *testing.T) {
	inv := obsInv(true,
		runtimeWorkload{Kind: corrosion.WorkloadVM, Name: "grown", State: health.RuntimeRunning, CPU: 8, MemoryMiB: 8192},
		runtimeWorkload{Kind: corrosion.WorkloadVM, Name: "match", State: health.RuntimeRunning, CPU: 2, MemoryMiB: 2048},
	)
	vms := []corrosion.VMRecord{
		{Name: "grown", State: "running", CPUActual: 4, MemActual: 4096}, // runtime outgrew the DB
		{Name: "match", State: "running", CPUActual: 2, MemActual: 2048},
		{Name: "db-only", State: "running", CPUActual: 1, MemActual: 1024}, // probe raced a start
	}
	obs := computeCapacityObservation("h1", inv, vms, nil)
	if obs.DBCPU != 7 || obs.DBMemMiB != 7168 {
		t.Fatalf("db charge = %d/%d, want 7/7168", obs.DBCPU, obs.DBMemMiB)
	}
	// grown: max(8,4)=8; match: 2; db-only: 1 → 11 vCPU. Memory likewise.
	if obs.EffectiveCPU != 11 || obs.EffectiveMemMiB != 11264 {
		t.Fatalf("effective = %d/%d, want 11/11264 (greater-of for grown, DB kept for db-only)",
			obs.EffectiveCPU, obs.EffectiveMemMiB)
	}
	if !obs.Complete {
		t.Fatalf("complete observation marked incomplete: %s", obs.Detail)
	}
	if obs.ExtraCPU != 4 || obs.ExtraMemMiB != 4096 {
		t.Fatalf("extra = %d/%d, want the grown delta 4/4096", obs.ExtraCPU, obs.ExtraMemMiB)
	}
}

func TestCapacityObservation_RuntimeOnlyWorkloadAdds(t *testing.T) {
	inv := obsInv(true,
		// A VM: a rogue container is charged memory only
		// (TestCapacityObservation_ContainerChargesMemoryOnly).
		runtimeWorkload{Kind: corrosion.WorkloadVM, Name: "rogue", State: health.RuntimeRunning, CPU: 2, MemoryMiB: 1024},
	)
	obs := computeCapacityObservation("h1", inv, nil, nil)
	if obs.EffectiveCPU != 2 || obs.EffectiveMemMiB != 1024 {
		t.Fatalf("effective = %d/%d, want the rogue's 2/1024", obs.EffectiveCPU, obs.EffectiveMemMiB)
	}
	if obs.ExtraCPU != 2 || obs.ExtraMemMiB != 1024 {
		t.Fatalf("extra = %d/%d, want 2/1024", obs.ExtraCPU, obs.ExtraMemMiB)
	}
	if !obs.Complete {
		t.Fatal("a CAPPED rogue is attributable — the observation stays complete")
	}
	if obs.Detail == "" {
		t.Fatal("a rogue must be named in the detail")
	}
}

func TestCapacityObservation_UncappedRogueMakesIncomplete(t *testing.T) {
	inv := obsInv(true,
		runtimeWorkload{Kind: corrosion.WorkloadContainer, Name: "unbounded", State: health.RuntimeRunning, Uncapped: true},
	)
	obs := computeCapacityObservation("h1", inv, nil, nil)
	if obs.Complete {
		t.Fatal("an uncapped runtime-only container must make the observation INCOMPLETE — its consumption cannot be attributed")
	}
}

func TestCapacityObservation_ProbeErrorMakesIncomplete(t *testing.T) {
	inv := obsInv(true,
		runtimeWorkload{Kind: corrosion.WorkloadVM, Name: "wedged", State: health.RuntimeRunning, ProbeError: "dump xml: timeout"},
	)
	obs := computeCapacityObservation("h1", inv, nil, nil)
	if obs.Complete {
		t.Fatal("a failed per-item probe must make the observation incomplete")
	}
	// Inventory-level incompleteness propagates too.
	obs = computeCapacityObservation("h1", obsInv(false), nil, nil)
	if obs.Complete {
		t.Fatal("an incomplete inventory must make the observation incomplete")
	}
}

// TestCapacityObservation_StoppedIsNotCharged: neither a stopped DB row nor a
// defined-stopped runtime domain consumes running capacity.
func TestCapacityObservation_StoppedIsNotCharged(t *testing.T) {
	inv := obsInv(true,
		runtimeWorkload{Kind: corrosion.WorkloadVM, Name: "sleeper", State: health.RuntimeDefinedStopped, CPU: 8, MemoryMiB: 8192},
	)
	vms := []corrosion.VMRecord{{Name: "sleeper", State: "stopped", CPUActual: 8, MemActual: 8192}}
	obs := computeCapacityObservation("h1", inv, vms, nil)
	if obs.EffectiveCPU != 0 || obs.EffectiveMemMiB != 0 {
		t.Fatalf("stopped workload charged %d/%d, want 0/0", obs.EffectiveCPU, obs.EffectiveMemMiB)
	}
}

// A container's cpu_limit is a cap in cores, not a reservation, so capacity
// charges a container its memory and nothing else — the rule placement uses
// (corrosion.ContainerHoldsHostMemory). The runtime side must follow it too:
// a matched container whose cgroup reports its 8-core cap is not 8 vCPU of
// EXTRA, and a rogue container costs only the memory it is capped at.
func TestCapacityObservation_ContainerChargesMemoryOnly(t *testing.T) {
	inv := obsInv(true,
		runtimeWorkload{Kind: corrosion.WorkloadContainer, Name: "web-ct", State: health.RuntimeRunning, CPU: 8, MemoryMiB: 512},
		runtimeWorkload{Kind: corrosion.WorkloadContainer, Name: "rogue", State: health.RuntimeRunning, CPU: 4, MemoryMiB: 256},
	)
	cts := []corrosion.ContainerRecord{
		{Name: "web-ct", HostName: "h1", State: "running", CPULimit: 8, MemMiB: 512},
		{Name: "idle", HostName: "h1", State: "stopped", CPULimit: 2, MemMiB: 1024},
	}
	obs := computeCapacityObservation("h1", inv, nil, cts)
	if obs.DBCPU != 0 || obs.DBMemMiB != 512 {
		t.Fatalf("db charge = %dc/%dMiB, want 0c/512MiB (memory of the running container only)", obs.DBCPU, obs.DBMemMiB)
	}
	if obs.ExtraCPU != 0 || obs.ExtraMemMiB != 256 {
		t.Fatalf("extra = %dc/%dMiB, want 0c/256MiB (the rogue's memory; no container cpu, no double count of web-ct)",
			obs.ExtraCPU, obs.ExtraMemMiB)
	}
	if obs.EffectiveCPU != 0 || obs.EffectiveMemMiB != 768 {
		t.Fatalf("effective = %dc/%dMiB, want 0c/768MiB", obs.EffectiveCPU, obs.EffectiveMemMiB)
	}
}
