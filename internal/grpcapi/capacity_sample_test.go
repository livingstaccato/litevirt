package grpcapi

import (
	"context"
	"errors"
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

// A VM the database records as "starting" is already charged by placement
// (countsAgainstHost) and by admission (SumVMResourcesByHost). Its qemu is
// often running before the row says "running" (a restart, a reconciler start),
// and the sample charged that qemu again as runtime-only load, on top of the
// database's charge, until the next sample.
func TestCapacityObservation_StartingVMIsNotChargedTwice(t *testing.T) {
	inv := obsInv(true,
		runtimeWorkload{Kind: corrosion.WorkloadVM, Name: "booting", State: health.RuntimeRunning, CPU: 1, MemoryMiB: 1024},
	)
	vms := []corrosion.VMRecord{{Name: "booting", State: "starting", CPUActual: 1, MemActual: 1024}}
	obs := computeCapacityObservation("h1", inv, vms, nil)
	if obs.ExtraCPU != 0 || obs.ExtraMemMiB != 0 {
		t.Fatalf("extra = %d/%d for a starting VM the database already charges; want 0/0 (%s)",
			obs.ExtraCPU, obs.ExtraMemMiB, obs.Detail)
	}
	if obs.DBCPU != 1 || obs.DBMemMiB != 1024 {
		t.Fatalf("db charge = %d/%d, want the starting VM's 1/1024", obs.DBCPU, obs.DBMemMiB)
	}
}

// The other side of the same rule: a VM in a state neither placement nor
// admission charges ("migrating", "creating", "stopped") whose qemu runs here
// is real load the database does not count, and stays runtime-only.
func TestCapacityObservation_UncountedStatesWithALiveQemuStayRuntimeOnly(t *testing.T) {
	for _, st := range []string{"migrating", "creating", "stopped", "pending"} {
		inv := obsInv(true,
			runtimeWorkload{Kind: corrosion.WorkloadVM, Name: "mover", State: health.RuntimeRunning, CPU: 1, MemoryMiB: 1024},
		)
		vms := []corrosion.VMRecord{{Name: "mover", State: st, CPUActual: 1, MemActual: 1024}}
		obs := computeCapacityObservation("h1", inv, vms, nil)
		if obs.ExtraCPU != 1 || obs.ExtraMemMiB != 1024 {
			t.Errorf("state %q: extra = %d/%d, want the live qemu's 1/1024", st, obs.ExtraCPU, obs.ExtraMemMiB)
		}
	}
}

// fakeSampling scripts capacitySampler's two inputs.
type fakeSampling struct {
	fp        string
	fpErr     error
	obs       corrosion.HostCapacityObservation
	sampleErr error
	samples   int
}

func (f *fakeSampling) sampler() *capacitySampler {
	return &capacitySampler{
		fingerprint: func(context.Context) (string, error) { return f.fp, f.fpErr },
		sample: func(context.Context) (corrosion.HostCapacityObservation, error) {
			f.samples++
			return f.obs, f.sampleErr
		},
	}
}

var cleanObs = corrosion.HostCapacityObservation{HostName: "h1", Complete: true}

// The lab 2 failure (ac2139ed): a sample taken while a VM migrated away charged
// its qemu as runtime-only load, and placement kept subtracting it for the rest
// of the 60 s interval, after the VM had left. A change to the database's record
// of this host's workloads now samples again at the next check.
func TestCapacitySampler_ResamplesWhenTheHostsWorkloadsChange(t *testing.T) {
	ctx := context.Background()
	f := &fakeSampling{fp: "with-mover", obs: cleanObs}
	cs := f.sampler()
	cs.take(ctx, false)
	cs.poll(ctx)
	if f.samples != 1 {
		t.Fatalf("samples = %d after a check with nothing changed; want 1 (the first)", f.samples)
	}
	f.fp = "mover-gone"
	cs.poll(ctx)
	if f.samples != 2 {
		t.Fatalf("samples = %d after the host's workloads changed; want 2", f.samples)
	}
	cs.poll(ctx)
	if f.samples != 2 {
		t.Fatalf("samples = %d after a second check with nothing new; want still 2", f.samples)
	}
}

// A sample can pair a runtime read that began before the change with the
// database after it (concurrent inventory reads share one libvirt scan), and
// then charge a workload that has already gone. A change-triggered sample that
// charges any runtime-only load, or cannot account for the host, is confirmed
// once at the next check; one that charges nothing is not.
func TestCapacitySampler_ConfirmsAChangeTriggeredSampleThatChargedRuntimeLoad(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		obs     corrosion.HostCapacityObservation
		confirm bool
	}{
		{"clean", cleanObs, false},
		{"runtime-only memory", corrosion.HostCapacityObservation{Complete: true, ExtraMemMiB: 1024}, true},
		{"runtime-only cpu", corrosion.HostCapacityObservation{Complete: true, ExtraCPU: 1}, true},
		{"incomplete", corrosion.HostCapacityObservation{Complete: false}, true},
	} {
		f := &fakeSampling{fp: "a", obs: cleanObs}
		cs := f.sampler()
		cs.take(ctx, false)
		f.fp, f.obs = "b", tc.obs
		cs.poll(ctx) // the change
		cs.poll(ctx) // the confirmation, if any
		cs.poll(ctx) // never a second one
		want := 2
		if tc.confirm {
			want = 3
		}
		if f.samples != want {
			t.Errorf("%s: samples = %d, want %d", tc.name, f.samples, want)
		}
	}
	// A sample taken on the interval is not confirmed, whatever it charged: a
	// real rogue would otherwise be re-read on every check.
	f := &fakeSampling{fp: "a", obs: corrosion.HostCapacityObservation{Complete: true, ExtraMemMiB: 1024}}
	cs := f.sampler()
	cs.take(ctx, false)
	cs.poll(ctx)
	if f.samples != 1 {
		t.Fatalf("samples = %d; an interval sample must not be confirmed", f.samples)
	}
}

// A check that cannot read the database samples nothing (the interval still
// does), and a sample whose fingerprint could not be read is retried at the
// next check that can.
func TestCapacitySampler_FingerprintErrors(t *testing.T) {
	ctx := context.Background()
	f := &fakeSampling{fp: "a", obs: cleanObs}
	cs := f.sampler()
	cs.take(ctx, false)
	f.fpErr = errors.New("database is locked")
	cs.poll(ctx)
	if f.samples != 1 {
		t.Fatalf("samples = %d after a check that could not read the database; want 1", f.samples)
	}

	f = &fakeSampling{fp: "a", fpErr: errors.New("database is locked"), obs: cleanObs}
	cs = f.sampler()
	cs.take(ctx, false)
	f.fpErr = nil
	cs.poll(ctx)
	if f.samples != 2 {
		t.Fatalf("samples = %d; a sample with no fingerprint must be retaken at the next good check", f.samples)
	}
}

// A sample that failed published nothing, so the change it was taken for is
// sampled again at the next check.
func TestCapacitySampler_AFailedSampleIsRetakenAtTheNextCheck(t *testing.T) {
	ctx := context.Background()
	f := &fakeSampling{fp: "a", obs: cleanObs}
	cs := f.sampler()
	cs.take(ctx, false)
	f.fp, f.sampleErr = "b", errors.New("upsert: database is locked")
	cs.poll(ctx)
	f.sampleErr = nil
	cs.poll(ctx)
	if f.samples != 3 {
		t.Fatalf("samples = %d; the change whose sample failed must be sampled again", f.samples)
	}
	cs.poll(ctx)
	if f.samples != 3 {
		t.Fatalf("samples = %d after the retake succeeded; want no more", f.samples)
	}
}
