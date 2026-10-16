package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Effective host capacity — what the host is ACTUALLY carrying, not what the
// database believes it allocated. Computed over the UNION of database and
// runtime workloads, so a rogue runtime the database does not know about still
// consumes headroom in every placement decision:
//
//   - a workload present on BOTH sides charges the GREATER configured
//     allocation (a runtime grown past its DB spec is really using the grown
//     size; a DB spec bigger than the runtime is still the promise placement
//     must honor);
//   - a DB-only RUNNING workload keeps its DB charge (the runtime probe may
//     have raced a start);
//   - a runtime-only workload ADDS its runtime allocation on top;
//   - an UNCAPPED runtime-only container, or any probe failure, makes the
//     observation INCOMPLETE — its consumption cannot be attributed, and
//     placement must treat the host as unknown, never as headroom.
//
// A container is charged its memory and nothing else, on both sides: its cpu
// is a cap in cores, not a reservation (the rule placement uses).
//
// Only the observed host samples itself (host_name is the row's ownership),
// from its own runtime inventory — replicated telemetry is never the input.

// SampleHostCapacity computes and publishes this host's effective capacity
// observation. Called by the daemon's capacity sampler loop.
func (s *Server) SampleHostCapacity(ctx context.Context) error {
	_, err := s.sampleHostCapacity(ctx)
	return err
}

// sampleHostCapacity is SampleHostCapacity returning what it published.
func (s *Server) sampleHostCapacity(ctx context.Context) (corrosion.HostCapacityObservation, error) {
	inv := s.collectRuntimeInventory(ctx)
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		return corrosion.HostCapacityObservation{}, fmt.Errorf("list VMs: %w", err)
	}
	cts, err := corrosion.ListContainers(ctx, s.db, s.hostName)
	if err != nil {
		return corrosion.HostCapacityObservation{}, fmt.Errorf("list containers: %w", err)
	}
	obs := computeCapacityObservation(s.hostName, inv, vms, cts)
	return obs, corrosion.UpsertHostCapacityObservation(ctx, s.db, obs)
}

// defaultCapacityResampleCheck is how often the sampler looks for a change to
// the database's record of this host's workloads (capacitySampler.poll).
const defaultCapacityResampleCheck = 2 * time.Second

// SetCapacityResampleCheckForTest sets how often RunCapacitySampler checks for
// a change to this host's workloads. Zero is the default.
func (s *Server) SetCapacityResampleCheckForTest(d time.Duration) { s.capacityResampleCheck = d }

// RunCapacitySampler publishes this host's observation on a fixed interval,
// and again whenever the database's record of this host's workloads changes
// (capacitySampler).
func (s *Server) RunCapacitySampler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	check := s.capacityResampleCheck
	if check <= 0 {
		check = defaultCapacityResampleCheck
	}
	cs := &capacitySampler{
		fingerprint: func(ctx context.Context) (string, error) {
			return corrosion.HostWorkloadFingerprint(ctx, s.db, s.hostName)
		},
		sample: s.sampleHostCapacity,
	}
	cs.take(ctx, false)
	full := time.NewTicker(interval)
	defer full.Stop()
	poll := time.NewTicker(check)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-full.C:
			cs.take(ctx, false)
		case <-poll.C:
			cs.poll(ctx)
		}
	}
}

// capacitySampler decides when this host samples its capacity.
type capacitySampler struct {
	fingerprint func(context.Context) (string, error)
	sample      func(context.Context) (corrosion.HostCapacityObservation, error)

	// last is the workload fingerprint read before the last good sample;
	// known is false until there is one.
	last  string
	known bool
	// confirm asks the next poll to sample again.
	confirm bool
}

// take samples now. changed marks a sample taken because the workloads changed.
//
// The fingerprint is read BEFORE the sample, so a change that lands while the
// sample runs differs from it and is sampled again at the next check.
func (c *capacitySampler) take(ctx context.Context, changed bool) {
	fp, ferr := c.fingerprint(ctx)
	obs, err := c.sample(ctx)
	c.confirm = false
	if err != nil {
		slog.Warn("capacity sampler", "error", err)
		return
	}
	c.last, c.known = fp, ferr == nil
	// A sample's runtime read can begin before the change it was taken for
	// (concurrent inventory reads share one libvirt scan) and so still charge
	// a workload that has gone. Only load that a sample charges outside the
	// database can be stale that way, so only then is it confirmed, once.
	c.confirm = changed && (obs.ExtraCPU != 0 || obs.ExtraMemMiB != 0 || !obs.Complete)
}

// poll samples when the database's record of this host's workloads has changed
// since the last sample, and confirms a change-triggered sample (take). A check
// that cannot read the database samples nothing: the interval still does.
func (c *capacitySampler) poll(ctx context.Context) {
	if c.confirm {
		c.take(ctx, false)
		return
	}
	fp, err := c.fingerprint(ctx)
	if err != nil {
		return
	}
	if !c.known || fp != c.last {
		c.take(ctx, true)
	}
}

// computeCapacityObservation is the pure union computation (see the file doc).
func computeCapacityObservation(
	host string,
	inv runtimeInventory,
	vms []corrosion.VMRecord,
	cts []corrosion.ContainerRecord,
) corrosion.HostCapacityObservation {
	obs := corrosion.HostCapacityObservation{
		HostName:  host,
		Complete:  inv.Complete,
		SampledAt: inv.SampledAt,
	}
	var details []string
	if !inv.Complete {
		details = append(details, "runtime inventory incomplete: "+strings.Join(inv.Errors, "; "))
	}

	// The database's charge, by the rules placement uses (dbVMCharge,
	// dbContainerCharge).
	type dbEntry struct{ cpu, mem int }
	dbSide := map[finding]dbEntry{}
	for _, vm := range vms {
		if cpu, mem, ok := dbVMCharge(vm); ok {
			dbSide[finding{kind: corrosion.WorkloadVM, target: vm.Name}] = dbEntry{cpu: cpu, mem: mem}
		}
	}
	for _, ct := range cts {
		if mem, ok := dbContainerCharge(ct); ok {
			dbSide[finding{kind: corrosion.WorkloadContainer, target: ct.Name}] = dbEntry{mem: mem}
		}
	}
	for _, e := range dbSide {
		obs.DBCPU += e.cpu
		obs.DBMemMiB += e.mem
	}

	// Union: start from the DB charge, then walk the runtime side.
	obs.EffectiveCPU, obs.EffectiveMemMiB = obs.DBCPU, obs.DBMemMiB
	for _, w := range inv.Workloads {
		if w.State != health.RuntimeRunning {
			continue
		}
		if w.ProbeError != "" {
			obs.Complete = false
			details = append(details, fmt.Sprintf("%s %s: %s", w.Kind, w.Name, w.ProbeError))
		}
		// A container's cpu is a cap in cores, not a reservation: capacity
		// never charges it, on the runtime side any more than on the DB side.
		if w.Kind == corrosion.WorkloadContainer {
			w.CPU = 0
		}
		key := finding{kind: w.Kind, target: w.Name}
		if db, matched := dbSide[key]; matched {
			// Matching workload: charge the greater allocation per dimension.
			if w.CPU > db.cpu {
				obs.EffectiveCPU += w.CPU - db.cpu
				details = append(details, fmt.Sprintf("%s %s runs at %d vCPU, DB says %d", w.Kind, w.Name, w.CPU, db.cpu))
			}
			if w.MemoryMiB > db.mem {
				obs.EffectiveMemMiB += w.MemoryMiB - db.mem
				details = append(details, fmt.Sprintf("%s %s runs at %d MiB, DB says %d", w.Kind, w.Name, w.MemoryMiB, db.mem))
			}
			continue
		}
		// Runtime-only: the database does not know this workload exists.
		if w.Uncapped {
			// Unbounded consumption that cannot be attributed: the whole
			// observation is unknowable, not merely bigger.
			obs.Complete = false
			details = append(details, fmt.Sprintf("uncapped runtime-only container %q", w.Name))
			continue
		}
		obs.EffectiveCPU += w.CPU
		obs.EffectiveMemMiB += w.MemoryMiB
		details = append(details, fmt.Sprintf("runtime-only %s %q (+%d vCPU/+%d MiB)", w.Kind, w.Name, w.CPU, w.MemoryMiB))
	}
	obs.ExtraCPU = obs.EffectiveCPU - obs.DBCPU
	obs.ExtraMemMiB = obs.EffectiveMemMiB - obs.DBMemMiB

	sort.Strings(details)
	obs.Detail = strings.Join(details, "; ")
	return obs
}

// dbVMCharge is what the database says a VM holds on its host: a running or
// starting VM at its recorded actuals. ok=false for a VM that holds nothing.
//
// Those are the states every reader of the observation already charges from
// the database: placement (countsAgainstHost: running, starting, creating) and
// admission (corrosion.SumVMResourcesByHost: running, starting). A qemu running
// for a VM in any other state is runtime-only load here, so no reader counts it
// twice and none counts it not at all.
func dbVMCharge(vm corrosion.VMRecord) (cpu, mem int, ok bool) {
	if vm.State != "running" && vm.State != "starting" {
		return 0, 0, false
	}
	return vm.CPUActual, vm.MemActual, true
}

// dbContainerCharge is what the database says a container holds on its host:
// its memory, by corrosion.ContainerHoldsHostMemory — the rule placement
// counts and releases containers by. A container's cpu_limit is a cap in
// cores, not a reservation, so it is never charged. ok is true for every
// running container: one with no memory cap holds 0 MiB but is still the
// database's record of that runtime, so the runtime side matches it rather
// than reading it as a rogue.
func dbContainerCharge(ct corrosion.ContainerRecord) (mem int, ok bool) {
	if ct.State != "running" {
		return 0, false
	}
	if corrosion.ContainerHoldsHostMemory(ct) {
		mem = ct.MemMiB
	}
	return mem, true
}
