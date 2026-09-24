package health

import (
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The start grace.
//
// For healthCheckGracePeriod after a VM starts, a failed probe does not count
// toward the healthcheck's action (sweep). "Starts" means every start of a new
// incarnation on this host, not only the VM's creation: a VM restarted by its
// own healthcheck is booting again, and probing it straight into another
// restart is the loop the grace exists to prevent.
//
// The grace runs from when THIS host saw the start, which is one of:
//
//   - the VM was created less than the grace ago (created_at);
//   - this checker started the VM itself — a healthcheck restart or a
//     restart-policy start (noteStarted);
//   - a sweep saw the VM running where the previous sweep saw it not running
//     (an operator start, a redefine and start, a restart policy);
//   - a sweep saw it running under a different owner host, owner epoch or
//     created_at than before (a migration or failover here, a recreate);
//   - a sweep saw it for the first time, other than on the checker's first
//     sweep (it arrived here).
//
// It is deliberately NOT "the row changed". The incarnation a verdict is bound
// to includes the row's updated_at, which moves on any write to the VM row; a
// grace renewed by every such write could hold a failing VM's action off
// indefinitely. The signals above are ones only a start produces.
//
// The first sweep after the checker starts sees every VM for the first time
// and cannot tell one that has run for weeks from one that just started, so a
// first sighting there opens no grace (created_at still covers a new VM). A
// restart through a path that leaves the row running throughout — the
// RestartVM RPC destroys and starts the domain under a running row — is not
// visible to the sweep and opens no grace; the healthcheck's action backoff
// still applies to it.

// vmSighting is what the sweep last saw of one owned VM.
type vmSighting struct {
	state      string
	host       string
	ownerEpoch int64
	createdAt  string
	// startedAt is when this host last saw the VM start; zero when it has
	// not seen one.
	startedAt time.Time
}

// observeStarts folds one sweep's listing of this host's VMs into the
// sightings, recording a start for each VM that has just started. Called with
// the listing a successful ListVMs returned, after pruneVMState.
func (v *VMChecker) observeStarts(vms []corrosion.VMRecord, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sightings == nil {
		v.sightings = make(map[string]*vmSighting)
	}
	for i := range vms {
		vm := &vms[i]
		s := v.sightings[vm.Name]
		started := false
		if vm.State == "running" {
			switch {
			case s == nil:
				started = v.swept
			case s.state != "running",
				s.host != vm.HostName,
				s.ownerEpoch != vm.OwnerEpoch,
				s.createdAt != vm.CreatedAt:
				started = true
			}
		}
		if s == nil {
			s = &vmSighting{}
			v.sightings[vm.Name] = s
		}
		s.state, s.host, s.ownerEpoch, s.createdAt = vm.State, vm.HostName, vm.OwnerEpoch, vm.CreatedAt
		if started {
			v.startedLocked(vm.Name, s, now)
		}
	}
	v.swept = true
}

// noteStarted records that this checker has just started vm itself.
func (v *VMChecker) noteStarted(name string, at time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sightings == nil {
		v.sightings = make(map[string]*vmSighting)
	}
	s := v.sightings[name]
	if s == nil {
		s = &vmSighting{state: "running"}
		v.sightings[name] = s
	}
	v.startedLocked(name, s, at)
}

// startedLocked records a start. The consecutive failures counted against the
// previous incarnation say nothing about this one, so they are dropped; the
// count of actions without recovery is kept — it is what the action backoff
// is measured from. Caller holds mu.
func (v *VMChecker) startedLocked(name string, s *vmSighting, at time.Time) {
	s.startedAt = at
	if v.failures != nil {
		delete(v.failures, name)
	}
}

// inStartGrace reports whether vm is within healthCheckGracePeriod of its
// creation or of the last start this host saw.
func (v *VMChecker) inStartGrace(vm corrosion.VMRecord, now time.Time) bool {
	if created, err := time.Parse(time.RFC3339, vm.CreatedAt); err == nil && now.Sub(created) < healthCheckGracePeriod {
		return true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if s := v.sightings[vm.Name]; s != nil && !s.startedAt.IsZero() {
		return now.Sub(s.startedAt) < healthCheckGracePeriod
	}
	return false
}
