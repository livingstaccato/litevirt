package health

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ErrStartDeferred marks a start-preparation answer that is not a failure:
// the start has to wait — its storage did not answer (Ceph re-electing its
// monitors during the very event that caused a failover), or the walk has no
// time left to ask it. The hooks wired with SetHardwareStartPreparer and
// SetStartDeferral return an error that errors.Is this.
//
// A deferred start is never parked in error, whatever it is: a proof-less
// LOCAL recovery (onboot autostart, a running row whose domain is gone, an
// interrupted start) waits in "starting", which reconcile re-drives, and a
// failover keeps its proof in_progress, back in "pending"
// (deferPendingStart). The VM is walked first on the next pass.
var ErrStartDeferred = errors.New("start deferred")

// startDeferredSet is the VMs whose start was deferred since the last walk
// began: the next walk takes them first, so the same VMs — late in the
// walk's fixed order, behind a slow one — are not deferred on every pass.
type startDeferredSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (s *startDeferredSet) add(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]bool{}
	}
	s.m[name] = true
}

// take returns the set and empties it: a VM deferred again re-enters it.
func (s *startDeferredSet) take() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.m
	s.m = nil
	return m
}

// SetStartDeferral wires the check the reconciler makes BEFORE it does any
// work for a VM's start — its lock, a proof's claim, the define: an answer
// that errors.Is ErrStartDeferred leaves the VM exactly as it is, to be walked
// first on the next pass. The daemon wires the Server's CephStartDeferral (a
// VM whose ceph key must be proven, with less time left than that takes).
// nil — unwired — defers nothing.
func (r *Reconciler) SetStartDeferral(fn func(ctx context.Context, vm *corrosion.VMRecord) error) {
	r.startDeferral = fn
}

// deferredBeforeWork reports whether vm's start is deferred before any work
// for it, remembering it to walk first if so.
func (r *Reconciler) deferredBeforeWork(ctx context.Context, vm corrosion.VMRecord) bool {
	if r.startDeferral == nil {
		return false
	}
	err := r.startDeferral(ctx, &vm)
	if err == nil || !errors.Is(err, ErrStartDeferred) {
		return false
	}
	slog.Info("reconciler: start deferred to the next pass, where it goes first", "vm", vm.Name, "reason", err)
	r.startDeferred.add(vm.Name)
	return true
}

// deferStart records a start the preparation deferred (ErrStartDeferred):
// re-armed with deferPendingStart — "pending" with its proof, "starting"
// without — and walked first on the next pass. A proof-less transfer is
// remembered as one (deferredTransfers), as for an image still in transit.
func (r *Reconciler) deferStart(ctx context.Context, vmName, proofID string, transfer bool, cause error) {
	slog.Info("reconciler: start deferred; the next pass re-drives it first", "vm", vmName, "reason", cause)
	if transfer && proofID == "" {
		r.deferredTransfers.add(vmName)
	}
	r.startDeferred.add(vmName)
	r.deferPendingStart(ctx, vmName, proofID, "start deferred: "+cause.Error())
}

// deferredFirst orders a walk's VMs with the deferred ones first, each group
// in the walk's own order.
func deferredFirst(vms []corrosion.VMRecord, deferred map[string]bool) []corrosion.VMRecord {
	if len(deferred) == 0 {
		return vms
	}
	out := append([]corrosion.VMRecord(nil), vms...)
	sort.SliceStable(out, func(i, j int) bool { return deferred[out[i].Name] && !deferred[out[j].Name] })
	return out
}
