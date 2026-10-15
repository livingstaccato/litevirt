package health

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A held start is an operator's `lv start` libvirt has not answered within
// its wait (grpcapi markStartHeld): the start goes on in the daemon that
// asked for it, its row says starting (HeldStartDetailPrefix), and it holds
// the VM's start lease (OperatorStartLockHolder, renewed) until libvirt
// answers, when that daemon records the outcome. A daemon that restarts
// first loses the start, while libvirtd still completes it. Its lease then
// stood until its TTL ran out, up to ten minutes after libvirt had started
// the domain, before the reconciler took the row over, and nothing recorded
// the start's outcome (lab 2, 339a79f4, B2 concern 2).
//
// So the reconciler takes over such a lease once nothing in this daemon
// holds it (SetHeldStartProbe: no start of the VM in flight here) and
// libvirt says the domain runs: the start has answered, and succeeded. It
// then records the VM running as for any start it finds already running,
// and records the start's outcome once, with the row's move from starting
// to running. A domain that does not run proves nothing (a start may still
// be queued behind another job, reading shut off meanwhile): its lease runs
// out as before, and the reconciler then re-drives the start.

// HeldStartDetailPrefix starts the state detail of a VM's row while a held
// start goes on; the RFC 3339 time the start was asked for follows it.
const HeldStartDetailPrefix = "operator start: libvirt has not answered the start asked for at "

// HeldStartDetail is the state detail of a VM's row while the start asked
// for at since is held.
func HeldStartDetail(since time.Time) string {
	return HeldStartDetailPrefix + since.UTC().Format(time.RFC3339)
}

// heldStartAsked is when the held start a row's detail names was asked for
// (as written), and whether the detail names one.
func heldStartAsked(detail string) (string, bool) {
	if !strings.HasPrefix(detail, HeldStartDetailPrefix) {
		return "", false
	}
	return strings.TrimPrefix(detail, HeldStartDetailPrefix), true
}

// SetHeldStartProbe wires the probe that says whether a start of a VM this
// daemon asked libvirt for has not settled yet (grpcapi
// Server.HasStartInFlight): while one has, the held start's lease is that
// start's. nil: a held start's lease is never taken over.
func (r *Reconciler) SetHeldStartProbe(fn func(name string) bool) { r.heldStartLive = fn }

// SetVMEventRecorder wires how the reconciler records a VM event (grpcapi
// Server.RecordVMEvent); nil records none.
func (r *Reconciler) SetVMEventRecorder(fn func(ctx context.Context, vm, typ, result, detail string)) {
	r.recordVMEvent = fn
}

// takeOverOrphanedHeldStart takes vm's start lease when it is a held start's
// that no start in this daemon holds and libvirt says the domain runs (see
// above). It reports whether this reconciler now holds the lease.
func (r *Reconciler) takeOverOrphanedHeldStart(ctx context.Context, vm corrosion.VMRecord) bool {
	if r.heldStartLive == nil || r.virt == nil || vm.State != "starting" {
		return false
	}
	if _, ok := heldStartAsked(vm.StateDetail); !ok {
		return false
	}
	holder := OperatorStartLockHolder(r.hostName)
	by, _, ok, err := ReadVMStartLease(ctx, r.db, vm.Name)
	if err != nil || !ok || by != holder || r.heldStartLive(vm.Name) {
		return false
	}
	st, err := r.virtWait.domainState(r.virt, vm.Name)
	if err != nil || st != RuntimeRunning {
		return false
	}
	slog.Info("reconciler: a held start's daemon restarted before libvirt answered it, and libvirt has started the domain; its start lease is taken over",
		"vm", vm.Name)
	ReleaseVMStartLease(ctx, r.db, holder, vm.Name)
	return r.acquireVMLock(ctx, vm.Name)
}

// recordHeldStartRan records, once, that the held start a row said was going
// on (its detail, before the reconciler recorded the VM running) has started
// the domain, when no start in this daemon is left to record it.
func (r *Reconciler) recordHeldStartRan(ctx context.Context, name, detail string) {
	asked, ok := heldStartAsked(detail)
	if !ok || r.recordVMEvent == nil || (r.heldStartLive != nil && r.heldStartLive(name)) {
		return
	}
	r.recordVMEvent(ctx, name, "vm.started", "ok",
		fmt.Sprintf("libvirt answered the start asked for at %s after the daemon that asked for it had restarted; the VM is running", asked))
}
