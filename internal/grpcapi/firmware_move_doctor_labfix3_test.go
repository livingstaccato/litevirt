package grpcapi

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// cleaningMarker puts run's marker in cleaning, as a cleanup stopped at its
// first step leaves it.
func cleaningMarker(t *testing.T, r *fwlRig, run *liveFirmwareRun) fwmig.Marker {
	t.Helper()
	m := run.marker
	m.Phase = fwmig.PhaseCleaning
	if err := r.src.fwRecords().PutMarker(m); err != nil {
		t.Fatal(err)
	}
	return m
}

// removeTarget is `lv host rm --dead dst-host` after its proof-grade fence.
func removeTarget(t *testing.T, r *fwlRig) {
	t.Helper()
	r.fenceTarget()
	if err := corrosion.DeleteHost(context.Background(), r.src.db, "dst-host"); err != nil {
		t.Fatal(err)
	}
	if h, err := corrosion.GetHost(context.Background(), r.src.db, "dst-host"); err != nil || h != nil {
		t.Fatalf("fixture: dst-host still a member (%+v, %v)", h, err)
	}
}

// Re-review 2, I-A (1): a stopped cleanup whose target was removed with `lv
// host rm --dead` keeps holding: a removed host has no row to be fenced on,
// and the source's copy may be the only one that can still run. The doctor's
// --accept-source takes the removed target's proof of its last life.
//
// Mutations: hold only on HostProvedOff — the cleanup undefines and wipes,
// red; the doctor reads HostProvedOff — the return is refused, red.
func TestFwmigCleanup_HoldsAfterTheTargetIsRemoved(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	cleaningMarker(t, r, run)
	removeTarget(t, r)
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st == libvirtfake.StateRunning {
		t.Fatalf("source domain %s (defined %v) after the cleanup retry, want defined and shut off", st, ok)
	}
	r.requireSourceIntact("after the cleanup retry")
	requireMarker(t, r, fwmig.PhaseCleaning, "")
	_, err := r.doctor(actAcceptSource, withAck)
	r.resolved(err, "src-host", "stopped")
	r.requireSourceIntact("after --accept-source")
}

// Re-review 2, I-A (2): a return that landed and stopped before its unmark,
// whose target is then removed, is finished by the recovery's fence
// resolution, which takes the removed target's proof: no marker is left to
// refuse `lv start`.
//
// Mutation: fence resolution reads HostProvedOff — the marker stays, red.
func TestRecovery_FinishesAReturnWhoseTargetWasRemoved(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	cleaningMarker(t, r, run)
	r.fenceTarget()
	o := fwDoctorAfterReturnHook
	fwDoctorAfterReturnHook = func() error { return errors.New("daemon died after the return") }
	_, _ = r.doctor(actAcceptSource, withAck)
	fwDoctorAfterReturnHook = o
	removeTarget(t, r)
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left after the recovery: %s (from %s): %s", m.Phase, m.ParkedFrom, m.Detail)
	}
	if row := r.row(); row.HostName != "src-host" || row.State != "stopped" {
		t.Errorf("row %s on %s, want stopped on src-host", row.State, row.HostName)
	}
	r.requireSourceIntact("after the recovery")
}

// Re-review 2, m-B: a re-run of an interrupted return from cleaning (marker
// target_unreachable, parked from cleaning) still refuses when the source's
// domain is no longer defined.
//
// Mutation: check the definition only for a marker in cleaning — the return
// lands with no domain here, red.
func TestDoctorFirmwareMove_ParkedFromCleaningNeedsTheDomain(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	m := cleaningMarker(t, r, run)
	// The cleanup undefined the domain before the marker was parked.
	if err := r.srcFake.UndefineFirmwareMoveLeftover(fwlVM, fwLiveUUID, m.Attempt); err != nil {
		t.Fatal(err)
	}
	pm, err := m.Park(fwmig.PhaseTargetUnreachable)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.src.fwRecords().PutMarker(pm); err != nil {
		t.Fatal(err)
	}
	r.fenceTarget()
	before := r.snap()
	_, err = r.doctor(actAcceptSource, withAck)
	r.refused(err, "already undefined the VM's domain", before)
}

// Re-review 2, m-C: the end of a move leaves another source's cleanup_failed
// open.
//
// Mutation: resolve cleanup_failed by VM only — red.
func TestDoctorFirmwareMove_ExitLeavesAnotherSourcesCleanupFailed(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCommitted)
	if err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{
		Code: condFwmigCleanupFailed, VM: fwlVM, Attempt: "a-later-hop", Source: "dst-host", Target: "third-host",
		Detail: "the later hop's cleanup stopped", Action: "test",
	}); err != nil {
		t.Fatal(err)
	}
	r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
	r.fenceTarget()
	_, err := r.doctor(actAcceptSource, withAck)
	r.resolved(err, "src-host", "stopped")
	requireFwmigCondition(t, r.src, condFwmigCleanupFailed)
}

// Re-review 2, m-D: an owed-DISCARD record whose return never landed (the
// row names the target for the incarnation, and no marker of the attempt is
// here) is dropped, with no critical condition and no advice the doctor would
// refuse; one its move's marker still names is left to the move.
//
// Mutations: drop the never-landed rule — the record stays, red; drop the
// marker rule — discard_owed is raised while the move still owns it, red.
func TestRetryOwedDiscards_AReturnThatNeverLanded(t *testing.T) {
	put := func(t *testing.T, r *fwlRig, m fwmig.Marker) {
		t.Helper()
		if err := r.src.fwRecords().PutOwedDiscard(fwmig.OwedDiscard{VM: m.VM, Binding: m.Binding, Target: m.Target, Since: m.Since}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("no_marker_dropped", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		put(t, r, run.marker)
		if err := r.src.fwRecords().RemoveMarker(fwlVM); err != nil {
			t.Fatal(err)
		}
		r.src.RetryOwedFirmwareDiscardsOnce(context.Background())
		if owed, _ := r.src.fwRecords().ListOwedDiscards(); len(owed) != 0 {
			t.Errorf("owed discards %+v, want none", owed)
		}
		requireNoFwmigCondition(t, r.src, condFwmigDiscardOwed)
		if st, ok := r.dstFake.RawState(fwlVM); !ok || st == "" {
			t.Errorf("the target's copy was touched (%s, %v)", st, ok)
		}
	})
	t.Run("marker_left_to_the_move", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.park(run, fwmig.PhaseTargetUnreachable, "an operator is returning the VM")
		put(t, r, run.marker)
		r.src.RetryOwedFirmwareDiscardsOnce(context.Background())
		requireNoFwmigCondition(t, r.src, condFwmigDiscardOwed)
		if owed, _ := r.src.fwRecords().ListOwedDiscards(); len(owed) != 1 {
			t.Errorf("owed discards %+v, want the move's", owed)
		}
	})
}

// lab-2 D2: the seed a move wrote on its target for the copy goes when that
// copy is discarded there (a DISCARD, or an operator's --discard-target),
// and a seed of another VM of the name is kept.
//
// Mutation: drop the seed removal from the hold quarantine — red.
func TestDiscard_RemovesTheDiscardedCopysSeed(t *testing.T) {
	for _, owner := range []string{fwLiveUUID, "another-vm-uuid"} {
		t.Run(owner, func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			run := r.crashAt(fwmig.PhaseMigrating)
			r.land()
			r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
			r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
			r.park(run, fwmig.PhaseTargetRan, "the target holds a domain the abort could not account for")
			iso := lv.CloudInitISOPath(r.dst.dataDir, fwlVM)
			r.write(iso, []byte("seed"))
			if err := cloudinit.StampSeed(iso, owner); err != nil {
				t.Fatal(err)
			}
			_, err := r.doctor(actDiscard, withStop)
			r.resolved(err, "src-host", "running")
			_, statErr := os.Stat(iso)
			if gone := os.IsNotExist(statErr); gone != (owner == fwLiveUUID) {
				t.Errorf("seed stamped for %s gone=%v after the discard", owner, gone)
			}
		})
	}
}

// lab-2 D2: the reconciler's quarantine of a firmware leftover whose row
// names another host takes the leftover's seed (stamped for its uuid) with
// it.
//
// Mutation: drop the seed removal from quarantineLeftoverFirmware — red.
func TestReconciler_LeftoverQuarantineRemovesItsSeed(t *testing.T) {
	ctx := context.Background()
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
	r.fenceTarget()
	if _, err := r.doctor(actAcceptSource, withAck); err != nil {
		t.Fatalf("accept-source: %v", err)
	}
	r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
	r.dstFake.SetStateReason(fwlVM, "destroyed")
	// The leftover holds no hold or record here any more.
	_ = r.dst.fwRecords().RemoveHold(fwlVM)
	_ = r.dst.fwRecords().RemoveLeftover(fwlVM)
	iso := lv.CloudInitISOPath(r.dst.dataDir, fwlVM)
	r.write(iso, []byte("seed"))
	if err := cloudinit.StampSeed(iso, fwLiveUUID); err != nil {
		t.Fatal(err)
	}
	rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
	rc.SetFirmwareStore(r.dstStore)
	rc.ReconcileOnce(ctx)
	if _, ok := r.dstFake.RawState(fwlVM); ok {
		t.Fatal("fixture: the reconciler did not take the leftover")
	}
	if _, err := os.Stat(iso); !os.IsNotExist(err) {
		t.Errorf("the quarantined leftover's seed is still there (%v)", err)
	}
}
