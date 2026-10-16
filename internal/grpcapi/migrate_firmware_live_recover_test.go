package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/vfio"
)

// T-24: restart recovery of a live firmware move on its source (spec §8.1),
// one sub-test per row, on the fwlRig. crashAt builds the state a source
// daemon leaves when it dies with its marker in a phase — through the move's
// own steps, so the target's hold, domain and state are what that phase
// implies — and restart runs the recovery as the daemon does at start.

// crashAt runs os1's move up to phase p, as a source that then died: the
// marker in p, the target's hold, domain and state as the move left them.
func (r *fwlRig) crashAt(p fwmig.Phase) *liveFirmwareRun {
	r.t.Helper()
	ctx := context.Background()
	vm := r.row()
	target, err := corrosion.GetHost(ctx, r.src.db, "dst-host")
	if err != nil || target == nil {
		r.t.Fatalf("target host: %v %v", target, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, r.src.db, fwlVM)
	if err != nil {
		r.t.Fatal(err)
	}
	elig, err := r.src.liveFirmwareStageA(ctx, liveFirmwareMove{vm: vm, target: target, withStorage: r.storage, disks: disks})
	if err != nil {
		r.t.Fatalf("stage A: %v", err)
	}
	run, err := r.src.beginLiveFirmwareMove(ctx, vm, target, elig)
	if err != nil {
		r.t.Fatalf("Prepare: %v", err)
	}
	step := func(err error) {
		r.t.Helper()
		if err != nil {
			r.t.Fatalf("crashAt(%s): %v", p, err)
		}
	}
	switch p {
	case fwmig.PhasePreparing:
		step(r.src.putLiveFirmwareMarker(run, fwmig.PhasePreparing))
		return run
	case fwmig.PhasePrepared:
		return run
	}
	step(corrosion.UpdateVMState(ctx, r.src.db, fwlVM, "migrating", "→ dst-host"))
	step(r.src.putLiveFirmwareMarker(run, fwmig.PhaseMigrating))
	if p == fwmig.PhaseMigrating {
		return run
	}
	r.land()
	st, err := r.srcFake.DomainStateReason(fwlVM)
	step(err)
	run.marker.SrcStopReason = st.Reason
	if !r.sbOnly {
		run.marker.SrcPermallSHA256 = fwtSHA(fwlPermall)
	}
	run.marker.SrcNvramSHA256 = fwtSHA(fwlNvram)
	step(r.src.putLiveFirmwareMarker(run, fwmig.PhaseCutover))
	if p == fwmig.PhaseCutover {
		return run
	}
	step(r.src.verifyLiveFirmwareMove(ctx, run))
	if p == fwmig.PhaseVerified {
		return run
	}
	step(r.src.finalizeMigrationOwnership(ctx, r.row(), "dst-host", r.storage, disks))
	step(r.src.liveFirmwareCommitted(run))
	if p == fwmig.PhaseCommitted {
		return run
	}
	old := liveFirmwareSourceCleanup
	liveFirmwareSourceCleanup = nil
	defer func() { liveFirmwareSourceCleanup = old }()
	step(r.src.releaseLiveFirmwareMove(ctx, run))
	if p == fwmig.PhaseReleased {
		return run
	}
	if p != fwmig.PhaseCleaning {
		r.t.Fatalf("crashAt(%s): not a phase this builds", p)
	}
	// Cleaning, crashed part way: the bundle written, the leftover undefined.
	m := run.marker
	m.Phase = fwmig.PhaseCleaning
	step(r.src.fwRecords().PutMarker(m))
	run.marker = m
	step(r.src.writeRetainedFirmwareBundle(m))
	step(r.srcFake.UndefineFirmwareMoveLeftover(fwlVM, fwLiveUUID, m.Attempt))
	return run
}

// land is libvirt landing os1 on the target as a firmware move does: the
// target domain paused with the copied permall, the source shut off with
// reason migrated (or unknown, ReportSourceReasonUnknown).
func (r *fwlRig) land() {
	r.t.Helper()
	if err := r.srcFake.MigrateToTarget(fwlVM, "qemu+tls://dst-host/system", lv.MigrateParams{Live: true, FirmwareLive: true}); err != nil {
		r.t.Fatalf("land the migration: %v", err)
	}
}

// withLeaseJournal gives the source an operation journal.
func (r *fwlRig) withLeaseJournal() *opjournal.Journal {
	r.t.Helper()
	j, err := opjournal.Open(r.t.TempDir())
	if err != nil {
		r.t.Fatal(err)
	}
	r.src.SetOpJournal(j)
	return j
}

// restart is the daemon's start: the recovery of every marker, waited for.
func (r *fwlRig) restart() {
	r.src.RecoverFirmwareMoves(context.Background())
	r.src.MarkStartupWired()
	r.src.fwLive.recovering.Wait()
}

// fastRecovery shortens the recovery's job poll.
func fastRecovery(t *testing.T) {
	t.Helper()
	o := firmwareRecoveryJobPoll
	firmwareRecoveryJobPoll = 5 * time.Millisecond
	t.Cleanup(func() { firmwareRecoveryJobPoll = o })
}

func (r *fwlRig) requireTargetPausedWithHold(why string) {
	r.t.Helper()
	if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StatePaused {
		r.t.Errorf("%s: target domain %q, want paused", why, st)
	}
	if _, ok := r.hold(); !ok {
		r.t.Errorf("%s: the target's hold is gone", why)
	}
}

// requireNothingCommitted: the row still names the source and no commit ran.
func (r *fwlRig) requireNothingCommitted(why string) {
	r.t.Helper()
	if r.log.has("commit") {
		r.t.Errorf("%s: committed", why)
	}
	if vm := r.row(); vm.HostName != "src-host" {
		r.t.Errorf("%s: row on %s, want src-host", why, vm.HostName)
	}
}

func TestRecoverFirmwareMoves(t *testing.T) {
	// ── preparing, prepared ──

	// Mutation: leave the marker after the target answered — red.
	t.Run("preparing/anything", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhasePreparing)
		r.restart()
		r.requireUndone("after recovering a preparing marker")
	})
	// The row was written migrating before the marker (§6.1 step 5): it is
	// set from the running source domain.
	//
	// Mutation: skip the row — red.
	t.Run("prepared/row_migrating", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhasePrepared)
		if err := corrosion.UpdateVMState(context.Background(), r.src.db, fwlVM, "migrating", "→ dst-host"); err != nil {
			t.Fatal(err)
		}
		r.restart()
		r.requireUndone("after recovering a prepared marker with the row migrating")
	})
	// A refused abort parks target_unreachable (§8.1), retried each interval,
	// not target_ran; nothing on either host goes.
	//
	// Mutation: remove the marker on a refusal; park target_ran — red.
	t.Run("prepared/abort_refused", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhasePrepared)
		r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
			return &pb.AbortLiveFirmwareTargetResponse{Refused: true, HoldState: string(fwmig.HoldPrepared),
				TargetDomain: &pb.TargetDomain{Present: true, State: "shutoff", Uuid: fwLiveUUID}, Detail: "a domain of the VM is defined here"}, nil
		}
		r.restart()
		requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhasePrepared)
		requireFwmigCondition(t, r.src, condFwmigTargetUnreachable)
		if _, ok := r.hold(); !ok {
			t.Error("the target's hold went on a refused abort")
		}
		r.requireSourceIntact("after a refused abort")
	})
	// Mutation: remove the marker when the abort is not answered — red.
	t.Run("prepared/target_unreachable", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhasePrepared)
		r.peerC.dialErr = func() error { return status.Error(codes.Unavailable, "connection refused") }
		r.restart()
		requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhasePrepared)
		if vm := r.row(); vm.State != "running" {
			t.Errorf("row %s, want running", vm.State)
		}
	})

	// ── migrating ──

	// Active with a migration job: recovery waits for the job, then looks
	// again. Here the job lands the guest: cutover, Verify, commit, Release,
	// cleanup — and no abort was sent while the job ran.
	//
	// Mutation: treat the job as M1 (abort while it runs) — red.
	t.Run("migrating/job_running", func(t *testing.T) {
		fastRecovery(t)
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		var polls atomic.Int32
		r.srcFake.JobActive = func(string) (bool, error) {
			if polls.Add(1) < 3 {
				return true, nil
			}
			r.land()
			return false, nil
		}
		r.restart()
		if polls.Load() < 3 {
			t.Fatalf("the job was looked at %d times, want recovery to wait for it", polls.Load())
		}
		if len(r.aborts()) != 0 {
			t.Fatalf("aborts %v sent while libvirt still ran the migration", r.aborts())
		}
		r.requireCleanedUp("after the migration job ended")
	})
	// Active, running, no job: M1. Abort PRE_CUTOVER, the row restored, the
	// marker removed.
	//
	// Mutation: Abort on inactive instead (cutover here) — red.
	t.Run("migrating/running_no_job", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.restart()
		r.requireUndone("after recovering a running source with no job")
		if r.log.has("verify") {
			t.Error("Verify was called before cutover")
		}
	})
	// Active, PAUSED, no job, the target holding no domain: M1p. The source
	// is resumed, the row restored, the marker removed.
	//
	// Mutation: leave a paused source paused — red.
	t.Run("migrating/paused_no_job", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		r.restart()
		r.requireUndone("after recovering a paused source with no job")
	})
	// M1p with a domain on the target: parked source_paused, both guests
	// paused, the row still migrating.
	//
	// Mutation: resume the source anyway — red.
	t.Run("migrating/paused_no_job_target_domain", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		r.restart()
		requireMarker(t, r, fwmig.PhaseSourcePaused, fwmig.PhaseMigrating)
		if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StatePaused {
			t.Errorf("source domain %q, want paused", st)
		}
		r.requireTargetPausedWithHold("source_paused")
		if vm := r.row(); vm.State != "migrating" {
			t.Errorf("row %s, want migrating", vm.State)
		}
	})
	// Inactive, reason migrated: the final state read, cutover, Verify, and
	// the move carried to its end.
	//
	// Mutation: Abort on inactive — red.
	t.Run("migrating/inactive_migrated", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.restart()
		if len(r.aborts()) != 0 {
			t.Fatalf("aborts %v sent for a guest that left", r.aborts())
		}
		r.requireCleanedUp("after recovering a migration that landed")
	})
	// M1b: the migration call failed after the guest left (a Confirm-phase
	// error, a crash), the source stopped with another reason: Verify
	// decides, and MATCH carries the move on.
	//
	// Mutation: Abort on inactive; park on any reason but migrated — red.
	t.Run("migrating/M1b_inactive_other_reason_match", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.srcFake.ReportSourceReasonUnknown = func(string) bool { return true }
		r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.restart()
		r.requireCleanedUp("after M1b with MATCH")
	})
	// A source host reboot after the guest left: reason unknown, and the
	// target's copy does not match: V1b, source_state_suspect (I6), both
	// copies kept, the target paused, nothing discarded.
	//
	// Mutation: V1 on reason unknown — red.
	t.Run("migrating/reboot_mismatch", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.srcFake.ReportSourceReasonUnknown = func(string) bool { return true }
		r.dstFake.CorruptLandedPermall = func(string) bool { return true }
		r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.restart()
		m := requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseCutover)
		if m.SrcStopReason != "unknown" {
			t.Errorf("recorded stop reason %q, want unknown", m.SrcStopReason)
		}
		requireAbortModes(t, r)
		r.requireTargetPausedWithHold("V1b")
		r.requireSourceIntact("V1b")
		r.requireNothingCommitted("V1b")
		requireFwmigCondition(t, r.src, condFwmigSourceStateSuspect)
	})
	// Inactive, unreadable state: parked source_state_missing (V2), nothing
	// read as final.
	//
	// Mutation: read an unreadable domain as inactive and verify — red.
	t.Run("migrating/unreadable", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.FailDomainState = func(name string) error {
			if name == fwlVM {
				return errors.New("injected: libvirt does not answer")
			}
			return nil
		}
		r.restart()
		requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseMigrating)
		if r.log.has("verify") {
			t.Error("Verify was called with the source state unreadable")
		}
		r.requireTargetPausedWithHold("V2 unreadable")
		r.requireNothingCommitted("V2 unreadable")
	})
	// Inactive, the final state missing: V2.
	//
	// Mutation: treat missing as a mismatch — red.
	t.Run("migrating/inactive_state_missing", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.land()
		if err := os.Remove(r.srcPermallPath()); err != nil {
			t.Fatal(err)
		}
		r.restart()
		requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseMigrating)
		requireAbortModes(t, r)
		r.requireTargetPausedWithHold("V2 missing")
	})
	// Inactive with another reason, Verify NOT_HELD and no domain there: V4,
	// the guest runs nowhere; the row stopped on the source, the state kept,
	// the marker removed.
	//
	// Mutation: keep the marker on V4 — red.
	t.Run("migrating/inactive_not_held_V4", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
		if err := r.dst.fwRecords().RemoveHold(fwlVM); err != nil {
			t.Fatal(err)
		}
		r.restart()
		if m, ok := r.marker(); ok {
			t.Fatalf("marker left %+v", m)
		}
		if vm := r.row(); vm.State != "stopped" || vm.HostName != "src-host" {
			t.Errorf("row %s on %s, want stopped on src-host", vm.State, vm.HostName)
		}
		r.requireSourceIntact("V4")
	})
	// NOT_HELD with a domain there: V3, parked target_unreachable.
	//
	// Mutation: V4 whatever TargetDomain says — red.
	t.Run("migrating/inactive_not_held_domain_V3", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseMigrating)
		r.land()
		if err := r.dst.fwRecords().RemoveHold(fwlVM); err != nil {
			t.Fatal(err)
		}
		r.restart()
		requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCutover)
		r.requireSourceIntact("V3")
		r.requireNothingCommitted("V3")
	})

	// ── cutover ──

	// Mutation: skip Verify (commit straight from cutover) — red via the log.
	t.Run("cutover/unchanged", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseCutover)
		r.restart()
		if !r.log.has("verify") {
			t.Error("committed without Verify")
		}
		r.requireCleanedUp("after recovering a cutover marker")
	})
	// The source state changed since the cutover recorded it: parked
	// source_state_suspect, nothing verified, committed or deleted.
	//
	// Mutation: skip the re-hash — red.
	t.Run("cutover/changed", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseCutover)
		changed := []byte("an NVRAM written after the cutover")
		r.write(r.srcStore.NvramPath(fwlVM), changed)
		r.restart()
		requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseCutover)
		if b, _ := os.ReadFile(r.srcStore.NvramPath(fwlVM)); string(b) != string(changed) {
			t.Errorf("source NVRAM %q, want the changed one kept", b)
		}
		r.requireTargetPausedWithHold("changed at cutover")
		r.requireNothingCommitted("changed at cutover")
	})
	// V1 by the recorded reason (migrated): DISCARD, the row stopped on the
	// source, the target's copy quarantined, the marker removed.
	//
	// Mutation: V1b for a recorded migrated — red.
	t.Run("cutover/V1_mismatch_migrated", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.dstFake.CorruptLandedPermall = func(string) bool { return true }
		r.crashAt(fwmig.PhaseCutover)
		r.restart()
		requireAbortModes(t, r, modeDiscard)
		if m, ok := r.marker(); ok {
			t.Fatalf("marker left %+v", m)
		}
		if vm := r.row(); vm.State != "stopped" || vm.HostName != "src-host" {
			t.Errorf("row %s on %s, want stopped on src-host", vm.State, vm.HostName)
		}
		if !r.quarantined() {
			t.Error("the target's copy was not quarantined")
		}
		requireFwmigCondition(t, r.src, condFwmigUnverified)
		r.requireSourceIntact("V1")
	})
	// V1b by the recorded reason (unknown): source_state_suspect.
	//
	// Mutation: V1 on reason unknown — red.
	t.Run("cutover/V1b_mismatch_unknown", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.srcFake.ReportSourceReasonUnknown = func(string) bool { return true }
		r.dstFake.CorruptLandedPermall = func(string) bool { return true }
		r.crashAt(fwmig.PhaseCutover)
		r.restart()
		requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseCutover)
		requireAbortModes(t, r)
		r.requireTargetPausedWithHold("V1b at cutover")
	})
	// A source domain active again after the cutover (only a path outside
	// the guard runs it) is never committed or released: two copies would
	// run.
	//
	// Mutation: skip the source check — red.
	t.Run("cutover/source_active_again", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseCutover)
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.restart()
		requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseCutover)
		r.requireTargetPausedWithHold("source active at cutover")
		r.requireNothingCommitted("source active at cutover")
	})

	// ── verified ──

	// The row names the source: commit, then Release and the cleanup.
	//
	// Mutation: skip the commit (leave verified) — red.
	t.Run("verified/row_names_source", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseVerified)
		r.restart()
		if !r.log.has("commit") {
			t.Error("no commit")
		}
		r.requireCleanedUp("after recovering a verified marker")
	})
	// The row names the target for this incarnation: the commit landed; the
	// marker goes on to committed, Release and the cleanup.
	//
	// Mutation: commit only when the row names the source and stop — red.
	t.Run("verified/row_names_target", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseVerified)
		disks, _ := corrosion.GetVMDisks(context.Background(), r.src.db, fwlVM)
		if err := r.src.finalizeMigrationOwnership(context.Background(), r.row(), "dst-host", false, disks); err != nil {
			t.Fatal(err)
		}
		r.restart()
		r.requireCleanedUp("after recovering a verified marker whose commit landed")
	})
	// A source domain active again is never committed.
	//
	// Mutation: skip the source check before the commit — red.
	t.Run("verified/source_active_again", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseVerified)
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.restart()
		requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseVerified)
		r.requireNothingCommitted("source active at verified")
		r.requireTargetPausedWithHold("source active at verified")
	})

	// ── committed, released ──

	// Mutation: skip Release for committed — red.
	t.Run("committed/release", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseCommitted)
		r.restart()
		r.requireCleanedUp("after recovering a committed marker")
	})
	// Released: Release sent again (the target answers that the guest runs
	// there), then the cleanup.
	//
	// Mutation: leave a released marker — red.
	t.Run("released/target_holds_guest", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseReleased)
		releases := strings.Count(strings.Join(r.log.get(), ","), "release")
		r.restart()
		if got := strings.Count(strings.Join(r.log.get(), ","), "release"); got <= releases {
			t.Error("the target was not checked (Release not sent again) before the cleanup")
		}
		r.requireCleanedUp("after recovering a released marker")
	})
	// Released with the target proved off (review D2-12c I-2): nothing is
	// cleaned up; the move parks for an operator (D-5 --accept-source).
	//
	// Mutation: clean up without checking the target — red.
	t.Run("released/target_fenced", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseReleased)
		r.fenceTarget()
		r.restart()
		requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseReleased)
		r.requireSourceIntact("released with the target fenced")
		if st, ok := r.srcFake.RawState(fwlVM); !ok || st != libvirtfake.StateShutdown {
			t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
		}
		if ents, _ := os.ReadDir(filepath.Join(r.src.dataDir, fwmig.RetainedDir)); len(ents) != 0 {
			t.Errorf("the cleanup began: retained %v", ents)
		}
	})

	// ── cleaning ──

	// Resumed at the first undone step (the undefine done): the bundle kept,
	// the state wiped, the marker removed.
	//
	// Mutation: leave a cleaning marker at start — red.
	t.Run("cleaning/resume", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseCleaning)
		r.restart()
		r.requireCleanedUp("after recovering a cleaning marker")
	})

	// ── owed DISCARD records ──

	// An owed DISCARD (no marker) is sent at start, and the record dropped
	// once answered.
	//
	// Mutation: send no owed DISCARD at start — red.
	t.Run("owed_discard/sent", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.parkUnreachableAtVerify()
		m, _ := r.marker()
		r.fenceTarget()
		if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || !ok {
			t.Fatalf("resolve: %v %v", ok, err)
		}
		r.restart()
		requireAbortModes(t, r, modeDiscard)
		if _, ok, _ := r.src.fwRecords().GetOwedDiscardFor(fwlVM, m.Binding); ok {
			t.Fatal("the owed-discard record is left after the DISCARD answered")
		}
	})
}

// §8.1 "other parked": the interval's pass retries the blocked call. A move
// parked target_unreachable at Verify continues once Verify is answered, and
// the condition of the park it left is resolved.
//
// Mutations: retry nothing; leave the left park's condition open — red.
func TestFirmwareMoveRecovery_RetriesParkedCall(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.parkUnreachableAtVerify()
	requireFwmigCondition(t, r.src, condFwmigTargetUnreachable)
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	r.requireCleanedUp("after the parked Verify was retried")
	requireNoFwmigCondition(t, r.src, condFwmigTargetUnreachable)
}

// A retry that ends in the same park for the same reason writes nothing: no
// marker write, no condition upsert, no event.
//
// Mutation: re-park on every pass — red.
func TestFirmwareMoveRecovery_SameParkWritesNothing(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.parkUnreachableAtVerify()
	r.peerC.verifyAnswer = func(func() (*pb.VerifyLiveFirmwareTargetResponse, error)) (*pb.VerifyLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	before, _, _ := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigTargetUnreachable, "vm", fwlVM)
	m0, _ := r.marker()
	for i := 0; i < 3; i++ {
		r.src.FirmwareMoveRecoveryOnce(context.Background())
	}
	after, _, _ := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigTargetUnreachable, "vm", fwlVM)
	if after.ObserveCount != before.ObserveCount {
		t.Fatalf("the same park was raised %d more times", after.ObserveCount-before.ObserveCount)
	}
	m1 := requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCutover)
	if m1.Detail != m0.Detail {
		t.Errorf("detail changed: %q -> %q", m0.Detail, m1.Detail)
	}
}

// target_ran takes no further step (V5); its condition is raised again when
// it is no longer open.
//
// Mutations: retry Release for target_ran; never re-raise — red.
func TestFirmwareMoveRecovery_TargetRanOnlyReraises(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return &pb.ReleaseLiveFirmwareTargetResponse{Verdict: pb.FirmwareVerdict_FIRMWARE_VERDICT_TARGET_RAN, Detail: "the guest ran"}, nil
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetRan, fwmig.PhaseCommitted)
	if err := r.src.resolveFirmwareMigrationCondition(context.Background(), condFwmigTargetRan, fwlVM); err != nil {
		t.Fatal(err)
	}
	releases := strings.Count(strings.Join(r.log.get(), ","), "release")
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	if got := strings.Count(strings.Join(r.log.get(), ","), "release"); got != releases {
		t.Error("Release was sent again for a move parked target_ran")
	}
	requireMarker(t, r, fwmig.PhaseTargetRan, fwmig.PhaseCommitted)
	requireFwmigCondition(t, r.src, condFwmigTargetRan)
}

// nvram_unconfirmed retries Release; one that now confirms carries the move
// to its cleanup.
//
// Mutation: no retry for nvram_unconfirmed — red.
func TestFirmwareMoveRecovery_NvramUnconfirmedRetriesRelease(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	fwvFast(t, 5*time.Millisecond, 50*time.Millisecond)
	var once atomic.Bool
	r.dstFake.OnRunning = func(string) {
		if once.CompareAndSwap(false, true) {
			r.write(r.dstStore.NvramPath(fwlVM), []byte("a variable the guest wrote at once"))
		}
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseNvramUnconfirmed, fwmig.PhaseCommitted)
	// The guest's NVRAM is the source's final one again.
	r.write(r.dstStore.NvramPath(fwlVM), fwlNvram)
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	r.requireCleanedUp("after the unconfirmed NVRAM confirmed on a retry")
	requireNoFwmigCondition(t, r.src, condFwmigNvramUnconfirmed)
}

// The interval's pass resolves a move parked target_unreachable by fence
// (§7); a pass sends the DISCARD it then owes (the next one at the latest:
// the owed DISCARDs are sent beside the moves, not after them).
//
// Mutation: no fence resolution in the pass — red.
func TestFirmwareMoveRecovery_ResolvesByFence(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.parkUnreachableAtVerify()
	r.fenceTarget()
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v", m)
	}
	if vm := r.row(); vm.State != "stopped" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s, want stopped on src-host", vm.State, vm.HostName)
	}
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	requireAbortModes(t, r, modeDiscard)
}

// A move in progress holds its VM's lock: the pass leaves it alone.
//
// Mutation: wait on (or ignore) the lock — red.
func TestFirmwareMoveRecovery_SkipsLockedVM(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.parkUnreachableAtVerify()
	verifies := strings.Count(strings.Join(r.log.get(), ","), "verify")
	unlock := r.src.lockVM(fwlVM)
	done := make(chan struct{})
	go func() {
		r.src.FirmwareMoveRecoveryOnce(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		unlock()
		t.Fatal("the pass waited on a VM lock a move holds")
	}
	unlock()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCutover)
	if got := strings.Count(strings.Join(r.log.get(), ","), "verify"); got != verifies {
		t.Errorf("Verify sent again under a held lock: %v", r.log.get())
	}
}

// Start-up recovery holds each marker's VM lock from before the server serves
// until its move is resolved or parked.
//
// Mutation: take the lock inside the goroutine — red.
func TestRecoverFirmwareMoves_LocksBeforeReturning(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseMigrating)
	release := make(chan struct{})
	r.srcFake.JobActive = func(string) (bool, error) {
		<-release
		return false, nil
	}
	r.src.RecoverFirmwareMoves(context.Background())
	r.src.MarkStartupWired()
	unlock, ok := r.src.tryLockVM(fwlVM)
	if ok {
		unlock()
		close(release)
		r.src.fwLive.recovering.Wait()
		t.Fatal("the VM's lock was free when RecoverFirmwareMoves returned")
	}
	close(release)
	r.src.fwLive.recovering.Wait()
	r.requireUndone("after the start-up recovery")
}

// Review D2-12c n-1: a released marker left by a cleanup that could not record
// its cleaning phase is taken by the interval's pass (not only at a restart):
// the target checked, then the cleanup.
//
// Mutation: the pass skips released markers — red.
func TestFirmwareMoveRecovery_ReleasedTakenEachPass(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseReleased)
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	r.requireCleanedUp("after the interval's pass over a released marker")
}

// source_state_suspect takes no further step (I6): a move parked because its
// source domain ran again after the cutover is not verified, committed or
// released once that domain is off again — the source's run may have written
// what the target's paused copy does not know of.
//
// Mutation: retry source_state_suspect from its phase — red.
func TestFirmwareMoveRecovery_SourceSuspectTakesNoStep(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseCutover)
	r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
	r.restart()
	requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseCutover)
	r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseCutover)
	if r.log.has("verify") {
		t.Error("Verify was sent for a move parked source_state_suspect")
	}
	r.requireNothingCommitted("source_state_suspect retried")
	r.requireTargetPausedWithHold("source_state_suspect retried")
}

// ── SR-IOV VFs of a recovered move (review D2-13 I-1) ──

const fwlVF = "0000:41:10.0"

// fwlVFs gives os1 an SR-IOV VF in its guest on the source, and the source an
// operation journal, so the move detaches the VF under a migration lease as
// MigrateVM does. targetAttached records the target attaches the source asks
// for.
type fwlVFs struct {
	fs             *pciUnbindRecordingFS
	j              *opjournal.Journal
	targetAttached *[]string
}

func (r *fwlRig) withVF() *fwlVFs {
	r.t.Helper()
	v := &fwlVFs{fs: newPCIUnbindRecordingFS(), targetAttached: &[]string{}}
	r.t.Cleanup(vfio.SetFS(v.fs))
	v.j = r.withLeaseJournal()
	if err := corrosion.UpsertPCIDevice(adminCtx(), r.src.db, corrosion.PCIDeviceRecord{
		HostName: "src-host", Address: fwlVF, Type: "net", VendorID: "8086", VMName: fwlVM}); err != nil {
		r.t.Fatal(err)
	}
	v.fs.setVF(fwlVF)
	v.fs.setBound(fwlVF)
	if err := r.srcFake.AttachHostdev(fwlVM, fwlVF); err != nil {
		r.t.Fatal(err)
	}
	var mu = &r.paramsMu
	old := reattachVFsOnTargetHook
	reattachVFsOnTargetHook = func(target, vm string, vfs []corrosion.PCIDeviceRecord) []string {
		mu.Lock()
		defer mu.Unlock()
		for _, vf := range vfs {
			*v.targetAttached = append(*v.targetAttached, target+":"+vf.Address)
		}
		return nil
	}
	r.t.Cleanup(func() { reattachVFsOnTargetHook = old })
	return v
}

// detachForMove is MigrateVM's step before the migration call: the lease,
// then the VF out of the guest (still owned by the VM).
func (r *fwlRig) detachForMove() {
	r.t.Helper()
	if err := r.src.beginMigrationVFLease(fwlVM, []string{fwlVF}); err != nil {
		r.t.Fatal(err)
	}
	if err := r.src.detachHostdevIfPresent(adminCtx(), fwlVM, fwlVF); err != nil {
		r.t.Fatal(err)
	}
}

// restartWithLeases is the daemon's start: the device leases, then the
// firmware move recovery.
func (r *fwlRig) restartWithLeases() {
	r.src.RecoverDeviceLeases(context.Background())
	r.restart()
}

func (r *fwlRig) srcVFOwner() string {
	r.t.Helper()
	devs, err := corrosion.ListPCIDevices(adminCtx(), r.src.db, "src-host", "")
	if err != nil {
		r.t.Fatal(err)
	}
	for _, d := range devs {
		if d.Address == fwlVF {
			return d.VMName
		}
	}
	return ""
}

func (v *fwlVFs) leaseLeft(t *testing.T) bool {
	t.Helper()
	_, found, err := v.j.Read(deviceLeaseOpID(fwlVM))
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// requireVFsMovedOut: the source's VF released (unowned, lease gone) and the
// target asked to attach one.
func (r *fwlRig) requireVFsMovedOut(v *fwlVFs, why string) {
	r.t.Helper()
	if o := r.srcVFOwner(); o != "" {
		r.t.Errorf("%s: the source's VF is still owned by %q", why, o)
	}
	if v.leaseLeft(r.t) {
		r.t.Errorf("%s: the migration lease is left", why)
	}
	r.paramsMu.Lock()
	got := strings.Join(*v.targetAttached, ",")
	r.paramsMu.Unlock()
	if got != "dst-host:"+fwlVF {
		r.t.Errorf("%s: target attaches %q, want dst-host:%s", why, got, fwlVF)
	}
}

// A move parked at Verify (no restart) and retried by the interval's pass:
// after the commit the source's VF is released and its lease ended, and the
// target is asked to attach one.
//
// Mutations: no VFs on a recovered run; no release after the recovered
// commit; no target attach — red.
func TestFirmwareMoveRecovery_VFsAfterRetriedVerify(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	r.parkUnreachableAtVerify()
	if !v.leaseLeft(t) || r.srcVFOwner() != fwlVM {
		t.Fatalf("parked at Verify: lease %v, owner %q; want the VF held for the move", v.leaseLeft(t), r.srcVFOwner())
	}
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	r.requireCleanedUp("after the retried Verify")
	r.requireVFsMovedOut(v, "after the retried Verify")
}

// A restart while libvirt still runs the migration: the device lease
// recovery leaves the move's lease to the firmware recovery (one owner), which
// waits the job out, commits, releases the source's VF and asks the target to
// attach one.
//
// Mutations: RecoverDeviceLeases takes a marked VM's lease — red.
func TestRecoverFirmwareMoves_VFsAfterRunningJob(t *testing.T) {
	fastRecovery(t)
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	r.crashAt(fwmig.PhaseMigrating)
	r.detachForMove()
	var polls atomic.Int32
	r.srcFake.JobActive = func(string) (bool, error) {
		if polls.Add(1) < 3 {
			return true, nil
		}
		r.land()
		return false, nil
	}
	r.restartWithLeases()
	r.requireCleanedUp("after the job ended")
	r.requireVFsMovedOut(v, "after the job ended")
}

// M1p after a restart: the paused source is resumed and gets its VF back, the
// lease ended; no VF-missing condition.
//
// Mutation: no reattach after the recovered M1p resume — red.
func TestRecoverFirmwareMoves_M1pResumedGuestGetsItsVFs(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	r.crashAt(fwmig.PhaseMigrating)
	r.detachForMove()
	r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
	r.restartWithLeases()
	r.requireUndone("after M1p with a VF")
	if !guestHasHostdev(t, r.src, fwlVM, fwlVF) {
		t.Fatal("the resumed guest runs without its VF")
	}
	if v.leaseLeft(t) {
		t.Error("the lease is left after the VF went back")
	}
	requireNoFwmigCondition(t, r.src, condFwmigVFMissing)
}

// A resumed guest whose VF cannot go back raises firmware_migration_vf_missing:
// it runs without its NIC, and says so.
//
// Mutation: no condition — red.
func TestRecoverFirmwareMoves_VFNotBackRaisesCondition(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	r.crashAt(fwmig.PhaseMigrating)
	r.detachForMove()
	r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
	r.srcFake.FailAttachHostdev = func(string, string, string) error { return errors.New("injected attach failure") }
	r.restartWithLeases()
	if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		t.Fatalf("source domain %q, want resumed", st)
	}
	requireFwmigCondition(t, r.src, condFwmigVFMissing)
	if !v.leaseLeft(t) {
		t.Error("the lease went with the VF out of the guest")
	}
}

// VFs that cannot be read (the lease names a VF with no device row) park the
// move before the guest runs anywhere: the paused source is not resumed.
//
// Mutation: go on without the VFs — red.
func TestRecoverFirmwareMoves_UnreadableVFsPark(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	r.crashAt(fwmig.PhaseMigrating)
	if err := r.src.beginMigrationVFLease(fwlVM, []string{fwlVF, "0000:41:10.7"}); err != nil {
		t.Fatal(err)
	}
	_ = v
	r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
	r.restartWithLeases()
	requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseMigrating)
	if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StatePaused {
		t.Errorf("source domain %q, want left paused", st)
	}
	requireAbortModes(t, r)
}

// ── Review m-5: the remaining rows ──

// An unreadable job state is never read as "no job" (M1 would abort, and
// discard a copy libvirt may still be making): recovery keeps waiting.
//
// Mutation: read an unreadable job as no job — red.
func TestRecoverFirmwareMoves_JobStateUnreadableWaits(t *testing.T) {
	fastRecovery(t)
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseMigrating)
	var polls atomic.Int32
	r.srcFake.JobActive = func(string) (bool, error) {
		if polls.Add(1) < 3 {
			return false, errors.New("injected: the job cannot be read")
		}
		r.land()
		return false, nil
	}
	r.restart()
	if len(r.aborts()) != 0 {
		t.Fatalf("aborts %v sent with the job state unreadable", r.aborts())
	}
	r.requireCleanedUp("after the job state became readable")
}

// m-9: a target whose build has no Abort holds nothing of the attempt: the
// move is undone, not parked.
//
// Mutation: park on Unimplemented — red.
func TestRecoverFirmwareMoves_AbortUnimplementedHoldsNothing(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhasePrepared)
	r.peerC.mu.Lock()
	r.peerC.unimplemented["AbortLiveFirmwareTarget"] = true
	r.peerC.mu.Unlock()
	r.restart()
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v", m)
	}
	if vm := r.row(); vm.State != "running" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s, want running on src-host", vm.State, vm.HostName)
	}
	r.requireSourceIntact("after an Unimplemented abort")
}

// committed with the source domain running again: never released.
//
// Mutation: skip the source check at committed — red.
func TestRecoverFirmwareMoves_CommittedSourceActiveAgain(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseCommitted)
	r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
	r.restart()
	requireMarker(t, r, fwmig.PhaseSourceStateSuspect, fwmig.PhaseCommitted)
	r.requireTargetPausedWithHold("committed with the source active")
}

// released, Release answering NOT_HELD with no domain there: the target does
// not have the VM, so the source state is kept.
//
// Mutation: accept NOT_HELD whatever the domain — red.
func TestRecoverFirmwareMoves_ReleasedNotHeldNoDomainParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseReleased)
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return &pb.ReleaseLiveFirmwareTargetResponse{Verdict: pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_HELD, TargetDomain: &pb.TargetDomain{}}, nil
	}
	r.restart()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseReleased)
	r.requireSourceIntact("released, NOT_HELD with no domain")
}

// released with the row naming a third host: the source state is kept.
//
// Mutation: clean up whatever the row names — red.
func TestRecoverFirmwareMoves_ReleasedRowOtherHostParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseReleased)
	if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "third-host", "running"); err != nil {
		t.Fatal(err)
	}
	releases := strings.Count(strings.Join(r.log.get(), ","), "release")
	r.restart()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseReleased)
	if got := strings.Count(strings.Join(r.log.get(), ","), "release"); got != releases {
		t.Error("Release was sent to a target the row does not name")
	}
	r.requireSourceIntact("released, row on a third host")
}

// source_state_missing is retried: once the source domain can be read, the
// move goes on from where it parked.
//
// Mutation: no retry for source_state_missing — red.
func TestFirmwareMoveRecovery_SourceStateMissingRetried(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseMigrating)
	r.land()
	r.srcFake.FailDomainState = func(name string) error {
		if name == fwlVM {
			return errors.New("injected: libvirt does not answer")
		}
		return nil
	}
	r.restart()
	requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseMigrating)
	r.srcFake.FailDomainState = nil
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	r.requireCleanedUp("after source_state_missing was retried")
	requireNoFwmigCondition(t, r.src, condFwmigSourceStateMissing)
}

// discard_pending is retried: the DISCARD lands, the row is stopped on the
// source and the marker removed.
//
// Mutation: no retry for discard_pending — red.
func TestFirmwareMoveRecovery_DiscardPendingRetried(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.dstFake.CorruptLandedPermall = func(string) bool { return true }
	r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseDiscardPending, fwmig.PhaseCutover)
	r.peerC.mu.Lock()
	r.peerC.abortAnswer = nil
	r.peerC.mu.Unlock()
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v", m)
	}
	if vm := r.row(); vm.State != "stopped" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s, want stopped on src-host", vm.State, vm.HostName)
	}
	if !r.quarantined() {
		t.Error("the target's copy was not quarantined")
	}
	requireFwmigCondition(t, r.src, condFwmigUnverified)
	requireNoFwmigCondition(t, r.src, condFwmigTargetUnreachable)
}

// Review m-7: the recovery's waits end with the daemon's context: a move whose
// migration job never ends does not outlive it, and is left as it was.
//
// Mutation: wait on a context detached from the daemon's — red.
func TestRecoverFirmwareMoves_WaitsEndWithTheContext(t *testing.T) {
	fastRecovery(t)
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseMigrating)
	r.srcFake.JobActive = func(string) (bool, error) { return true, nil }
	ctx, cancel := context.WithCancel(context.Background())
	r.src.RecoverFirmwareMoves(ctx)
	r.src.MarkStartupWired()
	time.Sleep(50 * time.Millisecond)
	cancel()
	done := make(chan struct{})
	go func() {
		r.src.fwLive.recovering.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the recovery kept waiting on the job after its context ended")
	}
	requireMarker(t, r, fwmig.PhaseMigrating, "")
	if len(r.aborts()) != 0 {
		t.Errorf("aborts %v sent", r.aborts())
	}
}

// ── Fix round 2 (re-review trackD2-13-rereview-1.md) ──

// N-1: the start-up recovery, locked at the journal barrier, goes on only once
// the daemon marks the start wired: a late setter (here the step hook, which
// the recovery reads at its commit, as the finish reads the container
// runtime) writes before any recovery reads. -race reports the write without
// the barrier.
//
// Mutation: recover before the start is wired — red (and a DATA RACE).
func TestRecoverFirmwareMoves_WaitsForStartupWired(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseVerified)
	before := len(r.log.get())
	r.src.RecoverFirmwareMoves(context.Background())
	var committed atomic.Bool
	r.src.fwLive.stepHook = func(step string) { // the late setter
		r.log.add(step)
		if step == "commit" {
			committed.Store(true)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if got := r.log.get(); len(got) != before {
		t.Fatalf("the start-up recovery ran before the start was wired: %v", got[before:])
	}
	requireMarker(t, r, fwmig.PhaseVerified, "")
	r.src.MarkStartupWired()
	r.src.fwLive.recovering.Wait()
	if !committed.Load() {
		t.Error("the recovery did not commit once wired")
	}
	r.requireCleanedUp("after the start was wired")
}

// N-1: the start-up resource and hardware operation recoveries skip a VM
// whose lock a firmware move's recovery holds until the start is wired, so
// the start cannot deadlock on it.
//
// Mutation: the start-up variants wait on the lock — red.
func TestRecoverFirmwareMoves_StartupOpRecoveryDoesNotBlock(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	j, err := opjournal.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r.src.SetOpJournal(j)
	r.crashAt(fwmig.PhaseMigrating)
	if err := r.src.db.Execute(context.Background(), `UPDATE vms SET active_operation_id = ? WHERE name = ?`, "op-1", fwlVM); err != nil {
		t.Fatal(err)
	}
	r.src.RecoverFirmwareMoves(context.Background())
	done := make(chan struct{})
	go func() {
		r.src.RecoverResourceOperationsAtStart(context.Background())
		r.src.RecoverHardwareOperationsAtStart(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		r.src.MarkStartupWired()
		<-done
		t.Fatal("the start-up operation recoveries waited on a VM a firmware move's recovery holds")
	}
	r.src.MarkStartupWired()
	r.src.fwLive.recovering.Wait()
}

// N-2: after the migration call, a target whose build answers Abort
// Unimplemented cannot say whether it holds the paused incoming copy. M1
// (source running) parks target_unreachable, the source keeps running; M1p
// (source paused) parks source_paused and the source is not resumed. Neither
// remedy names repair-owner.
//
// Mutation: treat Unimplemented as holding nothing whatever the phase — red.
func TestRecoverFirmwareMoves_AbortUnimplementedAfterMigrationParks(t *testing.T) {
	for _, paused := range []bool{false, true} {
		name := "M1_running"
		if paused {
			name = "M1p_paused"
		}
		t.Run(name, func(t *testing.T) {
			r := newFwlRig(t, fwlOpts{})
			r.crashAt(fwmig.PhaseMigrating)
			if paused {
				r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
			}
			r.peerC.mu.Lock()
			r.peerC.unimplemented["AbortLiveFirmwareTarget"] = true
			r.peerC.mu.Unlock()
			r.restart()
			want := fwmig.PhaseTargetUnreachable
			wantState := libvirtfake.StateRunning
			if paused {
				want, wantState = fwmig.PhaseSourcePaused, libvirtfake.StatePaused
			}
			m := requireMarker(t, r, want, fwmig.PhaseMigrating)
			if st, _ := r.srcFake.RawState(fwlVM); st != wantState {
				t.Errorf("source domain %q, want %q", st, wantState)
			}
			if !strings.Contains(m.Detail, "rolled back") || strings.Contains(m.Detail, "repair-owner") {
				t.Errorf("detail %q: want the rolled-back target named, and no repair-owner", m.Detail)
			}
		})
	}
}

// N-3, source path: the VF-missing condition raised when the resumed guest's
// VF could not go back clears on its own once the VF is back in the running
// guest, with no marker left.
//
// Mutation: no resolver in the pass — red.
func TestFirmwareVFMissing_ResolvedWhenTheVFIsBack(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.withVF()
	r.crashAt(fwmig.PhaseMigrating)
	r.detachForMove()
	r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
	r.srcFake.FailAttachHostdev = func(string, string, string) error { return errors.New("injected attach failure") }
	r.restartWithLeases()
	requireFwmigCondition(t, r.src, condFwmigVFMissing)
	if _, ok := r.marker(); ok {
		t.Fatal("the marker is left; this checks the resolver after it")
	}
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	requireFwmigCondition(t, r.src, condFwmigVFMissing) // still missing
	r.srcFake.FailAttachHostdev = nil
	if err := r.srcFake.AttachHostdev(fwlVM, fwlVF); err != nil {
		t.Fatal(err)
	}
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	requireNoFwmigCondition(t, r.src, condFwmigVFMissing)
}

// N-3: a stopped or deleted VM no longer misses its VFs.
//
// Mutation: resolve only on VFs back — red.
func TestFirmwareVFMissing_ResolvedWhenStoppedOrDeleted(t *testing.T) {
	for _, how := range []string{"stopped", "deleted"} {
		t.Run(how, func(t *testing.T) {
			r := newFwlRig(t, fwlOpts{})
			r.withVF()
			r.crashAt(fwmig.PhaseMigrating)
			r.detachForMove()
			r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
			r.srcFake.FailAttachHostdev = func(string, string, string) error { return errors.New("injected attach failure") }
			r.restartWithLeases()
			requireFwmigCondition(t, r.src, condFwmigVFMissing)
			if how == "stopped" {
				r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
			} else if err := corrosion.DeleteVM(context.Background(), r.src.db, fwlVM); err != nil {
				t.Fatal(err)
			}
			r.src.FirmwareMoveRecoveryOnce(context.Background())
			requireNoFwmigCondition(t, r.src, condFwmigVFMissing)
		})
	}
}

// N-3, target path: a target attach that fails raises the condition for the
// target; the target's own pass clears it once the guest runs there with as
// many VFs it owns there as it had.
//
// Mutation: no target-side resolve (only the source judges) — red.
func TestFirmwareVFMissing_TargetPathResolvesOnTheTarget(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	_ = v
	reattachVFsOnTargetHook = func(_, _ string, vfs []corrosion.PCIDeviceRecord) []string { return pciAddresses(vfs) }
	r.crashAt(fwmig.PhaseMigrating)
	r.detachForMove()
	r.land()
	r.restartWithLeases()
	r.requireCleanedUp("after a move whose target attach failed")
	requireFwmigCondition(t, r.src, condFwmigVFMissing)
	r.dst.FirmwareMoveRecoveryOnce(context.Background())
	requireFwmigCondition(t, r.src, condFwmigVFMissing) // no VF there yet
	const dstVF = "0000:81:10.0"
	if err := corrosion.UpsertPCIDevice(adminCtx(), r.dst.db, corrosion.PCIDeviceRecord{
		HostName: "dst-host", Address: dstVF, Type: "net", VendorID: "8086", VMName: fwlVM}); err != nil {
		t.Fatal(err)
	}
	if err := r.dstFake.AttachHostdev(fwlVM, dstVF); err != nil {
		t.Fatal(err)
	}
	r.dst.FirmwareMoveRecoveryOnce(context.Background())
	requireNoFwmigCondition(t, r.src, condFwmigVFMissing)
}

// N-4: a committed marker left by a process that died, taken by the interval's
// pass (not the start), finishes the move: the target is asked to attach the
// VFs, not only the source's released.
//
// Mutation: a pass takes committed without the finish — red.
func TestFirmwareMoveRecovery_CommittedPassAttachesOnTarget(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	r.crashAt(fwmig.PhaseCommitted)
	if err := r.src.beginMigrationVFLease(fwlVM, []string{fwlVF}); err != nil {
		t.Fatal(err)
	}
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	r.requireCleanedUp("after the pass took a committed marker")
	r.requireVFsMovedOut(v, "after the pass took a committed marker")
}

// N-5: a marked VM's device lease is left to the firmware recovery even when
// the VM's row reads as gone (a replica not caught up): its VFs are not
// reclaimed as an orphan's.
//
// Mutation: the orphan branch before the marker check — red.
func TestRecoverDeviceLeases_MarkedVMRowGoneKeepsLease(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	v := r.withVF()
	r.crashAt(fwmig.PhaseMigrating)
	r.detachForMove()
	if err := corrosion.DeleteVM(context.Background(), r.src.db, fwlVM); err != nil {
		t.Fatal(err)
	}
	r.src.RecoverDeviceLeases(context.Background())
	if !v.leaseLeft(t) {
		t.Fatal("the marked VM's lease was reclaimed as an orphan's")
	}
	if !v.fs.isBound(fwlVF) {
		t.Error("the marked VM's VF was unbound")
	}
}

// N-6: main never live-moved a firmware VM, so a live firmware move of a VM
// with VFs is refused while the operation journal is unavailable, before
// anything is detached or asked of the target.
//
// Mutation: no refusal — red.
func TestMigrateVM_FirmwareLive_VFsWithoutJournalRefused(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.withVF()
	r.src.SetOpJournal(nil)
	err := r.migrate()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "opjournal") {
		t.Fatalf("got %v, want a refusal naming the operation journal", err)
	}
	if r.log.has("prepare") {
		t.Error("the target was asked to prepare")
	}
	if !guestHasHostdev(t, r.src, fwlVM, fwlVF) {
		t.Error("the VF was detached")
	}
	if _, ok := r.marker(); ok {
		t.Error("a marker was written")
	}
}

// N-6: at recovery with no journal, a VM that owns a PCI device parks with an
// Action that names the journal.
//
// Mutation: the generic Action — red.
func TestRecoverFirmwareMoves_NoJournalParkNamesTheJournal(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.withVF()
	r.crashAt(fwmig.PhaseMigrating)
	r.src.SetOpJournal(nil)
	r.restart()
	requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseMigrating)
	c, _, err := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigSourceStateMissing, "vm", fwlVM)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Evidence, "opjournal") {
		t.Errorf("the park's condition does not name the journal: %s", c.Evidence)
	}
}

// N-7 / m-1: a recovered run makes one attempt per call: an unanswered Verify
// is asked once per pass, and the next pass is its backoff.
//
// Mutation: retry within the pass — red.
func TestFirmwareMoveRecovery_OneAttemptPerPass(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.parkUnreachableAtVerify()
	r.peerC.verifyAnswer = func(func() (*pb.VerifyLiveFirmwareTargetResponse, error)) (*pb.VerifyLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	before := strings.Count(strings.Join(r.log.get(), ","), "verify")
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	if got := strings.Count(strings.Join(r.log.get(), ","), "verify") - before; got != 1 {
		t.Fatalf("Verify asked %d times in one pass, want 1", got)
	}
}

// N-7 / m-6: the owed DISCARDs at start wait for the replica to catch up: a
// stale replica sends none and drops none.
//
// Mutation: send the owed DISCARDs at start without the wait — red.
func TestRecoverFirmwareMoves_OwedDiscardWaitsForReplica(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.parkUnreachableAtVerify()
	r.fenceTarget()
	if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || !ok {
		t.Fatalf("resolve: %v %v", ok, err)
	}
	o := firmwareRecoveryCatchUpWait
	firmwareRecoveryCatchUpWait = 50 * time.Millisecond
	t.Cleanup(func() { firmwareRecoveryCatchUpWait = o })
	r.src.db.MarkReplicaStale("test: not caught up")
	r.restart()
	if len(r.aborts()) != 0 {
		t.Fatalf("aborts %v sent from a replica that has not caught up", r.aborts())
	}
	if owed, _ := r.src.fwRecords().ListOwedDiscards(); len(owed) != 1 {
		t.Errorf("owed discards %v, want the record kept", owed)
	}
}
