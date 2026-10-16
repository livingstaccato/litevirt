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

// restart is the daemon's start: the recovery of every marker, waited for.
func (r *fwlRig) restart() {
	r.src.RecoverFirmwareMoves(context.Background())
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
// (§7), and sends the DISCARD it then owes.
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
