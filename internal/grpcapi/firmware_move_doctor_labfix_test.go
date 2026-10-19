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
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// lab2-D2-proof F3: a released move whose source cleanup stopped before the
// wipe (marker cleaning, the source's state still what the cutover recorded,
// its domain still defined) and whose target is then powered off and fenced
// had no exit: --accept-source refused it, saying the target's copy runs. It
// now takes the post-commit return, as a committed move with its target
// proved off does: the VM and its disks back here, stopped, the DISCARD owed
// to the target, the cleanup's condition resolved. A target that answers, or
// a cleanup that already undefined the source's domain, is refused with what
// is really there.
func TestDoctorFirmwareMove_CleaningTargetFenced(t *testing.T) {
	// cleaningStopped: released, then the cleanup stopped at its first step
	// (the retained bundle), so the marker is cleaning and nothing is gone.
	cleaningStopped := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		m := run.marker
		m.Phase = fwmig.PhaseCleaning
		if err := r.src.fwRecords().PutMarker(m); err != nil {
			t.Fatal(err)
		}
		if err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{
			Code: condFwmigCleanupFailed, VM: fwlVM, Attempt: m.Attempt, Source: "src-host", Target: "dst-host",
			Detail: "write the retained bundle: read-only file system", Action: "fix it",
		}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Mutation: refuse cleaning outright again — red.
	t.Run("accept_source", func(t *testing.T) {
		r := cleaningStopped(t)
		r.fenceTarget()
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		disks, _ := corrosion.GetVMDisks(context.Background(), r.src.db, fwlVM)
		for _, d := range disks {
			if d.HostName != "src-host" {
				t.Errorf("disk %s on %s, want src-host", d.DiskName, d.HostName)
			}
		}
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		if len(owed) != 1 || owed[0].Target != "dst-host" {
			t.Errorf("owed discards %+v, want one to dst-host", owed)
		}
		if st, ok := r.srcFake.RawState(fwlVM); !ok || st == libvirtfake.StateRunning {
			t.Errorf("source domain %s (defined %v), want it defined and not running", st, ok)
		}
		r.requireSourceIntact("after the return")
		requireNoFwmigCondition(t, r.src, condFwmigCleanupFailed)
	})
	t.Run("accept_source_needs_ack", func(t *testing.T) {
		r := cleaningStopped(t)
		r.fenceTarget()
		before := r.snap()
		_, err := r.doctor(actAcceptSource)
		r.refused(err, "--acknowledge-rollback", before)
	})
	// The target answers with the released guest running: the VM is there.
	// Mutation: drop the cleaning row from the answering branch — red (the
	// "holds no hold" text, which does not say the copy runs there).
	t.Run("accept_source_target_answers_refused", func(t *testing.T) {
		r := cleaningStopped(t)
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "its domain of the VM is running", before)
		if owed, _ := r.src.fwRecords().ListOwedDiscards(); len(owed) != 0 {
			t.Errorf("a refused return left owed discards %+v", owed)
		}
	})
	// A cleanup that got past the undefine: no domain here to start.
	// Mutation: drop the definition check — red (the return lands with no
	// domain on the source).
	t.Run("accept_source_source_undefined_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseCleaning)
		r.fenceTarget()
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "already undefined the VM's domain", before)
	})
	// A source state changed since the cutover is never taken.
	t.Run("accept_source_changed_source_refused", func(t *testing.T) {
		r := cleaningStopped(t)
		r.fenceTarget()
		r.write(r.srcStore.NvramPath(fwlVM), []byte("changed since cutover"))
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "recorded at cutover", before)
	})
}

// lab2-D2-proof F4: --adopt-target-copy on target_ran, where the guest that
// ran on the target wrote an EFI variable, so the target's NVRAM is no longer
// the source's final one. The adopt records the target's NVRAM in the hold,
// and the release is confirmed against it: the move resolves, with no
// nvram_unconfirmed park after the adopt succeeded.
//
// Mutation: confirm against the source's final NVRAM only — the move parks
// nvram_unconfirmed, red.
func TestDoctorFirmwareMove_AdoptConfirmsTheAdoptedNvram(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCutover)
	r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
	r.write(r.dstStore.NvramPath(fwlVM), []byte("the target's guest wrote a variable"))
	r.park(run, fwmig.PhaseTargetRan, "TARGET_RAN")
	_, err := r.doctor(actAdopt)
	r.resolved(err, "dst-host", "running")
	if _, ok := r.hold(); ok {
		t.Error("the target's hold is left")
	}
	requireNoFwmigCondition(t, r.src, condFwmigNvramUnconfirmed)
}

// lab2-D2-proof F5: a park whose marker write failed raises its condition
// with the marker left in another phase; an operator exit then resolved only
// the condition of the marker's phase, and the other stayed critical with no
// move behind it. Every park condition of the VM is resolved when the move
// ends.
//
// Mutation: resolve only the marker phase's condition on unmark — red.
func TestDoctorFirmwareMove_ExitResolvesEveryParkCondition(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCommitted)
	m := run.marker
	if err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{
		Code: condFwmigNvramUnconfirmed, VM: fwlVM, Attempt: m.Attempt, Source: "src-host", Target: "dst-host",
		Detail: "raised while the marker could not be written", Action: "test",
	}); err != nil {
		t.Fatal(err)
	}
	r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
	r.fenceTarget()
	_, err := r.doctor(actAcceptSource, withAck)
	r.resolved(err, "src-host", "stopped")
	requireNoFwmigCondition(t, r.src, condFwmigNvramUnconfirmed)
	requireNoFwmigCondition(t, r.src, condFwmigTargetUnreachable)
}

// lab2-D2-proof F6: the source quarantine an adopt leaves names the adopt,
// not --accept-target, and records the hash of each part that is there: a
// missing NVRAM no longer drops the TPM state's hash.
//
// Mutations: the --accept-target reason text for the adopt — red; hash both
// parts together (a missing NVRAM drops the permall hash) — red.
func TestDoctorFirmwareMove_AdoptQuarantineRecordsTheAdopt(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseMigrating)
	r.land()
	r.park(run, fwmig.PhaseSourceStateMissing, "the source's final NVRAM cannot be read")
	if err := os.Remove(r.srcStore.NvramPath(fwlVM)); err != nil {
		t.Fatal(err)
	}
	_, err := r.doctor(actAdopt)
	r.resolved(err, "dst-host", "running")
	dir, _ := r.src.fwRecords().QuarantinePath(fwlVM, run.marker.Attempt)
	b, err := os.ReadFile(filepath.Join(dir, "reason.txt"))
	if err != nil {
		t.Fatal(err)
	}
	reason := string(b)
	if !strings.Contains(reason, "--adopt-target-copy") || strings.Contains(reason, "--accept-target") {
		t.Errorf("reason.txt names the wrong action:\n%s", reason)
	}
	if want := "quarantined_permall: " + fwtSHA(fwlPermall); !strings.Contains(reason, want) {
		t.Errorf("reason.txt lacks %q:\n%s", want, reason)
	}
	if !strings.Contains(reason, "quarantined_nvram: none") {
		t.Errorf("reason.txt does not record the missing NVRAM:\n%s", reason)
	}
}

// lab2-D2-proof F7: --accept-source on a move parked source_state_missing
// from migrating is refused, and the refusal no longer suggests
// --discard-target, which would discard what may be the only complete copy.
func TestDoctorFirmwareMove_SourceStateMissingAcceptSourceText(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseMigrating)
	r.land()
	r.park(run, fwmig.PhaseSourceStateMissing, "the source's final NVRAM cannot be read")
	before := r.snap()
	_, err := r.doctor(actAcceptSource, withAck)
	r.refused(err, "--adopt-target-copy", before)
	if strings.Contains(err.Error(), "--discard-target") {
		t.Errorf("the refusal suggests --discard-target: %v", err)
	}
}

// Review I1: an --accept-source return from cleaning that stops after the
// return landed and before its unmark (the daemon died) leaves no cleaning
// marker: the doctor takes it out of cleaning before the return, so the
// cleanup retry and the recovery never undefine and wipe the copy the VM was
// returned to. A re-run of the doctor finishes the return.
//
// Mutation: drop the park before the return — the marker stays cleaning, red.
func TestDoctorFirmwareMove_CleaningReturnInterruptedKeepsTheCopy(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	m := run.marker
	m.Phase = fwmig.PhaseCleaning
	if err := r.src.fwRecords().PutMarker(m); err != nil {
		t.Fatal(err)
	}
	r.fenceTarget()
	o := fwDoctorAfterReturnHook
	fwDoctorAfterReturnHook = func() error { return errors.New("daemon died after the return") }
	_, err := r.doctor(actAcceptSource, withAck)
	fwDoctorAfterReturnHook = o
	if err == nil {
		t.Fatal("the interrupted return reported success")
	}
	cur, ok := r.marker()
	if !ok || cur.Phase == fwmig.PhaseCleaning {
		t.Fatalf("marker after the interrupted return: %s (present %v), want it out of cleaning", cur.Phase, ok)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	r.src.FirmwareMoveRecoveryOnce(context.Background())
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st == libvirtfake.StateRunning {
		t.Fatalf("source domain %s (defined %v) after the cleanup retry and recovery, want defined and shut off", st, ok)
	}
	r.requireSourceIntact("after the cleanup retry and recovery")
	if _, ok := r.marker(); ok {
		_, err = r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
	}
	if row := r.row(); row.HostName != "src-host" || row.State != "stopped" {
		t.Errorf("row %s on %s, want stopped on src-host", row.State, row.HostName)
	}
	r.requireSourceIntact("after the re-run")
}

// Review I1, the cleanup's own guard: a cleaning marker of a VM whose row
// names the source for the move's incarnation (a return that left one) is
// never cleaned up: the domain stays defined and the state in place, and
// cleanup_failed names the doctor's exit.
//
// Mutation: drop the row check in the cleanup — the domain is undefined and
// the state wiped, red.
func TestFwmigCleanup_RefusesAVMReturnedHere(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	m := run.marker
	m.Phase = fwmig.PhaseCleaning
	if err := r.src.fwRecords().PutMarker(m); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "src-host", "stopped"); err != nil {
		t.Fatal(err)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st == libvirtfake.StateRunning {
		t.Fatalf("source domain %s (defined %v), want defined and shut off", st, ok)
	}
	r.requireSourceIntact("after the cleanup retry")
	requireMarker(t, r, fwmig.PhaseCleaning, "")
	requireFwmigCondition(t, r.src, condFwmigCleanupFailed)
}

// Review I2: a stopped cleanup whose fault clears while its target is proved
// off holds after the retained bundle: the source domain stays defined and
// its state in place, so `--accept-source` stays open; cleanup_failed names
// it. An operator's --accept-target cleanup is not held.
//
// Mutation: drop the proved-off hold — the domain is undefined and the state
// wiped, red.
func TestFwmigCleanup_HoldsWhileTheTargetIsProvedOff(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	m := run.marker
	m.Phase = fwmig.PhaseCleaning
	if err := r.src.fwRecords().PutMarker(m); err != nil {
		t.Fatal(err)
	}
	r.fenceTarget()
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st == libvirtfake.StateRunning {
		t.Fatalf("source domain %s (defined %v), want defined and shut off", st, ok)
	}
	r.requireSourceIntact("after the cleanup retry")
	requireMarker(t, r, fwmig.PhaseCleaning, "")
	requireFwmigCondition(t, r.src, condFwmigCleanupFailed)
	// The exit stays open.
	_, err := r.doctor(actAcceptSource, withAck)
	r.resolved(err, "src-host", "stopped")
	r.requireSourceIntact("after --accept-source")
}

// Review m1: the end of a move resolves only the park conditions this host
// raised as the move's source; another host's park of its own move of the
// VM (a later hop) stays open.
//
// Mutation: resolve every park code of the VM — red.
func TestDoctorFirmwareMove_ExitLeavesAnotherSourcesPark(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCommitted)
	// Raised as the later hop's source records it (the conditions replicate).
	if err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{
		Code: condFwmigSourcePaused, VM: fwlVM, Attempt: "a-later-hop", Source: "dst-host", Target: "third-host",
		Detail: "the later hop parked", Action: "test",
	}); err != nil {
		t.Fatal(err)
	}
	r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
	r.fenceTarget()
	_, err := r.doctor(actAcceptSource, withAck)
	r.resolved(err, "src-host", "stopped")
	requireFwmigCondition(t, r.src, condFwmigSourcePaused)
}

// Review m5: the guest of an adopted target_ran copy writes a variable
// between the adopt and the release: the release confirms the adopted copy as
// it is then, and does not park nvram_unconfirmed.
//
// Mutation: confirm the running adopted guest against the adopt-time hash
// only — red.
func TestDoctorFirmwareMove_AdoptVariableBeforeReleaseConfirms(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCutover)
	r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
	r.park(run, fwmig.PhaseTargetRan, "TARGET_RAN")
	r.peerC.releaseAnswer = func(call func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		r.write(r.dstStore.NvramPath(fwlVM), []byte("a variable written after the adopt"))
		return call()
	}
	_, err := r.doctor(actAdopt)
	r.resolved(err, "dst-host", "running")
	if _, ok := r.hold(); ok {
		t.Error("the target's hold is left")
	}
	requireNoFwmigCondition(t, r.src, condFwmigNvramUnconfirmed)
}

// Review m7: a recovery's wait on a Release refusal ends with the daemon (its
// waitCtx): one call, then the park, without waiting out the backoff.
//
// Mutation: sleep the backoff regardless of waitCtx — more calls and a
// second or more, red.
func TestRecoveryReleaseWait_EndsWithTheDaemon(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCommitted)
	ob := fwLiveRetryBackoff
	fwLiveRetryBackoff = 300 * time.Millisecond
	t.Cleanup(func() { fwLiveRetryBackoff = ob })
	var calls atomic.Int32
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		calls.Add(1)
		return nil, status.Error(codes.FailedPrecondition, "its row names src-host: the move has not committed")
	}
	rr := r.src.recoveredFirmwareRun(context.Background(), run.marker)
	dctx, cancel := context.WithCancel(context.Background())
	cancel()
	rr.waitCtx = dctx
	start := time.Now()
	_ = r.src.releaseLiveFirmwareMove(context.Background(), rr)
	if n, d := calls.Load(), time.Since(start); n != 1 || d > 250*time.Millisecond {
		t.Errorf("Release asked %d times over %s with the daemon stopping, want once at once", n, d)
	}
}

// lab2-D2-proof F11: a move whose finish fails says so, with the cause's
// message, not "migrated to X, but is rpc error: ...".
//
// Mutation: the old "but is %v" text — red.
func TestMigrate_FinishFailureText(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	err := r.migrate()
	if err == nil {
		t.Fatal("the move reported success with Release unanswered")
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, `migrated to dst-host, but finishing the move failed: VM "os1"`) || strings.Contains(msg, "failed: rpc error") {
		t.Errorf("message: %s", msg)
	}
}
