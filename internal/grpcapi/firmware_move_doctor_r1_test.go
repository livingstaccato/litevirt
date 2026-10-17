package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Review D2-18 round 1: each operator action that could drop the only copy
// of a VM (C-1, I-1, I-2) is refused; the return is idempotent (I-4) and
// guarded by the commit's disks (I-3); the VM's network follows the copy
// (I-5); an owed DISCARD with no hold left has a doctor exit (I-6).

// lostWithOwed is a target hold whose source holds no marker: the source
// lost (fenced) or, owing the DISCARD, answering with the owed record.
func lostWithOwed(t *testing.T, fence, owed bool, dst libvirtfake.State) (*fwlRig, fwmig.Marker) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCutover)
	m := run.marker
	if err := r.src.fwRecords().RemoveMarker(fwlVM); err != nil {
		t.Fatal(err)
	}
	if owed {
		if err := r.src.fwRecords().PutOwedDiscard(fwmig.OwedDiscard{VM: fwlVM, Binding: m.Binding, Target: "dst-host",
			CreatedStubs: m.CreatedStubs, Since: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if fence {
		if err := corrosion.RecordFenceWithState(context.Background(), r.src.db,
			corrosion.FenceLogRecord{ID: "fc-src", HostName: "src-host", Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
			t.Fatal(err)
		}
	}
	if dst != "" {
		r.dstFake.SetState(fwlVM, dst)
	}
	return r, m
}

func TestDoctorFirmwareMove_R1(t *testing.T) {
	// ── C-1: never discard the target's copy for a source that has none ──
	// Mutation: drop requireSourceCopy — red (the target's only copy is
	// quarantined and the row set stopped on a source with no state).
	t.Run("source_state_missing_from_cutover_state_absent/accept_source_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		r.park(run, fwmig.PhaseSourceStateMissing, "after a daemon restart, the source's final TPM state cannot be read")
		if err := os.Remove(filepath.Join(r.srcStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "--adopt-target-copy", before)
		r.requireTargetPausedWithHold("after the refusal")
	})
	t.Run("source_state_missing_from_cutover_no_recorded_hash/accept_source_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		run.marker.SrcPermallSHA256 = ""
		r.park(run, fwmig.PhaseSourceStateMissing, "after a daemon restart, whether the source domain is still shut off cannot be read")
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "not the source's final state", before)
	})

	// After the commit, a target_ran park skips the cutover re-hash: the
	// source's state must still be there before the target's guest is
	// stopped and its copy discarded. Mutation: drop requireSourceCopy after
	// the commit — red.
	t.Run("target_ran_from_committed_state_absent/accept_source_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseTargetRan, "TARGET_RAN")
		if err := os.Remove(filepath.Join(r.srcStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck, withStop)
		r.refused(err, "--adopt-target-copy", before)
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("the target's guest is %s, want it left running", st)
		}
	})
	// Before the commit, a source domain that is active and not running
	// (paused mid-move) is not taken. Mutation: drop the check — red.
	t.Run("source_state_suspect_source_paused/accept_source_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		r.park(run, fwmig.PhaseSourceStateSuspect, "test")
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "is active", before)
		r.requireTargetPausedWithHold("after the refusal")
	})

	// ── I-1: source_paused with a target guest that runs, --stop-target given ──
	// Mutation: honour --stop-target there — red.
	t.Run("source_paused_target_running/accept_source_stop_target_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseSourcePaused, "test")
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withStop)
		r.refused(err, "it ran after the source paused", before)
		// Its exit: the source's domain shut off, then the target's copy adopted.
		r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
		_, err = r.doctor(actAdopt)
		r.resolved(err, "dst-host", "running")
	})

	// A source_paused target that never ran is not adopted, even with the
	// source shut off. Mutation: drop the check — red.
	t.Run("source_paused_target_paused/adopt_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.dstFake.SetState(fwlVM, libvirtfake.StatePaused)
		r.park(run, fwmig.PhaseSourcePaused, "test")
		before := r.snap()
		_, err := r.doctor(actAdopt)
		r.refused(err, "never ran", before)
	})

	// ── I-2: a target-local --discard-target --stop-target ──
	// Mutation: let --stop-target stop a running held guest without the
	// source's owed record — red.
	t.Run("hold_no_marker_source_fenced_guest_running/discard_stop_target_refused", func(t *testing.T) {
		r, _ := lostWithOwed(t, true, false, libvirtfake.StateRunning)
		before := r.snap()
		_, err := r.doctor(actDiscard, withStop)
		r.refused(err, "may be the only copy", before)
	})
	t.Run("hold_no_marker_no_owed_record_guest_running/discard_stop_target_refused", func(t *testing.T) {
		r, _ := lostWithOwed(t, false, false, libvirtfake.StateRunning)
		before := r.snap()
		_, err := r.doctor(actDiscard, withStop)
		r.refused(err, "may be the only copy", before)
	})
	t.Run("owed_discard_target_running/discard_needs_stop_target", func(t *testing.T) {
		r, _ := lostWithOwed(t, false, true, libvirtfake.StateRunning)
		before := r.snap()
		_, err := r.doctor(actDiscard)
		r.refused(err, "add --stop-target", before)
	})
	t.Run("owed_discard_target_running/discard_stop_target", func(t *testing.T) {
		r, _ := lostWithOwed(t, false, true, libvirtfake.StateRunning)
		if _, err := r.doctor(actDiscard, withStop); err != nil {
			t.Fatalf("discard: %v", err)
		}
		r.discardedOnTarget("owed discard, --stop-target")
	})

	// ── I-3: the return's disks are the commit's ──
	committedFenced := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		if len(run.marker.CommitDisks) != 1 {
			t.Fatalf("the committed marker records disks %+v", run.marker.CommitDisks)
		}
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		return r
	}
	// Mutation: pass the rows as they are now to the return writer — red.
	t.Run("committed_target_fenced_disk_moved_since/accept_source_refused", func(t *testing.T) {
		r := committedFenced(t)
		if err := corrosion.UpdateDiskHostAndPath(context.Background(), r.src.db, fwlVM, "root", "dst-host", "/srv/nfs/os1-root-moved.qcow2"); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "changed since the commit", before)
		if _, ok, _ := r.src.fwRecords().GetOwedDiscard(fwlVM, before.marker.Attempt); ok {
			t.Error("a declined return left its owed-discard record")
		}
	})
	// Mutation: drop the shared-storage check — red.
	t.Run("committed_target_fenced_local_disk_added/accept_source_refused", func(t *testing.T) {
		r := committedFenced(t)
		if err := corrosion.InsertDisk(context.Background(), r.src.db, corrosion.DiskRecord{VMName: fwlVM, DiskName: "data",
			HostName: "dst-host", Path: "/var/lib/litevirt/disks/os1-data.qcow2", StorageType: "local", TargetDev: "vdb"}); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "not on shared storage", before)
	})

	// ── I-4: interrupted after the return, run again ──
	// Mutations: record the owed DISCARD after the return; refuse a row
	// already returned — red.
	t.Run("committed_target_fenced/accept_source_interrupted_after_return", func(t *testing.T) {
		r := committedFenced(t)
		crash := errors.New("daemon died after the return")
		o := fwDoctorAfterReturnHook
		fwDoctorAfterReturnHook = func() error { return crash }
		_, err := r.doctor(actAcceptSource, withAck)
		fwDoctorAfterReturnHook = o
		if err == nil || !strings.Contains(err.Error(), crash.Error()) {
			t.Fatalf("first run: %v, want the interruption", err)
		}
		m, ok := r.marker()
		if !ok {
			t.Fatal("the marker went with the interrupted run")
		}
		if vm := r.row(); vm.HostName != "src-host" {
			t.Fatalf("the return did not land: row on %s", vm.HostName)
		}
		if _, ok, _ := r.src.fwRecords().GetOwedDiscard(fwlVM, m.Attempt); !ok {
			t.Fatal("no owed-discard record after the return")
		}
		_, err = r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		if _, ok, _ := r.src.fwRecords().GetOwedDiscard(fwlVM, m.Attempt); !ok {
			t.Error("the owed-discard record went, the target still holds its copy")
		}
	})

	// The earlier run's DISCARD landed and dropped the owed record, and the
	// run stopped before the marker went: the next run records it again.
	// Mutation: require the owed record for a returned row — red.
	t.Run("committed_target_fenced/accept_source_interrupted_after_owed_dropped", func(t *testing.T) {
		r := committedFenced(t)
		o := fwDoctorAfterReturnHook
		fwDoctorAfterReturnHook = func() error { return errors.New("daemon died after the return") }
		_, err := r.doctor(actAcceptSource, withAck)
		fwDoctorAfterReturnHook = o
		if err == nil {
			t.Fatal("first run did not stop")
		}
		m, _ := r.marker()
		if err := r.src.fwRecords().RemoveOwedDiscard(fwlVM, m.Attempt); err != nil {
			t.Fatal(err)
		}
		_, err = r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		if _, ok, _ := r.src.fwRecords().GetOwedDiscard(fwlVM, m.Attempt); !ok {
			t.Error("no owed-discard record after the second run")
		}
	})
	// target_ran after the commit, the target answering: the first run's
	// DISCARD landed (the hold is gone), and the run stopped before the
	// marker went. Mutation: refuse a target with no hold for a returned
	// row — red.
	t.Run("target_ran_from_committed/accept_source_interrupted_after_discard", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		m := r.park(run, fwmig.PhaseTargetRan, "TARGET_RAN")
		o := fwDoctorAfterReturnHook
		fwDoctorAfterReturnHook = func() error { return errors.New("daemon died after the return") }
		_, err := r.doctor(actAcceptSource, withAck, withStop)
		fwDoctorAfterReturnHook = o
		if err == nil {
			t.Fatal("first run did not stop")
		}
		if vm := r.row(); vm.HostName != "src-host" {
			t.Fatalf("the return did not land: row on %s", vm.HostName)
		}
		if _, err := r.src.sendLiveFirmwareAbort(context.Background(), "dst-host", fwlVM, m.Binding,
			pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED, m.CreatedStubs); err != nil {
			t.Fatal(err)
		}
		if _, ok := r.hold(); ok {
			t.Fatal("the DISCARD did not land")
		}
		_, err = r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		r.discardedOnTarget("target_ran after the commit, run again")
	})

	// ── I-5: the network follows the copy ──
	// Mutation: drop the convergence after the return — red.
	t.Run("committed_target_fenced/accept_source_converges_here", func(t *testing.T) {
		r := committedFenced(t)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		if !r.log.has("converge:dst-host->src-host") {
			t.Errorf("no convergence on the return (steps %v)", r.log.get())
		}
	})
	// Mutations: drop the convergence, or the VF condition, after the adopt —
	// red.
	t.Run("hold_no_marker/adopt_converges_and_names_missing_vfs", func(t *testing.T) {
		r, _ := lostWithOwed(t, true, false, "")
		if err := corrosion.UpsertPCIDevice(context.Background(), r.src.db, corrosion.PCIDeviceRecord{HostName: "src-host",
			Address: "0000:3b:02.1", Type: "network", VMName: fwlVM}); err != nil {
			t.Fatal(err)
		}
		r.dst.fwLive.stepHook = func(step string) { r.log.add(step) }
		if _, err := r.doctor(actAdopt); err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if vm := r.row(); vm.HostName != "dst-host" || vm.State != "running" {
			t.Errorf("row %s on %s, want running on dst-host", vm.State, vm.HostName)
		}
		if !r.log.has("converge:src-host->dst-host") {
			t.Errorf("no convergence on the adopt (steps %v)", r.log.get())
		}
		c, found, err := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigVFMissing, "vm", fwlVM)
		if err != nil || !found || c.Lifecycle == corrosion.ConditionResolved || !strings.Contains(c.Evidence, "0000:3b:02.1") {
			t.Errorf("vf_missing %+v found=%v err=%v, want it open naming 0000:3b:02.1", c, found, err)
		}
	})

	// ── I-6: post-commit --accept-source needs the target proved off or
	// holding the attempt; an owed DISCARD with no hold left has an exit ──
	released := func(t *testing.T, fence bool) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		if fence {
			r.fenceTarget()
		}
		return r
	}
	// Mutation: drop the no-hold refusal — red.
	t.Run("released_target_unfenced/accept_source_refused", func(t *testing.T) {
		r := released(t, false)
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "fence-confirm dst-host", before)
	})
	// With the domain gone too, the missing hold alone refuses.
	t.Run("released_target_unfenced_domain_gone/accept_source_refused", func(t *testing.T) {
		r := released(t, false)
		r.dstFake.VanishDomain(fwlVM)
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "holds no hold of the attempt", before)
	})
	// The committed row takes a target proved off: a target that answers
	// with its held domain keeps the committed copy, and is retried.
	// Mutation: let a held domain on an answering target be discarded — red.
	t.Run("committed_target_unfenced_holds_copy/accept_source_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "holds the committed copy", before)
		r.requireTargetPausedWithHold("after the refusal")
	})
	t.Run("released_target_fenced/accept_source_then_discard_leftover", func(t *testing.T) {
		r := released(t, true)
		if _, err := r.doctor(actAcceptSource, withAck); err != nil {
			t.Fatalf("accept-source: %v", err)
		}
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		if len(owed) != 1 {
			t.Fatalf("owed discards %+v, want one", owed)
		}
		// The target comes back powered off; its leftover domain is defined.
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		before := r.snap()
		_, err := r.doctor(actDiscard)
		r.refused(err, "is running", before)
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		if _, err := r.doctor(actDiscard); err != nil {
			t.Fatalf("discard the leftover: %v", err)
		}
		if st, ok := r.dstFake.RawState(fwlVM); ok {
			t.Errorf("the leftover domain is still defined (%s)", st)
		}
		dir, _ := r.dst.fwRecords().QuarantinePath(fwlVM, owed[0].Attempt)
		if b, _ := os.ReadFile(filepath.Join(dir, "swtpm", "tpm2", "tpm2-00.permall")); len(b) == 0 {
			t.Error("the leftover's TPM state is not in the quarantine")
		}
		r.src.RetryOwedFirmwareDiscardsOnce(context.Background())
		if left, _ := r.src.fwRecords().ListOwedDiscards(); len(left) != 0 {
			t.Errorf("owed discards %+v after the leftover went", left)
		}
	})

	// ── m-6: held_domain_absent with the hold resuming takes the push ──
	t.Run("held_domain_absent_resuming/push_source_nvram", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.dstFake.VanishDomain(fwlVM)
		if err := r.src.releaseLiveFirmwareMove(context.Background(), run); err == nil {
			t.Fatal("Release of a vanished held domain succeeded")
		}
		h, _ := r.hold()
		h.State = fwmig.HoldResuming
		if err := r.dst.fwRecords().PutHold(h); err != nil {
			t.Fatal(err)
		}
		_, err := r.doctor(actPush)
		r.resolved(err, "dst-host", "stopped")
	})

	// ── m-1: a refusal before any host acts is audited where it was asked ──
	t.Run("no_record/refusal_audited", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		if _, err := r.doctor(actAcceptTarget); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("no record anywhere: %v", err)
		}
		rows, err := r.src.db.Query(context.Background(), `SELECT result FROM audit_log WHERE action = ? AND target = ?`, fwDoctorVerb, fwlVM)
		if err != nil || len(rows) == 0 || rows[0].String("result") != "error" {
			t.Errorf("audit rows %v (%v), want the refusal", rows, err)
		}
	})

	// ── m-3: a source-side quarantine keeps the target's path named ──
	t.Run("quarantine_condition_keeps_both_paths", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		if err := r.dst.raiseQuarantineCondition(context.Background(), fwmigCondition{VM: fwlVM, Attempt: "a", Paths: []string{"/dst/q"}, Detail: "target side"}); err != nil {
			t.Fatal(err)
		}
		if err := r.src.raiseQuarantineCondition(context.Background(), fwmigCondition{VM: fwlVM, Attempt: "a", Paths: []string{"/src/q"}, Detail: "source side"}); err != nil {
			t.Fatal(err)
		}
		c, _, _ := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigQuarantine, "vm", fwlVM)
		var ev struct {
			Paths []string `json:"paths"`
		}
		_ = json.Unmarshal([]byte(c.Evidence), &ev)
		if strings.Join(ev.Paths, ",") != "/src/q,/dst/q" {
			t.Errorf("paths %v, want both", ev.Paths)
		}
	})

	// ── m-4: the acknowledgement refusal names the state ──
	t.Run("source_state_suspect/ack_refusal_names_the_state", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		r.park(run, fwmig.PhaseSourceStateSuspect, "test")
		_, err := r.doctor(actAcceptSource)
		if err == nil || !strings.Contains(err.Error(), "the source's state is suspect") {
			t.Errorf("err %v, want it to name the suspect state", err)
		}
	})
}
