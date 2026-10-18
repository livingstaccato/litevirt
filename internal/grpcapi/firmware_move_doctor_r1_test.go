package grpcapi

import (
	"bytes"
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
	"github.com/litevirt/litevirt/internal/health"
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
	// m-1 (re-review 1): only the SR-IOV VFs the spec asks for; a VM whose
	// spec asks for none raises nothing, whatever rows the source holds.
	// Mutation: count every PCI row of the VM on the source — red.
	t.Run("hold_no_marker/adopt_no_sriov_in_spec_raises_no_vf_missing", func(t *testing.T) {
		r, _ := lostWithOwed(t, true, false, "")
		if err := corrosion.UpsertPCIDevice(context.Background(), r.src.db, corrosion.PCIDeviceRecord{HostName: "src-host",
			Address: "0000:3b:02.1", Type: "network", VMName: fwlVM}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.doctor(actAdopt); err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if _, found, _ := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigVFMissing, "vm", fwlVM); found {
			t.Error("vf_missing raised for a VM whose spec asks for no SR-IOV VF")
		}
	})
	t.Run("hold_no_marker/adopt_converges_and_names_missing_vfs", func(t *testing.T) {
		r, _ := lostWithOwed(t, true, false, "")
		r.specDevices(`[{"sriov":true}]`)
		for _, d := range []corrosion.PCIDeviceRecord{
			{HostName: "src-host", Address: "0000:3b:02.1", Type: "network", VMName: fwlVM},
			{HostName: "src-host", Address: "0000:3b:00.0", Type: "network", SRIOVCapable: true, VMName: fwlVM},
			{HostName: "src-host", Address: "0000:5e:00.0", Type: "gpu", VMName: fwlVM},
		} {
			if err := corrosion.UpsertPCIDevice(context.Background(), r.src.db, d); err != nil {
				t.Fatal(err)
			}
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
		if err != nil || !found || c.Lifecycle == corrosion.ConditionResolved || !strings.Contains(c.Evidence, "0000:3b:02.1") ||
			strings.Contains(c.Evidence, "0000:3b:00.0") || strings.Contains(c.Evidence, "0000:5e:00.0") {
			t.Errorf("vf_missing %+v found=%v err=%v, want it open naming 0000:3b:02.1 only", c, found, err)
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

// specDevices sets the device list of the VM's stored spec.
func (r *fwlRig) specDevices(devices string) {
	r.t.Helper()
	vm := r.row()
	var sp map[string]any
	if err := json.Unmarshal([]byte(vm.Spec), &sp); err != nil {
		r.t.Fatal(err)
	}
	var d any
	if err := json.Unmarshal([]byte(devices), &d); err != nil {
		r.t.Fatal(err)
	}
	sp["devices"] = d
	b, _ := json.Marshal(sp)
	if err := r.src.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = ?`, string(b), fwlVM); err != nil {
		r.t.Fatal(err)
	}
}

// Re-review 1 of D2-18 (round 2): the owed leftover kept from the target's
// reconciler (I-1), a target-local adopt rerun after its resume landed
// (I-2), every refusal before the target's guest is stopped (I-3), and the
// minors.
func TestDoctorFirmwareMove_R2(t *testing.T) {
	ctx := context.Background()
	// A released move returned to the fenced source; the target comes back
	// with the leftover the owed DISCARD names.
	returnedReleased := func(t *testing.T) (*fwlRig, fwmig.OwedDiscard) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		if _, err := r.doctor(actAcceptSource, withAck); err != nil {
			t.Fatalf("accept-source: %v", err)
		}
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		if len(owed) != 1 {
			t.Fatalf("owed discards %+v, want one", owed)
		}
		return r, owed[0]
	}
	reconcileDst := func(r *fwlRig) {
		rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
		rc.SetFirmwareStore(r.dstStore)
		rc.ReconcileOnce(ctx)
	}
	quarantined := func(t *testing.T, r *fwlRig, o fwmig.OwedDiscard) {
		t.Helper()
		if st, ok := r.dstFake.RawState(fwlVM); ok {
			t.Errorf("the leftover domain is still defined (%s)", st)
		}
		dir, _ := r.dst.fwRecords().QuarantinePath(fwlVM, o.Attempt)
		if b, _ := os.ReadFile(filepath.Join(dir, "nvram")); len(b) == 0 {
			t.Error("the leftover's NVRAM is not in the quarantine")
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "swtpm", "tpm2", "tpm2-00.permall")); len(b) == 0 {
			t.Error("the leftover's TPM state is not in the quarantine")
		}
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); ok {
			t.Error("the leftover record stays")
		}
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		if left, _ := r.src.fwRecords().ListOwedDiscards(); len(left) != 0 {
			t.Errorf("owed discards %+v after the leftover went", left)
		}
	}

	// ── I-1: the owed DISCARD puts the leftover under a record, and the
	// target's reconciler leaves it alone ──
	// Mutation: answer a no-hold DISCARD without the leftover record — red
	// (the reconciler undefines the domain with its NVRAM).
	t.Run("released_target_back_shut_off/reconciler_keeps_leftover", func(t *testing.T) {
		r, o := returnedReleased(t)
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.dstFake.SetStateReason(fwlVM, "destroyed")
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); !ok {
			t.Fatal("the owed DISCARD left no leftover record")
		}
		reconcileDst(r)
		if _, ok := r.dstFake.RawState(fwlVM); !ok {
			t.Fatal("the target's reconciler undefined the leftover")
		}
		if b, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM)); len(b) == 0 {
			t.Fatal("the leftover's NVRAM is gone")
		}
		if _, err := r.doctor(actDiscard); err != nil {
			t.Fatalf("discard the leftover: %v", err)
		}
		quarantined(t, r, o)
	})
	// I-1 (a): a running leftover is stopped by the doctor itself, under the
	// record, never handed to the operator. Mutation: drop the record write
	// in the doctor's discard — red (the guard refuses the exempt stop).
	t.Run("released_target_back_running/discard_stop_target", func(t *testing.T) {
		r, o := returnedReleased(t)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		_, err := r.doctor(actDiscard)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "add --stop-target") || strings.Contains(err.Error(), "virsh") {
			t.Fatalf("err %v, want the --stop-target refusal with no virsh hint", err)
		}
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); !ok {
			t.Fatal("the refusal left the running leftover without a record")
		}
		if _, err := r.doctor(actDiscard, withStop); err != nil {
			t.Fatalf("discard --stop-target: %v", err)
		}
		quarantined(t, r, o)
	})
	// m-3: a run that stops between the quarantine and the undefine is taken
	// up by the next; the owed DISCARD in between keeps its record.
	// Mutation: undefine before the quarantine — red.
	t.Run("released_target_back_shut_off/discard_interrupted", func(t *testing.T) {
		r, o := returnedReleased(t)
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		old := fwDoctorLeftoverHook
		fwDoctorLeftoverHook = func() error { return errors.New("daemon died") }
		_, err := r.doctor(actDiscard)
		fwDoctorLeftoverHook = old
		if err == nil {
			t.Fatal("first run did not stop")
		}
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		if left, _ := r.src.fwRecords().ListOwedDiscards(); len(left) != 1 {
			t.Fatalf("owed discards %+v, want the record kept", left)
		}
		if _, err := r.doctor(actDiscard); err != nil {
			t.Fatalf("rerun: %v", err)
		}
		quarantined(t, r, o)
	})

	// ── I-2: the target-local adopt is rerun after its resume landed ──
	// Mutation: refuse a held domain that is not paused — red.
	for _, step := range []string{"resumed", "published"} {
		t.Run("hold_no_marker/adopt_interrupted_after_"+step, func(t *testing.T) {
			r, _ := lostWithOwed(t, true, false, "")
			old := fwDoctorAdoptHook
			fwDoctorAdoptHook = func(s string) error {
				if s == step {
					return errors.New("daemon died after " + s)
				}
				return nil
			}
			_, err := r.doctor(actAdopt)
			fwDoctorAdoptHook = old
			if err == nil {
				t.Fatal("first run did not stop")
			}
			if h, ok := r.hold(); !ok || h.State != fwmig.HoldResuming {
				t.Fatalf("hold %+v (%v), want resuming", h.State, ok)
			}
			if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
				t.Fatalf("target domain %s, want running", st)
			}
			if _, err := r.doctor(actAdopt); err != nil {
				t.Fatalf("rerun: %v", err)
			}
			if vm := r.row(); vm.HostName != "dst-host" || vm.State != "running" {
				t.Errorf("row %s on %s, want running on dst-host", vm.State, vm.HostName)
			}
			if _, ok := r.hold(); ok {
				t.Error("the hold stays")
			}
		})
	}

	// ── I-3: the disk refusal comes before the target's guest is stopped ──
	// Mutation: drop the commit-disk comparison in returnDisks — red (the
	// return writer declines only after the stop).
	t.Run("target_ran_from_committed_disk_changed/accept_source_stop_target_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseTargetRan, "TARGET_RAN")
		if err := corrosion.UpdateDiskHostAndPath(ctx, r.src.db, fwlVM, "root", "dst-host", "/srv/nfs/os1-root-moved.qcow2"); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck, withStop)
		r.refused(err, "changed since the commit", before)
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("the target's guest is %s, want it left running", st)
		}
		if owed, _ := r.src.fwRecords().ListOwedDiscards(); len(owed) != 0 {
			t.Errorf("a refused return left owed discards %+v", owed)
		}
	})

	// ── m-4: source_paused ──
	// Mutation: accept a paused target under any hold — red.
	t.Run("source_paused_target_paused_after_running/accept_source_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		r.dstFake.SetState(fwlVM, libvirtfake.StatePaused)
		h, _ := r.hold()
		h.State = fwmig.HoldResuming
		if err := r.dst.fwRecords().PutHold(h); err != nil {
			t.Fatal(err)
		}
		r.park(run, fwmig.PhaseSourcePaused, "test")
		before := r.snap()
		_, err := r.doctor(actAcceptSource)
		r.refused(err, "may have run", before)
	})
	t.Run("source_paused_source_running/refusal_names_its_state", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseSourcePaused, "test")
		before := r.snap()
		_, err := r.doctor(actAcceptSource)
		r.refused(err, "shut the source's running domain off", before)
	})

	// ── m-5: a forward that never reaches the host that acts is audited at
	// the entry; one the host audited is not audited twice ──
	// Mutations: audit only Unavailable at the entry; ignore the trailer —
	// red.
	auditRows := func(t *testing.T, r *fwlRig) []string {
		rows, err := r.src.db.Query(ctx, `SELECT result FROM audit_log WHERE action = ? AND target = ?`, fwDoctorVerb, fwlVM)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, row := range rows {
			out = append(out, row.String("result"))
		}
		return out
	}
	t.Run("forward_deadline/audited_at_entry", func(t *testing.T) {
		r, _ := lostWithOwed(t, true, false, "")
		r.peerC.mu.Lock()
		r.peerC.actionErr = status.Error(codes.DeadlineExceeded, "context deadline exceeded")
		r.peerC.mu.Unlock()
		if _, err := r.doctor(actAdopt); status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("err %v, want the deadline", err)
		}
		if got := auditRows(t, r); len(got) != 1 || got[0] != "error" {
			t.Errorf("audit rows %v, want one error", got)
		}
	})
	t.Run("forwarded_refusal/audited_once", func(t *testing.T) {
		r, _ := lostWithOwed(t, false, false, "")
		if _, err := r.doctor(actAdopt); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("adopt with the source not proved off: %v", err)
		}
		if got := auditRows(t, r); len(got) != 1 || got[0] != "error" {
			t.Errorf("audit rows %v, want one error (the target's)", got)
		}
	})
}

// Re-review 2 of D2-18 (round 3): the leftover record whenever the row does
// not name the target (I-1 a), the reconciler that quarantines instead of
// wiping a leftover's firmware state (I-1 b), the doctor's exit once the row
// left the owing host or no host owes it (I-2), and the minors.
func TestDoctorFirmwareMove_R3(t *testing.T) {
	ctx := context.Background()
	returnedReleased := func(t *testing.T) (*fwlRig, fwmig.OwedDiscard) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		if _, err := r.doctor(actAcceptSource, withAck); err != nil {
			t.Fatalf("accept-source: %v", err)
		}
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		if len(owed) != 1 {
			t.Fatalf("owed discards %+v, want one", owed)
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.dstFake.SetStateReason(fwlVM, "destroyed")
		return r, owed[0]
	}
	reconcileDst := func(r *fwlRig) {
		rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
		rc.SetFirmwareStore(r.dstStore)
		rc.ReconcileOnce(ctx)
	}
	exec := func(t *testing.T, r *fwlRig, q string, args ...any) {
		t.Helper()
		if err := r.src.db.Execute(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	leftoverKept := func(t *testing.T, r *fwlRig) {
		t.Helper()
		if _, ok := r.dstFake.RawState(fwlVM); !ok {
			t.Fatal("the leftover domain is gone")
		}
		if b, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM)); len(b) == 0 {
			t.Fatal("the leftover's NVRAM is gone")
		}
		if b, _ := os.ReadFile(filepath.Join(r.dstStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")); len(b) == 0 {
			t.Fatal("the leftover's TPM state is gone")
		}
	}
	resolvedOnSource := func(t *testing.T, r *fwlRig) {
		t.Helper()
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		if left, _ := r.src.fwRecords().ListOwedDiscards(); len(left) != 0 {
			t.Errorf("owed discards %+v after the leftover went", left)
		}
		if c, found, _ := corrosion.GetHealthCondition(ctx, r.src.db, firmwareMigrationEvaluator, condFwmigDiscardOwed, "vm", fwlVM); found && c.Lifecycle != corrosion.ConditionResolved {
			t.Errorf("discard_owed %s, want resolved", c.Lifecycle)
		}
	}
	discarded := func(t *testing.T, r *fwlRig, attempt string) {
		t.Helper()
		if st, ok := r.dstFake.RawState(fwlVM); ok {
			t.Errorf("the leftover domain is still defined (%s)", st)
		}
		dir, _ := r.dst.fwRecords().QuarantinePath(fwlVM, attempt)
		if b, _ := os.ReadFile(filepath.Join(dir, "swtpm", "tpm2", "tpm2-00.permall")); len(b) == 0 {
			t.Error("the leftover's TPM state is not in the quarantine")
		}
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); ok {
			t.Error("the leftover record stays")
		}
	}

	// I-1 (a), deterministic: the row on a third host. Mutation: record only
	// a row naming the caller — red.
	t.Run("released_target_back_row_on_third_host/discard_records_leftover", func(t *testing.T) {
		r, o := returnedReleased(t)
		exec(t, r, `UPDATE vms SET host_name = ? WHERE name = ?`, "third-host", fwlVM)
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); !ok {
			t.Fatal("no leftover record for a row on a third host")
		}
		reconcileDst(r)
		leftoverKept(t, r)
		// m-3: the doctor shows it.
		rep, err := r.doctor(pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED)
		if err != nil {
			t.Fatal(err)
		}
		shown := false
		for _, h := range rep.GetHosts() {
			shown = shown || (h.GetHost() == "dst-host" && strings.Contains(h.GetLeftoverJson(), o.Attempt))
		}
		if !shown {
			t.Errorf("the doctor does not show the leftover record: %+v", rep.GetHosts())
		}
		// I-2: the row left the owing host; the doctor still discards it.
		if _, err := r.doctor(actDiscard); err != nil {
			t.Fatalf("discard: %v", err)
		}
		discarded(t, r, o.Attempt)
		resolvedOnSource(t, r)
	})
	// I-1 (b), the race: the reconciler runs before any DISCARD reaches the
	// target. Mutation: wipe instead of quarantine — red.
	t.Run("released_target_back_reconciler_first/state_quarantined", func(t *testing.T) {
		r, _ := returnedReleased(t)
		nv, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM))
		reconcileDst(r)
		ents, _ := os.ReadDir(filepath.Join(r.dst.dataDir, fwmig.QuarantineDir))
		var dir string
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), fwlVM+"-reconciled-") {
				dir = filepath.Join(r.dst.dataDir, fwmig.QuarantineDir, e.Name())
			}
		}
		if dir == "" {
			t.Fatalf("no reconciled quarantine (entries %v)", ents)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "nvram")); !bytes.Equal(b, nv) || len(b) == 0 {
			t.Errorf("quarantined NVRAM %q, want %q", b, nv)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "swtpm", "tpm2", "tpm2-00.permall")); len(b) == 0 {
			t.Error("the leftover's TPM state is not in the quarantine")
		}
		if _, err := os.Stat(filepath.Join(dir, "reason.txt")); err != nil {
			t.Errorf("no reason.txt: %v", err)
		}
		resolvedOnSource(t, r)
	})
	// I-2: the VM deleted after the record was written. Mutation: require the
	// row on the owing host — red.
	t.Run("leftover_vm_deleted/discard", func(t *testing.T) {
		r, o := returnedReleased(t)
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		exec(t, r, `DELETE FROM vms WHERE name = ?`, fwlVM)
		if _, err := r.doctor(actDiscard); err != nil {
			t.Fatalf("discard: %v", err)
		}
		discarded(t, r, o.Attempt)
		resolvedOnSource(t, r)
	})
	// I-2: no host owes the DISCARD any more; the local record is the exit,
	// for a guest that is not running only. Mutation: refuse without an
	// owing host — red; stop a running guest on the local record — red.
	t.Run("leftover_no_owner/discard_local_record", func(t *testing.T) {
		r, o := returnedReleased(t)
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		if err := r.src.fwRecords().RemoveOwedDiscard(fwlVM, o.Attempt); err != nil {
			t.Fatal(err)
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		if _, err := r.doctor(actDiscard, withStop); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "no host that answered owes") {
			t.Fatalf("running leftover on the local record: %v", err)
		}
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Fatalf("the leftover is %s, want it left running", st)
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		if _, err := r.doctor(actDiscard); err != nil {
			t.Fatalf("discard: %v", err)
		}
		discarded(t, r, o.Attempt)
	})
	// m-2: a run stopped before the undefine has already announced the
	// quarantine. Mutation: raise it only at the end — red.
	t.Run("leftover_discard_interrupted/quarantine_announced", func(t *testing.T) {
		r, o := returnedReleased(t)
		old := fwDoctorLeftoverHook
		fwDoctorLeftoverHook = func() error { return errors.New("daemon died") }
		_, err := r.doctor(actDiscard)
		fwDoctorLeftoverHook = old
		if err == nil {
			t.Fatal("the run did not stop")
		}
		dir, _ := r.dst.fwRecords().QuarantinePath(fwlVM, o.Attempt)
		c, found, _ := corrosion.GetHealthCondition(ctx, r.src.db, firmwareMigrationEvaluator, condFwmigQuarantine, "vm", fwlVM)
		if !found || c.Lifecycle == corrosion.ConditionResolved || !strings.Contains(c.Evidence, dir) {
			t.Errorf("quarantine condition %+v (found %v), want it open naming %s", c, found, dir)
		}
	})
	// m-1: a refused return drops its owed record, and a discard_owed raised
	// on it meanwhile goes with it. Mutation: drop the resolve — red.
	t.Run("refused_return_resolves_stale_discard_owed", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		m := r.park(run, fwmig.PhaseTargetRan, "TARGET_RAN")
		if err := r.src.raiseFirmwareMigrationCondition(ctx, fwmigCondition{Code: condFwmigDiscardOwed, VM: fwlVM, Attempt: m.Attempt,
			Source: "src-host", Target: "dst-host", Severity: corrosion.SeverityCritical, Detail: "raised by a retry during the action"}); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "add --stop-target", before)
		if c, found, _ := corrosion.GetHealthCondition(ctx, r.src.db, firmwareMigrationEvaluator, condFwmigDiscardOwed, "vm", fwlVM); found && c.Lifecycle != corrosion.ConditionResolved {
			t.Errorf("discard_owed %s with no owed record left, want resolved", c.Lifecycle)
		}
	})
}
