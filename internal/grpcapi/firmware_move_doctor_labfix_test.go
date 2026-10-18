package grpcapi

import (
	"context"
	"testing"

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
