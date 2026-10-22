package health

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// These pin where the bounded resume pass (fix/crash-safety), the pauser's
// own mark (fix/pause-never-resumes-ioerror) and the memory snapshot
// registry meet.

// A resume abandoned at its step bound took the mark off before it was
// issued. When it lands late and is paused again (lateResume's undo), the
// pause is still this host's, so the mark goes back on, and a later heal
// resumes the VM instead of holding it as someone else's pause.
//
// Mutation: undo without the mark — vm-ha is held as "does not carry this
// pause's mark" and never resumes; red.
func TestPartitionPause_ALateResumePausedAgainKeepsItsMark(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	release := abandonResume(f)
	rec := f.records()[0]
	if rec.Token == "" {
		t.Fatal("setup: vm-ha's record carries no token")
	}
	f.set(QuorumNo) // the landing is not as safe as an on-time one
	release()
	f.waitReturned("vm/vm-ha")
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s after its late landing was undone, want paused", st)
	}
	if tok, ok, _ := f.virt.PartitionPauseMark("vm-ha"); !ok || tok != rec.Token {
		t.Fatalf("vm-ha's mark = %q (set %v) after the undo, want the record's %q", tok, ok, rec.Token)
	}
	f.p.SetVMBackend(f.virt)
	f.regain()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after the heal, want resumed: the undo's pause is this host's", st)
	}
}

// A VM paused again because the majority went away during the pass that
// resumed it is a pause of its own: a fresh token, and its mark, so the next
// heal resumes it.
//
// Mutation: re-pause without the mark — vm-ha is held as someone else's
// pause; red. Mutation: keep the old token — the token check below; red.
func TestPartitionPause_ARepauseIsMarkedAndResumesAtTheNextHeal(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	first := f.records()[0]
	f.waitMark("vm-ha")
	f.p.SetVMBackend(&quorumFlipVMs{PauseVMBackend: f.virt, flip: func() { f.set(QuorumNo) }})
	f.healedPass()
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s after the majority went during its resume, want paused again", st)
	}
	recs := f.records()
	if len(recs) != 1 || recs[0].Token == "" || recs[0].Token == first.Token {
		t.Fatalf("records = %+v, want vm-ha's with a fresh token (the first was %q)", recs, first.Token)
	}
	if tok := f.waitMark("vm-ha"); tok != recs[0].Token {
		t.Fatalf("vm-ha's mark is %q, want the re-pause's %q", tok, recs[0].Token)
	}
	f.p.SetVMBackend(f.virt)
	f.regain()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after the next heal, want resumed", st)
	}
}

// The re-pause wins over a memory snapshot as a pause pass does. The pass
// resumes vm-ha and drops its record, which releases the registry hold, and
// a user's capture of the running VM begins; the pass's reading after its
// last resume then finds the majority gone (here the capture begins inside
// that reading, the last moment it can). The re-pause holds the capture, so
// its job is aborted and libvirt's cleanup waited out before the suspend:
// no memory image is written, the VM stays paused after the capture ends,
// and the pause is not reported failed.
//
// Mutation: drop the registry Hold from repause — the suspend lands in the
// middle of the live job, which then completes, and libvirt's switch-over
// resumes the guest before the capture suspends it again; red.
func TestPartitionPause_ARepauseWinsOverACaptureBegunAfterTheResume(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0})
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	errc := make(chan error, 1)
	var started sync.Once
	began := false
	dir := t.TempDir()
	f.p.SetQuorum(func(context.Context) (QuorumState, int, int) {
		f.mu.Lock()
		q := f.quorum
		f.mu.Unlock()
		if q != QuorumYes {
			return q, 1, 2
		}
		st, _ := f.virt.RawState("vm-ha")
		if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); held || st != libvirtfake.StateRunning {
			return q, 1, 2
		}
		started.Do(func() {
			go func() {
				_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(dir, "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
				errc <- err
			}()
			for i := 0; i < 5000 && !f.virt.LiveJobRunning("vm-ha"); i++ {
				time.Sleep(time.Millisecond)
			}
			began = f.virt.LiveJobRunning("vm-ha")
			f.set(QuorumNo)
		})
		return QuorumNo, 1, 2
	})
	f.healedPass()
	f.tick()
	if !began {
		t.Fatal("setup: the capture never began its live job after the resume")
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the capture succeeded across the re-pause: libvirt's switch-over resumed the guest the re-pause suspended")
		}
	case <-time.After(40 * time.Second):
		t.Fatal("the capture never ended")
	}
	if c := f.virt.Captures("vm-ha"); len(c) != 0 {
		t.Fatalf("a memory image of vm-ha was written after its re-pause (%d captures): the re-pause did not abort the capture", len(c))
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after the re-pause and the capture's end, want paused", st)
	}
	if recs := f.records(); len(recs) != 1 {
		t.Fatalf("records = %+v, want vm-ha's", recs)
	}
	if row, ok := f.condition(corrosion.CondPartitionPauseFailed); ok && row.Lifecycle == corrosion.ConditionConfirmed {
		t.Fatalf("partition_pause_failed is open: %s", row.Evidence)
	}
}

// hungClearVMs hangs the first mark clear of vm-ha until release.
type hungClearVMs struct {
	PauseVMBackend
	release chan struct{}
	once    sync.Once
}

func (h *hungClearVMs) ClearPartitionPauseMark(name string) error {
	if name == "vm-ha" {
		hung := false
		h.once.Do(func() { hung = true })
		if hung {
			<-h.release
		}
	}
	return h.PauseVMBackend.ClearPartitionPauseMark(name)
}

// The mark's removal before a resume is a call of the resume step, bounded
// by R like the resume itself: one that hangs is abandoned, the VM is held
// and not resumed, and the pauser's loop goes on. When the clear returns it
// puts the mark back (the resume was never issued), so a later pass resumes
// the VM.
//
// Mutation: an unbounded clear — the pass is held until the release; red.
// Mutation: no mark put back after an abandoned clear — vm-ha is held as
// someone else's pause and never resumes; red.
func TestPartitionPause_AHungMarkClearIsAbandonedAtItsBound(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	rec := f.records()[0]
	f.waitMark("vm-ha")
	hung := &hungClearVMs{PauseVMBackend: f.virt, release: make(chan struct{})}
	release := releaser(t, hung.release)
	f.p.SetVMBackend(hung)
	f.healedPass()
	start := time.Now()
	f.tick()
	if held := time.Since(start); held > partitionResumeStepBound+2*time.Second {
		t.Fatalf("a hung mark clear held the pauser for %s, past R = %s", held.Round(time.Millisecond), partitionResumeStepBound)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with its mark clear hung, want paused", st)
	}
	release()
	waitFor(t, "the abandoned clear to return and the mark lock to be free", func() bool {
		l := f.p.markLock("vm-ha")
		if !l.TryLock() {
			return false
		}
		l.Unlock()
		return true
	})
	if tok, ok, _ := f.virt.PartitionPauseMark("vm-ha"); !ok || tok != rec.Token {
		t.Fatalf("vm-ha's mark = %q (set %v) after the abandoned clear returned, want %q back", tok, ok, rec.Token)
	}
	f.regain()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after a later heal, want resumed", st)
	}
}

// A resume pass that reads the majority gone (No) between its steps refuses
// new captures at once, as Evaluate's own No reading does: the host has lost
// the voter majority, and a pause pass follows.
//
// Mutation: majorityLost does not refuse captures — vm-none's capture is
// admitted right after the pass; red.
func TestPartitionPause_ALossReadMidPassRefusesCaptures(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-none", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	f.p.SetVMBackend(&quorumFlipVMs{PauseVMBackend: f.virt, flip: func() { f.set(QuorumNo) }})
	f.healedPass()
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s, want paused again", st)
	}
	_, _, err := f.virt.CreateLiveSnapshot("vm-none", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-none"))
	var nt *lv.CaptureNotTakenError
	if !errors.As(err, &nt) {
		t.Fatalf("a capture right after a pass that read the majority gone: err = %v, want refused", err)
	}
}

// hungRepauseVMs asks for a capture of vm-none from inside the re-pause's
// suspend of vm-ha.
type hungRepauseVMs struct {
	PauseVMBackend
	try func()
}

func (h *hungRepauseVMs) SuspendDomain(name string) error {
	if name == "vm-ha" {
		h.try()
	}
	return h.PauseVMBackend.SuspendDomain(name)
}

// No capture starts while a re-pause runs, as during a pause pass, even when
// the reading that stopped the pass was Unknown (an unreadable voter set),
// which does not refuse captures by itself.
//
// Mutation: drop PausePass from repause — the capture asked for mid-re-pause
// is admitted; red.
func TestPartitionPause_NoCaptureStartsDuringARepause(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-none", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	var once sync.Once
	var midErr error
	tried := false
	f.p.SetVMBackend(&hungRepauseVMs{
		PauseVMBackend: &quorumFlipVMs{PauseVMBackend: f.virt, flip: func() { f.set(QuorumUnknown) }},
		try: func() {
			once.Do(func() {
				_, _, midErr = f.virt.CreateLiveSnapshot("vm-none", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-none"))
				tried = true
			})
		},
	})
	f.healedPass()
	f.tick()
	if !tried {
		t.Fatal("setup: no re-pause ran")
	}
	var nt *lv.CaptureNotTakenError
	if !errors.As(midErr, &nt) {
		t.Fatalf("a capture asked for during a re-pause: err = %v, want refused", midErr)
	}
}

// Every way a VM's record goes takes the registry hold with it
// (removeRecord): the on-time resume, the drop of a record whose VM runs
// again (checkRecord), and a late resume that stands (lateResume). A hold
// left behind would keep the capture of a later memory snapshot from
// resuming the running guest it paused.
//
// Mutations: either drop through store.remove instead of removeRecord — the
// hold outlives its record; red.
func TestPartitionPause_EveryDroppedRecordReleasesItsCaptureHold(t *testing.T) {
	t.Run("the VM runs again", func(t *testing.T) {
		f := newPauseFixture(t)
		reg := lv.NewCaptureRegistry()
		f.p.SetCaptureRegistry(reg)
		f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
		if !reg.Holding("vm-ha") {
			t.Fatal("setup: the pause holds no capture of vm-ha")
		}
		if err := f.virt.ResumeDomain("vm-ha"); err != nil { // virsh resume
			t.Fatal(err)
		}
		f.regain()
		if recs := f.records(); len(recs) != 0 {
			t.Fatalf("setup: records = %+v, want vm-ha's dropped", recs)
		}
		if reg.Holding("vm-ha") {
			t.Fatal("the registry still holds vm-ha after its record was dropped")
		}
	})
	t.Run("a late resume stands", func(t *testing.T) {
		shortStepBound(t)
		f := newPauseFixture(t)
		reg := lv.NewCaptureRegistry()
		f.p.SetCaptureRegistry(reg)
		release := abandonResume(f)
		if !reg.Holding("vm-ha") {
			t.Fatal("setup: the pause holds no capture of vm-ha")
		}
		release()
		f.waitReturned("vm/vm-ha")
		if recs := f.records(); len(recs) != 0 || f.raw("vm-ha") != libvirtfake.StateRunning {
			t.Fatalf("setup: vm-ha %s, records %+v; want its late resume to stand", f.raw("vm-ha"), recs)
		}
		if reg.Holding("vm-ha") {
			t.Fatal("the registry still holds vm-ha after its late resume stood and its record went")
		}
	})
}

// hungMarkReadVMs hangs every read of vm-ha's mark until release.
type hungMarkReadVMs struct {
	PauseVMBackend
	release chan struct{}
}

func (h *hungMarkReadVMs) PartitionPauseMark(name string) (string, bool, error) {
	if name == "vm-ha" {
		<-h.release
	}
	return h.PauseVMBackend.PartitionPauseMark(name)
}

// The check that the pause is this host's (§3.5 step 2) reads the mark from
// libvirt inside a resume step, so that read ends by the step's deadline
// like every other: a hung read holds the VM, never the pass.
//
// Mutation: bound the mark read by the call timeout (2 s) instead of the
// step's deadline — the pass overruns R; red.
func TestPartitionPause_AHungMarkReadEndsWithItsStep(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	f.waitMark("vm-ha")
	hung := &hungMarkReadVMs{PauseVMBackend: f.virt, release: make(chan struct{})}
	releaser(t, hung.release)
	f.p.SetVMBackend(hung)
	f.healedPass()
	start := time.Now()
	f.tick()
	if held := time.Since(start); held > partitionResumeStepBound+time.Second {
		t.Fatalf("a hung mark read held the resume pass for %s, past R = %s", held.Round(time.Millisecond), partitionResumeStepBound)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with its mark unreadable, want paused", st)
	}
}
