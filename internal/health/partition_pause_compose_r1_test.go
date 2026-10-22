package health

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// failResumeHangMarkVMs refuses vm-ha's resume, and then hangs every write
// of its mark until release: the mark the resume path puts back is slow.
type failResumeHangMarkVMs struct {
	PauseVMBackend
	release chan struct{}
	armed   atomic.Bool
}

func (h *failResumeHangMarkVMs) ResumePartitionPaused(name, uuid string) error {
	if name == "vm-ha" {
		h.armed.Store(true)
		return errors.New("refused: cutover")
	}
	return h.PauseVMBackend.ResumePartitionPaused(name, uuid)
}

func (h *failResumeHangMarkVMs) MarkPartitionPaused(name, token string) error {
	if name == "vm-ha" && h.armed.Load() {
		<-h.release
	}
	return h.PauseVMBackend.MarkPartitionPaused(name, token)
}

// A refused resume leaves the VM paused, and its mark goes back on. That
// write has no timeout, and it is no resume: while it is out, the VM must not
// count as a resume that may yet land, or a lost majority's pause pass kills
// the QEMU of a paused guest (ppmerge review F1). While it is out, the VM is
// held as this host's own pause, and once it lands a heal resumes the VM.
//
// Red on c353470ab: the put-back ran inside the resume call, so vm-ha stayed
// in resuming and the pass SIGKILLed it. Mutation: run the put-back in the
// call's goroutine before it lets go of the key and hands back its result —
// the pass waits on the write, past R; red.
func TestPartitionPause_ASlowMarkPutBackIsNotAResumeInFlight(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	rec := f.records()[0]
	f.waitMark("vm-ha")
	h := &failResumeHangMarkVMs{PauseVMBackend: f.virt, release: make(chan struct{})}
	release := releaser(t, h.release)
	f.p.SetVMBackend(h)
	f.healedPass()
	start := time.Now()
	f.tick()
	if held := time.Since(start); held > partitionResumeStepBound+time.Second {
		t.Fatalf("a slow mark put-back held the resume pass for %s, past R = %s", held.Round(time.Millisecond), partitionResumeStepBound)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s, want paused (resume refused)", st)
	}
	inFlight := f.p.resumeInFlight("vm/vm-ha")
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	st := f.raw("vm-ha")
	release()
	if st == libvirtfake.StateShutdown {
		t.Fatal("a pause pass SIGKILLed vm-ha, which was paused and whose resume was refused")
	}
	if inFlight {
		t.Fatal("vm-ha counted as a resume in flight while only its mark was being put back")
	}
	waitFor(t, "the put-back mark", func() bool {
		tok, ok, _ := f.virt.PartitionPauseMark("vm-ha")
		return ok && tok == rec.Token
	})
	f.p.SetVMBackend(f.virt)
	f.regain()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after a later heal, want resumed", st)
	}
}

// An abandoned resume keeps the VM's mark lock until the call returns, past
// the step that issued it: the mark a late failure or an undone landing puts
// back stays ordered with every other mark write and clear of the VM, and a
// pass meanwhile holds the VM ("a write of the partition-pause mark is in
// flight") rather than clearing a mark under it.
//
// Mutation: release the mark lock when resume() returns — red.
func TestPartitionPause_AnAbandonedResumeKeepsTheMarkLockUntilItReturns(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	release := abandonResume(f)
	l := f.p.markLock("vm-ha")
	if l.TryLock() {
		l.Unlock()
		t.Fatal("vm-ha's mark lock is free while its abandoned resume is still out")
	}
	f.set(QuorumNo) // the landing is undone
	release()
	f.waitReturned("vm/vm-ha")
	waitFor(t, "the mark lock to be free once the call and its put-back returned", func() bool {
		if !l.TryLock() {
			return false
		}
		l.Unlock()
		return true
	})
}

// A resume that is never issued (here an earlier call on the VM is still
// out) has already had its mark taken off: the mark goes back on, so a later
// heal resumes the VM instead of holding it as someone else's pause.
//
// Mutation: drop the put-back on the not-started path — vm-ha is held as
// "does not carry this pause's mark" for good; red.
func TestPartitionPause_AResumeNeverIssuedPutsTheMarkBack(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	rec := f.records()[0]
	f.waitMark("vm-ha")
	f.p.mu.Lock()
	f.p.inflight["vm/vm-ha"] = true // an earlier call that has not returned
	f.p.mu.Unlock()
	f.healedPass()
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s with an earlier call out, want paused", st)
	}
	waitFor(t, "the mark put back after a resume never issued", func() bool {
		tok, ok, _ := f.virt.PartitionPauseMark("vm-ha")
		return ok && tok == rec.Token
	})
	f.p.mu.Lock()
	delete(f.p.inflight, "vm/vm-ha")
	f.p.mu.Unlock()
	f.regain()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after a later heal, want resumed", st)
	}
}
