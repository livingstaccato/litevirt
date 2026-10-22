package health

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// waitMark waits for the mark the pause sets on name after its suspend.
func (f *pauseFixture) waitMark(name string) string {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if tok, ok, _ := f.virt.PartitionPauseMark(name); ok {
			return tok
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.t.Fatalf("setup: %s never got its pause mark", name)
	return ""
}

// pauseAndResume runs one real pause of vm-ha and its resume, and returns the
// record the pause wrote.
func (f *pauseFixture) pauseAndResume() PauseRecord {
	f.t.Helper()
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	recs := f.records()
	if len(recs) != 1 || f.raw("vm-ha") != libvirtfake.StatePaused {
		f.t.Fatalf("setup: vm-ha %s, records %+v", f.raw("vm-ha"), recs)
	}
	f.waitMark("vm-ha")
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		f.t.Fatalf("setup: vm-ha is %s after the heal", st)
	}
	return recs[0]
}

// The pauser resumes only a pause it made itself (ppfull re-review R1). A
// record a crash left behind after the resume, beside a VM an operator then
// suspended, is held: the VM stays paused, the record stays, and
// partition_paused names the VM as not paused by this host. Once the operator
// resumes it, the record is dropped and the condition resolves.
//
// Mutation: skip the mark check (pauseNotOurs returns "" for a "user" pause)
// — vm-ha is resumed and this goes red.
func TestPartitionPause_AStaleRecordDoesNotResumeAnOperatorsPause(t *testing.T) {
	f := newPauseFixture(t)
	stale := f.pauseAndResume()
	if stale.Token == "" {
		t.Fatal("setup: the pause recorded no token")
	}
	if err := f.virt.SuspendDomain("vm-ha"); err != nil { // virsh suspend
		t.Fatal(err)
	}
	if err := WritePauseRecordForTests(f.dataDir, stale); err != nil {
		t.Fatal(err)
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s: a stale record resumed an operator's pause", st)
	}
	if recs := f.records(); len(recs) != 1 {
		t.Fatalf("records %+v: the held VM's record must stay, to keep it visible", recs)
	}
	c, ok := f.condition(corrosion.CondPartitionPaused)
	if !ok || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("partition_paused is not open while vm-ha is held (ok=%v %+v)", ok, c)
	}
	var ev pausedEvidence
	if err := json.Unmarshal([]byte(c.Evidence), &ev); err != nil || ev.NotPausedByThisHost["vm/vm-ha"] == "" {
		t.Fatalf("partition_paused evidence %q does not name vm-ha as not paused by this host (%v)", c.Evidence, err)
	}

	if err := f.virt.ResumeDomain("vm-ha"); err != nil { // the operator resumes it
		t.Fatal(err)
	}
	f.tick()
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("records %+v after the operator resumed vm-ha", recs)
	}
	if c, ok := f.condition(corrosion.CondPartitionPaused); ok && c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("partition_paused still open after the held VM ran again: %s", c.Evidence)
	}
}

// QEMU's I/O-error pause is never this host's pause, even of a VM that still
// carries its mark: here the pauser paused vm-ha, an operator resumed it by
// hand during the partition (the mark lives as long as the QEMU process), and
// then a write to a full pool paused it on an I/O error. After the heal it
// stays paused.
//
// Mutation: drop the paused-reason check — vm-ha is resumed and this goes red.
func TestPartitionPause_NeverResumesAnIOErrorPause(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	f.waitMark("vm-ha")
	if err := f.virt.ResumeDomain("vm-ha"); err != nil {
		t.Fatal(err)
	}
	if err := f.virt.PauseOnIOError("vm-ha"); err != nil {
		t.Fatal(err)
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s: the pauser resumed a guest QEMU paused on an I/O error", st)
	}
	if recs := f.records(); len(recs) != 1 {
		t.Fatalf("records %+v, want vm-ha's kept while it is held", recs)
	}
}

// A record from a build without the mark carries no token. It still resumes
// a suspend (libvirt's paused reason "user"), as it did, so a host upgraded
// mid-partition is not left holding its own pauses.
//
// Mutation: hold every record without a token — vm-ha stays paused, red.
func TestPartitionPause_ARecordWithoutATokenStillResumesASuspend(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	recs := f.records()
	if len(recs) != 1 {
		t.Fatalf("setup: records %+v", recs)
	}
	legacy := recs[0]
	legacy.Token = ""
	if err := WritePauseRecordForTests(f.dataDir, legacy); err != nil {
		t.Fatal(err)
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s: a record from an older build no longer resumes its own pause", st)
	}
}

// A mark that cannot be set does not stop the pause (the majority relies on
// it); the VM is then held after the heal, since nothing proves the pause
// this host's.
//
// Mutation: skip the suspend when the mark fails — vm-ha keeps running
// through the partition, red.
func TestPartitionPause_AnUnsettableMarkStillPausesAndHolds(t *testing.T) {
	f := newPauseFixture(t)
	f.virt.FailMarkPartitionPaused = func(string) error { return errors.New("libvirtd: metadata write failed") }
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with its mark unsettable; the pause must happen anyway", st)
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s: resumed without this pause's mark", st)
	}
	if c, ok := f.condition(corrosion.CondPartitionPaused); !ok || !strings.Contains(c.Evidence, "could not mark") {
		t.Fatalf("partition_paused does not say this host's pause could not be marked (ok=%v %+v)", ok, c)
	}
}

// The mark is taken off before the resume, so a resume that fails puts it
// back: the pause is still this host's, and a later pass resumes it.
//
// Mutation: do not put the mark back — vm-ha stays held for good, red.
func TestPartitionPause_AFailedResumeKeepsItsMark(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	f.waitMark("vm-ha")
	var fails atomic.Int32
	f.virt.FailResumeDomain = func(string) error {
		if fails.Add(1) == 1 {
			return errors.New("libvirtd: resume failed")
		}
		return nil
	}
	f.regain()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ { // the next resume checks
		f.tick()
		f.advance(time.Second)
	}
	if fails.Load() < 2 {
		t.Fatalf("setup: %d resume attempts, want a failed one and a retry", fails.Load())
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after its first resume failed; the retry must resume it", st)
	}
	if _, ok, _ := f.virt.PartitionPauseMark("vm-ha"); ok {
		t.Fatal("vm-ha still carries the mark after its resume")
	}
}

// N1 (ppfull re-review): of two reserve slots holding one key, the one with
// the higher sequence number is the record, whichever slot index it is in.
//
// Mutation: let the later slot index win (seq ignored) — "newer first" goes
// red.
func TestPartitionPause_OfTwoReserveSlotsOfOneKeyTheHigherSeqWins(t *testing.T) {
	for _, newerFirst := range []bool{true, false} {
		name := "newer last"
		if newerFirst {
			name = "newer first"
		}
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			s := newPauseStore(dataDir)
			if err := s.ensureReserve(); err != nil {
				t.Fatal(err)
			}
			older := PauseRecord{Kind: PauseKindVM, Name: "vm-ha", Host: "node-a", OwnerEpoch: 3, Incarnation: "inc"}
			newer := older
			newer.OwnerEpoch = 4
			ob, _ := json.Marshal(older)
			nb, _ := json.Marshal(newer)
			oi, ni := 2, 7
			if newerFirst {
				oi, ni = 7, 2
			}
			if err := s.writeSlot(oi, ob, 10); err != nil {
				t.Fatal(err)
			}
			if err := s.writeSlot(ni, nb, 11); err != nil {
				t.Fatal(err)
			}
			forgetPauseProcessStateForTests(dataDir) // a new process reads the file
			rec, ok, err := ReadPauseRecord(dataDir, PauseKindVM, "vm-ha")
			if err != nil || !ok {
				t.Fatalf("ReadPauseRecord = %v, %v", ok, err)
			}
			if rec.OwnerEpoch != 4 {
				t.Fatalf("read the record at epoch %d, want the higher seq's 4", rec.OwnerEpoch)
			}
		})
	}
}

// N2 (ppfull re-review): with no record fallback (self_fence, a verified
// watchdog), a record write that does not return in time fails the pause,
// and the write still in flight is cancelled: when the disk answers, it must
// not land a record for a pause that never happened.
//
// Mutation: no gen++ on that path in record — the late write lands the
// record file, red.
func TestPartitionPause_ATimedOutRecordOfAFailedPauseIsCancelled(t *testing.T) {
	f := newPauseFixture(t)
	f.armedFence()
	f.p.SetRecordFailure(PauseRecordFailureSelfFence)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var hang atomic.Bool
	hang.Store(true)
	f.p.SetRecordFaultForTests(func(layer string, _ PauseRecord) error {
		if layer == PauseRecordLayerDisk && hang.Load() {
			<-release
		}
		return nil
	})
	f.set(QuorumNo)
	for i := 0; i <= int(PartitionPauseAfter/time.Second)+3 && f.fences() == 0; i++ {
		f.tick()
		f.advance(time.Second)
	}
	if f.fences() == 0 {
		t.Fatal("setup: no failed pause (and self-fence) with the record write hung")
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("setup: vm-ha is %s; a pause whose record failed must not happen", st)
	}
	hang.Store(false)
	once.Do(func() { close(release) })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(f.recordFile()); err == nil {
			// It may show between the rename and the check that undoes it.
			time.Sleep(50 * time.Millisecond)
			if _, err := os.Stat(f.recordFile()); err == nil {
				t.Fatal("the late write of a failed pause's record landed")
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); err != nil || ok {
		t.Fatalf("ReadPauseRecord = %v, %v: a failed pause left a record", ok, err)
	}
	if c, ok := f.condition(corrosion.CondPartitionPauseFailed); !ok || !strings.Contains(c.Evidence, "vm/vm-ha") {
		t.Fatalf("partition_pause_failed does not name vm-ha (ok=%v %+v)", ok, c)
	}
}

// F1 (ppio review): the mark is set after the suspend, outside the pause's
// timed window. libvirt can hold the metadata write behind a running job for
// up to 30 s; a mark that slow must not make the pause late or failed, and
// with a verified watchdog it must not self-fence the host.
//
// Mutation: mark before the suspend, inside the pause call (the first cut) —
// vm-ha is still running at the end of the pass, the pause is reported
// failed and the host self-fences, red.
func TestPartitionPause_ASlowMarkNeverDelaysThePause(t *testing.T) {
	f := newPauseFixture(t)
	f.armedFence()
	f.virt.FailMarkPartitionPaused = func(string) error {
		time.Sleep(3 * time.Second) // a MODIFY job waiting behind an async job
		return errors.New("libvirtd: cannot acquire state change lock")
	}
	f.set(QuorumNo)
	for i := 0; i <= int(PartitionPauseAfter/time.Second)+2 && f.raw("vm-ha") == libvirtfake.StateRunning; i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s at the end of the pausing pass; a slow mark held the suspend back", st)
	}
	f.tick()
	if failed, err := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); err != nil || failed {
		t.Fatalf("partition_pause_failed = %v (%v): a slow mark failed a pause that happened", failed, err)
	}
	if n := f.fences(); n != 0 {
		t.Fatalf("the host self-fenced %d time(s) over a slow mark", n)
	}
}

// The mark must carry THIS record's token: a mark of another pause (a later
// one's, or one a downgrade left) is not this pause's.
//
// Mutation: accept any mark (token not compared) — vm-ha is resumed, red.
func TestPartitionPause_AMarkWithAnotherTokenIsNotThisPause(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	if tok := f.waitMark("vm-ha"); tok == "someone-elses" {
		t.Fatal("setup: token collision")
	}
	if err := f.virt.MarkPartitionPaused("vm-ha", "someone-elses"); err != nil {
		t.Fatal(err)
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s: resumed under a mark whose token is not the record's", st)
	}
}

// A recorded VM seen running loses its mark at once, before the heal is
// sustained: an operator resumes it by hand as the partition heals and
// suspends it again; that suspend is the operator's, and the VM is held.
//
// Mutation: do not clear the marks of running recorded VMs — the stale mark
// matches the operator's suspend and vm-ha is resumed, red.
func TestPartitionPause_ARunningRecordedVMLosesItsMark(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	f.waitMark("vm-ha")
	f.set(QuorumYes)
	if err := f.virt.ResumeDomain("vm-ha"); err != nil { // virsh resume
		t.Fatal(err)
	}
	f.tick() // a Yes, not yet sustained
	f.advance(time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok, _ := f.virt.PartitionPauseMark("vm-ha"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("vm-ha runs and still carries this host's pause mark")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := f.virt.SuspendDomain("vm-ha"); err != nil { // virsh suspend
		t.Fatal(err)
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s: an operator's suspend matched a mark left on a running VM", st)
	}
}

// healWithAResumeAtTheFirstSustainedPass regains the majority, and has an
// operator resume vm-ha by hand just before the first sustained pass: no
// not-yet-sustained pass sees it running, so the record is dropped by the
// resume checks themselves.
func (f *pauseFixture) healWithAResumeAtTheFirstSustainedPass() {
	f.t.Helper()
	f.set(QuorumYes)
	for i := 0; i <= int(PartitionPauseAfter/time.Second)+1; i++ {
		if i == int(PartitionPauseAfter/time.Second) {
			if err := f.virt.ResumeDomain("vm-ha"); err != nil { // virsh resume
				f.t.Fatal(err)
			}
		}
		f.tick()
		f.advance(time.Second)
	}
	if recs := f.records(); len(recs) != 0 {
		f.t.Fatalf("setup: records %+v after vm-ha ran again at the heal", recs)
	}
}

// ppio re-review r1, F1: a background clear is ordered against a later
// pause's mark, and clears only the mark it was meant for. Here an operator
// resumes vm-ha as the partition heals, the clear of its mark is slow (a
// libvirt job), and the partition comes back: this host pauses vm-ha again
// under a new token. The old clear must not erase the new mark, or this
// host's own pause is held for good as someone else's after the heal.
//
// Mutation: clear unconditionally and outside the mark lock (the first cut)
// — the new mark is erased and vm-ha stays paused, red.
func TestPartitionPause_ASlowClearNeverErasesANewerPausesMark(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	first := f.waitMark("vm-ha")
	var calls atomic.Int32
	f.virt.FailClearPartitionPauseMark = func(string) error {
		if calls.Add(1) == 1 {
			time.Sleep(2 * time.Second) // waits behind a libvirt job
		}
		return nil
	}
	f.set(QuorumYes)
	if err := f.virt.ResumeDomain("vm-ha"); err != nil { // virsh resume
		t.Fatal(err)
	}
	f.tick() // a Yes, not yet sustained: the clear starts, and is slow
	f.advance(time.Second)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s after the partition came back", st)
	}
	recs := f.records()
	if len(recs) != 1 || recs[0].Token == first {
		t.Fatalf("setup: records %+v, want a new pause of vm-ha", recs)
	}
	time.Sleep(2500 * time.Millisecond) // the slow clear returns
	f.regain()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s: a slow clear erased this host's newer pause mark, and its own pause is held", st)
	}
}

// ppio re-review r1, N1: a mark that is only late is not someone else's
// pause. While it is being written vm-ha is held, saying so, and it is not
// named as paused by someone else; once it lands, vm-ha resumes.
//
// Mutation: no pending state (a late mark reads as an operator's pause) —
// the hold names vm-ha as not paused by this host, red.
func TestPartitionPause_ALateMarkIsHeldAsPendingNotForeign(t *testing.T) {
	f := newPauseFixture(t)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f.virt.FailMarkPartitionPaused = func(string) error { <-release; return nil }
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s before its mark landed", st)
	}
	f.p.mu.Lock()
	why, foreign := f.p.heldWhy["vm/vm-ha"], f.p.notOurs["vm/vm-ha"]
	f.p.mu.Unlock()
	if !strings.Contains(why, "still being written") || foreign != "" {
		t.Fatalf("held as %q, not ours %q; want a pending mark, not someone else's pause", why, foreign)
	}
	once.Do(func() { close(release) })
	f.waitMark("vm-ha")
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after its late mark landed", st)
	}
}

// ppio re-review r1, N2: a record dropped by the resume checks (its VM runs
// again) takes the VM's mark with it, and what this process remembers about
// the mark.
//
// Mutations: no clear on the drop path — the mark stays on the running VM,
// red; keep markFailed entries past the drop — the "mark failed" subtest goes
// red.
func TestPartitionPause_ADroppedRecordTakesItsMarkWithIt(t *testing.T) {
	t.Run("mark set", func(t *testing.T) {
		f := newPauseFixture(t)
		f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
		f.waitMark("vm-ha")
		f.healWithAResumeAtTheFirstSustainedPass()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, ok, _ := f.virt.PartitionPauseMark("vm-ha"); !ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("vm-ha runs with its record dropped and still carries this host's pause mark")
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	t.Run("mark failed", func(t *testing.T) {
		f := newPauseFixture(t)
		f.virt.FailMarkPartitionPaused = func(string) error { return errors.New("libvirtd: metadata write failed") }
		f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
		deadline := time.Now().Add(5 * time.Second)
		for {
			f.p.mu.Lock()
			n := len(f.p.markFailed)
			f.p.mu.Unlock()
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("setup: the failed mark was not remembered")
			}
			time.Sleep(5 * time.Millisecond)
		}
		f.healWithAResumeAtTheFirstSustainedPass()
		f.p.mu.Lock()
		left := len(f.p.markFailed)
		f.p.mu.Unlock()
		if left != 0 {
			t.Fatalf("%d markFailed entries outlive the dropped record", left)
		}
	})
}

// ppio re-review r2, F1: a clear takes a mark off only while it carries the
// token the clear was for. Here the clear for token A gets the mark lock only
// after a newer pause wrote its mark B: B stays.
//
// Mutation: clear whatever mark is there (no token comparison) — B is
// erased, red.
func TestPartitionPause_AClearForAnOlderTokenLeavesANewerMark(t *testing.T) {
	f := newPauseFixture(t)
	l := f.p.markLock("vm-ha")
	l.Lock()
	f.p.clearMarkBackground(context.Background(), "vm-ha", "token-a") // waits for the lock
	if err := f.virt.MarkPartitionPaused("vm-ha", "token-b"); err != nil {
		t.Fatal(err) // the newer pause's mark, written first
	}
	l.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.p.mu.Lock()
		busy := len(f.p.clearing) > 0
		f.p.mu.Unlock()
		if !busy {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if tok, ok, _ := f.virt.PartitionPauseMark("vm-ha"); !ok || tok != "token-b" {
		t.Fatalf("mark = %q, %v after a clear for token-a; the newer pause's token-b must stay", tok, ok)
	}
}

// ppio re-review r2, F2: the resume never waits on the mark lock. While a
// mark write or clear of the VM is in flight (here the lock is held), the
// heal's passes return promptly and hold the VM; it resumes on a later pass.
//
// Mutations: take no lock in resume — vm-ha resumes while the lock is held,
// red; wait for the lock (Lock, not TryLock) — the passes do not return, red.
func TestPartitionPause_AResumeNeverWaitsOnTheMarkLock(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	f.waitMark("vm-ha")
	l := f.p.markLock("vm-ha")
	l.Lock()
	done := make(chan struct{})
	go func() { defer close(done); f.regain() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		l.Unlock()
		t.Fatal("the heal's passes waited on the mark lock")
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		l.Unlock()
		t.Fatalf("vm-ha is %s: resumed while a mark write was in flight", st)
	}
	f.p.mu.Lock()
	why := f.p.heldWhy["vm/vm-ha"]
	f.p.mu.Unlock()
	if !strings.Contains(why, "in flight") {
		t.Errorf("held as %q, want the in-flight mark write named", why)
	}
	l.Unlock()
	for i := 0; i <= int(2*partitionResumeRecheck/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s once the mark lock was free", st)
	}
}

// ppio re-review r2, F3: a clear is per mark, not per VM. A slow clear of
// token A's mark is in flight when vm-ha is paused again under token B and an
// operator resumes it once more: B's clear must still run, and no mark may
// stay on the running VM.
//
// Mutation: dedupe clears by VM name only (the r2 code) — B's clear is
// dropped and its mark stays on the running VM, red.
func TestPartitionPause_ANewerTokensClearIsNotDropped(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	first := f.waitMark("vm-ha")
	var calls atomic.Int32
	f.virt.FailClearPartitionPauseMark = func(string) error {
		if calls.Add(1) == 1 {
			time.Sleep(2 * time.Second) // waits behind a libvirt job
		}
		return nil
	}
	f.set(QuorumYes)
	if err := f.virt.ResumeDomain("vm-ha"); err != nil { // virsh resume
		t.Fatal(err)
	}
	f.tick() // a Yes, not yet sustained: A's clear starts, and is slow
	f.advance(time.Second)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	recs := f.records()
	if len(recs) != 1 || recs[0].Token == first || f.raw("vm-ha") != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha %s, records %+v; want a new pause", f.raw("vm-ha"), recs)
	}
	// The operator resumes it again, and the heal drops the record while A's
	// clear is still in flight.
	f.set(QuorumYes)
	if err := f.virt.ResumeDomain("vm-ha"); err != nil {
		t.Fatal(err)
	}
	f.regain()
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("setup: records %+v after vm-ha ran again", recs)
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		f.p.mu.Lock()
		busy := len(f.p.clearing) > 0 || len(f.p.markPending) > 0
		f.p.mu.Unlock()
		if _, ok, _ := f.virt.PartitionPauseMark("vm-ha"); !ok && !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("vm-ha runs and still carries this host's pause mark: a newer token's clear was dropped")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("setup: vm-ha is %s", st)
	}
}

// ppio re-review r3, F-r3-1: a clear waits for its own mark. vm-ha is
// suspended as token T and an operator resumes it before T's mark write has
// even started; a clear for T is queued then. It must wait for the mark to
// land and take it off, not find nothing, return, and leave the mark that
// lands after it on the running VM.
//
// Mutations: drop the wait in clearMarkBackground — the clear runs first,
// red; note the mark as pending only in markPaused, not at the suspend
// (suspendPendingMark) — nothing to wait on yet, red.
func TestPartitionPause_AClearWaitsForItsOwnMark(t *testing.T) {
	f := newPauseFixture(t)
	rec := PauseRecord{Kind: PauseKindVM, Name: "vm-ha", Token: "token-t"}
	if err := f.p.suspendPendingMark(rec); err != nil {
		t.Fatal(err)
	}
	if err := f.virt.ResumeDomain("vm-ha"); err != nil { // virsh resume
		t.Fatal(err)
	}
	f.p.clearMarkBackground(context.Background(), "vm-ha", rec.Token)
	clearDone := func() bool {
		f.p.mu.Lock()
		defer f.p.mu.Unlock()
		return len(f.p.clearing) == 0
	}
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline) && !clearDone(); {
		time.Sleep(5 * time.Millisecond)
	}
	f.p.markPaused(rec) // the mark lands only now
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && !clearDone(); {
		time.Sleep(5 * time.Millisecond)
	}
	if !clearDone() {
		t.Fatal("the clear did not finish once its mark landed")
	}
	if tok, ok, _ := f.virt.PartitionPauseMark("vm-ha"); ok {
		t.Fatalf("vm-ha runs and carries mark %q: the clear ran before its own mark landed", tok)
	}
}

// ppio re-review r3, F-r3-2: a clear's wait for its own mark is bounded. The
// mark write hangs (libvirt's metadata write has no timeout): a clear for its
// token gives up when the pauser's ctx ends, or after markWaitBound, so its
// goroutine does not leak; and the VM stays held while the write is in flight.
//
// Mutations: ignore ctx in the wait — the cancel subtest's clear never ends,
// red; no deadline — the bound subtest's clear never ends, red.
func TestPartitionPause_AHungMarkWriteNeverStrandsItsClear(t *testing.T) {
	for _, tc := range []string{"cancel", "bound"} {
		t.Run(tc, func(t *testing.T) {
			f := newPauseFixture(t)
			release := make(chan struct{})
			var released sync.Once
			unhang := func() { released.Do(func() { close(release) }) }
			defer unhang()
			f.virt.FailMarkPartitionPaused = func(string) error { <-release; return nil }
			f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
			recs := f.records()
			if len(recs) != 1 || f.raw("vm-ha") != libvirtfake.StatePaused {
				t.Fatalf("setup: vm-ha %s, records %+v; want it paused", f.raw("vm-ha"), recs)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc == "bound" {
				f.p.mu.Lock()
				f.p.markWaitBound = 200 * time.Millisecond
				f.p.mu.Unlock()
			}
			f.p.clearMarkBackground(ctx, "vm-ha", recs[0].Token)
			if tc == "cancel" {
				time.Sleep(100 * time.Millisecond)
				cancel()
			}
			ended := false
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
				f.p.mu.Lock()
				ended = len(f.p.clearing) == 0
				f.p.mu.Unlock()
				if ended {
					break
				}
			}
			if !ended {
				t.Fatal("the clear still waits on a hung mark write: its goroutine leaks")
			}
			// The heal holds the VM: its mark write is still in flight.
			done := make(chan struct{})
			go func() { defer close(done); f.regain() }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the heal's passes waited on the hung mark write")
			}
			if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
				t.Fatalf("vm-ha is %s: resumed while its mark write hung", st)
			}
			f.p.mu.Lock()
			why := f.p.heldWhy["vm/vm-ha"]
			f.p.mu.Unlock()
			if !strings.Contains(why, "in flight") && !strings.Contains(why, "still being written") {
				t.Errorf("held as %q, want the mark write in flight named", why)
			}
			unhang()
		})
	}
}

// clearsDone waits up to 3 s for every background clear to end.
func (f *pauseFixture) clearsDone() bool {
	for d := time.Now().Add(3 * time.Second); time.Now().Before(d); time.Sleep(5 * time.Millisecond) {
		f.p.mu.Lock()
		n := len(f.p.clearing)
		f.p.mu.Unlock()
		if n == 0 {
			return true
		}
	}
	return false
}

// hangMarkWrites makes vm-ha's mark writes hang until the returned release
// runs (after which they pass at once), and shortens the clear's wait for
// them.
func (f *pauseFixture) hangMarkWrites(t *testing.T) (release func()) {
	ch := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	f.virt.FailMarkPartitionPaused = func(string) error { <-ch; return nil }
	f.p.mu.Lock()
	f.p.markWaitBound = 200 * time.Millisecond
	f.p.mu.Unlock()
	return release
}

// ppio re-review r4, F-r4-1: a mark that lands after its clear gave up
// waiting for it is still taken off. The write hangs, the operator resumes
// vm-ha, the heal drops the record and its clear gives up; then the mark
// lands on the running VM, and no record is left for a sweep to find.
//
// Mutation: give up without handing the mark to its write (no clearWanted)
// — the late mark stays on the running VM, red.
func TestPartitionPause_ALateMarkAfterItsClearGaveUpIsTakenOff(t *testing.T) {
	f := newPauseFixture(t)
	release := f.hangMarkWrites(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	recs := f.records()
	if len(recs) != 1 || f.raw("vm-ha") != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha %s, records %+v; want it paused", f.raw("vm-ha"), recs)
	}
	if err := f.virt.ResumeDomain("vm-ha"); err != nil { // virsh resume
		t.Fatal(err)
	}
	f.regain()
	if !f.clearsDone() {
		t.Fatal("setup: the clear did not give up")
	}
	if n := len(f.records()); n != 0 {
		t.Fatalf("setup: %d records left; want the heal to drop it", n)
	}
	release()
	// More passes: a sustained Yes, then a short Yes after a blip.
	f.regain()
	f.loseFor(QuorumNo, 2*time.Second)
	f.set(QuorumYes)
	for i := 0; i < 5; i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	for d := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		tok, ok, _ := f.virt.PartitionPauseMark("vm-ha")
		if !ok {
			break
		}
		if time.Now().After(d) {
			t.Fatalf("running vm-ha keeps the late mark %q: nothing took it off once it landed", tok)
		}
	}
}

// ppio re-review r4: the same give-up while the record is still there (a Yes
// not yet sustained runs clearMarksOfRunning): the late mark goes too.
func TestPartitionPause_ALateMarkAfterItsClearGaveUpGoesWithTheRecordKept(t *testing.T) {
	f := newPauseFixture(t)
	release := f.hangMarkWrites(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if err := f.virt.ResumeDomain("vm-ha"); err != nil {
		t.Fatal(err)
	}
	f.set(QuorumYes)
	f.tick() // a short Yes: clearMarksOfRunning starts a clear, which gives up
	f.advance(time.Second)
	if !f.clearsDone() {
		t.Fatal("setup: the clear did not give up")
	}
	if len(f.records()) != 1 {
		t.Fatal("setup: the record should still exist")
	}
	release()
	time.Sleep(200 * time.Millisecond)
	f.tick() // still a short Yes: the sweep runs again
	f.clearsDone()
	if tok, ok, _ := f.virt.PartitionPauseMark("vm-ha"); ok {
		t.Fatalf("late mark %q stayed on the running vm-ha with its record present", tok)
	}
}
