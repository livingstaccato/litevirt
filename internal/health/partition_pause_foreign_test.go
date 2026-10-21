package health

import (
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

// pauseAndResume runs one real pause of vm-ha and its resume, and returns the
// record the pause wrote.
func (f *pauseFixture) pauseAndResume() PauseRecord {
	f.t.Helper()
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	recs := f.records()
	if len(recs) != 1 || f.raw("vm-ha") != libvirtfake.StatePaused {
		f.t.Fatalf("setup: vm-ha %s, records %+v", f.raw("vm-ha"), recs)
	}
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
