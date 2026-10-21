package health

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A full data_dir while the majority is lost: the pause record
// cannot be written. These pin enforcement.partition_pause_record_failure.

// enospcOn fails every record write to the named layers with ENOSPC.
func enospcOn(layers ...string) func(string, PauseRecord) error {
	return func(layer string, _ PauseRecord) error {
		for _, l := range layers {
			if l == layer {
				return &os.PathError{Op: "write", Path: "partition-pause", Err: syscall.ENOSPC}
			}
		}
		return nil
	}
}

func (f *pauseFixture) armedFence() {
	f.p.SetSelfFence(func() bool { return true }, func() { f.mu.Lock(); f.fenced++; f.mu.Unlock() })
}

func (f *pauseFixture) fences() int { f.mu.Lock(); defer f.mu.Unlock(); return f.fenced }

func (f *pauseFixture) recordFile() string {
	return filepath.Join(f.dataDir, partitionPauseDir, "vm-vm-ha.json")
}

// The default: a record that cannot be written anywhere does not stop the
// pause. vm-ha is paused, no self-fence is tripped although a verified
// watchdog is armed, partition_pause_failed is not raised (the majority keeps
// relying on a pause that DID happen), and partition_paused lists vm-ha, as
// the majority's bridge rule reads it. Every reader in this process sees the
// record, and it reaches the record directory once space returns.
//
// Mutations: make the default fail the pause on a record write error (mode
// self_fence) — vm-ha keeps running, the fence trips, and this goes red; drop
// the flush — the record never reaches the directory and the last check goes
// red; keep the memory layer out of ReadPauseRecord — the reader check goes red.
func TestPartitionPause_FullDiskDefaultPausesAnywayAndPersistsLater(t *testing.T) {
	f := newPauseFixture(t)
	f.armedFence()
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk, PauseRecordLayerReserve))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)

	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with its record unwritable; the default pauses anyway", st)
	}
	if n := f.fences(); n != 0 {
		t.Fatalf("the host self-fenced %d time(s) over a record it could not write", n)
	}
	if failed, err := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); err != nil || failed {
		t.Fatalf("partition_pause_failed = %v (%v) for a pause that happened", failed, err)
	}
	if c, ok := f.condition(corrosion.CondPartitionPaused); !ok || c.Lifecycle == corrosion.ConditionResolved || !strings.Contains(c.Evidence, "vm/vm-ha") {
		t.Fatalf("partition_paused does not list vm-ha (ok=%v %+v)", ok, c)
	}
	if _, held, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); err != nil || !held {
		t.Fatalf("ReadPauseRecord = %v, %v: the snapshot and NIC-guard paths would not see the pause", held, err)
	}
	if _, err := os.Stat(f.recordFile()); err == nil {
		t.Fatal("setup: the record file exists although every write failed")
	}
	// Space returns: the next pass writes the record to the directory.
	f.p.SetRecordFaultForTests(nil)
	f.tick()
	if _, err := os.Stat(f.recordFile()); err != nil {
		t.Fatalf("the record is not in the record directory once space returned: %v", err)
	}
	// And it still resumes through the same checks.
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after the majority confirmed it", st)
	}
}

// self_fence is the behaviour before the setting: the record write failing is
// a failed pause, raised, and with a verified watchdog a self-fence.
//
// Mutation: let self_fence fall back to the reserve or memory — vm-ha pauses,
// nothing fences, and this goes red.
func TestPartitionPause_FullDiskSelfFenceModeIsTheOldBehaviour(t *testing.T) {
	f := newPauseFixture(t)
	f.armedFence()
	f.p.SetRecordFailure(PauseRecordFailureSelfFence)
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s; self_fence never pauses without a written record", st)
	}
	if f.fences() == 0 {
		t.Fatal("self_fence did not self-fence on an unwritable record with a verified watchdog")
	}
	if failed, _ := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); !failed {
		t.Fatal("partition_pause_failed is not open")
	}
}

// reserve: the record lands in the reserve made at the first pass, before the
// pause, and survives the process: a new daemon reads it from there and
// resumes through the same checks. With the reserve unwritable too, the pause
// fails as in self_fence: record-before-pause holds.
//
// Mutations: skip the reserve in record — vm-ha stays running and the fence
// trips, red; do not make the reserve at the first pass — the same; leave the
// reserve out of list — the restarted pauser finds no record and vm-ha stays
// paused, red.
func TestPartitionPause_FullDiskReserveModeWritesTheReserve(t *testing.T) {
	t.Run("reserve writable", func(t *testing.T) {
		f := newPauseFixture(t)
		f.armedFence()
		f.p.SetRecordFailure(PauseRecordFailureReserve)
		f.tick() // the first pass, with room on the disk, makes the reserve
		f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk))
		f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
		if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
			t.Fatalf("vm-ha is %s; reserve mode pauses on a record in the reserve", st)
		}
		if n := f.fences(); n != 0 {
			t.Fatalf("self-fenced %d time(s) with the reserve writable", n)
		}
		if _, err := os.Stat(f.recordFile()); err == nil {
			t.Fatal("setup: the record file exists although the directory write failed")
		}
		// The daemon dies: only what is on disk remains.
		forgetPauseProcessStateForTests(f.dataDir)
		rec, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha")
		if err != nil || !ok || rec.Name != "vm-ha" {
			t.Fatalf("the record is not in the reserve after the process went: %+v %v %v", rec, ok, err)
		}
		restarted := f.restartPauser()
		restarted.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk)) // still full
		for i := 0; i <= int(PartitionPauseAfter/time.Second); i++ {
			restarted.Evaluate(context.Background())
			f.advance(time.Second)
		}
		if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
			t.Fatalf("vm-ha is %s after a restarted pauser regained the majority with the record in the reserve", st)
		}
		if _, ok, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); ok {
			t.Fatal("the resumed record outlived its resume")
		}
	})
	t.Run("reserve unwritable too", func(t *testing.T) {
		f := newPauseFixture(t)
		f.armedFence()
		f.p.SetRecordFailure(PauseRecordFailureReserve)
		f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk, PauseRecordLayerReserve))
		f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
		if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
			t.Fatalf("vm-ha is %s with no durable record; reserve mode keeps record-before-pause", st)
		}
		if f.fences() == 0 {
			t.Fatal("no self-fence with neither the directory nor the reserve writable")
		}
	})
}

// A daemon that dies while it holds a record in memory only comes back to a
// paused domain with no record. That is held, never free to run: the new
// process does not resume it however clean the majority's answer, and it is
// not paused again or touched.
//
// Mutation: resume a paused recoverable domain that has no record on regain —
// vm-ha runs and this goes red.
func TestPartitionPause_ACrashWithAnInMemoryRecordStaysHeld(t *testing.T) {
	f := newPauseFixture(t)
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk, PauseRecordLayerReserve))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	forgetPauseProcessStateForTests(f.dataDir) // the daemon dies
	restarted := f.restartPauser()
	for i := 0; i <= 2*int(PartitionPauseAfter/time.Second); i++ {
		restarted.Evaluate(context.Background())
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after a restart lost its in-memory record; it must stay held", st)
	}
}

// reservePath is the fixture's reserve file.
func (f *pauseFixture) reservePath() string {
	return filepath.Join(f.dataDir, partitionPauseDir, pauseReserveFile)
}

// reserveSlotsOf lists the reserve slots whose bytes hold name's record.
func (f *pauseFixture) reserveSlotsOf(name string) []int {
	f.t.Helper()
	b, err := os.ReadFile(f.reservePath())
	if err != nil {
		f.t.Fatalf("read the reserve: %v", err)
	}
	var out []int
	needle := []byte(`"name":"` + name + `"`)
	for i := 0; i+reserveSlotSize <= len(b); i += reserveSlotSize {
		if bytes.Contains(b[i:i+reserveSlotSize], needle) {
			out = append(out, i/reserveSlotSize)
		}
	}
	return out
}

// tearSlot writes a half-written header and payload over slot i.
func (f *pauseFixture) tearSlot(i int) {
	f.t.Helper()
	fh, err := os.OpenFile(f.reservePath(), os.O_RDWR, 0)
	if err != nil {
		f.t.Fatalf("no reserve: %v", err)
	}
	defer fh.Close()
	if _, err := fh.WriteAt([]byte{0x20, 0, 0, 0, 1, 2, 3, 4, '{'}, int64(i)*reserveSlotSize); err != nil {
		f.t.Fatal(err)
	}
}

// A torn reserve slot is one record's problem, not the host's: live slots
// are never overwritten in place, so a slot that fails its checksum is a torn
// first write (its pause never happened) or a torn clear (no longer the
// record's copy). It is skipped with a warning; the other records read, the
// snapshot and NIC-guard readers get an answer for every other workload, and
// the pauser resumes what it holds.
//
// Mutation: fail the whole reserve on a slot that does not check (the
// behaviour before) — ReadPauseRecord errors and vm-ha stays paused, red.
func TestPartitionPause_ATornReserveSlotIsSkipped(t *testing.T) {
	f := newPauseFixture(t)
	f.tick() // the first pass, with room on the disk, makes the reserve
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	if got := f.reserveSlotsOf("vm-ha"); len(got) != 1 {
		t.Fatalf("setup: vm-ha's record is in reserve slots %v, want one", got)
	}
	f.tearSlot(reserveSlots - 1)
	forgetPauseProcessStateForTests(f.dataDir) // the daemon dies
	if _, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "other"); err != nil || ok {
		t.Fatalf("ReadPauseRecord(other) = %v, %v; a torn slot of no record must not block every reader", ok, err)
	}
	if _, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); err != nil || !ok {
		t.Fatalf("ReadPauseRecord(vm-ha) = %v, %v beside a torn slot", ok, err)
	}
	restarted := f.restartPauser()
	restarted.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk)) // still full
	for i := 0; i <= int(PartitionPauseAfter/time.Second); i++ {
		restarted.Evaluate(context.Background())
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after the majority confirmed it, beside a torn slot", st)
	}
}

// A reserve that cannot be read at all (here the wrong size) still holds
// every resume, and ReadPauseRecord reports the error the snapshot and
// NIC-guard paths refuse on.
//
// Mutation: treat an unreadable reserve as empty — vm-ha's record, which is
// only in the reserve, is lost and the reader check goes red.
func TestPartitionPause_AnUnreadableReserveHoldsEverything(t *testing.T) {
	f := newPauseFixture(t)
	f.tick()
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	if err := os.Truncate(f.reservePath(), reserveSlotSize*3); err != nil {
		t.Fatal(err)
	}
	forgetPauseProcessStateForTests(f.dataDir)
	if _, _, err := ReadPauseRecord(f.dataDir, PauseKindVM, "other"); err == nil {
		t.Fatal("ReadPauseRecord read past an unreadable reserve")
	}
	restarted := f.restartPauser()
	for i := 0; i <= int(PartitionPauseAfter/time.Second); i++ {
		restarted.Evaluate(context.Background())
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with the pause state unreadable", st)
	}
}

// A record held in memory reaches the record directory once space returns,
// even when the reserve cannot be read: the reserve's trouble must not widen
// the window in which a crash loses the record.
//
// Mutation: return from flush on a reserve that does not read (the behaviour
// before) — the record never reaches the directory, red.
func TestPartitionPause_MemoryRecordsFlushPastAnUnreadableReserve(t *testing.T) {
	f := newPauseFixture(t)
	dir := filepath.Join(f.dataDir, partitionPauseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.reservePath(), make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	if _, err := os.Stat(f.recordFile()); err == nil {
		t.Fatal("setup: the record file exists although the directory write failed")
	}
	f.p.SetRecordFaultForTests(nil)
	f.tick()
	if _, err := os.Stat(f.recordFile()); err != nil {
		t.Fatalf("the in-memory record did not reach the directory past an unreadable reserve: %v", err)
	}
}

// The default mode tries the reserve before memory: the reserve survives a
// crash, memory does not. And once the record reaches the record directory,
// its reserve slot is zeroed, so a later resume that removes the file cannot
// leave a stale copy behind to come back at the next start.
//
// Mutations: let the default mode skip the reserve and go straight to memory —
// the record is not in the reserve, red; leave the slot once the file is
// written — the reserve still holds vm-ha, red.
func TestPartitionPause_DefaultModeUsesTheReserveBeforeMemory(t *testing.T) {
	f := newPauseFixture(t)
	f.tick()
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	if got := f.reserveSlotsOf("vm-ha"); len(got) != 1 {
		t.Fatalf("vm-ha's record is in reserve slots %v; the default mode holds it in the reserve before memory", got)
	}
	// It survives the process.
	other := t.TempDir()
	if err := os.CopyFS(other, os.DirFS(f.dataDir)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadPauseRecord(other, PauseKindVM, "vm-ha"); err != nil || !ok {
		t.Fatalf("a fresh process reads no record for vm-ha: %v, %v", ok, err)
	}
	f.p.SetRecordFaultForTests(nil)
	f.tick()
	if _, err := os.Stat(f.recordFile()); err != nil {
		t.Fatalf("the record is not in the record directory once space returned: %v", err)
	}
	if got := f.reserveSlotsOf("vm-ha"); len(got) != 0 {
		t.Fatalf("reserve slots %v still hold vm-ha once the record directory does", got)
	}
}

// A second record of a key whose record is in the reserve goes to another
// slot, synced before the older is zeroed: a live slot is never overwritten
// in place, so a write torn by a crash cannot destroy the one copy.
//
// Mutation: reuse the key's slot (the behaviour before) — the slot does not
// change, red.
func TestPartitionPause_AReserveSlotIsNeverOverwrittenInPlace(t *testing.T) {
	f := newPauseFixture(t)
	f.tick()
	f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk))
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	first := f.reserveSlotsOf("vm-ha")
	if len(first) != 1 {
		t.Fatalf("setup: vm-ha's record is in reserve slots %v", first)
	}
	// An operator resumes vm-ha by hand while the majority is still lost;
	// the next pass pauses and records it again.
	f.virt.SetState("vm-ha", libvirtfake.StateRunning)
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s after the second pass", st)
	}
	second := f.reserveSlotsOf("vm-ha")
	if len(second) != 1 || second[0] == first[0] {
		t.Fatalf("vm-ha's record went from slot %v to %v; a live slot must not be overwritten in place", first, second)
	}
}

// A record write that hangs (a dying disk) is bounded: the pause happens with
// the record in memory. When the write finally returns after a resume removed
// the record, it must not bring the record back.
//
// Mutations: wait for the write without a bound — the pass never returns, red;
// drop the generation check when the write lands — the file reappears, red.
func TestPartitionPause_AHungRecordWriteIsBoundedAndNeverResurrects(t *testing.T) {
	f := newPauseFixture(t)
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
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the pause passes did not return with the record write hung")
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with its record write hung", st)
	}
	if _, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); err != nil || !ok {
		t.Fatalf("ReadPauseRecord = %v, %v while the write hangs", ok, err)
	}
	// A resume removes the record; then the disk answers.
	if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-ha"); err != nil {
		t.Fatal(err)
	}
	hang.Store(false)
	once.Do(func() { close(release) })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(f.recordFile()); err == nil {
			// It may show between the rename and the check that undoes it.
			time.Sleep(50 * time.Millisecond)
			if _, err := os.Stat(f.recordFile()); err == nil {
				t.Fatal("a write that returned after the resume brought the record file back")
			}
		}
		if _, ok, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); ok {
			if _, err := os.Stat(f.recordFile()); err == nil {
				t.Fatal("a write that returned after the resume brought the record back")
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// reserve and self_fence promise a self-fence on a record that cannot be
// written, and need a verified watchdog to keep it. With none armed they
// pause as pause does, with the record in memory, and raise nothing.
//
// Mutation: fail the pause whatever the watchdog says — vm-ha keeps running,
// red.
func TestPartitionPause_RecordFailureModesWithoutAWatchdogPause(t *testing.T) {
	for _, mode := range []string{PauseRecordFailureReserve, PauseRecordFailureSelfFence} {
		t.Run(mode, func(t *testing.T) {
			f := newPauseFixture(t) // its self-fence is not armed
			f.p.SetRecordFailure(mode)
			f.tick()
			f.p.SetRecordFaultForTests(enospcOn(PauseRecordLayerDisk, PauseRecordLayerReserve))
			f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
			if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
				t.Fatalf("vm-ha is %s; %s without a verified watchdog pauses", st, mode)
			}
			if failed, err := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); err != nil || failed {
				t.Fatalf("partition_pause_failed = %v (%v) for a pause that happened", failed, err)
			}
			if _, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); err != nil || !ok {
				t.Fatalf("ReadPauseRecord = %v, %v", ok, err)
			}
		})
	}
}
