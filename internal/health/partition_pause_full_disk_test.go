package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// A pause state the new process cannot read is held: a corrupt reserve slot
// stops every resume, and ReadPauseRecord reports the error the snapshot and
// NIC-guard paths refuse on.
//
// Mutation: skip a slot that fails its checksum in loadReserveLocked — the
// record on disk resumes and this goes red.
func TestPartitionPause_AnUnreadableReserveHoldsEverything(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	path := filepath.Join(f.dataDir, partitionPauseDir, pauseReserveFile)
	fh, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("no reserve was made at the first pass: %v", err)
	}
	if _, err := fh.WriteAt([]byte{0x20, 0, 0, 0, 1, 2, 3, 4, '{'}, 3*reserveSlotSize); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	forgetPauseProcessStateForTests(f.dataDir)
	if _, _, err := ReadPauseRecord(f.dataDir, PauseKindVM, "other"); err == nil {
		t.Fatal("ReadPauseRecord read past a corrupt reserve")
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
