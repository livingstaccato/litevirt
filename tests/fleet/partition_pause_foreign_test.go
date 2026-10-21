package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A stale pause record must not let the partition pauser resume a VM that
// something else paused (ppfull re-review R1). The record is stale because a
// crash fell between the pauser's resume and the record's removal, so the
// file is back beside a VM that ran again. Then QEMU pauses the VM on a disk
// I/O error, or an operator suspends it. After the next heal the record
// still matches the row and the voters, and the pauser resumed the VM:
// a guest on a full pool was pushed into another failed write, or an
// operator's pause was undone.
//
// The pauser now resumes only a pause it made itself: the domain is paused by
// a suspend (not an I/O error), and it carries the mark this pause put on the
// live domain. Anything else is held. The record stays, so partition_paused
// stays open and names the VM.
//
// Mutations: resume on the record alone (no paused-reason check, no mark
// check) — both go red; drop only the mark check — the operator variant goes
// red. Dropping only the paused-reason check leaves both green: the stale
// record's token is gone from the domain either way, so the mark check holds
// the I/O-error variant too. The reason check is pinned where the mark does
// match (TestPartitionPause_NeverResumesAnIOErrorPause).
func TestFleet_PartitionPause_AStaleRecordNeverResumesAnIOErrorPause(t *testing.T) {
	ppForeignPauseAfterAStaleRecord(t, true)
}

func TestFleet_PartitionPause_AStaleRecordNeverResumesAnOperatorPause(t *testing.T) {
	ppForeignPauseAfterAStaleRecord(t, false)
}

func ppForeignPauseAfterAStaleRecord(t *testing.T, ioError bool) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, Relays: 3, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "ppio", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("ppio", libvirtfake.StateRunning)
	s := newPPStack(t, c, ppOpts{latched: true})
	pn := s.node(owner)
	recFile := filepath.Join(pn.dataDir, "partition-pause", "vm-ppio.json")

	// A real pause and resume, through a fleet-wide blip (nothing can move):
	// the record the pauser itself wrote.
	c.SplitAll()
	var stale []byte
	eventually(t, 60*time.Second, owner.Name+" to pause ppio and record it", func() bool {
		if st, _ := owner.Virt.RawState("ppio"); st != libvirtfake.StatePaused {
			return false
		}
		b, err := os.ReadFile(recFile)
		if err != nil {
			return false
		}
		stale = b
		return true
	})
	c.HealGossip()
	eventually(t, 90*time.Second, "ppio to resume after the heal, and its record to go", func() bool {
		st, _ := owner.Virt.RawState("ppio")
		_, err := os.Stat(recFile)
		return st == libvirtfake.StateRunning && os.IsNotExist(err)
	})

	// Something else pauses ppio, and the record a crash between the resume
	// and its removal would have left is back.
	if ioError {
		if err := owner.Virt.PauseOnIOError("ppio"); err != nil {
			t.Fatalf("PauseOnIOError: %v", err)
		}
	} else if err := owner.Virt.SuspendDomain("ppio"); err != nil { // virsh suspend
		t.Fatalf("SuspendDomain: %v", err)
	}
	if err := os.WriteFile(recFile, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	resumesBefore := countOps(owner, "resume", "ppio")

	// Another blip, and its heal.
	c.SplitAll()
	eventually(t, 60*time.Second, owner.Name+"'s pauser to see the loss", func() bool {
		return !pn.pauser.HealedForTests()
	})
	time.Sleep(ppTPause)
	c.HealGossip()
	eventually(t, 90*time.Second, owner.Name+"'s pauser to see the heal", pn.pauser.HealedForTests)
	// Every resume check of the heal runs at once, then every 5 s.
	time.Sleep(12 * time.Second)

	if st, _ := owner.Virt.RawState("ppio"); st != libvirtfake.StatePaused {
		t.Fatalf("ppio is %s after the heal: the pauser resumed a VM it did not pause, on a stale record", st)
	}
	if n := countOps(owner, "resume", "ppio") - resumesBefore; n != 0 {
		t.Fatalf("ppio was resumed %d time(s) after something else paused it", n)
	}
	if _, err := os.Stat(recFile); err != nil {
		t.Fatalf("the record of the held VM is gone (%v): nothing shows why it stays paused", err)
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, owner.DB, corrosion.PartitionPauseEvaluator,
		corrosion.CondPartitionPaused, "host", owner.Name)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("partition_paused is not open on %s while ppio is held (ok=%v err=%v %+v)", owner.Name, ok, err, row)
	}
	if ioError {
		row, ok, err := corrosion.GetHealthCondition(ctx, owner.DB, health.VMIOPausedEvaluator, health.CondVMIOPaused, "vm", "ppio")
		if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
			t.Fatalf("vm_io_paused is not open about ppio (ok=%v err=%v %+v)", ok, err, row)
		}
	}
}

// countOps counts the fake's libvirt calls op on vm.
func countOps(n *Node, op, vm string) int {
	k := 0
	for _, ev := range n.Virt.EventLog() {
		if ev.Op == op && ev.Domain == vm {
			k++
		}
	}
	return k
}
