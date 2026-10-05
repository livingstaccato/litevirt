// Fleet scenarios for a source daemon that dies in the middle of a drain's
// cold move of a RUNNING VM. Between the shutdown and the start that ends the
// move, the VM is off and its row says the operator stopped it, which nothing
// restarts; the move's journal (corrosion.BeginDrainColdMove) is what tells a
// restarted daemon the VM must run again. ResumeDrainColdMoves is what the
// daemon runs at startup; these call it directly after a crash point.
//
// A crash is the drainCrashAt seam: the drain stops right there, with nothing
// cleaned up and the journal as it was. The fake's domains survive it, as
// qemu survives a daemon.

package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// assertRunsOnExactlyOneHost: os1 runs on want, its row names want and says
// running, and no other node has it active.
func (sc *coldStoppedScenario) assertRunsOnExactlyOneHost(t *testing.T, want *Node) {
	t.Helper()
	vm := sc.vm(t)
	if vm.HostName != want.Name || vm.State != "running" {
		t.Errorf("os1 row = host %s state %s/%q, want host %s running", vm.HostName, vm.State, vm.StateDetail, want.Name)
	}
	for _, n := range []*Node{sc.src, sc.dst} {
		active, _ := n.Virt.DomainIsActive("os1")
		if active != (n == want) {
			t.Errorf("os1 active on %s = %t, want %t", n.Name, active, n == want)
		}
	}
}

func (sc *coldStoppedScenario) pendingMoves(t *testing.T) int {
	t.Helper()
	ms, err := corrosion.ListDrainColdMoves(context.Background(), sc.src.DB, sc.src.Name)
	if err != nil {
		t.Fatalf("ListDrainColdMoves: %v", err)
	}
	return len(ms)
}

// A daemon that dies at any point of a running VM's cold move leaves the move
// journaled, and the restarted daemon ends it with the VM running on exactly
// one host: here, if the handoff had not committed; on the target if it had.
//
//   - journaled: nothing done to the VM yet;
//   - recorded:  its row says stopped by the operator, the domain still runs —
//     the row is put back to running;
//   - shut_off:  the domain is shut off — it is started here again;
//   - handed_off: the VM and its disk are the target's — it is started there.
//
// Mutation: skip the startup recovery's start — shut_off and handed_off end
// with os1 stopped and go red. Journal nothing — the recovery finds nothing to
// do, and the same cases go red.
func TestFleet_DrainCrashMidMoveEndsWithTheVMRunningOnOneHost(t *testing.T) {
	for _, tc := range []struct {
		point  string
		onDest bool
	}{
		{"journaled", false},
		{"recorded", false},
		{"shut_off", false},
		{"handed_off", true},
	} {
		t.Run(tc.point, func(t *testing.T) {
			sc := newColdStoppedScenario(t)
			sc.makeRunning(t)
			sc.src.Server.SetDrainCrashForTest(func(p string) bool { return p == tc.point })

			_, _ = sc.drain(t) // the drain "dies" at the crash point
			if n := sc.pendingMoves(t); n != 1 {
				t.Fatalf("after the crash, %d journaled cold move(s) are pending, want 1", n)
			}
			sc.src.Server.SetDrainCrashForTest(nil)

			left, err := sc.src.Server.ResumeDrainColdMoves(context.Background())
			if err != nil || left != 0 {
				t.Fatalf("ResumeDrainColdMoves = %d left, %v; want 0, nil", left, err)
			}
			want := sc.src
			if tc.onDest {
				want = sc.dst
			}
			sc.assertRunsOnExactlyOneHost(t, want)
			if n := sc.pendingMoves(t); n != 0 {
				t.Errorf("the resumed move is still journaled as pending (%d)", n)
			}
		})
	}
}

// A move that ends normally — moved, or refused and started again — is
// recorded finished, so a later restart has nothing to resume.
//
// Mutation: do not finish the journal — a successful move stays pending.
func TestFleet_DrainFinishesItsJournal(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	if _, err := sc.drain(t); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n := sc.pendingMoves(t); n != 0 {
		t.Fatalf("a finished move is still journaled as pending (%d)", n)
	}
	sc.assertRunsOnExactlyOneHost(t, sc.dst)
}
