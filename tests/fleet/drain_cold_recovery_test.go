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
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
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

// crashAt drains the scenario's running os1 and "dies" at point, leaving the
// move journaled.
func (sc *coldStoppedScenario) crashAt(t *testing.T, point string) {
	t.Helper()
	sc.src.Server.SetDrainCrashForTest(func(p string) bool { return p == point })
	_, _ = sc.drain(t)
	sc.src.Server.SetDrainCrashForTest(nil)
	if n := sc.pendingMoves(t); n != 1 {
		t.Fatalf("after the crash at %s, %d journaled cold move(s) are pending, want 1", point, n)
	}
}

func (sc *coldStoppedScenario) drainEvent(t *testing.T, result, contains string) bool {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), sc.src.DB, "os1", 100, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	for _, e := range evs {
		if e.Type == "vm.drain" && e.Result == result && strings.Contains(e.Detail, contains) {
			return true
		}
	}
	return false
}

func (sc *coldStoppedScenario) resume(t *testing.T) {
	t.Helper()
	left, err := sc.src.Server.ResumeDrainColdMoves(context.Background())
	if err != nil || left != 0 {
		t.Fatalf("ResumeDrainColdMoves = %d left, %v; want 0, nil", left, err)
	}
	if n := sc.pendingMoves(t); n != 0 {
		t.Fatalf("the move is still journaled as pending (%d)", n)
	}
}

// A daemon that died after the stop timeout, with the guest still going down,
// is finished by waiting the shutdown out and then starting the VM here. A
// guest that never stops is left running, its row saying so.
//
// Mutation: do not wait for the requested shutdown in recovery — the late
// guest is recorded running while it is still going down (it then powers off
// for good), and the "started again" event check goes red.
func TestFleet_DrainRecoveryWaitsOutARequestedShutdown(t *testing.T) {
	t.Run("late", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		sc.makeRunning(t)
		sc.src.Virt.ShutdownLate = func(string) bool { return true }
		sc.crashAt(t, "stop_timed_out")
		sc.resume(t)
		if active, _ := sc.src.Virt.DomainIsActive("os1"); !active {
			// Late guests power off on the next start attempt in the fake, so
			// a start that did not wait leaves the domain off.
			t.Fatalf("os1 is not running on %s after recovery", sc.src.Name)
		}
		sc.assertRunsOnExactlyOneHost(t, sc.src)
		if !sc.drainEvent(t, "warn", "started again here") {
			t.Error("recovery did not start os1 again after its late shutdown (no \"started again here\" event)")
		}
	})
	t.Run("never", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		sc.makeRunning(t)
		sc.src.Virt.IgnoreShutdown = func(string) bool { return true }
		sc.crashAt(t, "stop_timed_out")
		sc.resume(t)
		sc.assertRunsOnExactlyOneHost(t, sc.src)
		if !sc.drainEvent(t, "warn", "shutdown was requested and is still in progress") {
			t.Error("no vm.drain event says the shutdown is still in progress")
		}
	})
}

// After the crash os1 was moved on (here its ownership back to the drained
// host, which is the adversarial case: the row names the source again, at a
// later owner epoch). Recovery does nothing to the VM, closes the move and
// says why.
//
// Mutation: drop the owner-epoch check on the source — recovery starts os1,
// which the operator left stopped, and goes red.
func TestFleet_DrainRecoveryLeavesAVMMovedSince(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.crashAt(t, "handed_off")
	// The ownership move an operator's cold migration commits, back to the
	// drained host (this fixture's disk paths live under the target's disk
	// root, so a real copy back has nowhere to land): the row names the source
	// again, at a later owner epoch, stopped.
	if err := corrosion.TransferVMOwnerFresh(context.Background(), sc.src.DB, "os1", sc.src.Name, "stopped"); err != nil {
		t.Fatalf("move os1's ownership back to %s: %v", sc.src.Name, err)
	}

	sc.resume(t)
	vm := sc.vm(t)
	if vm.HostName != sc.src.Name || vm.State != "stopped" {
		t.Errorf("os1 row = host %s state %s, want it left stopped on %s", vm.HostName, vm.State, sc.src.Name)
	}
	for _, n := range []*Node{sc.src, sc.dst} {
		if active, _ := n.Virt.DomainIsActive("os1"); active {
			t.Errorf("recovery started os1 on %s, which the operator had moved and left stopped", n.Name)
		}
	}
	if !sc.drainEvent(t, "warn", "was not finished") {
		t.Error("no vm.drain event says the move was not finished because the VM changed")
	}
}

// After the crash the operator started os1 and stopped it again on purpose.
// Recovery does nothing to it and closes the move.
//
// Mutation: accept any stopped row on the source (drop the move's own stop
// detail check) — recovery starts os1 against the operator's stop.
func TestFleet_DrainRecoveryLeavesAVMTheOperatorStopped(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.crashAt(t, "shut_off")
	ctx := context.Background()
	if _, err := sc.c.SelfClient(sc.src).StartVM(ctx, &pb.StartVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("operator start: %v", err)
	}
	if _, err := sc.c.SelfClient(sc.src).StopVM(ctx, &pb.StopVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("operator stop: %v", err)
	}

	sc.resume(t)
	if active, _ := sc.src.Virt.DomainIsActive("os1"); active {
		t.Error("recovery started os1, which the operator had stopped")
	}
	if vm := sc.vm(t); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Errorf("os1 row = %s/%q, want stopped/\"operator-stop\" as the operator left it", vm.State, vm.StateDetail)
	}
	if !sc.drainEvent(t, "warn", "was not finished") {
		t.Error("no vm.drain event says the move was not finished because the VM changed")
	}
}

// A move recovery cannot finish within its attempts is closed as failed, with
// a VM event telling the operator to start the VM; a later restart does not
// take it up again.
//
// Mutation: leave the move pending after the last attempt — it is still
// journaled and goes red.
func TestFleet_DrainRecoveryGivesUpOnce(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.crashAt(t, "handed_off")
	sc.dst.Virt.FailStartDomain = func(string) error { return errors.New("injected start failure") }
	defer grpcapi.SetDrainRecoveryRetryForTest(2, 10*time.Millisecond)()

	sc.src.Server.RunDrainColdMoveRecovery(context.Background())
	if n := sc.pendingMoves(t); n != 0 {
		t.Fatalf("a move recovery gave up on is still pending (%d); every restart would retry it", n)
	}
	if !sc.drainEvent(t, "error", "start it with `lv start os1`") {
		t.Error("no vm.drain error event tells the operator to start os1")
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os1"); active {
		t.Error("os1 is running on the target although every start failed")
	}
}

// The same on the target: after a crash past the handoff the operator started
// os1 there and stopped it on purpose. Recovery does not start it.
//
// Mutation: drop the state check on the target branch — recovery starts os1
// against the operator's stop.
func TestFleet_DrainRecoveryLeavesAVMTheOperatorStoppedOnTheTarget(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.crashAt(t, "handed_off")
	ctx := context.Background()
	if _, err := sc.c.SelfClient(sc.src).StartVM(ctx, &pb.StartVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("operator start: %v", err)
	}
	if _, err := sc.c.SelfClient(sc.src).StopVM(ctx, &pb.StopVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("operator stop: %v", err)
	}

	sc.resume(t)
	if active, _ := sc.dst.Virt.DomainIsActive("os1"); active {
		t.Error("recovery started os1 on the target, which the operator had stopped")
	}
	if !sc.drainEvent(t, "warn", "was not finished") {
		t.Error("no vm.drain event says the move was not finished because the VM changed")
	}
}

// Moved on and back RUNNING: the row names the source again, running, at a
// later epoch. Recovery has nothing to start either way, but the move it
// journaled is not the one that put the VM there, and it says so rather than
// claiming to have finished it. On the source, a stopped row is caught by the
// move's own stop detail too; this is the case only the owner epoch tells
// apart.
//
// Mutation: drop the owner-epoch check on the source — recovery reports the
// move finished ("it is running here") and the changed-VM event goes red.
func TestFleet_DrainRecoveryNamesAVMMovedBackRunning(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.crashAt(t, "handed_off")
	if err := corrosion.TransferVMOwnerFresh(context.Background(), sc.src.DB, "os1", sc.src.Name, "running"); err != nil {
		t.Fatalf("move os1's ownership back to %s: %v", sc.src.Name, err)
	}
	sc.resume(t)
	if !sc.drainEvent(t, "warn", "was not finished") {
		t.Error("no vm.drain event says the move was not finished because the VM changed owner")
	}
}

// A VM stopped by the move whose domain is gone from this host is closed as
// changed, not retried for ever.
//
// Mutation: drop the no-domain check — the domain lookup fails on every pass
// and the move stays pending.
func TestFleet_DrainRecoveryClosesAVMWithNoDomain(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.crashAt(t, "shut_off")
	if err := sc.src.Virt.UndefineDomain("os1", false); err != nil {
		t.Fatalf("undefine os1: %v", err)
	}
	sc.resume(t)
	if !sc.drainEvent(t, "warn", "it has no domain here") {
		t.Error("no vm.drain event says os1 has no domain here")
	}
}
