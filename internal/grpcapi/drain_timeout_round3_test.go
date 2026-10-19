package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func setDrainLockWait(t *testing.T, d time.Duration) {
	prev := drainLockWait
	drainLockWait = d
	t.Cleanup(func() { drainLockWait = prev })
}

func drainOneVMAsync(s *Server, vm corrosion.VMRecord) <-chan *pb.DrainProgress {
	done := make(chan *pb.DrainProgress, 1)
	go func() {
		done <- s.drainOneVM(adminCtx(), vm, corrosion.HostRecord{Name: "target-h", Address: "10.0.0.2"})
	}()
	return done
}

// A VM whose move is in flight (its row migrating) holds its lock until
// libvirt ends the move. A drain skips it at once instead of waiting.
//
// Mutation: wait on the lock whatever the row says — the call waits out the
// bound, and goes red.
func TestDrainOneVM_SkipsAVMInFlightWithoutWaiting(t *testing.T) {
	s := testServerR2(t)
	setDrainLockWait(t, 5*time.Second)
	insertTestVMR2(t, adminCtx(), s.db, "flight-vm", "test-host", "migrating")
	unlock := s.lockVM("flight-vm")
	defer unlock()
	start := time.Now()
	p := <-drainOneVMAsync(s, corrosion.VMRecord{Name: "flight-vm", HostName: "test-host", State: "running"})
	if time.Since(start) > time.Second {
		t.Fatalf("drainOneVM took %v on a VM in flight; want an immediate skip", time.Since(start))
	}
	if p.Status != "skipped" || !strings.Contains(p.Error, "in flight") {
		t.Errorf("progress = %q %q, want skipped, a move in flight", p.Status, p.Error)
	}
}

// Ordinary lock contention (a scheduled snapshot, a replication run, a
// hotplug) is waited for, as before: the drain moves the VM once it is free.
//
// Mutation: skip on any held lock — the progress names the lock, red.
func TestDrainOneVM_WaitsForAnOrdinaryLockHolder(t *testing.T) {
	s := testServerR2(t)
	setDrainLockWait(t, 5*time.Second)
	insertTestVMR2(t, adminCtx(), s.db, "busy-vm", "test-host", "running")
	unlock := s.lockVM("busy-vm")
	done := drainOneVMAsync(s, corrosion.VMRecord{Name: "busy-vm", HostName: "test-host", State: "running"})
	time.Sleep(300 * time.Millisecond)
	select {
	case p := <-done:
		t.Fatalf("drainOneVM returned %q %q while the lock was held; want it to wait", p.Status, p.Error)
	default:
	}
	unlock()
	select {
	case p := <-done:
		if strings.Contains(p.Error, "holds this VM") {
			t.Errorf("progress = %q %q; the drain gave up on a lock that was released", p.Status, p.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drainOneVM did not go on once the lock was released")
	}
}

// The wait is bounded: a holder that does not let go (a long replication)
// makes the drain skip the VM, naming what may hold it.
//
// Mutation: wait without a bound — the test's deadline goes red.
func TestDrainOneVM_GivesUpOnALockHeldPastTheBound(t *testing.T) {
	s := testServerR2(t)
	setDrainLockWait(t, 300*time.Millisecond)
	insertTestVMR2(t, adminCtx(), s.db, "held-vm", "test-host", "running")
	unlock := s.lockVM("held-vm")
	defer unlock()
	select {
	case p := <-drainOneVMAsync(s, corrosion.VMRecord{Name: "held-vm", HostName: "test-host", State: "running"}):
		if p.Status != "skipped" || !strings.Contains(p.Error, "scheduled snapshot") || !strings.Contains(p.Error, "replication") {
			t.Errorf("progress = %q %q, want skipped, naming scheduled snapshots and replication", p.Status, p.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drainOneVM waited past its bound on a held VM lock")
	}
}

// A background move that completes leaves drain_move_timed_out only once
// its commit has run: a judgement made in between, which reads the row, must
// not see it still migrating on the source.
//
// Mutation: forget before the commit — the row is still on the source when
// the forget runs, red.
func TestAdoptAbandonedMigration_DrainForgetRunsAfterTheCommit(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	vm := seedMigratingVM(t, s, "mig1")
	var hostAtForget string
	prev := drainForgetHookForTest
	drainForgetHookForTest = func() {
		if got, _ := corrosion.GetVM(adminCtx(), s.db, "mig1"); got != nil {
			hostAtForget = got.HostName
		}
	}
	t.Cleanup(func() { drainForgetHookForTest = prev })

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	s.adoptAbandonedMigration(context.Background(), vm, "h2", false, nil, done,
		func() { close(unlocked) }, migrationFinish{drainFrom: "test-host"})
	done <- nil
	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the adopted migration never ended")
	}
	if hostAtForget != "h2" {
		t.Fatalf("the row named %q when the drain condition was updated; want h2 (the commit first)", hostAtForget)
	}
}

func raiseDrainTimeouts(t *testing.T, s *Server, host string, vms ...string) {
	t.Helper()
	b, _ := json.Marshal(drainTimeoutEvidence{VMs: vms, Detail: "x"})
	s.setHostConditionOf(adminCtx(), drainEvaluator, condDrainMoveTimedOut, host, true, corrosion.SeverityWarning, string(b))
}

func drainTimeoutCondition(t *testing.T, s *Server, host string) (corrosion.HealthCondition, bool) {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(adminCtx(), s.db, drainEvaluator, condDrainMoveTimedOut, "host", host)
	if err != nil {
		t.Fatal(err)
	}
	return c, ok
}

func insertDrainHost(t *testing.T, s *Server, name, state string) {
	t.Helper()
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{
		Name: name, Address: "10.0.0.9", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: state, CertSerial: "x",
	}); err != nil {
		t.Fatal(err)
	}
}

// An undrain served by another host than the drained one never writes the
// drained host's name set back: while a VM there is still in flight, it
// leaves the condition to the drained host (its forget drops the rest), so it
// cannot restore a name that host just removed.
//
// Mutation: judge the full set from the other host — the evidence is
// rewritten (the aborted VM dropped), red.
func TestUndrainJudge_FromAnotherHostLeavesAnInFlightConditionAlone(t *testing.T) {
	s := testServerR2(t) // serves as test-host
	insertDrainHost(t, s, "drained-h", "active")
	insertTestVMR2(t, adminCtx(), s.db, "flying", "drained-h", "migrating")
	insertTestVMR2(t, adminCtx(), s.db, "aborted", "drained-h", "running")
	raiseDrainTimeouts(t, s, "drained-h", "aborted", "flying")
	before, _ := drainTimeoutCondition(t, s, "drained-h")

	s.undrainJudge(adminCtx(), "drained-h")
	after, _ := drainTimeoutCondition(t, s, "drained-h")
	if after.Evidence != before.Evidence || after.Lifecycle != before.Lifecycle {
		t.Fatalf("the condition was rewritten from another host: %+v -> %+v", before, after)
	}
}

// With nothing in flight, the undrain from another host resolves it.
func TestUndrainJudge_FromAnotherHostResolvesWhenNothingIsInFlight(t *testing.T) {
	s := testServerR2(t)
	insertDrainHost(t, s, "drained-h", "active")
	insertTestVMR2(t, adminCtx(), s.db, "aborted", "drained-h", "running")
	raiseDrainTimeouts(t, s, "drained-h", "aborted")

	s.undrainJudge(adminCtx(), "drained-h")
	if c, ok := drainTimeoutCondition(t, s, "drained-h"); !ok || c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition = %+v ok=%v; want resolved", c, ok)
	}
}

// Once the host is undrained, the forget of the last in-flight VM drops the
// names of moves that were aborted too: none of them is owed any more.
//
// Mutation: keep the other names on a forget — the aborted VM stays named,
// red.
func TestForgetDrainTimeout_OnAnUndrainedHostDropsTheAbortedNames(t *testing.T) {
	s := testServerR2(t)
	insertDrainHost(t, s, "drained-h", "active")
	insertTestVMR2(t, adminCtx(), s.db, "aborted", "drained-h", "running")
	raiseDrainTimeouts(t, s, "drained-h", "aborted", "flying")

	s.forgetDrainTimeout(adminCtx(), "drained-h", "flying")
	if c, ok := drainTimeoutCondition(t, s, "drained-h"); !ok || c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition = %+v ok=%v; want resolved once the host is undrained and nothing is in flight", c, ok)
	}
}

// A drain cancelled (Ctrl-C) while a worker waits on a VM's lock stops
// waiting at once, and says the drain was cancelled.
//
// Mutation: sleep without watching the context — the call waits out the
// bound, red.
func TestDrainOneVM_StopsWaitingOnALockWhenTheDrainIsCancelled(t *testing.T) {
	s := testServerR2(t)
	setDrainLockWait(t, time.Minute)
	insertTestVMR2(t, adminCtx(), s.db, "held-vm", "test-host", "running")
	unlock := s.lockVM("held-vm")
	defer unlock()
	ctx, cancel := context.WithCancel(adminCtx())
	done := make(chan *pb.DrainProgress, 1)
	go func() {
		done <- s.drainOneVM(ctx, corrosion.VMRecord{Name: "held-vm", HostName: "test-host", State: "running"},
			corrosion.HostRecord{Name: "target-h", Address: "10.0.0.2"})
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case p := <-done:
		if p.Status != "skipped" || !strings.Contains(p.Error, "cancelled") {
			t.Errorf("progress = %q %q, want skipped, the drain cancelled", p.Status, p.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drainOneVM kept waiting on the VM's lock after the drain was cancelled")
	}
}

// A VM whose row turns migrating while the drain waits on its lock (an
// `lv migrate` took the lock after a snapshot released it) is skipped as in
// flight, without waiting out the bound.
//
// Mutation: check for a move in flight only before the wait — the call
// waits out the bound, red.
func TestDrainOneVM_SkipsAVMThatGoesInFlightDuringTheWait(t *testing.T) {
	s := testServerR2(t)
	setDrainLockWait(t, 30*time.Second)
	insertTestVMR2(t, adminCtx(), s.db, "turn-vm", "test-host", "running")
	unlock := s.lockVM("turn-vm")
	defer unlock()
	done := drainOneVMAsync(s, corrosion.VMRecord{Name: "turn-vm", HostName: "test-host", State: "running"})
	time.Sleep(300 * time.Millisecond)
	if err := corrosion.UpdateVMState(adminCtx(), s.db, "turn-vm", "migrating", "→ elsewhere"); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-done:
		if p.Status != "skipped" || !strings.Contains(p.Error, "in flight") {
			t.Errorf("progress = %q %q, want skipped, a move in flight", p.Status, p.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drainOneVM waited on a VM whose move went in flight")
	}
}

// A job a cancelled drain reaches after it got the lock says the drain was
// cancelled, not that the VM no longer exists.
//
// Mutation: drop the cancelled check after the lock — "VM no longer exists",
// red.
func TestDrainOneVM_ACancelledDrainSaysSo(t *testing.T) {
	s := testServerR2(t)
	insertTestVMR2(t, adminCtx(), s.db, "c-vm", "test-host", "running")
	ctx, cancel := context.WithCancel(adminCtx())
	cancel()
	p := s.drainOneVM(ctx, corrosion.VMRecord{Name: "c-vm", HostName: "test-host", State: "running"},
		corrosion.HostRecord{Name: "target-h", Address: "10.0.0.2"})
	if p.Status != "skipped" || !strings.Contains(p.Error, "cancelled") {
		t.Errorf("progress = %q %q, want skipped, the drain cancelled", p.Status, p.Error)
	}
	if got, _ := corrosion.GetVM(adminCtx(), s.db, "c-vm"); got == nil || got.State != "running" || got.HostName != "test-host" {
		t.Errorf("row = %+v, want running on test-host", got)
	}
}
