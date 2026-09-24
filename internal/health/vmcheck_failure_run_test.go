package health

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The lab journal, same VM, one probe loop:
//
//	18:06:30.874 probe failed consecutive=3
//	18:06:30.874 action backoff active consecutive_actions=2
//	18:06:37.741 probe failed consecutive=1
//
// Crossing the threshold reset the failure run BEFORE the backoff was
// checked, so a run the backoff refused to act on was thrown away: after the
// backoff ended the VM needed `retries` fresh failures before anything
// happened, and the log read as if the counter had been reset by something
// else.
func TestVMCheck_BackoffDoesNotResetTheFailureRun(t *testing.T) {
	f := newGraceFixture(t, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:81", Interval: "10s", Retries: 3, Action: "restart"})
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	f.v.mu.Lock()
	f.v.actionCount["web"] = 2
	f.v.lastAction["web"] = f.clock.now() // backoff: 2 minutes from here
	f.v.mu.Unlock()

	for i := 0; i < 4; i++ {
		f.v.SweepOnce(f.ctx)
		f.clock.advance(10 * time.Second)
	}
	if n := f.starts(); n != 0 {
		t.Fatalf("the VM was restarted inside its action backoff (%d starts)", n)
	}
	if fails, _ := f.counters(); fails != 4 {
		t.Fatalf("failures = %d after four failed probes inside the backoff, want 4 (the run must not be reset while the backoff holds the action)", fails)
	}

	// The backoff ends: the next failed probe acts, without another
	// `retries` failures first.
	f.clock.advance(2 * time.Minute)
	f.v.SweepOnce(f.ctx)
	if n := f.starts(); n != 1 {
		t.Fatalf("the first failed probe after the backoff restarted the VM %d times, want 1", n)
	}
	if fails, acts := f.counters(); fails != 0 || acts != 3 {
		t.Errorf("after the action: failures=%d actions=%d, want 0 and 3", fails, acts)
	}
}

// Exactly one probe result per VM incarnation counts. A probe still running
// when the VM's incarnation changes (a restart, a move, a redefine) belongs
// to an incarnation that no longer exists; its verdict was already dropped,
// and now its failure is too. Otherwise the old probe and the new
// incarnation's probe both feed one failure run.
func TestVMCheck_AProbeOfASupersededIncarnationDoesNotCount(t *testing.T) {
	f := newGraceFixture(t, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:81", Interval: "10s", Retries: 2, Action: "restart"})
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	f.v.SetProbeFunc(func(ctx context.Context, vm corrosion.VMRecord, h *pb.HealthCheckSpec) (bool, string) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			<-release // the old incarnation's probe, still running
		}
		return false, "tcp 10.0.0.9:81: connection refused"
	})

	f.v.sweep(f.ctx) // probe A starts, and blocks
	if err := corrosion.UpdateVMStateStrict(f.ctx, f.db, "web", "running", "redefined"); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(10 * time.Second)
	f.v.sweep(f.ctx) // new incarnation: probe B runs and fails
	close(release)   // A finishes, failing, for an incarnation that is gone
	f.v.probes.Wait()

	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 2 {
		t.Fatalf("probes = %d, want 2", n)
	}
	if fails, _ := f.counters(); fails != 1 {
		t.Errorf("failures = %d, want 1: only the current incarnation's probe counts", fails)
	}
	if s := f.starts(); s != 0 {
		t.Fatalf("a superseded incarnation's probe pushed the VM over retries=2 and restarted it (%d starts)", s)
	}
}
