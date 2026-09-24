package health

import (
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The start grace follows every start of a new incarnation, not only the VM's
// creation. The lab failure: a VM created long ago whose probe never passed
// was restarted by its healthcheck, probed again straight away while still
// booting, failed, and was restarted again — only the action backoff slowed
// the loop down.

// testClock is a settable clock for the VMChecker's now seam.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type graceFixture struct {
	*probeFixture
	clock *testClock
	virt  *libvirtfake.Fake
}

// newGraceFixture is newProbeFixture with a VM created an hour ago (out of
// its creation grace), a running libvirt domain behind it, and a test clock.
func newGraceFixture(t *testing.T, hc *pb.HealthCheckSpec) *graceFixture {
	t.Helper()
	f := newProbeFixture(t, hc)
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := f.db.Execute(f.ctx, `UPDATE vms SET created_at = ? WHERE name = 'web'`, old); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}
	fake := libvirtfake.New()
	fake.DefineStoppedDomain("web", "52:54:00:aa:bb:01")
	fake.SetState("web", libvirtfake.StateRunning)
	f.v.virt = fake
	clk := &testClock{t: time.Now()}
	f.v.now = clk.now
	return &graceFixture{probeFixture: f, clock: clk, virt: fake}
}

func (f *graceFixture) starts() int {
	n := 0
	for _, e := range f.virt.EventLog() {
		if e.Op == "start" && e.Domain == "web" {
			n++
		}
	}
	return n
}

func (f *graceFixture) counters() (fails, acts int) {
	f.v.mu.Lock()
	defer f.v.mu.Unlock()
	return f.v.failures["web"], f.v.actionCount["web"]
}

var restartCheck = &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:81", Interval: "10s", Retries: 1, Action: "restart"}

func TestVMCheck_HealthRestartStartsAGrace(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")

	f.v.SweepOnce(f.ctx)
	if n := f.starts(); n != 1 {
		t.Fatalf("a failing VM out of its creation grace was restarted %d times, want 1", n)
	}

	// Two minutes on: past the first action's 60s backoff, well inside the
	// restarted incarnation's start grace. The probe runs and its failure is
	// published, but it does not count toward the action.
	f.clock.advance(2 * time.Minute)
	probes := f.probe.count()
	f.v.SweepOnce(f.ctx)
	if f.probe.count() != probes+1 {
		t.Fatalf("the restarted VM was not probed inside its start grace (%d probes, want %d)", f.probe.count(), probes+1)
	}
	if h := f.health(); h.Verdict != VerdictUnhealthy {
		t.Errorf("a failure inside the start grace was not published: %+v", h)
	}
	if n := f.starts(); n != 1 {
		t.Fatalf("the VM was restarted again %s after a health restart, inside its start grace (%d starts)", 2*time.Minute, n)
	}
	if fails, _ := f.counters(); fails != 0 {
		t.Errorf("a failure inside the start grace counted toward the action: failures=%d", fails)
	}

	// Once the grace has run out, failures count again.
	f.clock.advance(healthCheckGracePeriod)
	f.v.SweepOnce(f.ctx)
	if n := f.starts(); n != 2 {
		t.Fatalf("after the start grace the failing VM was restarted %d times in total, want 2", n)
	}
}

// A VM this host sees go from not running to running — an operator start, a
// restart policy, a redefine and start — has just booted, whatever its
// created_at says.
func TestVMCheck_ObservedStartStartsAGrace(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	if err := corrosion.UpdateVMState(f.ctx, f.db, "web", "stopped", "operator-stop"); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx)
	f.clock.advance(20 * time.Second)
	if err := corrosion.UpdateVMState(f.ctx, f.db, "web", "running", ""); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx)
	if f.probe.count() != 1 {
		t.Fatalf("the started VM was probed %d times, want 1", f.probe.count())
	}
	if n := f.starts(); n != 0 {
		t.Fatalf("a VM that had just been started was restarted by its healthcheck (%d starts)", n)
	}
	if fails, acts := f.counters(); fails != 0 || acts != 0 {
		t.Errorf("a failure right after a start counted toward the action: failures=%d actions=%d", fails, acts)
	}
}

// A VM that arrives on this host — migrated or failed over here — has just
// been started here. The first sweep after the daemon starts is the exception:
// it cannot tell a VM that has run for weeks from one that just arrived, and
// created_at still covers a new VM.
func TestVMCheck_ArrivalStartsAGraceButDaemonStartDoesNot(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	if err := corrosion.UpdateVMHost(f.ctx, f.db, "web", "node2", "running"); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx) // the VM is not ours: nothing to see
	f.clock.advance(20 * time.Second)
	if err := corrosion.UpdateVMHost(f.ctx, f.db, "web", "node1", "running"); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx)
	if f.probe.count() != 1 {
		t.Fatalf("the arrived VM was probed %d times, want 1", f.probe.count())
	}
	if n := f.starts(); n != 0 {
		t.Fatalf("a VM that had just arrived was restarted by its healthcheck (%d starts)", n)
	}

	// A fresh checker (a daemon restart) acts on its first sweep.
	g := newGraceFixture(t, restartCheck)
	g.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	g.v.SweepOnce(g.ctx)
	if n := g.starts(); n != 1 {
		t.Fatalf("a failing VM seen on the checker's first sweep was restarted %d times, want 1", n)
	}
}

// The backoff between actions on a VM that never recovers doubles and is
// capped: it never shrinks and never grows without bound.
func TestVMCheck_ActionBackoffDoublesToACap(t *testing.T) {
	want := []time.Duration{0, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		16 * time.Minute, 32 * time.Minute, 32 * time.Minute, 32 * time.Minute}
	for acts, w := range want {
		if got := actionBackoff(acts); got != w {
			t.Errorf("actionBackoff(%d) = %s, want %s", acts, got, w)
		}
	}
	if got := actionBackoff(1 << 20); got != maxActionBackoff {
		t.Errorf("actionBackoff(huge) = %s, want the cap %s", got, maxActionBackoff)
	}
}

// A new owner epoch is a new runtime generation — a proven start or an
// ownership transition — even when no sweep saw the row leave "running".
func TestVMCheck_NewOwnerEpochStartsAGrace(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	if err := f.db.Execute(f.ctx, `UPDATE vms SET vm_owner_epoch = vm_owner_epoch + 1 WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(10 * time.Second)
	f.v.SweepOnce(f.ctx)
	if f.probe.count() != 2 {
		t.Fatalf("probes = %d, want 2", f.probe.count())
	}
	if n := f.starts(); n != 0 {
		t.Fatalf("a VM in a new owner epoch was restarted inside its start grace (%d starts)", n)
	}
}

// Failures counted against the previous incarnation say nothing about a VM
// that has started since: once its grace is over, it needs `retries` failures
// of its own before the action runs.
func TestVMCheck_AStartDropsThePreviousIncarnationsFailures(t *testing.T) {
	f := newGraceFixture(t, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:81", Interval: "10s", Retries: 3, Action: "restart"})
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	f.v.SweepOnce(f.ctx)
	f.clock.advance(10 * time.Second)
	f.v.SweepOnce(f.ctx)
	if fails, _ := f.counters(); fails != 2 {
		t.Fatalf("precondition: failures = %d, want 2", fails)
	}
	if err := corrosion.UpdateVMState(f.ctx, f.db, "web", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(10 * time.Second)
	f.v.SweepOnce(f.ctx)
	if err := corrosion.UpdateVMState(f.ctx, f.db, "web", "running", ""); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(10 * time.Second)
	f.v.SweepOnce(f.ctx) // the start is seen; inside the grace
	f.clock.advance(healthCheckGracePeriod)
	f.v.SweepOnce(f.ctx)
	if n := f.starts(); n != 0 {
		t.Fatalf("the first failure after the grace restarted the VM on the strength of the previous incarnation's failures (%d starts)", n)
	}
	if fails, _ := f.counters(); fails != 1 {
		t.Errorf("failures = %d after the grace, want 1", fails)
	}
}
