// Fleet scenario: a host that restarts is not fenced in the seconds between
// its daemon's boot write and its first answered probe (lab 1, 2026-10-11).
//
// On lab 1 a quick node restart had the coordinator SSH-power the node off
// again about 25 s into its boot: node-5 twice, node-2 once. Each time the
// daemon's SIGTERM had recorded it 'upgrading', which held the fence back
// while it was down, and its boot write recorded it 'active' about 3 s before
// its gRPC server listened. Every observer had kept counting the host's
// failures through the restart, so its next unanswered probe published a
// count already past the fence threshold, stamped after the boot write. The
// coordinator dropped only observations OLDER than the host's activation, so
// that row counted, quorum formed at once, and the host was fenced as soon as
// sshd answered. node-1's journal, node-2:
//
//	10:48:44 failover: target is upgrading, skipping fence host=node-2
//	10:48:59 (node-2) boot write: active
//	10:49:02 failover: quorum reached — host exceeded failure threshold observers=4 quorum=3
//	10:49:02 (node-2) litevirtd starting grpc=0.0.0.0:7443
//
// A host that has just turned active is counted down afresh: a failing run
// that began before the activation counts only once the host has failed for a
// whole run's worth of probes since it.
package fleet

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// restartFleet is four nodes with real health checkers on the observers a, b
// and o, and a's coordinator polling on the real clock. d is the host that
// restarts. down makes d's probes go unanswered, as a host whose daemon is
// stopped, or not yet listening, does.
type restartFleet struct {
	c         *Cluster
	a, d      *Node
	observers []*Node
	down      atomic.Bool

	mu       sync.Mutex
	fencedAt []time.Time
	// fenceAs, when set, is what the fencer reports for d.
	fenceAs *fence.Result
	workers []<-chan struct{}
}

func newRestartFleet(t *testing.T, seed int64, tune ...func(*failover.Coordinator)) *restartFleet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: seed})
	f := &restartFleet{c: c, a: c.Nodes[0], d: c.Nodes[3], observers: []*Node{c.Nodes[0], c.Nodes[1], c.Nodes[2]}}
	f.ownWorkers(t, cancel) // after New registers Stop, including partial setup
	c.WaitConverged(t, convergeTimeout)
	// host_membership_split_v1 is mandatory and latched on any current
	// cluster, lab 1 included: every node reads host_membership, which is
	// where the coordinator learns when a host turned active.
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	settleByAntiEntropy(t, c, true)
	// What these scenarios pin is when d is fenced: give it a workload that
	// needs the fence (a host with nothing to recover is not fenced).
	needsFenceOn(t, f.a, f.d.Name)
	for _, n := range f.observers {
		ch := health.NewChecker(n.Name, n.PKIDir, n.DB)
		// The daemon's readiness prober, reduced to the one fact this
		// scenario turns on: d answers, or it does not.
		ch.SetPeerReadiness(func(_ context.Context, host, _ string) (bool, string, error) {
			if host == f.d.Name && f.down.Load() {
				return false, "", context.DeadlineExceeded
			}
			return true, "", nil
		})
		f.startWorker(func() { ch.Start(ctx) })
	}
	coord := failover.NewCoordinator(f.a.Name, f.a.DB)
	for _, fn := range tune {
		fn(coord)
	}
	coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		if h.Name == f.d.Name {
			f.mu.Lock()
			f.fencedAt = append(f.fencedAt, time.Now())
			as := f.fenceAs
			f.mu.Unlock()
			if as != nil {
				return *as
			}
		}
		return fence.Result{Method: "fleet-test", Success: true}
	})
	f.startWorker(func() {
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				coord.RunOnce(ctx)
			}
		}
	})
	return f
}

// Register after Cluster.New's Stop cleanup, before starting any worker. LIFO
// cleanup then cancels and joins these owners before DB/transport teardown.
func (f *restartFleet) ownWorkers(t *testing.T, cancel context.CancelFunc) {
	t.Helper()
	t.Cleanup(func() {
		cancel()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		for _, done := range f.workers {
			select {
			case <-done:
			case <-deadline.C:
				t.Error("restartFleet worker failed to join before dependency teardown")
				return
			}
		}
	})
}

func (f *restartFleet) startWorker(run func()) {
	done := make(chan struct{})
	f.workers = append(f.workers, done)
	go func() { defer close(done); run() }()
}

func (f *restartFleet) fences() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.fencedAt...)
}

// answer has d's probes answered from now on, and returns the moment before
// they were: an observer verdict published after it was made on a probe d
// answered. Stamped BEFORE the flip, not after it. An observer publishes a
// healthy verdict once, when its verdict changes, and never republishes it
// unchanged, so a verdict made between the flip and a later stamp (under load,
// an observer probes while the test is still confirming d serving) is older
// than the stamp for good, and a wait for one newer never ends.
func (f *restartFleet) answer() time.Time {
	at := time.Now()
	f.down.Store(false)
	return at
}

// restart takes d down as a graceful stop does — its SIGTERM records it
// 'upgrading' — and waits until every observer has counted it failing past
// the fence threshold, then makes the boot write that records it 'active'
// again, while it still does not answer. It returns the boot write's time.
func (f *restartFleet) restart(t *testing.T) time.Time {
	t.Helper()
	ctx := context.Background()
	f.gracefulStop(t)
	booted := time.Now()
	if err := corrosion.UpdateHostStartup(ctx, f.d.DB, f.d.Name, "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	return booted
}

// gracefulStop is restart up to the boot write: d's SIGTERM records it
// 'upgrading', and every observer counts it failing past the fence threshold.
// It returns when the 'upgrading' write was made.
func (f *restartFleet) gracefulStop(t *testing.T) time.Time {
	t.Helper()
	ctx := context.Background()
	stopped := time.Now()
	if err := corrosion.UpdateHostState(ctx, f.d.DB, f.d.Name, "upgrading"); err != nil {
		t.Fatalf("SIGTERM's 'upgrading' write: %v", err)
	}
	eventually(t, convergeTimeout, "the 'upgrading' write to reach every observer", func() bool {
		for _, n := range f.observers {
			if h, err := corrosion.GetHost(ctx, n.DB, f.d.Name); err != nil || h == nil || h.State != "upgrading" {
				return false
			}
		}
		return true
	})
	f.down.Store(true)
	past := health.FailuresToFence + 2
	eventually(t, time.Minute, "every observer to count d failing past the fence threshold", func() bool {
		for _, n := range f.observers {
			if got, _, ok := observedFailures(n, f.d.Name); !ok || got < past {
				return false
			}
		}
		return true
	})
	if n := len(f.fences()); n != 0 {
		t.Fatalf("fixture: d was fenced %d times while it was recorded 'upgrading'", n)
	}
	return stopped
}

// TestFleet_RestartedHostIsNotFencedBeforeItServes: d restarts, its boot write
// records it 'active', and its gRPC server answers 3 s later, as on lab 1. It
// must not be fenced in between, nor after.
//
// Mutation: drop the run-start check from the coordinator's activation filter
// (failover.countedSinceActive) — the first unanswered probe after the boot
// write carries the count from the restart and d is fenced at once.
func TestFleet_RestartedHostIsNotFencedBeforeItServes(t *testing.T) {
	f := newRestartFleet(t, 3401)
	booted := f.restart(t)

	// lab 1 measured 3 s from the boot write to the gRPC listener on every
	// one of the three re-fenced restarts.
	time.Sleep(3 * time.Second)
	served := f.answer()

	eventually(t, convergeTimeout, "every observer to see d answer", func() bool {
		for _, n := range f.observers {
			if got, at, ok := observedFailures(n, f.d.Name); !ok || got != 0 || !at.After(served) {
				return false
			}
		}
		return true
	})
	// Two more coordinator cycles past the last observer's healthy verdict.
	time.Sleep(time.Second)
	if fs := f.fences(); len(fs) != 0 {
		t.Fatalf("d was fenced %s after its boot write recorded it active, before it had failed a whole "+
			"run of probes since: the failure count from its restart carried over (%d fences)",
			fs[0].Sub(booted).Round(time.Millisecond), len(fs))
	}
}

// TestFleet_RestartedHostThatNeverServesIsFenced: the other half. d's boot
// write records it 'active' and it never answers. It is a failed host like any
// other and is fenced, once it has failed a whole run of probes since the
// activation and its restart allowance, timed from its 'upgrading' write, has
// passed: its observers' run began while it was 'upgrading'.
//
// Mutations: discard every failing run that began before the activation, with
// no allowance for its length since — the observers' runs never break, so d
// is never fenced; drop the restart allowance of a run begun while 'upgrading'
// (failover.upgradingLifeGrace) — d is fenced inside it; cap that allowance
// 15 s late — d is fenced past the 8 s slack.
func TestFleet_RestartedHostThatNeverServesIsFenced(t *testing.T) {
	const allowance = 40 * time.Second
	f := newRestartFleet(t, 3402, func(c *failover.Coordinator) { c.UpgradingTimeout = allowance })
	stopped := time.Now()
	booted := f.restart(t)
	eventually(t, allowance+convergeTimeout, "the coordinator to fence the restarted host that does not answer", func() bool {
		return len(f.fences()) > 0
	})
	first := f.fences()[0]
	if grace := time.Duration(health.FailuresToFence-1) * health.ProbeInterval; first.Sub(booted) < grace {
		t.Fatalf("d was fenced %s after its boot write, inside the %s its observers need to count it down afresh",
			first.Sub(booted).Round(time.Millisecond), grace)
	}
	if first.Sub(stopped) < allowance {
		t.Fatalf("d was fenced %s after its 'upgrading' write, inside its %s restart allowance",
			first.Sub(stopped).Round(time.Millisecond), allowance)
	}
	// And no later than the allowance's end, give or take the probes and
	// cycles that observe it: the guard never fences later than a host
	// stuck 'upgrading' is.
	if slack := 4 * health.ProbeInterval; first.Sub(stopped) > allowance+slack {
		t.Fatalf("d was fenced %s after its 'upgrading' write, more than %s past its %s restart allowance",
			first.Sub(stopped).Round(time.Millisecond), slack, allowance)
	}
}

// Exercise the same cleanup registration with zero, partially started and
// complete real checker sets. Early returns model assertion/setup exits;
// actual checker completion must precede Cluster.Stop's DB-close callback.
func TestRestartFleetWorkersStopBeforeDependencies(t *testing.T) {
	if marker := os.Getenv("LITEVIRT_RESTART_SETUP_FAILURE"); marker != "" {
		restartSetupFailureChild(t, marker)
		return
	}
	t.Run("actual-fatal-setup-exit", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "closed-dependencies")
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRestartFleetWorkersStopBeforeDependencies$", "-test.v")
		cmd.Env = append(os.Environ(), "LITEVIRT_RESTART_SETUP_FAILURE="+marker)
		output, err := cmd.CombinedOutput()
		t.Logf("expected setup-failure child output:\n%s", output)
		failure, ok := err.(*exec.ExitError)
		if !ok || failure.ExitCode() != 1 || !bytes.Contains(output, []byte("intentional partial setup failure")) || bytes.Contains(output, []byte("before actual worker exit")) || bytes.Contains(output, []byte("failed to join")) {
			t.Fatalf("setup-failure child: err=%v output=%s", err, output)
		}
		closed, err := os.ReadFile(marker)
		if err != nil || string(closed) != "node-0\nnode-1\nnode-2\nnode-3\n" {
			t.Fatalf("setup-failure dependency teardown: %q err=%v", closed, err)
		}
	})
	t.Run("complete-with-coordinator", func(t *testing.T) {
		f := newRestartFleet(t, 3413)
		if len(f.workers) != 4 {
			t.Fatalf("actual worker count = %d, want 3 checkers and coordinator", len(f.workers))
		}
		f.c.beforeDependencyClose = func(n *Node) {
			for _, done := range f.workers {
				select {
				case <-done:
				default:
					t.Errorf("%s dependency closed before actual worker exit", n.Name)
				}
			}
		}
	})
	for _, count := range []int{0, 1, 3} {
		t.Run(map[int]string{0: "before-workers", 1: "partial-setup", 3: "complete"}[count], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel) // covers failure inside New, before any workers exist
			c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 3412})
			f := &restartFleet{c: c}
			f.ownWorkers(t, cancel)
			c.beforeDependencyClose = func(n *Node) {
				for _, done := range f.workers {
					select {
					case <-done:
					default:
						t.Errorf("%s dependency closed before actual checker exit", n.Name)
					}
				}
			}
			started := make(chan struct{}, count)
			for _, n := range c.Nodes[:count] {
				ch := health.NewChecker(n.Name, n.PKIDir, n.DB)
				ch.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) { return true, "", nil })
				f.startWorker(func() { started <- struct{}{}; ch.Start(ctx) })
			}
			for range count {
				<-started
			}
			// Return while workers still own the real open databases. t.Cleanup
			// must handle both full and partial setup, without a success sleep.
		})
	}
}

// This child really fails setup via testing.T.Fatal after its actual checker
// has probed. The parent requires its expected failure and all four dependency
// callbacks after a successful worker join, rather than accepting a timeout.
func restartSetupFailureChild(t *testing.T, marker string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 3414})
	f := &restartFleet{c: c}
	f.ownWorkers(t, cancel)
	c.beforeDependencyClose = func(n *Node) {
		for _, done := range f.workers {
			select {
			case <-done:
			default:
				t.Errorf("%s dependency closed before actual worker exit", n.Name)
				return
			}
		}
		file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = file.WriteString(n.Name + "\n")
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Errorf("recording teardown: %v %v", err, closeErr)
		}
	}
	ch := health.NewChecker(c.Nodes[0].Name, c.Nodes[0].PKIDir, c.Nodes[0].DB)
	probed := make(chan struct{})
	var once sync.Once
	ch.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) {
		once.Do(func() { close(probed) })
		return true, "", nil
	})
	f.startWorker(func() { ch.Start(ctx) })
	select {
	case <-probed:
	case <-time.After(10 * time.Second):
		t.Fatal("actual checker never probed during partial setup")
	}
	t.Fatal("intentional partial setup failure")
}

// The child deliberately fails with a held heartbeat. Its cleanup must wait
// for the actual child, including the delayed-entry schedule where running is
// still false. This exercises real testing.T.Fatal cleanup, not SIGKILL.
func TestRestartFleetHeartbeatStopsBeforeDependencies(t *testing.T) {
	if marker := os.Getenv("LITEVIRT_RESTART_HEARTBEAT_FAILURE"); marker != "" {
		restartHeldHeartbeat(t, os.Getenv("LITEVIRT_RESTART_HEARTBEAT_SCHEDULE"), marker)
		t.Fatal("intentional held-heartbeat setup failure")
	}
	for _, schedule := range []string{"delayed-entry", "in-flight-tick"} {
		t.Run(schedule, func(t *testing.T) {
			t.Run("early-return", func(t *testing.T) { restartHeldHeartbeat(t, schedule, "") })
			t.Run("fatal-setup-exit", func(t *testing.T) {
				marker := filepath.Join(t.TempDir(), "closed-dependencies")
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRestartFleetHeartbeatStopsBeforeDependencies$", "-test.v")
				cmd.Env = append(os.Environ(), "LITEVIRT_RESTART_HEARTBEAT_FAILURE="+marker, "LITEVIRT_RESTART_HEARTBEAT_SCHEDULE="+schedule)
				output, err := cmd.CombinedOutput()
				t.Logf("expected held-heartbeat setup-failure child output:\n%s", output)
				failure, ok := err.(*exec.ExitError)
				if !ok || failure.ExitCode() != 1 || !bytes.Contains(output, []byte("intentional held-heartbeat setup failure")) || bytes.Contains(output, []byte("before held heartbeat exit")) || bytes.Contains(output, []byte("before actual heartbeat exit")) || bytes.Contains(output, []byte("failed to join")) {
					t.Fatalf("held-heartbeat child: err=%v output=%s", err, output)
				}
				closed, err := os.ReadFile(marker)
				if err != nil || string(closed) != "node-0\nnode-1\nnode-2\nnode-3\n" {
					t.Fatalf("held-heartbeat teardown: %q err=%v", closed, err)
				}
			})
		})
	}
}

func restartHeldHeartbeat(t *testing.T, schedule, marker string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 3415})
	f := &restartFleet{c: c}
	held, release, exited, controllerDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	// Registered before ownWorkers: its cancel/join runs first, while the
	// controller releases the held child only after checking completion blocked.
	t.Cleanup(func() {
		cancel()
		unblock()
		select {
		case <-controllerDone:
		case <-time.After(5 * time.Second):
			t.Error("heartbeat controller failed to join")
		}
	})
	f.ownWorkers(t, cancel)
	// This partial-setup checker stays in TLS retry: no peer probe can reach
	// its clock before the heartbeat, so the in-flight hold has one caller.
	ch := health.NewChecker(c.Nodes[0].Name, t.TempDir(), c.Nodes[0].DB)
	hold := func() { close(held); <-release }
	ch.SetStallHeartbeatHooksForTests(func() {
		if schedule == "delayed-entry" {
			hold()
		}
	}, func() { close(exited) })
	var clockHeld atomic.Bool
	if schedule == "in-flight-tick" {
		ch.SetClockForTests(func() time.Time {
			if clockHeld.CompareAndSwap(false, true) {
				hold()
			}
			return time.Now()
		})
	}
	f.startWorker(func() { ch.Start(ctx) })
	go func() {
		defer close(controllerDone)
		<-ctx.Done()
		select {
		case <-f.workers[0]:
			t.Error("checker returned before held heartbeat exit")
		case <-time.After(200 * time.Millisecond):
		}
		unblock()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("actual heartbeat failed to join")
		}
	}()
	c.beforeDependencyClose = func(n *Node) {
		select {
		case <-exited:
		default:
			t.Errorf("%s dependency closed before actual heartbeat exit", n.Name)
			return
		}
		if marker != "" {
			file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				t.Error(err)
				return
			}
			_, err = file.WriteString(n.Name + "\n")
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				t.Errorf("recording heartbeat teardown: %v %v", err, closeErr)
			}
		}
	}
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("actual heartbeat did not reach fixture hold")
	}
}
