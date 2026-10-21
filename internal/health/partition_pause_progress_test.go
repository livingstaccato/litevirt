package health

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// slowStopCT stops every container slowly, as lxc-stop -t 10 does on a frozen
// container that cannot act on its SIGPWR.
type slowStopCT struct {
	*fakeCT
	delay time.Duration
}

func (s slowStopCT) Stop(ctx context.Context, name string, timeout int) error {
	time.Sleep(s.delay)
	return s.fakeCT.Stop(ctx, name, timeout)
}

// relocatedContainersFixture freezes n recoverable containers under lost
// quorum, then has the majority relocate every one of them to node-b on a
// completed, verified claim, so the next healed pass settles all n.
func relocatedContainersFixture(t *testing.T, n int, stopDelay time.Duration) (*pauseFixture, *fakeCT) {
	t.Helper()
	f := newPauseFixture(t)
	f.p.SetVMBackend(nil)
	ctx := context.Background()
	var names []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("ct-%d", i)
		names = append(names, name)
		if err := corrosion.UpsertContainer(ctx, f.db, corrosion.ContainerRecord{HostName: "node-a", Name: name,
			State: "running", Image: "alpine:3.19", OnHostFailure: "image-recreate"}); err != nil {
			t.Fatal(err)
		}
	}
	rt := newFakeCT(names...)
	f.p.SetContainerRuntime(slowStopCT{fakeCT: rt, delay: stopDelay})
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	recs := map[string]PauseRecord{}
	for _, r := range f.records() {
		recs[r.Name] = r
	}
	if len(recs) != n {
		t.Fatalf("setup: %d records, want %d", len(recs), n)
	}
	for _, name := range names {
		if err := corrosion.RelocateContainer(ctx, f.db, "node-a", name, "node-b"); err != nil {
			t.Fatal(err)
		}
	}
	f.p.SetPeerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-b" {
			return RuntimeRunning, nil
		}
		return RuntimeAbsent, nil
	})
	f.p.settleProofs = func(_ context.Context, _ *corrosion.Client, _, name string) ([]corrosion.ProofRecord, error) {
		return []corrosion.ProofRecord{{ActionProof: corrosion.ActionProof{ID: "reloc-" + name, Action: corrosion.ActionRelocate,
			TargetKind: corrosion.ClaimKindContainer, TargetName: name, DestHost: "node-b", OwnerEpoch: "0",
			ClaimCertificate: "{}"}, Status: corrosion.ProofCompleted, ExecutorHost: "node-b"}}, nil
	}
	f.p.SetSettleVerifier(func(_ context.Context, ap corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
		r := recs[ap.TargetName]
		return corrosion.ClaimCertificate{Key: corrosion.ClaimKey{TargetKind: corrosion.ClaimKindContainer,
			TargetName: ap.TargetName, OwnerEpoch: r.OwnerEpoch, Incarnation: r.Incarnation}, ConfigGeneration: 1}, nil
	})
	return f, rt
}

// longestStill runs fn while sampling p.Progress, and returns the longest
// stretch the counter stood still, and how long fn took.
func longestStill(p *PartitionPauser, fn func()) (still, took time.Duration) {
	done := make(chan struct{})
	var mu sync.Mutex
	go func() {
		last, since := p.Progress(), time.Now()
		tk := time.NewTicker(5 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				now := time.Now()
				if v := p.Progress(); v != last {
					last, since = v, now
					continue
				}
				mu.Lock()
				if s := now.Sub(since); s > still {
					still = s
				}
				mu.Unlock()
			}
		}
	}()
	start := time.Now()
	fn()
	took = time.Since(start)
	close(done)
	mu.Lock()
	defer mu.Unlock()
	return still, took
}

// A healed pass that settles many slow containers is long, but it moves: the
// pauser's progress counter, which the watchdog's liveness gate watches,
// advances on every record, so the longest it stands still is one settle,
// never the whole pass. Timing the pass as a whole made a healthy, just
// healed host look wedged and self-fence.
//
// Mutation: drop the per-record progress (passBudgetLeft's noteProgress) and
// the counter stands still for the whole pass.
func TestPartitionPause_ASlowSettlePassKeepsMakingProgress(t *testing.T) {
	const n, delay = 8, 60 * time.Millisecond
	f, rt := relocatedContainersFixture(t, n, delay)
	f.set(QuorumYes)
	f.p.mu.Lock()
	f.p.samples = []lossSample{{at: f.now}}
	f.p.yesSince = f.now.Add(-2 * PartitionPauseAfter)
	f.p.mu.Unlock()
	still, took := longestStill(f.p, f.tick) // one pass: every settle
	stopped := 0
	for i := 0; i < n; i++ {
		if rt.get(fmt.Sprintf("ct-%d", i)) == "stopped" {
			stopped++
		}
	}
	if stopped != n {
		t.Fatalf("the pass settled %d of %d containers (took %s)", stopped, n, took)
	}
	if took < n*delay {
		t.Fatalf("setup: the pass took %s, shorter than its %d settles", took, n)
	}
	if still > 3*delay {
		t.Fatalf("progress stood still for %s during a %s pass of %d settles of %s each: "+
			"the liveness gate would read a healthy pass as a wedge", still, took, n, delay)
	}
}

// The resume and settle work of one pass is bounded: what the budget does
// not reach stays paused, untouched, for the next pass.
//
// Mutation: drop the budget check in passBudgetLeft and the first pass
// settles everything.
func TestPartitionPause_ResumePassIsBounded(t *testing.T) {
	const n, delay = 6, 50 * time.Millisecond
	f, rt := relocatedContainersFixture(t, n, delay)
	old := partitionResumePassBudget
	partitionResumePassBudget = 2*delay + delay/2
	t.Cleanup(func() { partitionResumePassBudget = old })
	f.set(QuorumYes)
	f.p.mu.Lock()
	f.p.samples = []lossSample{{at: f.now}}
	f.p.yesSince = f.now.Add(-2 * PartitionPauseAfter)
	f.p.mu.Unlock()
	count := func() int {
		c := 0
		for i := 0; i < n; i++ {
			if rt.get(fmt.Sprintf("ct-%d", i)) == "stopped" {
				c++
			}
		}
		return c
	}
	f.tick()
	if got := count(); got == 0 || got >= n {
		t.Fatalf("the first pass settled %d of %d; want some but not all under a %s budget", got, n, partitionResumePassBudget)
	}
	for i := 0; i < 2*n && count() < n; i++ {
		f.advance(time.Second)
		f.tick()
	}
	if got := count(); got != n {
		t.Fatalf("later passes settled only %d of %d", got, n)
	}
}
