package fencessh_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// closedGate is a release gate whose fence_ssh is not available yet: no row
// is published.
type closedGate struct{}

func (closedGate) ReleaseFeatureAvailable(capabilities.Feature) bool { return false }
func (closedGate) WithReleaseFeature(context.Context, capabilities.Feature,
	func(context.Context, capabilities.FeatureGrant) error) error {
	return errors.New("closed")
}

// evaluator is an sshd evaluation a test drives: each call is counted, and
// answer decides it.
type evaluator struct {
	calls  atomic.Int32
	answer func(ctx context.Context, call int32) (bool, string, error)
}

func (e *evaluator) agent(n *node, gate fencessh.Gate, timeout time.Duration) *fencessh.Agent {
	return e.agentWith(n, gate, timeout, false)
}

func (e *evaluator) agentWith(n *node, gate fencessh.Gate, timeout time.Duration, selfCheck bool) *fencessh.Agent {
	return fencessh.New(fencessh.Config{
		Self: n.name, PKIDir: n.pkiDir, DB: n.w.db, Gate: gate, Dir: n.dir, SSHUser: n.w.user,
		HostKeyGlob: n.hkPath + ".pub", ReevaluateTimeout: timeout, SelfCheck: selfCheck,
		Accepting: func(ctx context.Context, _ []string) (bool, string, error) {
			return e.answer(ctx, e.calls.Add(1))
		},
	})
}

func reevalWorld(t *testing.T) *node {
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	x.hostRow(x.ip, 22)
	y := w.node("node-y", "127.0.0.4")
	y.hostRow(y.ip, 22)
	return x
}

// TestReevaluate_SkipsTheCachedEvaluation: an ordinary sync reuses the last
// sshd evaluation for acceptTTL, so right after sshd changes it still
// publishes the old answer. Reevaluate evaluates anew, publishes the new
// answer and says so.
//
// Mutation: let a fresh sync take the cache (drop `fresh == nil &&` in
// sshdAccepting): the row still says not accepting, red.
func TestReevaluate_SkipsTheCachedEvaluation(t *testing.T) {
	ctx := context.Background()
	x := reevalWorld(t)
	var accepting atomic.Bool
	e := &evaluator{answer: func(context.Context, int32) (bool, string, error) {
		if accepting.Load() {
			return true, "", nil
		}
		return false, "modelled: not yet", nil
	}}
	a := e.agent(x, openGate{t}, 0)
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	accepting.Store(true) // the install
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := x.row(); r.Accepting {
		t.Fatalf("an ordinary sync re-evaluated within acceptTTL; the premise does not hold: %+v", r)
	}
	ok, why := a.Reevaluate(ctx)
	if !ok {
		t.Fatalf("Reevaluate: not proven: %s", why)
	}
	if r, _ := x.row(); !r.Accepting {
		t.Fatalf("after Reevaluate the row still says not accepting: %+v", r)
	}
	if got := e.calls.Load(); got != 2 {
		t.Fatalf("sshd evaluated %d times, want 2 (one ordinary, one fresh)", got)
	}
}

// TestReevaluate_NeverSatisfiedByASyncThatStartedBefore: requests arriving
// while a fresh sync runs do not share it; they share the next one, which
// starts after the running one ends, so the answer each gets reflects an
// evaluation made after it arrived. However many arrive, one sync is pending.
//
// Mutation: join the running sync when one runs (return q.running in join):
// the late requests get the first sync's stale answer, red.
func TestReevaluate_NeverSatisfiedByASyncThatStartedBefore(t *testing.T) {
	ctx := context.Background()
	x := reevalWorld(t)
	inFirst := make(chan struct{})
	release := make(chan struct{})
	e := &evaluator{answer: func(_ context.Context, call int32) (bool, string, error) {
		if call == 1 {
			close(inFirst)
			<-release
			return false, "modelled: the evaluation before the install", nil
		}
		return true, "", nil
	}}
	a := e.agent(x, openGate{t}, time.Minute)

	type res struct {
		ok  bool
		why string
	}
	first := make(chan res, 1)
	go func() {
		ok, why := a.Reevaluate(ctx)
		first <- res{ok, why}
	}()
	<-inFirst // the first fresh sync is evaluating

	const late = 5
	var wg sync.WaitGroup
	lateRes := make([]res, late)
	for i := range late {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, why := a.Reevaluate(ctx)
			lateRes[i] = res{ok, why}
		}(i)
	}
	// Let every late request join before the first sync ends.
	time.Sleep(200 * time.Millisecond)
	close(release)
	if r := <-first; !r.ok {
		t.Fatalf("the first request: %s", r.why)
	}
	wg.Wait()
	if r, _ := x.row(); !r.Accepting {
		t.Fatalf("the row after the late requests: %+v", r)
	}
	for i, r := range lateRes {
		if !r.ok {
			t.Fatalf("late request %d: not proven: %s", i, r.why)
		}
	}
	if got := e.calls.Load(); got != 2 {
		t.Fatalf("sshd evaluated %d times for 1+%d requests, want 2: the late ones share one sync", got, late)
	}
}

// TestReevaluate_WedgedAgentIsNotProof: an agent wedged inside a sync (an
// sshd -T that never returns, ignoring its context) answers false within the
// bound, whether the wedged sync is its own or an ordinary one holding the
// sync lock, and every later request does too while it stays wedged.
//
// Mutation: wait on the run alone, without the caller's bound (`case
// <-wctx.Done()` removed): the call hangs, and the test times out, red.
func TestReevaluate_WedgedAgentIsNotProof(t *testing.T) {
	ctx := context.Background()
	x := reevalWorld(t)
	unwedge := make(chan struct{})
	t.Cleanup(func() { close(unwedge) })
	e := &evaluator{answer: func(context.Context, int32) (bool, string, error) {
		<-unwedge
		return true, "", nil
	}}
	a := e.agent(x, openGate{t}, 300*time.Millisecond)
	go func() { _ = a.Sync(ctx) }() // the ordinary sync wedges, holding the lock
	for e.calls.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	for i := range 3 {
		start := time.Now()
		ok, why := a.Reevaluate(ctx)
		if ok {
			t.Fatalf("request %d: a wedged agent proved a fresh evaluation", i)
		}
		if !strings.Contains(why, "wedged") {
			t.Fatalf("request %d: why = %q", i, why)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("request %d took %s; the bound is 300ms", i, d)
		}
	}
	// The caller's own deadline bounds it too.
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if ok, _ := a.Reevaluate(cctx); ok {
		t.Fatal("proved under an expired deadline")
	}
}

// TestReevaluate_NoProofWithoutAnEvaluation: a sync whose sshd evaluation
// failed (the row carries the previous answer forward), or that made none (no
// row is published yet), proves nothing.
//
// Mutation: ignore the evaluation error in freshSync: red; ignore !ran: red.
func TestReevaluate_NoProofWithoutAnEvaluation(t *testing.T) {
	ctx := context.Background()
	x := reevalWorld(t)
	fail := &evaluator{answer: func(context.Context, int32) (bool, string, error) {
		return false, "", errors.New("modelled: sshd -T did not run")
	}}
	if ok, why := fail.agent(x, openGate{t}, 0).Reevaluate(ctx); ok || !strings.Contains(why, "could not be evaluated") {
		t.Fatalf("a failed evaluation: ok %v, why %q", ok, why)
	}
	none := &evaluator{answer: func(context.Context, int32) (bool, string, error) { return true, "", nil }}
	if ok, why := none.agent(x, closedGate{}, 0).Reevaluate(ctx); ok || !strings.Contains(why, "evaluated no sshd") {
		t.Fatalf("no publication: ok %v, why %q", ok, why)
	}
	if got := none.calls.Load(); got != 0 {
		t.Fatalf("premise: the closed gate still evaluated sshd %d times", got)
	}
}

// TestReevaluate_LogsInToTheRunningSSHD: with SelfCheck, the fresh sync logs
// in to the real running sshd: one that does not read the rendered file is
// proven not accepting, one that does is proven accepting.
func TestReevaluate_LogsInToTheRunningSSHD(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	y := w.node("node-y", "127.0.0.4")
	x.skipRendered = true
	x.start(false)
	x.hostRow(x.ip, x.port)
	y.start(false)
	y.hostRow(y.ip, y.port)

	if ok, why := x.publisher(true, true).Reevaluate(ctx); !ok {
		t.Fatalf("node-x: not proven: %s", why)
	}
	if r, _ := x.row(); r.Accepting || !strings.Contains(r.Detail, "the running sshd does not accept it") {
		t.Fatalf("node-x's row = %+v, want not accepting", r)
	}
	if ok, why := y.publisher(true, true).Reevaluate(ctx); !ok {
		t.Fatalf("node-y: not proven: %s", why)
	}
	if r, _ := y.row(); !r.Accepting {
		t.Fatalf("node-y's row = %+v, want accepting", r)
	}
}

// acceptingRow publishes x's row as accepting, through an agent with no
// self-check, so a test can watch whether a later run changes it.
func acceptingRow(t *testing.T, x *node) {
	t.Helper()
	if err := x.publisher(true, false).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, _ := x.row(); !r.Accepting {
		t.Fatalf("premise: %+v", r)
	}
}

// TestReevaluate_TooLittleBoundLeftDoesNotStart: a fresh sync that could not
// give its self-check login a full window (ssh's ConnectTimeout is cut to
// what is left) does not start: no evaluation, no publication, no proof.
//
// Mutation: drop the start check: sshd is evaluated, red.
func TestReevaluate_TooLittleBoundLeftDoesNotStart(t *testing.T) {
	x := reevalWorld(t)
	acceptingRow(t, x)
	e := &evaluator{answer: func(context.Context, int32) (bool, string, error) { return true, "", nil }}
	a := e.agentWith(x, openGate{t}, 2*time.Second, true)
	ok, why := a.Reevaluate(context.Background())
	if ok || !strings.Contains(why, "full self-check") {
		t.Fatalf("ok %v, why %q", ok, why)
	}
	if got := e.calls.Load(); got != 0 {
		t.Fatalf("sshd was evaluated %d times by a run with 2s left", got)
	}
	if r, _ := x.row(); !r.Accepting || r.Detail != "" {
		t.Fatalf("the row changed: %+v", r)
	}
}

// TestReevaluate_TruncatedSelfCheckIsNotProofNorCached: a fresh sync whose
// sshd evaluation left less than a full window for the self-check login
// does not log in on a cut-short window, whose failure would publish
// not-accepting as a proven answer: the evaluation counts as failed (the row
// keeps its answer), proves nothing, and is not cached for the next sync.
//
// Mutations: log in anyway (drop the window check in sshdAccepting): the
// login fails with no sshd here and publishes not-accepting, red; cache
// the cut-short result: the next sync does not evaluate, red.
func TestReevaluate_TruncatedSelfCheckIsNotProofNorCached(t *testing.T) {
	x := reevalWorld(t)
	acceptingRow(t, x)
	bound := fencessh.FreshWindowForTest + time.Second
	slow := bound - fencessh.ProbeTimeoutForTest + time.Second // leaves under probeTimeout
	e := &evaluator{answer: func(_ context.Context, call int32) (bool, string, error) {
		if call == 1 {
			time.Sleep(slow)
		}
		return true, "", nil
	}}
	a := e.agentWith(x, openGate{t}, bound, true)
	ok, why := a.Reevaluate(context.Background())
	if ok || !strings.Contains(why, "full self-check") {
		t.Fatalf("ok %v, why %q", ok, why)
	}
	if r, _ := x.row(); !r.Accepting {
		t.Fatalf("a cut-short self-check changed the row: %+v", r)
	}
	_ = a.Sync(context.Background()) // ordinary: logs in (and fails: no sshd here)
	if got := e.calls.Load(); got != 2 {
		t.Fatalf("sshd evaluated %d times: the cut-short evaluation was cached", got)
	}
}

// TestReevaluate_FailureKeepsTheAgentsLastError: a fresh sync that fails
// reports it to its request (reevaluate_outcome), not as the agent's
// last_error, which stays what its own syncs last said.
//
// Mutations: record a fresh sync's error in last_error: red; cache a failed
// fresh evaluation (the next ordinary sync reports it as its own): red.
func TestReevaluate_FailureKeepsTheAgentsLastError(t *testing.T) {
	ctx := context.Background()
	x := reevalWorld(t)
	var mode atomic.Int32
	e := &evaluator{answer: func(context.Context, int32) (bool, string, error) {
		switch mode.Load() {
		case 1:
			return false, "", errors.New("modelled: the ordinary sync's sshd -T failed")
		case 2:
			return false, "", errors.New("modelled: the requested sync's sshd -T failed")
		}
		return true, "", nil
	}}
	a := e.agent(x, openGate{t}, 0)
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	mode.Store(2)
	if ok, _ := a.Reevaluate(ctx); ok || a.LastError() != "" {
		t.Fatalf("after a failed fresh sync: ok %v, last_error %q", ok, a.LastError())
	}
	// The failed fresh evaluation is not cached: the agent's next sync
	// evaluates for itself, and its success is what last_error says.
	mode.Store(0)
	if err := a.Sync(ctx); err != nil || a.LastError() != "" {
		t.Fatalf("the ordinary sync after it: %v, last_error %q", err, a.LastError())
	}

	// An agent whose own sync failed keeps that error through a failed
	// fresh sync.
	b := e.agent(x, openGate{t}, 0)
	mode.Store(1)
	_ = b.Sync(ctx)
	want := b.LastError()
	if !strings.Contains(want, "ordinary sync") {
		t.Fatalf("premise: last_error %q", want)
	}
	mode.Store(2)
	if ok, _ := b.Reevaluate(ctx); ok || b.LastError() != want {
		t.Fatalf("after a failed fresh sync: ok %v, last_error %q, want %q", ok, b.LastError(), want)
	}
}
