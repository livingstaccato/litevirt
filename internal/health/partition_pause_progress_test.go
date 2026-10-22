package health

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
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
	return relocatedContainersFixtureVMs(t, n, stopDelay, false)
}

// relocatedContainersFixtureVMs is relocatedContainersFixture that, with
// vms, also pauses the fixture's recoverable VM (vm-ha), whose row stays here
// so the healed pass resumes it.
func relocatedContainersFixtureVMs(t *testing.T, n int, stopDelay time.Duration, vms bool) (*pauseFixture, *fakeCT) {
	t.Helper()
	f := newPauseFixture(t)
	if !vms {
		f.p.SetVMBackend(nil)
	}
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
	want := n
	if vms {
		want++
	}
	if len(recs) != want {
		t.Fatalf("setup: %d records, want %d", len(recs), want)
	}
	delete(recs, "vm-ha")
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
// Mutation: drop the per-record progress (resumePass.step's noteProgress) and
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
	// Each settle sleeps delay in its stop, and the counter moves between
	// steps, so the longest still stretch holds at most one of the n sleeps:
	// the other n-1 lie outside it. That is structural, not a timing guess,
	// so a loaded machine (or -race) that stretches the steps' own work
	// cannot fail it. A fixed 3×delay ceiling did, 2 runs in 5 under -race at
	// load 36 (365 ms): the stretch after the last step, the pass's closing
	// condition write, is not a settle and is not bounded by delay.
	if still > took-(n-1)*delay {
		t.Fatalf("progress stood still for %s during a %s pass of %d settles of %s each, so the stretch held "+
			"more than one settle: the liveness gate would read a healthy pass as a wedge", still, took, n, delay)
	}
}

// The resume and settle work of one pass is bounded: what the budget does
// not reach stays paused, untouched, for the next pass.
//
// Mutation: drop the budget check in resumePass.step and the first pass
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

// healedPass makes the next tick a healed pass: the majority has been back
// for longer than T_pause.
func (f *pauseFixture) healedPass() {
	f.set(QuorumYes)
	f.p.mu.Lock()
	f.p.samples = []lossSample{{at: f.now}}
	f.p.yesSince = f.now.Add(-2 * PartitionPauseAfter)
	f.p.mu.Unlock()
}

// stuckHeadCT fails ct-0's stop slowly on every call, as lxc-stop does on a
// container hung in D state on a dead NFS rootfs: its settle overruns the
// pass budget on every pass.
type stuckHeadCT struct {
	*fakeCT
	delay time.Duration
}

func (s stuckHeadCT) Stop(ctx context.Context, name string, timeout int) error {
	if name == "ct-0" {
		time.Sleep(s.delay)
		return errors.New("lxc-stop: timed out")
	}
	return s.fakeCT.Stop(ctx, name, timeout)
}

// One record that is slow and fails on every pass, at the head of the sorted
// records ("ct/" sorts before "vm/"), must not starve the rest: each pass
// starts where the last one stopped. Before the cursor, every other container
// and every paused VM on the host stayed paused for as long as that one
// container was stuck (re-review 2, N4).
//
// Mutation: drop the cursor (start every pass at the first record) and no
// healthy settle runs and the VM stays paused.
func TestPartitionPause_AStuckRecordDoesNotStarveTheRest(t *testing.T) {
	const n, delay = 5, 80 * time.Millisecond
	f, rt := relocatedContainersFixtureVMs(t, n, 0, true)
	f.p.SetContainerRuntime(stuckHeadCT{fakeCT: rt, delay: delay})
	old := partitionResumePassBudget
	partitionResumePassBudget = delay / 2
	t.Cleanup(func() { partitionResumePassBudget = old })
	f.healedPass()
	for i := 0; i < 20; i++ {
		f.tick()
		f.advance(time.Second)
	}
	settled := 0
	for i := 1; i < n; i++ {
		if rt.get(fmt.Sprintf("ct-%d", i)) == "stopped" {
			settled++
		}
	}
	if settled != n-1 {
		t.Errorf("after 20 passes %d of %d healthy settles ran: one stuck record starves the rest", settled, n-1)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Errorf("vm-ha is %s after 20 healed passes: the stuck container starves every VM", st)
	}
}

// quorumFlipVMs loses the majority (via flip) right after the first resume,
// and counts the resumes issued.
type quorumFlipVMs struct {
	PauseVMBackend
	once    sync.Once
	flip    func()
	mu      sync.Mutex
	resumes []string
}

func (q *quorumFlipVMs) ResumePartitionPaused(name, uuid string) error {
	q.mu.Lock()
	q.resumes = append(q.resumes, name)
	q.mu.Unlock()
	err := q.PauseVMBackend.ResumePartitionPaused(name, uuid)
	q.once.Do(q.flip)
	return err
}

// The partition comes back in the middle of a resume pass: the pass stops
// resuming at once, and what it already resumed is paused again, so nothing
// it resumed runs beside a replacement the majority's wait may now start
// (re-review 2, N5).
//
// A container resumed in the same pass (ct-ha: "ct/" sorts first, so it is
// resumed before any VM) is frozen again too.
//
// No resume is ISSUED after the loss: the pass reads the quorum before each
// step (resumePass.step), and that reading is the one §4.1's R term counts —
// the longest a healed host goes without one. Asserting only that every VM
// ends paused could not tell it from the read after the last resume, which
// re-pauses what the pass resumed either way (re-review 4, finding 2).
//
// Mutations: drop the quorum read between steps (resumePass.step) — three
// more resumes are issued after the loss; drop the re-pause — the first
// stays running; skip containers in the re-pause — ct-ha stays running.
func TestPartitionPause_MajorityLostMidPassStopsAndRepauses(t *testing.T) {
	f := newPauseFixture(t)
	ctx := context.Background()
	names := []string{"vm-ha", "vm-r1", "vm-r2", "vm-r3"}
	for _, name := range names[1:] {
		if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: name, HostName: "node-a",
			Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		f.virt.SetState(name, libvirtfake.StateRunning)
	}
	if err := corrosion.UpsertContainer(ctx, f.db, corrosion.ContainerRecord{HostName: "node-a", Name: "ct-ha",
		State: "running", Image: "alpine:3.19", OnHostFailure: "image-recreate"}); err != nil {
		t.Fatal(err)
	}
	rt := newFakeCT("ct-ha")
	f.p.SetContainerRuntime(rt)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	for _, name := range names {
		if st := f.raw(name); st != libvirtfake.StatePaused {
			t.Fatalf("setup: %s is %s, want paused", name, st)
		}
	}
	if st := rt.get("ct-ha"); st != "frozen" {
		t.Fatalf("setup: ct-ha is %s, want frozen", st)
	}
	flip := &quorumFlipVMs{PauseVMBackend: f.virt, flip: func() { f.set(QuorumNo) }}
	f.p.SetVMBackend(flip)
	f.healedPass()
	f.tick()
	flip.mu.Lock()
	issued := append([]string(nil), flip.resumes...)
	flip.mu.Unlock()
	if len(issued) != 1 {
		t.Errorf("resumes issued = %v, want only the one during which the majority was lost", issued)
	}
	for _, name := range names {
		if st := f.raw(name); st != libvirtfake.StatePaused {
			t.Errorf("%s is %s after the majority was lost mid-pass, want paused", name, st)
		}
	}
	if st := rt.get("ct-ha"); st != "frozen" {
		t.Errorf("ct-ha is %s after the majority was lost mid-pass, want frozen again", st)
	}
	if recs := f.records(); len(recs) != len(names)+1 {
		t.Errorf("records = %+v, want one for each of %v and ct-ha", recs, names)
	}
}
