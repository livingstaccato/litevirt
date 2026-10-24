package health

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/lxc"
)

// callOut reports whether the call on key is still out. A test whose hung
// call is held until released asserts this once the pass has returned: the
// pass ended without waiting for the call, whatever the machine's load. A
// wall-clock ceiling on the pass instead failed on a loaded host (a race
// shard took 5.96 s over a 3 s step) without anything having waited.
func (f *pauseFixture) callOut(key string) bool {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	return f.p.inflight[key]
}

// hungResumeVMs hangs every partition-pause resume of one domain until
// release is closed, and only then resumes it: a qemu whose monitor is wedged
// takes the libvirt job and answers the cont late.
type hungResumeVMs struct {
	PauseVMBackend
	name    string
	release chan struct{}
}

func (h *hungResumeVMs) ResumePartitionPaused(name, uuid string) error {
	if name == h.name {
		<-h.release
	}
	return h.PauseVMBackend.ResumePartitionPaused(name, uuid)
}

// A VM resume that hangs no longer holds the pauser: the pass abandons it at
// its step bound, the VM keeps its record and stays paused. While the
// abandoned call is out, a lost majority's pause pass kills the VM's QEMU
// (AnAbandonedResumeIsKilledUnderALostMajority); here that kill fails (no
// pid file), so the pass reports the pause as failed, since the call may yet
// land, and self-fences with a verified watchdog; and when the call does
// land the VM is paused again at once. Before, the pass waited for the
// call, taking no quorum sample, and every workload resumed earlier ran on
// unwatched (re-review 3, finding 1).
//
// Mutations: wait for the call (no step bound) — the pass takes as long as
// the hang; drop the undo of a late landing — vm-ha runs after release; count
// a failed kill as a stop — no failure is reported and no self-fence.
func TestPartitionPause_AHungResumeIsAbandonedAtItsBound(t *testing.T) {
	f := newPauseFixture(t)
	f.virt.FailKillPartitionPaused = func(string) error { return errors.New("no pid file") }
	f.p.SetSelfFence(func() bool { return true }, func() { f.mu.Lock(); f.fenced++; f.mu.Unlock() })
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s, want paused", st)
	}
	hung := &hungResumeVMs{PauseVMBackend: f.virt, name: "vm-ha", release: make(chan struct{})}
	release := releaser(t, hung.release)
	f.p.SetVMBackend(hung)

	f.healedPass()
	f.tick()
	if !f.callOut("vm/vm-ha") {
		t.Fatal("the pass returned only once the hung resume had: no quorum sample was taken meanwhile")
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with its resume still hung, want paused", st)
	}
	if len(f.records()) != 1 {
		t.Fatalf("records = %+v, want vm-ha's kept", f.records())
	}

	// The partition returns while the call is out: the pause cannot be
	// promised, since the call may still land.
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	row, ok := f.condition(corrosion.CondPartitionPauseFailed)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(row.Evidence, "vm/vm-ha") {
		t.Fatalf("partition_pause_failed = %+v (found %v), want it open for vm/vm-ha while its resume is out", row, ok)
	}
	f.mu.Lock()
	fenced := f.fenced
	f.mu.Unlock()
	if fenced == 0 {
		t.Fatal("no self-fence for a VM whose abandoned resume may still land and whose QEMU could not be killed")
	}

	// The call lands: the VM is paused again at once, with no pass to do it.
	release()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.p.mu.Lock()
		out := f.p.inflight["vm/vm-ha"]
		f.p.mu.Unlock()
		if !out {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the abandoned resume never returned")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after its abandoned resume landed, want paused again", st)
	}
}

// hungStopCT hangs ct-0's stop until release, as lxc-stop does on a
// container in D state, and then fails it.
type hungStopCT struct {
	*fakeCT
	release chan struct{}
}

func (h hungStopCT) Stop(ctx context.Context, name string, timeout int) error {
	if name == "ct-0" {
		<-h.release
		return errors.New("lxc-stop: timed out")
	}
	return h.fakeCT.Stop(ctx, name, timeout)
}

// A container settle whose stop hangs (lxc-stop on a container in D state)
// is abandoned at its step bound the same way, and the pass ends.
//
// Mutation: no step bound on the settle stop — the pass takes the whole hang.
func TestPartitionPause_AHungSettleStopIsAbandonedAtItsBound(t *testing.T) {
	f, rt := relocatedContainersFixture(t, 2, 0)
	hung := hungStopCT{fakeCT: rt, release: make(chan struct{})}
	releaser(t, hung.release)
	f.p.SetContainerRuntime(hung)
	f.healedPass()
	f.tick()
	if !f.callOut("ct/ct-0") {
		t.Fatal("the pass returned only once the hung settle stop had (or never started it): no quorum sample was taken meanwhile")
	}
}

// failSlowVMs fails one domain's resume slowly, as a resume that times out
// on the libvirt job lock does, and logs every resume in call order.
type failSlowVMs struct {
	PauseVMBackend
	name  string
	delay time.Duration
	mu    sync.Mutex
	calls []string
}

func (s *failSlowVMs) ResumePartitionPaused(name, uuid string) error {
	s.mu.Lock()
	s.calls = append(s.calls, name)
	s.mu.Unlock()
	if name == s.name {
		time.Sleep(s.delay)
		return errors.New("timed out during operation: cannot acquire state change lock")
	}
	return s.PauseVMBackend.ResumePartitionPaused(name, uuid)
}

func (s *failSlowVMs) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// A resume that fails slowly at the head of the candidates is not retried
// first on every pass: the resume loop keeps its own place, so the next pass
// starts after it, and every healthy VM comes back before the failing one is
// tried again, rather than one per pass or never (re-review 3, finding 2).
//
// The failing resume outlasts the pass budget, so the first pass resumes
// nothing else. The budget is a second, far above what the record checks
// and healthy resumes take on a loaded host, and the assertion is on the
// order of the resume calls, not on how many passes the rest took. A 40 ms
// budget was spent by the checks alone under load (they took up to 130 ms),
// and healthy VMs slipped to a third pass.
//
// Mutation: start the resume loop at the first candidate on every pass — the
// failing VM is tried again before any healthy one, which never comes back.
func TestPartitionPause_AFailingResumeDoesNotHoldUpTheRest(t *testing.T) {
	const healthy = 5
	f := newPauseFixture(t)
	ctx := context.Background()
	var names []string
	for i := 1; i <= healthy; i++ {
		name := fmt.Sprintf("vm-r%d", i)
		names = append(names, name)
		if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: name, HostName: "node-a",
			Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		f.virt.SetState(name, libvirtfake.StateRunning)
	}
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if n := len(f.records()); n != healthy+1 {
		t.Fatalf("setup: %d records, want %d", n, healthy+1)
	}
	const budget = time.Second
	vms := &failSlowVMs{PauseVMBackend: f.virt, name: "vm-ha", delay: budget + 200*time.Millisecond}
	f.p.SetVMBackend(vms)
	old := partitionResumePassBudget
	partitionResumePassBudget = budget
	t.Cleanup(func() { partitionResumePassBudget = old })
	f.healedPass()
	running := func() int {
		n := 0
		for _, name := range names {
			if f.raw(name) == libvirtfake.StateRunning {
				n++
			}
		}
		return n
	}
	f.tick()
	if got := vms.log(); len(got) != 1 || got[0] != "vm-ha" || running() != 0 {
		t.Fatalf("setup: the first pass made resume calls %v and left %d healthy VMs running, want only vm-ha's, which spends the budget", got, running())
	}
	for pass := 2; pass <= 2*healthy && running() < healthy; pass++ {
		f.advance(partitionResumeRecheck)
		f.tick()
	}
	calls := vms.log()
	first := map[string]int{}
	for i, name := range calls {
		if _, ok := first[name]; !ok {
			first[name] = i
		}
	}
	retry := len(calls)
	for i, name := range calls[1:] {
		if name == "vm-ha" {
			retry = i + 1
			break
		}
	}
	for _, name := range names {
		if i, ok := first[name]; !ok || i > retry {
			t.Fatalf("%s was not resumed before vm-ha's failing resume was tried again (resume calls in order: %v)", name, calls)
		}
	}
	if n := running(); n != healthy {
		t.Fatalf("%d healthy VMs running, want all %d (resume calls in order: %v)", n, healthy, calls)
	}
}

// After a pass stops because the majority was lost mid-pass, a single Yes
// reading is not a heal: the loss it saw counts like any other reading, so
// resuming again needs the unbroken T_pause of Yes readings §4.1 requires
// (re-review 3, finding 3).
//
// Mutation: drop the loss sample majorityLost records — one Yes tick resumes
// both VMs again.
func TestPartitionPause_ALossSeenMidPassNeedsAFullHeal(t *testing.T) {
	f := newPauseFixture(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: "vm-r1", HostName: "node-a",
		Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	f.virt.SetState("vm-r1", libvirtfake.StateRunning)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	f.p.SetVMBackend(&quorumFlipVMs{PauseVMBackend: f.virt, flip: func() { f.set(QuorumNo) }})
	f.healedPass()
	f.tick()
	for _, name := range []string{"vm-ha", "vm-r1"} {
		if st := f.raw(name); st != libvirtfake.StatePaused {
			t.Fatalf("setup: %s is %s after the majority was lost mid-pass, want paused", name, st)
		}
	}
	f.advance(6 * time.Second)
	f.set(QuorumYes)
	f.tick()
	for _, name := range []string{"vm-ha", "vm-r1"} {
		if st := f.raw(name); st != libvirtfake.StatePaused {
			t.Errorf("%s is %s after one Yes reading following a mid-pass loss, want paused until a full heal", name, st)
		}
	}
}

// The majority is lost during the last (here the only) resume of a pass: the
// pass reads the quorum once more after it, and pauses that workload again.
// Before, the re-read came only before each resume, so the last one was never
// checked (re-review 3, finding 1).
//
// Mutation: drop the read after the last resume — vm-ha stays running.
func TestPartitionPause_MajorityLostDuringTheLastResumeRepauses(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	f.p.SetVMBackend(&quorumFlipVMs{PauseVMBackend: f.virt, flip: func() { f.set(QuorumNo) }})
	f.healedPass()
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after the majority was lost during its resume, want paused again", st)
	}
	if recs := f.records(); len(recs) != 1 {
		t.Fatalf("records = %+v, want vm-ha's", recs)
	}
}

// pendingStateCT answers lxc-info slowly for one container and counts the
// state reads, with every container listed and its state unreadable, so a
// pending settle stays pending (copyUnproven) pass after pass.
type pendingStateCT struct {
	lxc.Runtime
	names []string
	slow  string
	delay time.Duration
	mu    sync.Mutex
	calls map[string]int
}

func (p *pendingStateCT) List(context.Context) ([]string, error) { return p.names, nil }

func (p *pendingStateCT) State(_ context.Context, name string) (lxc.State, error) {
	p.mu.Lock()
	p.calls[name]++
	p.mu.Unlock()
	if name == p.slow {
		time.Sleep(p.delay)
	}
	return lxc.StateUnknown, errors.New("lxc-info: timed out")
}

// The pending-settle retries of a healed pass take turns like the records:
// a record whose copy is slow to read on every pass does not keep the rest
// from ever being retried (re-review 3, finding 4).
//
// Mutation: ignore retryCursor — ct-0 is retried on every pass and nothing
// else is.
func TestPartitionPause_PendingSettleRetriesTakeTurns(t *testing.T) {
	const n, delay = 5, 80 * time.Millisecond
	f := newPauseFixture(t)
	f.p.SetVMBackend(nil)
	rt := &pendingStateCT{slow: "ct-0", delay: delay, calls: map[string]int{}}
	store := newSettlePendingStore(f.dataDir)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("ct-%d", i)
		rt.names = append(rt.names, name)
		if err := store.put(settlePending{Kind: PauseKindContainer, Name: name, Host: "node-a",
			Phase: settlePhaseStopping, AuditID: fmt.Sprintf("a%031x", i)}); err != nil {
			t.Fatal(err)
		}
	}
	f.p.SetContainerRuntime(rt)
	old := partitionResumePassBudget
	partitionResumePassBudget = delay / 2
	t.Cleanup(func() { partitionResumePassBudget = old })
	f.healedPass()
	for pass := 0; pass < 4; pass++ {
		f.tick()
		f.advance(time.Second)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, name := range rt.names[1:] {
		if rt.calls[name] == 0 {
			t.Fatalf("after 4 passes the pending settle of %s was never retried (state reads %v)", name, rt.calls)
		}
	}
}
