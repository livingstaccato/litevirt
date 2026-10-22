package health

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// shortStepBound shortens R for a test whose resume is abandoned, so it
// does not wait the production 3 s for each.
func shortStepBound(t *testing.T) {
	t.Helper()
	old := partitionResumeStepBound
	partitionResumeStepBound = 300 * time.Millisecond
	t.Cleanup(func() { partitionResumeStepBound = old })
}

// releaser closes ch once, from the test or from its cleanup, so a hung
// call never outlives the test.
func releaser(t *testing.T, ch chan struct{}) func() {
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	safety := time.AfterFunc(20*time.Second, release)
	t.Cleanup(func() { safety.Stop() })
	return release
}

// waitReturned waits until key's abandoned call has returned.
func (f *pauseFixture) waitReturned(key string) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.p.mu.Lock()
		out := f.p.inflight[key]
		f.p.mu.Unlock()
		if !out {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("the abandoned call on %s never returned", key)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// abandonResume leaves vm-ha's resume hung and abandoned by a healed pass:
// vm-ha paused, its record kept, its call still out.
func abandonResume(f *pauseFixture) (release func()) {
	f.t.Helper()
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	hung := &hungResumeVMs{PauseVMBackend: f.virt, name: "vm-ha", release: make(chan struct{})}
	release = releaser(f.t, hung.release)
	f.p.SetVMBackend(hung)
	f.healedPass()
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		f.t.Fatalf("setup: vm-ha is %s with its resume hung, want paused", st)
	}
	if !f.p.resumeInFlight("vm/vm-ha") {
		f.t.Fatal("setup: vm-ha's resume is not out")
	}
	return release
}

// eventsOf is the fake's log for one domain, as "op" strings in order.
func eventsOf(f *pauseFixture, name string) []string {
	var out []string
	for _, e := range f.virt.EventLog() {
		if e.Domain == name {
			out = append(out, e.Op)
		}
	}
	return out
}

// A resume abandoned at its step bound may land at any moment, and a pause
// pass under a lost majority cannot promise a suspend comes after it. So
// the pass kills the domain's QEMU, without libvirt: when the call finally
// returns there is nothing for it to land on, and the guest never runs
// again on this host. No pause failure is reported for it, so no self-fence.
// Before, the pass reported the failure and relied on an undo after the
// landing, leaving two copies for at least a libvirt round trip after the
// majority's wait (re-review 4, (c)).
//
// Mutation: no kill in the pause pass — vm-ha is not shut off, and resumes
// when the call returns.
func TestPartitionPause_AnAbandonedResumeIsKilledUnderALostMajority(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	release := abandonResume(f)

	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-ha is %s after a pause pass with its resume still out, want its QEMU killed", st)
	}
	if st := f.raw("vm-none"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-none is %s, want running: only an abandoned resume's QEMU is killed", st)
	}
	if row, ok := f.condition(corrosion.CondPartitionPauseFailed); ok && row.Lifecycle == corrosion.ConditionConfirmed && strings.Contains(row.Evidence, "vm/vm-ha") {
		t.Fatalf("partition_pause_failed names vm/vm-ha after its QEMU was killed: %s", row.Evidence)
	}
	f.mu.Lock()
	fenced := f.fenced
	f.mu.Unlock()
	if fenced != 0 {
		t.Fatalf("self-fenced %d times for a VM whose QEMU was killed", fenced)
	}

	// The call returns: it lands on nothing, and vm-ha never runs again.
	release()
	f.waitReturned("vm/vm-ha")
	ev := eventsOf(f, "vm-ha")
	killed := -1
	for i, op := range ev {
		if op == "kill" {
			killed = i
		}
		if op == "resume" && killed >= 0 {
			t.Fatalf("vm-ha resumed after its QEMU was killed: events %v", ev)
		}
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-ha is %s after its abandoned resume returned, want shut off", st)
	}
}

// A resume abandoned at its step bound that lands later, with the majority
// there throughout and confirming again at the landing, stands: it is as
// safe as a resume that landed on time, and undoing it would keep a guest
// whose libvirt is slow on every call paused for good (re-review 4, finding
// 5). Its record goes, and the next loss pauses it on the ordinary path.
//
// Red on 9d89e1518 (every late landing was undone).
func TestPartitionPause_ALateResumeStandsWhileTheMajorityStays(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	release := abandonResume(f)
	release()
	f.waitReturned("vm/vm-ha")
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after its late resume landed with the majority there throughout, want running", st)
	}
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("records = %+v, want vm-ha's dropped", recs)
	}
	// An ordinary running VM now: a loss pauses it.
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after a loss, want paused", st)
	}
}

// A late landing stands only on all three: an unbroken run of Yes readings
// since its step, a fresh Yes, and a fresh majority confirmation. Each case
// breaks one, and the landing is paused again at once, its record kept.
//
// Mutations: drop the unbroken-run check — "a blip" runs; drop the fresh
// reading — "no majority now" runs; drop the fresh confirmation — "the
// voters refuse" runs.
func TestPartitionPause_ALateResumeIsPausedAgainUnlessItIsAsSafeAsOnTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(f *pauseFixture)
	}{
		{"a blip", func(f *pauseFixture) {
			f.set(QuorumNo)
			f.tick()
			f.set(QuorumYes)
			f.advance(time.Second)
			f.tick()
		}},
		{"no majority now", func(f *pauseFixture) { f.set(QuorumNo) }},
		{"the voters refuse", func(f *pauseFixture) {
			f.confirm = func(recs []PauseRecord) map[string]ResumeVerdict {
				out := map[string]ResumeVerdict{}
				for _, r := range recs {
					out[r.Key()] = ResumeVerdict{Reason: "test: a claim moved it"}
				}
				return out
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortStepBound(t)
			f := newPauseFixture(t)
			release := abandonResume(f)
			tc.break_(f)
			release()
			f.waitReturned("vm/vm-ha")
			if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
				t.Fatalf("vm-ha is %s after a late landing (%s), want paused again", st, tc.name)
			}
			if recs := f.records(); len(recs) != 1 {
				t.Fatalf("records = %+v, want vm-ha's kept", recs)
			}
		})
	}
}

// hungSuspendVMs hangs every suspend of the named domains until release,
// as a qemu stop does that drains I/O to a dead NFS fabric, and loses the
// majority (flip) after the last of them is resumed.
type hungSuspendVMs struct {
	PauseVMBackend
	hang    map[string]bool
	release chan struct{}
	mu      sync.Mutex
	resumed int
	flip    func()
}

func (h *hungSuspendVMs) ResumePartitionPaused(name, uuid string) error {
	err := h.PauseVMBackend.ResumePartitionPaused(name, uuid)
	if h.hang[name] {
		h.mu.Lock()
		h.resumed++
		last := h.resumed == len(h.hang)
		h.mu.Unlock()
		if last {
			h.flip()
		}
	}
	return err
}

func (h *hungSuspendVMs) SuspendDomain(name string) error {
	if h.hang[name] {
		<-h.release
	}
	return h.PauseVMBackend.SuspendDomain(name)
}

// The majority is lost after a pass resumed eight VMs, and every one of
// their re-pauses hangs. The re-pause runs them at once and returns within
// its bound, so the pauser's loop goes on taking readings, and the VM an
// earlier pass resumed (vm-ha) is paused on the ordinary path in time.
// Before, the re-pause waited 2 s for each in turn: the loop was held 16 s,
// and vm-ha paused that much later than §4.1 counts (re-review 4, finding 1).
func TestPartitionPause_ARepauseOfHungSuspendsDoesNotHoldThePauser(t *testing.T) {
	const n = 8
	f := newPauseFixture(t)
	ctx := context.Background()
	hang := map[string]bool{}
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("vm-r%d", i)
		hang[name] = true
		if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: name, HostName: "node-a",
			Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		f.virt.SetState(name, libvirtfake.StateRunning)
	}
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if recs := f.records(); len(recs) != n+1 {
		t.Fatalf("setup: %d records, want %d", len(recs), n+1)
	}
	// Pass 1 resumes vm-ha alone.
	f.confirm = func(recs []PauseRecord) map[string]ResumeVerdict {
		out := map[string]ResumeVerdict{}
		for _, r := range recs {
			out[r.Key()] = ResumeVerdict{OK: r.Name == "vm-ha", Reason: "test"}
		}
		return out
	}
	f.healedPass()
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("setup: vm-ha is %s after pass 1, want running", st)
	}
	// Pass 2 resumes the eight, and the majority goes as the last resumes.
	f.confirm = nil
	vms := &hungSuspendVMs{PauseVMBackend: f.virt, hang: hang, release: make(chan struct{}), flip: func() { f.set(QuorumNo) }}
	releaser(t, vms.release)
	f.p.SetVMBackend(vms)
	f.advance(partitionResumeRecheck)
	start := time.Now()
	f.tick()
	held := time.Since(start)
	if held > partitionRepauseBound+time.Second {
		t.Fatalf("the re-pause of %d hung suspends held the pauser for %s, past its bound %s", n, held.Round(time.Millisecond), partitionRepauseBound)
	}
	// The ordinary path: vm-ha is paused T_pause after the loss.
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after the loss, want paused", st)
	}
	if total := time.Since(start); total > partitionRepauseBound+PartitionPauseExecBudget+time.Second {
		t.Fatalf("vm-ha was paused %s (real time) after the loss, past re-pause + one pause pass", total.Round(time.Millisecond))
	}
}

// hungUnfreezeCT hangs every Unfreeze until release, ignoring its context
// as an lxc-unfreeze in an uninterruptible wait does, and then thaws.
type hungUnfreezeCT struct {
	*fakeCT
	release chan struct{}
}

func (h hungUnfreezeCT) Unfreeze(ctx context.Context, name string) error {
	<-h.release
	return h.fakeCT.Unfreeze(ctx, name)
}

// The container twin of AHungResumeIsAbandonedAtItsBound. An Unfreeze still
// out under a lost majority makes the container's pause a failure (it may
// yet thaw, and a container has no kill here), and when it lands after the
// loss the container is frozen again at once (re-review 4, finding 3).
//
// Mutations: drop pauseContainers' in-flight check — no failure is
// reported; make the Freeze undo a no-op — ct-ha runs after the landing.
func TestPartitionPause_AHungUnfreezeIsAbandonedAtItsBound(t *testing.T) {
	shortStepBound(t)
	f := newPauseFixture(t)
	f.p.SetVMBackend(nil)
	if err := corrosion.UpsertContainer(context.Background(), f.db, corrosion.ContainerRecord{HostName: "node-a", Name: "ct-ha",
		State: "running", Image: "alpine:3.19", OnHostFailure: "image-recreate"}); err != nil {
		t.Fatal(err)
	}
	rt := newFakeCT("ct-ha")
	f.p.SetContainerRuntime(rt)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := rt.get("ct-ha"); st != "frozen" {
		t.Fatalf("setup: ct-ha is %s, want frozen", st)
	}
	hung := hungUnfreezeCT{fakeCT: rt, release: make(chan struct{})}
	release := releaser(t, hung.release)
	f.p.SetContainerRuntime(hung)
	f.healedPass()
	start := time.Now()
	f.tick()
	if took := time.Since(start); took > stepBoundCeiling {
		t.Fatalf("a hung Unfreeze held the pauser for %s", took.Round(time.Millisecond))
	}
	if st := rt.get("ct-ha"); st != "frozen" {
		t.Fatalf("ct-ha is %s with its Unfreeze hung, want frozen", st)
	}

	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	row, ok := f.condition(corrosion.CondPartitionPauseFailed)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(row.Evidence, "ct/ct-ha") {
		t.Fatalf("partition_pause_failed = %+v (found %v), want it open for ct/ct-ha while its Unfreeze is out", row, ok)
	}

	release()
	f.waitReturned("ct/ct-ha")
	if st := rt.get("ct-ha"); st != "frozen" {
		t.Fatalf("ct-ha is %s after its abandoned Unfreeze landed under a lost majority, want frozen again", st)
	}
}
