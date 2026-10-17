package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Review mainconn I-1: the runtime inventory (the capacity sampler every
// 60 s, the dual-run detector's self-probe, and the GetRuntimeInventory RPC
// every peer's leader calls) listed the domains on the daemon's connection,
// unbounded and once per caller. libvirt's list waits on a domain it hangs
// on, so each pass left one more call on that connection, which filled
// within minutes and stalled the gated background passes again. The libvirt
// half of an inventory is read on a reader connection now, as one
// single-flight call within its wait: an inventory libvirt has not answered
// is incomplete (unknown, never absent), at once once latched, and nothing
// is asked on the daemon's connection.
//
// Mutations: the inventory read on s.virt, unbounded: the first inventory
// does not return: red. No single flight (each inventory asks anew): the
// second takes a wait: red. A joiner that finds the flight stalled and
// starts its own while answering at once: the flight-identity check, red. A
// joiner that waits one wall-clock tick, or the stall, before its first
// look: within, red. DumpXML or DomainState asked on s.virt: calls
// naming ok on the daemon's connection: red. (A stalled flight answered from
// the cache is pinned by TestRuntimeInventory_AStalledReadIsNotFilledFromTheCache:
// here the list itself hangs, so there is no list to fill.)
func TestRuntimeInventory_AListLibvirtDoesNotAnswerIsIncompleteAndOffTheDaemonsConnection(t *testing.T) {
	s, f := liveStateServer(t, "ok", "st")
	s.liveStateWait = 100 * time.Millisecond
	// A complete inventory first, so one is cached: a hung domain is never
	// answered from it (re-review n-1).
	if inv := s.collectRuntimeInventory(context.Background()); !inv.Complete {
		t.Fatalf("the first inventory: incomplete: %v", inv.Errors)
	}
	release := f.HangDomain("st")
	t.Cleanup(release)

	// The inventory's clock moves while the first caller waits, so the hung
	// list stalls; it stands still after, so a later caller that waited
	// anew for a stall would never return (within's bound), however slowly
	// or quickly this host runs them.
	clock := newInvTestClock(s)
	ticking := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticking:
				return
			case <-time.After(5 * time.Millisecond):
				clock.Advance(20 * time.Millisecond)
			}
		}
	}()
	inv := within(t, 5*time.Second, "an inventory while libvirt hangs on st", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	close(ticking)
	if inv.Complete || !strings.Contains(strings.Join(inv.Errors, ";"), "has not answered") {
		t.Fatalf("inventory: complete %v, errors %v; want incomplete saying libvirt has not answered", inv.Complete, inv.Errors)
	}
	if snap := snapshotFromInventory(inv); !snap.partial {
		t.Error("the dual-run snapshot of an incomplete inventory is not partial")
	}
	// Later callers join the hung list's flight and answer from their first
	// look. The stall becomes two minutes and the inventory clock moves five
	// past the flight's last progress, then stands still: the flight is
	// stalled, well inside its cap, and a joiner's wall-clock tick is now 12 s.
	// One that waited a tick, or the stall, on the wall clock before it looked
	// misses within's 5 s; one that looks at once returns. (The flight
	// goroutine never reads liveStateWait, and no caller is waiting now.)
	s.liveStateWait = 2 * time.Minute
	clock.Advance(5 * time.Minute)
	// One flight answers them all: the hung list's flight is still the
	// current one after each later caller, and none starts its own.
	flight := func() *inventoryFlight {
		s.invFlights.mu.Lock()
		defer s.invFlights.mu.Unlock()
		return s.invFlights.cur
	}
	hung := flight()
	if hung == nil {
		t.Fatal("fixture: no flight in progress while libvirt hangs on st")
	}
	for i := 0; i < 3; i++ {
		later := within(t, 5*time.Second, "a later inventory while the clock stands still", func() runtimeInventory {
			return s.collectRuntimeInventory(context.Background())
		})
		if later.Complete || !strings.Contains(strings.Join(later.Errors, ";"), "has not answered") {
			t.Fatalf("later inventory %d: complete %v, errors %v; want incomplete saying libvirt has not answered",
				i+1, later.Complete, later.Errors)
		}
		if cur := flight(); cur != hung {
			t.Fatalf("later inventory %d is not answered from the hung list's flight: it started its own", i+1)
		}
	}
	if n := f.MainConnCallsFor(""); n != 0 {
		t.Errorf("domain lists on the daemon's connection: %d, want 0", n)
	}

	release()
	deadline := time.Now().Add(5 * time.Second)
	for {
		inv := s.collectRuntimeInventory(context.Background())
		if inv.Complete {
			if _, ok := inv.find(corrosion.WorkloadVM, "ok"); !ok {
				t.Fatalf("complete inventory lacks ok: %+v", inv.Workloads)
			}
			for _, n := range []string{"", "ok", "st"} {
				if c := f.MainConnCallsFor(n); c != 0 {
					t.Errorf("calls naming %q on the daemon's connection: %d, want 0", n, c)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after libvirt answered: still incomplete: %v", inv.Errors)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Review mainconn I-2: at shutdown, Close closes the daemon's connection to
// libvirtd, which woke a held start's goroutine with a transport error. It
// then recorded the start failed, put the row back to stopped and let the
// start lease go, just before the database closed — while libvirtd went on
// to start the domain, under a stopped row with no lease, and the restarted
// daemon's takeover (health/held_start_orphan.go) never fired, the row no
// longer saying starting. A start whose connection went away records
// nothing now: the row stays starting, the lease the held start's, and no
// event is written.
//
// It is then the restarted daemon's to record (lab 2, 7c648824, B2 run 1,
// where the graceful restart left the VM running under a stopped row).
//
// Mutation: no connection-lost guard: the row is put back to stopped, the
// lease released and a vm.started error recorded, and the restarted daemon
// never records the VM running: red.
func TestStartVM_AHeldStartWokenByCloseRecordsNothing(t *testing.T) {
	st := heldStart(t)
	f := st.s.virt.(*libvirtfake.Fake)
	vm := st.row(t)
	if vm.State != "starting" {
		t.Fatalf("web while held: %s, want starting", vm.State)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	st.answer.Store(fmt.Errorf("start domain web: %w", golibvirt.ErrInterrupted))
	close(st.release)
	st.waitLockFree(t, "after the connection closed under the start")

	if got := st.row(t); got.State != "starting" || got.StateDetail != vm.StateDetail {
		t.Errorf("web after Close: %s/%q, want %s/%q", got.State, got.StateDetail, vm.State, vm.StateDetail)
	}
	if holder, _ := st.leaseHolder(t); holder != health.OperatorStartLockHolder(st.s.hostName) {
		t.Errorf("web's start lease after Close: %q, want the held start's", holder)
	}
	for _, r := range []string{"ok", "error"} {
		if evs := st.events(t, "vm.started", r); len(evs) != 0 {
			t.Errorf("vm.started %s events after Close: %+v, want none", r, evs)
		}
	}
	if _, live := st.s.startFlightOf("web"); live {
		t.Error("the start is still in flight in this daemon")
	}

	// The daemon restarts (lab 2, 7c648824, B2 run 1: a graceful
	// `systemctl stop`/start), and libvirtd completes the start once the
	// storage answers: the restarted daemon's reconciler takes the held
	// start over, records the VM running, and the start once.
	st2 := newStuckStart(t)
	st2.s.db, st2.s.dataDir = st.s.db, st.s.dataDir
	f2 := st2.s.virt.(*libvirtfake.Fake)
	f2.SetState("web", libvirtfake.StateRunning)
	r := health.NewReconciler(st2.s.hostName, st2.s.dataDir, st2.s.db, f2)
	r.SetHeldStartProbe(st2.s.HasStartInFlight)
	r.SetVMEventRecorder(st2.s.RecordVMEvent)
	within(t, 5*time.Second, "a reconcile pass of the restarted daemon", func() bool {
		r.ReconcileOnce(context.Background())
		return true
	})
	r.ReconcileOnce(context.Background())
	if got := st2.row(t); got.State != "running" {
		t.Errorf("web after the restart and libvirt's start: %s/%q, want running", got.State, got.StateDetail)
	}
	if evs := st2.events(t, "vm.started", "ok"); len(evs) != 1 || !strings.Contains(evs[0].Detail, "restarted") {
		t.Errorf("vm.started ok events: %+v, want one, naming the restart", evs)
	}
	if evs := st2.events(t, "vm.started", "error"); len(evs) != 0 {
		t.Errorf("vm.started error events: %+v, want none", evs)
	}
	// One qemu: the restarted daemon recorded the domain libvirtd started,
	// and started none of its own.
	if n := st2.calls.Load(); n != 0 {
		t.Errorf("the restarted daemon asked libvirt to start web %d times, want 0", n)
	}
	for _, e := range f2.EventLog() {
		if e.Domain == "web" && (e.Op == "start" || e.Op == "destroy") {
			t.Errorf("the restarted daemon acted on web's domain: %+v", e)
		}
	}
}

// The two halves of the guard, each alone (re-review n-3): a start answered
// with any error once the client is closing (Close fails the call first, and
// the error it sees may be the socket's), and a start whose connection was
// lost with the client not closing (libvirtd restarted under a daemon that
// stays up: libvirtd's restart ends the start, and the lease, no longer
// renewed, lapses for the reconciler). Neither records anything.
//
// Mutations: no Closing check: "closing" red. No IsConnectionLost check:
// "connection lost" red.
func TestStartVM_AHeldStartsConnectionGuardHalves(t *testing.T) {
	for _, c := range []struct {
		name  string
		close bool
		err   error
	}{
		{"closing", true, errors.New("start domain web: write unix ->/var/run/libvirt/libvirt-sock: use of a closed connection")},
		{"connection lost", false, fmt.Errorf("start domain web: %w", golibvirt.ErrInterrupted)},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := heldStart(t)
			vm := st.row(t)
			if c.close {
				_ = st.s.virt.(*libvirtfake.Fake).Close()
			}
			st.answer.Store(c.err)
			close(st.release)
			st.waitLockFree(t, "after the start's error")
			if got := st.row(t); got.State != "starting" || got.StateDetail != vm.StateDetail {
				t.Errorf("web: %s/%q, want %s/%q", got.State, got.StateDetail, vm.State, vm.StateDetail)
			}
			if holder, _ := st.leaseHolder(t); holder != health.OperatorStartLockHolder(st.s.hostName) {
				t.Errorf("web's start lease: %q, want the held start's", holder)
			}
			if evs := st.events(t, "vm.started", "error"); len(evs) != 0 {
				t.Errorf("vm.started error events: %+v, want none", evs)
			}
		})
	}
}

// m-5: the VNC proxy read the console's port and password on the daemon's
// connection, unbounded. They are read off it now, within the live-state
// wait; a console libvirt does not answer for is Unavailable at once.
//
// Mutation: the proxy's port read on s.virt, unbounded: it does not return:
// red.
func TestProxyVNC_AConsoleLibvirtDoesNotAnswerIsUnavailable(t *testing.T) {
	s, f := vncLabServer(t)
	release := f.HangCall(libvirtfake.CallVNCPort, "ok")
	t.Cleanup(release)
	err := within(t, 5*time.Second, "opening the VNC console of ok", func() error {
		ctx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs("x-vm-name", "ok"))
		ts := &transportStream{ctx: ctx, transport: make(chan struct{})}
		return s.ProxyVNC(&grpc.GenericServerStream[pb.VNCData, pb.VNCData]{ServerStream: ts})
	})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "has not answered") {
		t.Fatalf("ProxyVNC: %v, want Unavailable saying libvirt has not answered", err)
	}
}

// slowDomains is a host of n healthy domains each of whose state reads
// takes delay: slow, never hung.
func slowDomains(t *testing.T, n int) (*Server, *libvirtfake.Fake) {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("vm%02d", i)
	}
	s, f := liveStateServer(t, names...)
	s.liveStateWait = 100 * time.Millisecond
	return s, f
}

// Re-review n-1: the inventory's bound was fixed (three live-state waits), so a
// host whose many healthy domains take longer than that to read read
// incomplete on every call: admission refused new workloads on it, its
// capacity was unknown and dual-run coverage paged. A caller now waits as long
// as the inventory makes progress — each call answered within the live-state
// wait — and a slow but healthy host completes.
//
// Mutation: the wait measured from the flight's start, not its last answer
// (a fixed bound): the slow host reads incomplete: red.
func TestRuntimeInventory_ASlowButHealthyHostCompletes(t *testing.T) {
	s, f := slowDomains(t, 25)
	s.liveStateWait = 150 * time.Millisecond // stall 150 ms (reads 40 ms: 3.75x), cap 3 s
	clock := newInvTestClock(s)
	// 25 x 40 ms = 1 s: past any bound fixed from the flight's start. The
	// flight is held at vm10, 400 ms in on its clock, until the caller has
	// looked at it there: the flight reads no clock while held, so each read
	// is the caller's, and a look reads it twice (the stall, the cap).
	steppedSequence(f, clock, 40*time.Millisecond, func(n string) {
		if n != "vm10" {
			return
		}
		base := clock.Reads()
		for deadline := time.Now().Add(10 * time.Second); clock.Reads() < base+2 && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
	})
	inv := within(t, 10*time.Second, "an inventory of a slow host", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	if !inv.Complete || len(inv.Workloads) != 25 {
		t.Fatalf("slow host's inventory: complete %v, %d workloads, errors %v; want complete with 25",
			inv.Complete, len(inv.Workloads), inv.Errors)
	}
}

// waitFlightDone waits for the inventory's single flight to finish.
func waitFlightDone(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.invFlights.mu.Lock()
		cur := s.invFlights.cur
		s.invFlights.mu.Unlock()
		if cur == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the inventory's flight did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A flight that stalls on one domain after its list answered (a read libvirt
// leaves unanswered) is no answer: a hung domain is unknown, never filled in
// from an earlier inventory, even with a complete one taken just before.
//
// Mutation: no stall check (callers wait for the cap): the inventory does
// not return within the test's bound: red.
func TestRuntimeInventory_AStalledReadIsNoAnswer(t *testing.T) {
	s, f := liveStateServer(t, "ok", "st")
	s.liveStateWait = 100 * time.Millisecond
	if inv := s.collectRuntimeInventory(context.Background()); !inv.Complete {
		t.Fatalf("the first inventory: incomplete: %v", inv.Errors)
	}
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	f.FailDomainState = func(n string) error {
		if n == "st" {
			<-hang
		}
		return nil
	}
	inv := within(t, 5*time.Second, "an inventory stalled on st", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	if inv.Complete {
		t.Fatalf("an inventory stalled on st read complete: %+v", inv.Workloads)
	}
}

// invTestClock is the inventory's clock in a test (Server.invClock): it
// moves only when the test says time passed, so a read "takes" its step
// however fast or slow this host runs it. On the real clock these tests read
// "stalled" whenever the host paused a goroutine longer than the stall (150
// ms) between two reads, as a host at a load of 300 did, and "past the cap"
// without the flight having been slow.
type invTestClock struct {
	mu    sync.Mutex
	now   time.Time
	reads int // how many times Now was called
}

func newInvTestClock(s *Server) *invTestClock {
	c := &invTestClock{now: time.Unix(1_000_000_000, 0)}
	s.invClock = c.Now
	return c
}

func (c *invTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	return c.now
}

// Reads is how many times Now has been called.
func (c *invTestClock) Reads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func (c *invTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// steppedSequence makes every state read of the fake take step on clock,
// with hook called first for each domain (nil: none). A hook that blocks
// holds the flight with the clock where it is: not answering, but not
// stalled either until the test advances the clock.
func steppedSequence(f *libvirtfake.Fake, clock *invTestClock, step time.Duration, hook func(string)) {
	f.FailDomainState = func(n string) error {
		if hook != nil {
			hook(n)
		}
		clock.Advance(step)
		return nil
	}
}

// slowSequence makes every state read of the fake take delay, with hook
// called first for each domain (nil: none).
func slowSequence(f *libvirtfake.Fake, delay time.Duration, hook func(string)) {
	f.FailDomainState = func(n string) error {
		if hook != nil {
			hook(n)
		}
		time.Sleep(delay)
		return nil
	}
}

// pastTheCapAt has every state read take 50 ms on clock and holds the flight
// at domain at, past the 3 s cap, so a caller is answered while it is past
// its cap and still making progress, never after it finished. The returned
// func lets the flight go and waits for it to end.
func pastTheCapAt(t *testing.T, f *libvirtfake.Fake, clock *invTestClock, at string) func() {
	t.Helper()
	hold := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(hold) }) }
	t.Cleanup(release)
	steppedSequence(f, clock, 50*time.Millisecond, func(n string) {
		if n == at {
			<-hold
		}
	})
	return release
}

// Re-review 2, C-1: past the inventory's cap, the domains not yet read were
// filled in from the last complete inventory and the whole reported
// complete. vm69, shut off when that inventory was taken and running since,
// read defined_stopped: not a disk holder, in a snapshot not partial — a
// running copy the dual-run detector cannot see. Past the cap the inventory
// is incomplete now, and never says a domain it has not read holds no disks.
//
// Mutation: the list-and-cache answer back past the cap: vm69 reads a
// complete non-holder: red.
func TestRuntimeInventory_ADomainStartedSinceNeverReadsAsNotHoldingItsDisks(t *testing.T) {
	s, f := slowDomains(t, 70)
	s.liveStateWait = 150 * time.Millisecond // stall 150 ms, cap 3 s
	clock := newInvTestClock(s)
	_ = f.DestroyDomain("vm69")
	if inv := s.collectRuntimeInventory(context.Background()); !inv.Complete {
		t.Fatalf("the first inventory: incomplete: %v", inv.Errors)
	}
	if err := f.StartDomain("vm69"); err != nil {
		t.Fatal(err)
	}
	// 50 ms a read (3x under the stall): vm62 is reached at 3.1 s, past the
	// cap, and held there until the caller has its answer.
	pastCap := pastTheCapAt(t, f, clock, "vm62")
	inv := within(t, 15*time.Second, "an inventory past its cap", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	pastCap()
	snap := snapshotFromInventory(inv)
	holds := false
	for _, n := range snap.diskHolderVMs {
		holds = holds || n == "vm69"
	}
	if !snap.partial && !holds {
		t.Fatalf("vm69, running, reads as not holding its disks in a complete inventory: %+v", inv.Workloads)
	}
	if inv.Complete || !strings.Contains(strings.Join(inv.Errors, ";"), "past its cap") {
		t.Errorf("past the cap: complete %v, errors %v; want incomplete saying so", inv.Complete, inv.Errors)
	}
	waitFlightDone(t, s)
}

// C-1, settle's side: settle stops a source's live copy only when the
// destination's own runtime says the VM runs there (health/settle.go,
// destRunsVia), "the last line before stopping what may otherwise be the
// only copy". vm69 ran on the destination when its last complete inventory
// was taken and has stopped since: past the cap it read running from that
// inventory, and the source would be stopped with no copy running. It reads
// unknown now.
//
// Mutation: the list-and-cache answer back past the cap: vm69 reads running:
// red.
func TestRuntimeInventory_ADestinationStoppedSinceNeverReadsRunning(t *testing.T) {
	s, f := slowDomains(t, 70)
	s.liveStateWait = 150 * time.Millisecond
	clock := newInvTestClock(s)
	if inv := s.collectRuntimeInventory(context.Background()); !inv.Complete {
		t.Fatalf("the first inventory: incomplete: %v", inv.Errors)
	}
	_ = f.DestroyDomain("vm69")                  // shut off, still defined: still listed
	pastCap := pastTheCapAt(t, f, clock, "vm62") // 50 ms a read: past the 3 s cap
	inv := within(t, 15*time.Second, "an inventory past its cap", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	pastCap()
	got := runtimeStateIn(inventoryFromProto(inventoryToProto(inv)), corrosion.WorkloadVM, "vm69")
	if got == health.RuntimeRunning {
		t.Fatalf("vm69, stopped on the destination, reads %s to a peer's settle", got)
	}
	waitFlightDone(t, s)
}

// Re-review 2, I-2: the inventory's wait ignored its caller's context, so a
// Ping's readiness probe (10 s), a peer's RPC deadline or an admission waited
// as long as a slow host kept answering, up to the cap. A caller now stops
// waiting when its context is done: the inventory is incomplete for it, and
// the flight goes on for the others.
//
// Mutation: no ctx in the wait: the caller waits for the cap: red.
func TestRuntimeInventory_ACallerStopsWaitingWhenItsContextIsDone(t *testing.T) {
	s, f := slowDomains(t, 30)
	s.liveStateWait = 300 * time.Millisecond // stall 300 ms, cap 6 s
	clock := newInvTestClock(s)
	// The flight makes progress, 100 ms a read, and is held at vm05: neither
	// stalled nor past its cap on its clock, so only the caller's context can
	// end the wait.
	hold := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(hold) }) }
	t.Cleanup(release)
	steppedSequence(f, clock, 100*time.Millisecond, func(n string) {
		if n == "vm05" {
			<-hold
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	inv := within(t, 10*time.Second, "an inventory whose caller's context is done", func() runtimeInventory {
		return s.collectRuntimeInventory(ctx)
	})
	release()
	if inv.Complete || !strings.Contains(strings.Join(inv.Errors, ";"), "stopped waiting") {
		t.Errorf("complete %v, errors %v; want incomplete saying its caller stopped waiting", inv.Complete, inv.Errors)
	}
	waitFlightDone(t, s)
}

// I-2, admission: localInventoryCached held invCacheMu across the collect, so
// every concurrent create, start, resize or promote queued behind one slow
// inventory. The lock is not held across it now.
//
// Mutation: the collect under invCacheMu: the lock is held meanwhile: red.
func TestLocalInventoryCached_DoesNotHoldItsLockAcrossTheCollect(t *testing.T) {
	s, f := slowDomains(t, 10)
	s.liveStateWait = 300 * time.Millisecond
	slowSequence(f, 100*time.Millisecond, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.localInventoryCached(context.Background())
	}()
	time.Sleep(300 * time.Millisecond)
	if s.invCacheMu.TryLock() {
		s.invCacheMu.Unlock()
	} else {
		t.Error("invCacheMu is held while the inventory is collected")
	}
	<-done
}

// M-1: a caller that finds the flight both past its cap and stalled is told
// it stalled — a domain libvirt does not answer for — not merely that it was
// slow. Swapping the two checks goes red.
func TestRuntimeInventory_PastTheCapAndStalledSaysStalled(t *testing.T) {
	s, f := slowDomains(t, 70)
	s.liveStateWait = 150 * time.Millisecond // stall 150 ms, cap 3 s
	clock := newInvTestClock(s)
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	atHang := make(chan struct{})
	steppedSequence(f, clock, 50*time.Millisecond, func(n string) {
		if n == "vm65" { // reached at 3.25 s: past the cap
			close(atHang)
			<-hang
		}
	})
	_ = s.collectRuntimeInventory(context.Background()) // answered at the cap
	<-atHang
	clock.Advance(750 * time.Millisecond) // 4 s in: vm65 unanswered for 750 ms
	inv := within(t, 5*time.Second, "an inventory past its cap and stalled", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	if inv.Complete || !strings.Contains(strings.Join(inv.Errors, ";"), "has not answered") {
		t.Fatalf("past the cap and stalled: complete %v, errors %v; want incomplete saying libvirt has not answered", inv.Complete, inv.Errors)
	}
}
