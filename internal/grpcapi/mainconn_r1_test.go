package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
// second takes a wait: red. DumpXML or DomainState asked on s.virt: calls
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

	inv := within(t, 5*time.Second, "an inventory while libvirt hangs on st", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	if inv.Complete || !strings.Contains(strings.Join(inv.Errors, ";"), "has not answered") {
		t.Fatalf("inventory: complete %v, errors %v; want incomplete saying libvirt has not answered", inv.Complete, inv.Errors)
	}
	if snap := snapshotFromInventory(inv); !snap.partial {
		t.Error("the dual-run snapshot of an incomplete inventory is not partial")
	}
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		if inv := s.collectRuntimeInventory(context.Background()); inv.Complete {
			t.Fatal("a later inventory read complete while libvirt still hangs on st")
		}
	}
	if took := time.Since(t0); took >= s.inventoryWait() {
		t.Errorf("three later inventories took %v: they waited again instead of answering at once", took)
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
	f.FailDomainState = func(string) error { time.Sleep(40 * time.Millisecond); return nil }
	inv := within(t, 10*time.Second, "an inventory of a slow host", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	if !inv.Complete || len(inv.Workloads) != 25 {
		t.Fatalf("slow host's inventory: complete %v, %d workloads, errors %v; want complete with 25",
			inv.Complete, len(inv.Workloads), inv.Errors)
	}
}

// Past the inventory's cap, a flight still making progress is answered from
// its own fresh domain list, each domain not yet read filled from the last
// complete inventory: complete, and absence still this flight's own.
//
// Mutations: no cache (incomplete past the cap): red. The cached list used
// instead of the flight's (vm00, undefined since, reads present): red.
func TestRuntimeInventory_PastTheCapAProgressingInventoryIsAnsweredFromItsListAndTheCache(t *testing.T) {
	s, f := slowDomains(t, 30)
	s.liveStateWait = 200 * time.Millisecond // cap 4 s
	if inv := s.collectRuntimeInventory(context.Background()); !inv.Complete {
		t.Fatalf("the first inventory: incomplete: %v", inv.Errors)
	}
	_ = f.DestroyDomain("vm00")
	if err := f.UndefineDomain("vm00", false); err != nil {
		t.Fatal(err)
	}
	f.FailDomainState = func(string) error { time.Sleep(150 * time.Millisecond); return nil }
	inv := within(t, 15*time.Second, "an inventory past its cap", func() runtimeInventory {
		return s.collectRuntimeInventory(context.Background())
	})
	if !inv.Complete || len(inv.Workloads) != 29 {
		t.Fatalf("past the cap: complete %v, %d workloads, errors %v; want complete with 29", inv.Complete, len(inv.Workloads), inv.Errors)
	}
	if _, ok := inv.find(corrosion.WorkloadVM, "vm00"); ok {
		t.Error("vm00, undefined since the cached inventory, is listed")
	}
	waitFlightDone(t, s)
}

// The answer past the cap: a listed domain neither read nor cached is no
// answer, as is a cache older than its TTL or no list yet; a domain found
// undefined is left out.
//
// Mutations: an unread, uncached domain left out instead: complete: red. The
// TTL not checked: an old cache answers: red.
func TestRuntimeInventory_TheAnswerPastTheCapNeedsEveryListedDomain(t *testing.T) {
	s := testServerWithLocks(t)
	vm := func(n string) runtimeWorkload { return runtimeWorkload{Kind: corrosion.WorkloadVM, Name: n} }
	flight := func(listed ...string) *inventoryFlight {
		return &inventoryFlight{listed: listed, read: map[string]runtimeWorkload{"a": vm("a")}, gone: map[string]bool{"g": true}}
	}
	s.invFlights.last = map[string]runtimeWorkload{"b": vm("b")}
	s.invFlights.lastAt = time.Now()
	if got, err := s.inventoryFromListAndCache(flight("a", "b", "g")); err != nil || len(got.workloads) != 2 {
		t.Errorf("a read, b cached, g gone: %+v %v, want a and b", got.workloads, err)
	}
	if _, err := s.inventoryFromListAndCache(flight("a", "b", "c")); err == nil {
		t.Error("c neither read nor cached: answered")
	}
	if _, err := s.inventoryFromListAndCache(&inventoryFlight{read: map[string]runtimeWorkload{}}); err == nil {
		t.Error("no list yet: answered")
	}
	s.invFlights.lastAt = time.Now().Add(-2 * s.inventoryCacheTTL())
	if _, err := s.inventoryFromListAndCache(flight("a", "b")); err == nil {
		t.Error("a cache older than its TTL: answered")
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
// leaves unanswered) is no answer, even with a complete inventory cached and
// the list in hand: a hung domain is unknown, never filled in from before.
//
// Mutation: a stalled flight answered from its list and the cache: complete:
// red.
func TestRuntimeInventory_AStalledReadIsNotFilledFromTheCache(t *testing.T) {
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
