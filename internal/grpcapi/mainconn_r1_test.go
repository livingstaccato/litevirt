package grpcapi

import (
	"context"
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
// second takes a wait: red.
func TestRuntimeInventory_AListLibvirtDoesNotAnswerIsIncompleteAndOffTheDaemonsConnection(t *testing.T) {
	s, f := liveStateServer(t, "ok", "st")
	s.liveStateWait = 100 * time.Millisecond
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
