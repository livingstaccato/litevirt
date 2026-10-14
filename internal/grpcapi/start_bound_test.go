package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// stuckStart is a stopped VM "web" whose libvirt start does not answer until
// release is closed (or answers answer's error then). calls counts the
// starts libvirt was asked for.
type stuckStart struct {
	s       *Server
	release chan struct{}
	answer  atomic.Value // error, or nil
	calls   atomic.Int32
}

func newStuckStart(t *testing.T) *stuckStart {
	t.Helper()
	s := testServerWithLocks(t)
	f := libvirtfake.New()
	s.virt = f
	if err := f.DefineDomain("<domain><name>web</name></domain>"); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped", StateDetail: "operator-stop", Spec: string(spec)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.startDomainWait = 300 * time.Millisecond
	st := &stuckStart{s: s, release: make(chan struct{})}
	f.FailStartDomain = func(string) error {
		st.calls.Add(1)
		<-st.release
		if err, _ := st.answer.Load().(error); err != nil {
			return err
		}
		return nil
	}
	t.Cleanup(func() {
		select {
		case <-st.release:
		default:
			close(st.release)
		}
	})
	return st
}

func (st *stuckStart) row(t *testing.T) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), st.s.db, "web")
	if err != nil || vm == nil {
		t.Fatalf("web: %v", err)
	}
	return vm
}

// waitLockFree waits for web's VM lock to be free, and takes it back off.
func (st *stuckStart) waitLockFree(t *testing.T, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if unlock, ok := st.s.tryLockVM("web"); ok {
			unlock()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: web's lock is still held", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func wantStartInFlight(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "has not answered") ||
		!strings.Contains(err.Error(), "lv inspect web") {
		t.Fatalf("%s = %v, want Unavailable saying libvirt has not answered and naming lv inspect web", what, err)
	}
}

// Batch 2a, "Lock scope": StartDomain, a libvirt RPC, was unbounded under the
// VM lock, so `lv start` did not return while libvirt did not answer. The
// start now answers after a bound, saying it goes on. It is not given up: the
// VM lock stays held until libvirt answers, a second start does not ask
// libvirt again, and libvirt's late answer is recorded as the start's
// outcome before the lock is let go.
//
// Mutations: no bound (StartDomain waited for in place) — the start does not
// return: red. The lock let go at the bound — taken while libvirt has not
// answered: red. A second start queues behind the first — it does not
// return: red. The late answer not recorded — the row is never running: red.
func TestStartVM_AStartLibvirtDoesNotAnswerReturnsAndKeepsTheVMHeld(t *testing.T) {
	st := newStuckStart(t)
	err := within(t, 5*time.Second, "a start libvirt does not answer", func() error {
		_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
		return err
	})
	wantStartInFlight(t, "start", err)
	if unlock, ok := st.s.tryLockVM("web"); ok {
		unlock()
		t.Fatal("web's lock was let go while libvirt has not answered its start")
	}
	if vm := st.row(t); vm.State != "stopped" {
		t.Fatalf("web's row while the start is in flight: %s", vm.State)
	}

	// A second start answers the same, at once, and asks libvirt nothing.
	t0 := time.Now()
	err = within(t, 5*time.Second, "a second start while the first is in flight", func() error {
		_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
		return err
	})
	wantStartInFlight(t, "second start", err)
	if took := time.Since(t0); took > 2*time.Second {
		t.Errorf("the second start took %v", took)
	}
	if n := st.calls.Load(); n != 1 {
		t.Fatalf("libvirt was asked to start web %d times, want 1", n)
	}

	close(st.release)
	st.waitLockFree(t, "after libvirt answered")
	if vm := st.row(t); vm.State != "running" {
		t.Fatalf("web after libvirt's late answer: %s, want running", vm.State)
	}
	if _, ok := st.s.startFlightOf("web"); ok {
		t.Error("the start is still registered in flight after it settled")
	}
}

// A start libvirt answers late with a failure is recorded as a failed start
// (an event, the row left stopped) and lets the lock go.
//
// Mutation: the late failure not recorded — no event: red.
func TestStartVM_ALateFailureIsRecorded(t *testing.T) {
	st := newStuckStart(t)
	st.answer.Store(errors.New("qemu: cannot open disk"))
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	close(st.release)
	st.waitLockFree(t, "after libvirt's late failure")
	if vm := st.row(t); vm.State != "stopped" {
		t.Fatalf("web after a late failure: %s, want stopped", vm.State)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), st.s.db, "web", 50, "")
	found := false
	for _, e := range evs {
		if e.Type == "vm.started" && e.Result == "error" && strings.Contains(e.Detail, "cannot open disk") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no failed-start event for the late failure: %+v", evs)
	}
}

// A start libvirt answers within the bound is the start it always was.
func TestStartVM_AStartWithinTheBoundIsUnchanged(t *testing.T) {
	st := newStuckStart(t)
	close(st.release)
	vm, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if vm.GetState() != pb.VMState_VM_RUNNING || st.row(t).State != "running" {
		t.Fatalf("start answered %v, row %s; want running", vm.GetState(), st.row(t).State)
	}
	st.waitLockFree(t, "after the start")
}
