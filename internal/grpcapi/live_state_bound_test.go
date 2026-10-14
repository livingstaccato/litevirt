package grpcapi

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// hungLiveState is a host with two local VMs, "web" and "db", both running,
// whose libvirt does not answer for web's state until release is closed.
// asked counts the state calls libvirt was asked for web.
type hungLiveState struct {
	s       *Server
	release chan struct{}
	asked   atomic.Int32
}

func newHungLiveState(t *testing.T) *hungLiveState {
	t.Helper()
	s := testServerWithLocks(t)
	f := libvirtfake.New()
	s.virt = f
	ctx := context.Background()
	for _, name := range []string{"web", "db"} {
		if err := f.DefineDomain("<domain><name>" + name + "</name></domain>"); err != nil {
			t.Fatal(err)
		}
		if err := f.StartDomain(name); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(ctx, s.db,
			corrosion.VMRecord{Name: name, HostName: s.hostName, State: "running", Spec: "{}"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	s.liveStateWait = 200 * time.Millisecond
	h := &hungLiveState{s: s, release: make(chan struct{})}
	f.FailDomainState = func(name string) error {
		if name == "web" {
			h.asked.Add(1)
			<-h.release
		}
		return nil
	}
	t.Cleanup(func() {
		select {
		case <-h.release:
		default:
			close(h.release)
		}
	})
	return h
}

func (h *hungLiveState) list(t *testing.T) map[string]*pb.VM {
	t.Helper()
	resp := within(t, 5*time.Second, "lv ls while libvirt does not answer for one VM", func() *pb.ListVMsResponse {
		resp, err := h.s.ListVMs(adminCtx(), &pb.ListVMsRequest{})
		if err != nil {
			t.Fatalf("ListVMs: %v", err)
		}
		return resp
	})
	out := map[string]*pb.VM{}
	for _, vm := range resp.GetVms() {
		out[vm.GetName()] = vm
	}
	return out
}

// Lab 2 (batch 4, 5f12ab50): `lv ls` on the host whose libvirt hung never
// returned, while every other host answered. The list now waits a bounded
// time for each local VM's live state and reports a VM libvirt has not
// answered for as unknown, saying what the record says; the others are
// listed as before. The unanswered call is not asked again while it is
// outstanding, and once it returns the list reads it again.
//
// Mutations: the unbounded liveVMState back in ListVMs — the list does not
// return: red. The latch dropped (every read asks libvirt again): red on the
// call count. The read not waiting at all: db is unknown too: red.
func TestListVMs_ALocalLibvirtThatDoesNotAnswerIsReportedUnknown(t *testing.T) {
	h := newHungLiveState(t)

	got := h.list(t)
	if web := got["web"]; web.GetState() != pb.VMState_VM_UNKNOWN ||
		!strings.Contains(web.GetStateDetail(), "libvirt on "+h.s.hostName+" has not answered") ||
		!strings.Contains(web.GetStateDetail(), "record says running") {
		t.Fatalf("web while libvirt does not answer for it: %v %q, want VM_UNKNOWN naming the host and the record", web.GetState(), web.GetStateDetail())
	}
	if db := got["db"]; db.GetState() != pb.VMState_VM_RUNNING || db.GetStateDetail() != "" {
		t.Fatalf("db, which libvirt answers for: %v %q, want VM_RUNNING", db.GetState(), db.GetStateDetail())
	}

	// A second list does not wait on web again, nor ask libvirt again.
	t0 := time.Now()
	got = h.list(t)
	if took := time.Since(t0); took >= h.s.liveStateWaitOrDefault() {
		t.Errorf("a second list waited %v on a call already waited out", took)
	}
	if got["web"].GetState() != pb.VMState_VM_UNKNOWN {
		t.Fatalf("web on the second list: %v, want VM_UNKNOWN", got["web"].GetState())
	}
	if n := h.asked.Load(); n != 1 {
		t.Fatalf("libvirt was asked for web's state %d times while it had not answered, want 1", n)
	}

	close(h.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got = h.list(t); got["web"].GetState() == pb.VMState_VM_RUNNING {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("web after libvirt answered: %v, want VM_RUNNING", got["web"].GetState())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// `lv inspect` reads the same live state, through vmToProto, and answers the
// same way.
func TestInspectVM_ALocalLibvirtThatDoesNotAnswerIsReportedUnknown(t *testing.T) {
	h := newHungLiveState(t)
	vm := within(t, 5*time.Second, "lv inspect while libvirt does not answer", func() *pb.VM {
		vm, err := h.s.InspectVM(adminCtx(), &pb.InspectVMRequest{Name: "web"})
		if err != nil {
			t.Fatalf("InspectVM: %v", err)
		}
		return vm
	})
	if vm.GetState() != pb.VMState_VM_UNKNOWN || !strings.Contains(vm.GetStateDetail(), "has not answered") {
		t.Fatalf("inspect web: %v %q, want VM_UNKNOWN saying libvirt has not answered", vm.GetState(), vm.GetStateDetail())
	}
}
