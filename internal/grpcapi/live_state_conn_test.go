package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Lab 2 (03fe9868, check B2): with libvirt hung on one domain (st, a start
// waiting on a dead NFS export) and the owner daemon restarted, `lv ls` on
// that host read st as unknown, which is right, but a healthy running VM on
// the same host (ok) as unknown too, while `virsh domstate ok` answered in
// 23 ms. libvirtd serves at most max_client_requests (5) requests of one
// connection at a time and stops reading it past that; the daemon's
// background loops had filled its one connection with calls naming st, so
// the read of ok was never read by libvirtd. The fake models that
// (libvirtfake/conn_model.go): st hangs, five calls naming st fill the
// daemon's connection, and a call naming ok on it does not answer.
//
// A read of a VM's live state is asked on connections of its own now
// (libvirt.StateReader), so ok reads running and only st reads unknown, and
// the list waits on st once.
//
// Mutation: liveVMState asking s.virt (the daemon's connection) again: ok
// reads VM_UNKNOWN: red.
func TestListVMs_ADomainLibvirtHangsOnDoesNotMakeAnotherUnknown(t *testing.T) {
	s := testServerWithLocks(t)
	f := libvirtfake.New()
	s.virt = f
	ctx := context.Background()
	for _, vm := range []struct {
		name, state string
	}{{"st", "stopped"}, {"ok", "running"}} {
		if err := f.DefineDomain("<domain><name>" + vm.name + "</name></domain>"); err != nil {
			t.Fatal(err)
		}
		// Both domains run: the fake reads a defined domain as "shutoff",
		// which a list shows as unknown, and the test must tell libvirt's
		// answer from no answer. A stopped row whose domain runs reads
		// stopped (readVMState).
		if err := f.StartDomain(vm.name); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(ctx, s.db,
			corrosion.VMRecord{Name: vm.name, HostName: s.hostName, State: vm.state, Spec: "{}"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	s.liveStateWait = 300 * time.Millisecond
	f.SetConnRequests(5)
	release := f.HangDomain("st")
	t.Cleanup(release)

	// The daemon's background loops: each waits on a call naming st, on the
	// daemon's connection, until the connection is full.
	for i := 0; i < 5; i++ {
		go func() { _, _ = f.DomainState("st") }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.ConnInFlight() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("the daemon's connection has %d calls in flight, want 5", f.ConnInFlight())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The premise: the daemon's own connection answers nothing for ok now.
	okOnMain := make(chan struct{})
	go func() {
		_, _ = f.DomainState("ok")
		close(okOnMain)
	}()
	select {
	case <-okOnMain:
		t.Fatal("the fake's full connection answered for ok: the model does not hold")
	case <-time.After(100 * time.Millisecond):
	}

	type answer struct {
		resp *pb.ListVMsResponse
		err  error
	}
	t0 := time.Now()
	got := within(t, 5*time.Second, "lv ls while libvirt hangs on one domain", func() answer {
		resp, err := s.ListVMs(adminCtx(), &pb.ListVMsRequest{})
		return answer{resp, err}
	})
	took := time.Since(t0)
	if got.err != nil {
		t.Fatalf("ListVMs: %v", got.err)
	}
	vms := map[string]*pb.VM{}
	for _, vm := range got.resp.GetVms() {
		vms[vm.GetName()] = vm
	}
	if ok := vms["ok"]; ok.GetState() != pb.VMState_VM_RUNNING || ok.GetStateDetail() != "" {
		t.Errorf("ok, which libvirt answers for on another connection: %v %q, want VM_RUNNING", ok.GetState(), ok.GetStateDetail())
	}
	if st := vms["st"]; st.GetState() != pb.VMState_VM_UNKNOWN ||
		!strings.Contains(st.GetStateDetail(), "has not answered") ||
		!strings.Contains(st.GetStateDetail(), "record says stopped") {
		t.Errorf("st, which libvirt hangs on: %v %q, want VM_UNKNOWN saying the record", st.GetState(), st.GetStateDetail())
	}
	if took >= 2*s.liveStateWait {
		t.Errorf("the list took %v, want under two waits (%v): it waits on st once and on nothing else", took, 2*s.liveStateWait)
	}

	// Once libvirt answers for st, the list reads it.
	release()
	deadline = time.Now().Add(5 * time.Second)
	for {
		resp, err := s.ListVMs(adminCtx(), &pb.ListVMsRequest{})
		if err != nil {
			t.Fatalf("ListVMs: %v", err)
		}
		states := map[string]pb.VMState{}
		for _, vm := range resp.GetVms() {
			states[vm.GetName()] = vm.GetState()
		}
		if states["st"] == pb.VMState_VM_STOPPED && states["ok"] == pb.VMState_VM_RUNNING {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after libvirt answered: %v, want st VM_STOPPED and ok VM_RUNNING", states)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// liveStateServer is a server whose local VMs are the fake domains named, each
// running with a running row.
func liveStateServer(t *testing.T, names ...string) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServerWithLocks(t)
	f := libvirtfake.New()
	s.virt = f
	for _, n := range names {
		if err := f.DefineDomain("<domain><name>" + n + "</name></domain>"); err != nil {
			t.Fatal(err)
		}
		if err := f.StartDomain(n); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(context.Background(), s.db,
			corrosion.VMRecord{Name: n, HostName: s.hostName, State: "running", Spec: "{}"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	return s, f
}

func listStates(t *testing.T, s *Server) map[string]pb.VMState {
	t.Helper()
	resp, err := s.ListVMs(adminCtx(), &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	out := map[string]pb.VMState{}
	for _, vm := range resp.GetVms() {
		out[vm.GetName()] = vm.GetState()
	}
	return out
}

// The live state is read on the reader's connections only, the paused
// domain's reason included, and libvirt's own error is an answer: none of
// them asks on the daemon's connection, which may be full.
//
// Mutations: the reason asked on s.virt: a call on the daemon's connection:
// red. The fallback taken on any error: x's error asks the daemon's
// connection: red.
func TestListVMs_LiveStateIsNotAskedOnTheDaemonsConnection(t *testing.T) {
	s, f := liveStateServer(t, "p", "x")
	f.SetPaused("p")
	f.FailDomainState = func(name string) error {
		if name == "x" {
			return golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "no domain"}
		}
		return nil
	}
	got := listStates(t, s)
	if got["p"] != pb.VMState_VM_PAUSED {
		t.Errorf("p: %v, want VM_PAUSED", got["p"])
	}
	if n := f.MainConnCalls(); n != 0 {
		t.Errorf("state calls on the daemon's connection: %d, want 0", n)
	}
}

// A reader that cannot dial (libvirtd refuses it a connection) falls back to
// the daemon's connection, as before, for the state and the paused reason.
//
// Mutations: no fallback: p reads its record (running): red. No fallback for
// the reason: p reads stopped: red.
func TestListVMs_AReaderThatCannotDialFallsBackToTheDaemonsConnection(t *testing.T) {
	s, f := liveStateServer(t, "p")
	f.SetPaused("p")
	f.SetStateDial(func() error { return errors.New("libvirtfake: dial refused") })
	got := listStates(t, s)
	if got["p"] != pb.VMState_VM_PAUSED {
		t.Errorf("p: %v, want VM_PAUSED (read on the daemon's connection)", got["p"])
	}
	if n := f.MainConnCalls(); n < 2 {
		t.Errorf("state calls on the daemon's connection: %d, want the state and the reason", n)
	}
}

// The reader answered the state, then lost its connection before the paused
// reason and could not dial another: the reason is asked on the daemon's
// connection, so a paused domain still reads paused.
//
// Mutation: no fallback for the reason: p reads stopped: red.
func TestListVMs_TheReasonFallsBackWhenTheReaderLosesItsConnection(t *testing.T) {
	s, f := liveStateServer(t, "p")
	f.SetPaused("p")
	dials := 0
	f.SetStateDial(func() error {
		dials++
		if dials > 1 {
			return errors.New("libvirtfake: dial refused")
		}
		return nil
	})
	reasons := 0
	f.FailDomainStateReason = func(string) error {
		reasons++
		if reasons == 1 {
			return errors.New("libvirtfake: connection reset by peer")
		}
		return nil
	}
	if got := listStates(t, s); got["p"] != pb.VMState_VM_PAUSED {
		t.Errorf("p: %v, want VM_PAUSED", got["p"])
	}
	if dials != 2 {
		t.Errorf("reader dials: %d, want 2 (the state, then the failed redial)", dials)
	}
}
