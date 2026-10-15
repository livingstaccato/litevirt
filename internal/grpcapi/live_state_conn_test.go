package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

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
