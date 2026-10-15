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

// vncLabServer is lab 2's node-3 (339a79f4, B2 concern 1): ok runs with a VNC
// console password, st is defined and running too, both with running rows,
// and the host has an address for vnc_address.
func vncLabServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, f := liveStateServer(t, "st")
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	f.LandMigrated("<domain><name>ok</name><devices><graphics type='vnc' port='5901' passwd='s3cret'/></devices></domain>")
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "ok", HostName: s.hostName, State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.liveStateWait = 300 * time.Millisecond
	return s, f
}

// fillMainConn hangs st and fills the daemon's connection with calls naming
// it, as the daemon's background loops did on the lab.
func fillMainConn(t *testing.T, f *libvirtfake.Fake) {
	t.Helper()
	f.SetConnRequests(5)
	release := f.HangDomain("st")
	t.Cleanup(release)
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
}

func inspectWithin(t *testing.T, s *Server, name string) *pb.VM {
	t.Helper()
	type answer struct {
		vm  *pb.VM
		err error
	}
	got := within(t, 5*time.Second, "lv inspect "+name, func() answer {
		vm, err := s.InspectVM(adminCtx(), &pb.InspectVMRequest{Name: name})
		return answer{vm, err}
	})
	if got.err != nil {
		t.Fatalf("InspectVM %s: %v", name, got.err)
	}
	return got.vm
}

// Lab 2 (339a79f4, B2 concern 1): with libvirt hung on st and the daemon's
// connection full, `lv inspect ok` — a healthy running VM — did not answer
// in 60 s, while `lv ls` read it running: the state was read on the
// StateReader, but the VNC port and the console password of a running VM
// were read on the daemon's connection, unbounded. They are read on
// connections of their own now (the password on a read-write one: libvirt
// refuses a read-only connection the secure XML), so ok's inspect answers
// with its console.
//
// Mutations: the VNC port read on s.virt: ok's console reads unknown (the
// bound holds, the daemon's connection does not answer): red. The password
// read on s.virt: the password reads unknown: red. The password read on the
// read-only StateReader: libvirt refuses it, the password is unknown: red.
func TestInspectVM_AHealthyVMAnswersWhileLibvirtHangsOnAnother(t *testing.T) {
	s, f := vncLabServer(t)
	fillMainConn(t, f)

	vm := inspectWithin(t, s, "ok")
	if vm.GetState() != pb.VMState_VM_RUNNING {
		t.Errorf("ok: %v %q, want VM_RUNNING", vm.GetState(), vm.GetStateDetail())
	}
	if vm.GetVncAddress() != "vnc://10.0.0.1:5901" {
		t.Errorf("vnc_address %q, want vnc://10.0.0.1:5901", vm.GetVncAddress())
	}
	if !vm.GetVncPasswordRequired() || vm.GetVncUnknown() != "" {
		t.Errorf("vnc_password_required %v, vnc_unknown %q; want true and empty",
			vm.GetVncPasswordRequired(), vm.GetVncUnknown())
	}
	if n := f.MainConnCallsFor("ok"); n != 0 {
		t.Errorf("calls naming ok on the daemon's connection: %d, want 0", n)
	}
}

// A VNC read libvirt does not answer within the live-state wait is shown
// unknown, never guessed: no address (not "VNC not enabled"), and a password
// whose read did not answer is not reported as none. Once libvirt answers,
// inspect reads both again.
//
// Mutations: the VNC port read unbounded: inspect does not return: red. No
// vnc_unknown for an unanswered password read (the field left false): red.
func TestInspectVM_AVNCReadLibvirtDoesNotAnswerIsUnknown(t *testing.T) {
	s, f := vncLabServer(t)

	releasePort := f.HangCall(libvirtfake.CallVNCPort, "ok")
	t.Cleanup(releasePort)
	vm := inspectWithin(t, s, "ok")
	if vm.GetState() != pb.VMState_VM_RUNNING {
		t.Errorf("ok: %v, want VM_RUNNING (its state answered)", vm.GetState())
	}
	if vm.GetVncAddress() != "" || !strings.Contains(vm.GetVncUnknown(), "has not answered") {
		t.Errorf("port unanswered: vnc_address %q, vnc_unknown %q; want empty and saying libvirt has not answered",
			vm.GetVncAddress(), vm.GetVncUnknown())
	}
	releasePort()

	releasePw := f.HangCall(libvirtfake.CallConsolePassword, "ok")
	t.Cleanup(releasePw)
	waitLiveStateCallsDone(t, s)
	vm = inspectWithin(t, s, "ok")
	if vm.GetVncAddress() != "vnc://10.0.0.1:5901" {
		t.Errorf("password unanswered: vnc_address %q, want vnc://10.0.0.1:5901 (the port answered)", vm.GetVncAddress())
	}
	if vm.GetVncPasswordRequired() || !strings.Contains(vm.GetVncUnknown(), "password") ||
		!strings.Contains(vm.GetVncUnknown(), "has not answered") {
		t.Errorf("password unanswered: vnc_password_required %v, vnc_unknown %q; want false and saying the password is unknown",
			vm.GetVncPasswordRequired(), vm.GetVncUnknown())
	}
	releasePw()

	waitLiveStateCallsDone(t, s)
	vm = inspectWithin(t, s, "ok")
	if vm.GetVncAddress() != "vnc://10.0.0.1:5901" || !vm.GetVncPasswordRequired() || vm.GetVncUnknown() != "" {
		t.Errorf("after libvirt answered: %q %v %q, want the address, a password, nothing unknown",
			vm.GetVncAddress(), vm.GetVncPasswordRequired(), vm.GetVncUnknown())
	}
}

// waitLiveStateCallsDone waits until no bounded libvirt call is outstanding
// (a released one has returned and left the latch).
func waitLiveStateCallsDone(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.liveStateMu.Lock()
		n := len(s.liveStateCalls)
		s.liveStateMu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d bounded libvirt calls still outstanding", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
