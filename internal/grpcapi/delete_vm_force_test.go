package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

func seedForceVM(t *testing.T, s *Server, name string) *libvirtfake.Fake {
	t.Helper()
	seedNICVM(t, s, name, "running")
	fk := s.virt.(*libvirtfake.Fake)
	fk.SetState(name, libvirtfake.StateRunning)
	return fk
}

func assertStillRunning(t *testing.T, s *Server, fk *libvirtfake.Fake, name string) {
	t.Helper()
	if active, _ := fk.DomainIsActive(name); !active {
		t.Errorf("the refused delete powered %q off", name)
	}
	vm, _ := corrosion.GetVM(adminCtx(), s.db, name)
	if vm == nil {
		t.Fatalf("the refused delete removed %q", name)
	}
	if vm.State != "running" {
		t.Errorf("row state = %q after a refused delete, want running", vm.State)
	}
}

// F5: `lv rm --force` stopped the VM before DeleteVM looked at the operation
// barrier, so a refused delete left the VM powered off. The stop now happens
// inside the delete, after every refusal.
func TestDeleteVM_ForceRefusedByTheBarrierLeavesTheVMRunning(t *testing.T) {
	s := hotplugDiskServer(t)
	fk := seedForceVM(t, s, "vm1")
	if err := s.db.Execute(adminCtx(), `UPDATE vms SET active_operation_id = 'op-1' WHERE name = 'vm1'`); err != nil {
		t.Fatalf("set barrier: %v", err)
	}

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteVM err = %v, want FailedPrecondition from the barrier", err)
	}
	assertStillRunning(t, s, fk, "vm1")
}

// Every refusal before the stop, not only the barrier.
func TestDeleteVM_ForceRefusedByAnUnreadableCloneLookupLeavesTheVMRunning(t *testing.T) {
	s := hotplugDiskServer(t)
	fk := seedForceVM(t, s, "vm1")
	if err := s.db.Execute(adminCtx(), `DROP TABLE vm_disks`); err != nil {
		t.Fatalf("DROP TABLE vm_disks: %v", err)
	}

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true})
	if err == nil {
		t.Fatal("DeleteVM proceeded with an unreadable vm_disks")
	}
	assertStillRunning(t, s, fk, "vm1")
}

func TestDeleteVM_ForceRefusedByABoundDeleteLeavesTheVMRunning(t *testing.T) {
	s := hotplugDiskServer(t)
	fk := seedForceVM(t, s, "vm1")

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true, ExpectedStack: "some-other-stack"})
	if err == nil {
		t.Fatal("a delete bound to a stack the VM is not in was accepted")
	}
	assertStillRunning(t, s, fk, "vm1")
}

// A successful forced delete still goes through the stop path: the operator-stop
// event the separate StopVM used to record is kept.
func TestDeleteVM_ForceDeletesARunningVMThroughTheStopPath(t *testing.T) {
	s := hotplugDiskServer(t)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	seedForceVM(t, s, "vm1")

	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("DeleteVM force: %v", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "vm1"); vm != nil {
		t.Fatal("the forced delete left the VM row")
	}
	evs, err := corrosion.ListVMEvents(adminCtx(), s.db, "vm1", 50, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "vm.stopped" {
			found = true
		}
	}
	if !found {
		t.Errorf("no vm.stopped event from the forced delete: %+v", evs)
	}
}

// I4: a forced stop that fails AFTER the domain was destroyed (here the pre-latch
// PCI release) carries on as main did: the domain is down, so the failure is
// recorded as stopped/operator-stop, not left as a "running" row with a message
// claiming nothing happened.
func TestDeleteVM_ForceStopFailingAfterTheDestroyRecordsTheStop(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fk := seedForceVM(t, s, "vm1")
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatal(err)
	}
	fs.setBound(addr)
	recordVFIOBind(t, s, addr)
	fs.setFailUnbind(addr)

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1", Force: true})
	if err == nil {
		t.Fatal("the delete over an unreleasable device must fail")
	}
	if active, _ := fk.DomainIsActive("vm1"); active {
		t.Fatal("precondition: the forced stop destroyed the domain")
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	if vm == nil {
		t.Fatal("the failed delete removed the row")
	}
	if vm.State != "stopped" {
		t.Errorf("row state = %q after the domain was destroyed, want stopped (operator-stop)", vm.State)
	}
	if strings.Contains(status.Convert(err).Message(), "nothing was removed") {
		t.Errorf("message claims nothing happened although the domain was destroyed: %v", err)
	}
}

// forwardSpy is the owner a delete is forwarded to.
type forwardSpy struct {
	pb.LiteVirtClient
	deleteForce bool
	calls       []string
	deleteReqs  []*pb.DeleteVMRequest
}

func (f *forwardSpy) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{DeleteForce: f.deleteForce}, nil
}
func (f *forwardSpy) StopVM(_ context.Context, r *pb.StopVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	f.calls = append(f.calls, "stop")
	if !r.Force {
		return nil, status.Error(codes.Internal, "stop must be forced")
	}
	return &pb.VM{}, nil
}
func (f *forwardSpy) DeleteVM(_ context.Context, r *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.calls = append(f.calls, "delete")
	f.deleteReqs = append(f.deleteReqs, r)
	return &emptypb.Empty{}, nil
}

func forwardForce(t *testing.T, deleteForce bool) *forwardSpy {
	t.Helper()
	s := hotplugDiskServer(t)
	insertTestVM(t, adminCtx(), s.db, "remote", "other-host", "running")
	spy := &forwardSpy{deleteForce: deleteForce}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return spy, func() {}, nil }
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "remote", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	return spy
}

// I3: an owner that does not advertise delete_force ignores force, so the
// forward keeps main's flow for it: StopVM{force} first, then a plain delete.
func TestDeleteVM_ForceForwardedToAnOwnerThatIgnoresItStopsFirst(t *testing.T) {
	spy := forwardForce(t, false)
	if len(spy.calls) != 2 || spy.calls[0] != "stop" || spy.calls[1] != "delete" {
		t.Fatalf("calls = %v, want [stop delete]", spy.calls)
	}
	if spy.deleteReqs[0].Force {
		t.Error("force was forwarded to an owner that does not honour it")
	}
}

func TestDeleteVM_ForceForwardedToAnOwnerThatHonoursItIsNotStoppedFirst(t *testing.T) {
	spy := forwardForce(t, true)
	if len(spy.calls) != 1 || spy.calls[0] != "delete" || !spy.deleteReqs[0].Force {
		t.Fatalf("calls = %v force=%v, want one delete with force", spy.calls, spy.deleteReqs[0].Force)
	}
}
