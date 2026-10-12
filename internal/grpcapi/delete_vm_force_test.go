package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
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
