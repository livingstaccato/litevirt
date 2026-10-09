package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func bindingServer(t *testing.T) (*Server, context.Context) {
	t.Helper()
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	return s, ctx
}

// A delete bound to a stack deletes only a VM whose row records that stack:
// every host the delete reaches (the owner included) checks its own row.
func TestDeleteVM_BoundToAStackTheVMIsNotInIsRefused(t *testing.T) {
	s, ctx := bindingServer(t)
	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", ExpectedStack: "rc5iso"})
	if status.Code(err) != codes.FailedPrecondition || !isDeleteBindingMismatch(err) {
		t.Fatalf("DeleteVM bound to another stack = %v, want a binding mismatch", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("the VM was deleted")
	}
}

// A delete bound to an incarnation deletes only that one.
func TestDeleteVM_BoundToAnotherIncarnationIsRefused(t *testing.T) {
	s, ctx := bindingServer(t)
	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", ExpectedCreatedAt: "2001-01-01T00:00:00Z"})
	if status.Code(err) != codes.FailedPrecondition || !isDeleteBindingMismatch(err) {
		t.Fatalf("DeleteVM bound to another incarnation = %v, want a binding mismatch", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("the VM was deleted")
	}
}

// Bound to what it is, the delete goes ahead.
func TestDeleteVM_BoundToItsOwnIncarnationDeletes(t *testing.T) {
	s, ctx := bindingServer(t)
	row, _ := corrosion.GetVM(ctx, s.db, "web")
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", ExpectedCreatedAt: row.CreatedAt}); err != nil {
		t.Fatalf("DeleteVM bound to its own incarnation: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm != nil {
		t.Fatal("the VM was not deleted")
	}
}

// DeleteStack sends each listed member's delete bound to the stack and the
// member's incarnation, so the owner (after any forward) deletes that one
// only. A binding mismatch reported back is a kept VM, never a failure.
func TestDeleteVMWithFanout_SendsTheBinding(t *testing.T) {
	s, ctx := bindingServer(t)
	// A member of stack "st" whose listed incarnation is not the live row.
	err := s.deleteVMWithFanout(ctx, stackMember{Name: "web", Stack: "", CreatedAt: "2001-01-01T00:00:00Z"}, false)
	if err == nil {
		t.Fatal("a delete bound to another incarnation went ahead")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("the VM was deleted")
	}
}
