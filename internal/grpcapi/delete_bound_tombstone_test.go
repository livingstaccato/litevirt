package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Lab 2 2026-10-17, anomaly 2: compose down and the stack reconciler on
// another host delete the same members. The loser's delete is forwarded to
// the owner, which holds the winner's tombstone and answered NotFound; the
// coordinator, whose replica had not received the tombstone yet, reported
// the member as a failed deletion. A delete bound to a stack member's
// incarnation (expected_stack and expected_created_at) that finds that
// incarnation's tombstone is done: OK, not NotFound.
//
// Mutation: drop the tombstone answer in deleteVM — the bound case is
// NotFound, red.
func TestDeleteVM_ABoundDeleteOfADeletedMemberIsDone(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", StackName: "st", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	row, err := corrosion.GetVM(ctx, s.db, "web")
	if err != nil || row == nil || row.CreatedAt == "" {
		t.Fatalf("seeded row = %+v, %v", row, err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "web"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", ExpectedStack: "st", ExpectedCreatedAt: row.CreatedAt}); err != nil {
		t.Fatalf("a delete bound to the deleted member's incarnation: %v, want OK", err)
	}
	if live, _ := corrosion.GetVM(ctx, s.db, "web"); live != nil {
		t.Fatalf("the answer brought the row back: %+v", live)
	}

	// What the tombstone does not prove stays NotFound.
	notFound := []struct {
		name string
		ctx  context.Context
		req  *pb.DeleteVMRequest
	}{
		{"another incarnation", ctx, &pb.DeleteVMRequest{Name: "web", ExpectedStack: "st", ExpectedCreatedAt: "2099-01-01T00:00:00Z"}},
		{"another stack", ctx, &pb.DeleteVMRequest{Name: "web", ExpectedStack: "other", ExpectedCreatedAt: row.CreatedAt}},
		// No incarnation: a name the stored file lists with no row on the
		// coordinator. A tombstone of an older incarnation would say nothing
		// about a newer one a peer holds (the fan-out decides that).
		{"bound to the stack only", ctx, &pb.DeleteVMRequest{Name: "web", ExpectedStack: "st"}},
		{"unbound (lv rm)", ctx, &pb.DeleteVMRequest{Name: "web"}},
		{"a peer-search probe", metadata.NewIncomingContext(ctx, metadata.Pairs("x-lv-delete-local-only", "1")),
			&pb.DeleteVMRequest{Name: "web", ExpectedStack: "st", ExpectedCreatedAt: row.CreatedAt}},
		{"no row at all", ctx, &pb.DeleteVMRequest{Name: "never", ExpectedStack: "st", ExpectedCreatedAt: row.CreatedAt}},
	}
	for _, tc := range notFound {
		if _, err := s.DeleteVM(tc.ctx, tc.req); status.Code(err) != codes.NotFound {
			t.Errorf("%s: err = %v, want NotFound", tc.name, err)
		}
	}
}

// The answer is still the delete's: a caller with no grant on the VM's path
// is refused as on a live row, not told the VM is gone.
//
// Mutation: drop the permission check on the tombstone answer — red.
func TestDeleteVM_ABoundDeleteOfADeletedMemberChecksThePermission(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", StackName: "st", HostName: "test-host", State: "stopped", Project: "p1", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	row, _ := corrosion.GetVM(ctx, s.db, "web")
	if err := corrosion.DeleteVM(ctx, s.db, "web"); err != nil {
		t.Fatal(err)
	}
	// An operator whose token is scoped to another project passes the
	// pre-check and has no grant on the VM's path.
	other := context.WithValue(userCtx("op", "operator"), ctxKeyScopePaths, []string{"/projects/p2"})
	if _, err := s.DeleteVM(other, &pb.DeleteVMRequest{Name: "web", ExpectedStack: "st", ExpectedCreatedAt: row.CreatedAt}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an out-of-scope operator's bound delete of a deleted member: %v, want PermissionDenied", err)
	}
}
