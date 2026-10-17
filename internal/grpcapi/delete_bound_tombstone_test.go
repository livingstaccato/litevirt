package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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
	// Audited as the live path audits a denied delete (review m-1).
	//
	// Mutation: drop the audit call on the tombstone answer — red.
	rows, err := s.db.Query(ctx, `SELECT username, detail FROM audit_log WHERE action = 'vm.delete' AND target = 'web' AND result = 'denied'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].String("username") != "op" || rows[0].String("detail") != "permission denied" {
		t.Fatalf("denied audit rows = %v, want one for op, \"permission denied\"", rows)
	}
}

// The second no-live-row site: a delete that found the row live, then waited
// for the start lease while another deleter removed the member, re-reads the
// row and finds the tombstone (review m-3).
//
// Mutation: answer NotFound at the re-read after the lease — red.
func TestDeleteVM_ABoundDeleteFindsTheTombstoneAfterTheLease(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", StackName: "st", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	row, _ := corrosion.GetVM(ctx, s.db, "web")
	if by, err := health.TryVMStartLease(ctx, s.db, "other-holder", "web", time.Now()); err != nil || by != "other-holder" {
		t.Fatalf("setup: take the start lease: %q, %v", by, err)
	}
	s.SetDeleteLeaseWaitForTest(30 * time.Second)
	// The other deleter: the row goes while this delete waits on the lease,
	// and then the lease is free.
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(600 * time.Millisecond)
		if err := corrosion.DeleteVM(ctx, s.db, "web"); err != nil {
			t.Errorf("the other deleter: %v", err)
		}
		health.ReleaseVMStartLease(ctx, s.db, "other-holder", "web")
	}()
	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", ExpectedStack: "st", ExpectedCreatedAt: row.CreatedAt})
	<-done
	if err != nil {
		t.Fatalf("a bound delete that waited on the lease while the member was deleted: %v, want OK", err)
	}
}
