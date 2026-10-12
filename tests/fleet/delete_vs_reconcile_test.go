package fleet

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Lab 2 run c713, N-2: the reconciler restarted a VM whose delete was in
// progress. DeleteVM destroys and undefines the domain BEFORE it tombstones
// the row, and the row says "running" the whole time. A reconcile pass in
// that window reads "running here, no domain" — a crashed guest — and its
// self-heal defines and starts the VM again. The delete then tombstones the
// row over a running domain nothing names: on the lab, icr4-1 ran for 25
// minutes, visible only to the capacity evaluator.
//
// The reconciler's start path is serialised by the per-VM start lease, and
// the delete took none, so the two never excluded each other.

// The interleaving, made deterministic: a reconcile pass runs inside the
// delete, right after its undefine and before its tombstone.
func TestFleet_DeleteVMNotRestartedByReconcilerMidDelete(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployOneVM(t, ctx, node, client)

	rec := health.NewReconciler(node.Name, filepath.Join(c.tmpRoot, node.Name, "data"), node.DB, node.Virt)
	var once sync.Once
	ran := false
	node.Virt.OnUndefined = func(name string) {
		if name != "hb-1" {
			return
		}
		once.Do(func() {
			// The row must still be live here, or this is not the window.
			if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm == nil || vm.State != "running" {
				t.Errorf("mid-delete row = %+v, want hb-1 still running (the race window)", vm)
			}
			rec.ReconcileOnce(ctx)
			ran = true
		})
	}

	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	node.Virt.OnUndefined = nil
	if !ran {
		t.Fatal("the reconcile pass never ran inside the delete; the scenario did not reach the window")
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
		t.Fatalf("hb-1's row survived its delete: %+v", vm)
	}
	if node.Virt.DomainExists("hb-1") {
		st, _ := node.Virt.DomainState("hb-1")
		t.Fatalf("a %s domain hb-1 is left on %s after its delete: the reconciler restarted a VM being deleted",
			st, node.Name)
	}

	// Later passes, with the row gone, must not bring it back either.
	rec.ReconcileOnce(ctx)
	if node.Virt.DomainExists("hb-1") {
		t.Fatal("a reconcile pass after the delete defined hb-1 again")
	}
}

// The other order: a start the reconciler already holds the lease for. The
// delete must refuse — retryably, touching nothing — rather than tear down a
// domain that start is about to define, or tombstone the row under it.
func TestFleet_DeleteVMRefusedWhileAStartHoldsTheLease(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	disks := deployOneVM(t, ctx, node, client)

	// The reconciler's lease identity is the bare host name.
	if held, err := health.TryVMStartLease(ctx, node.DB, node.Name, "hb-1", time.Now()); err != nil || held != node.Name {
		t.Fatalf("take the reconciler's start lease: held=%q err=%v", held, err)
	}

	_, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteVM while a start holds the lease: err=%v, want FailedPrecondition", err)
	}
	vm := assertDeleteKeptHandle(t, ctx, node, disks)
	if vm.State != "running" {
		t.Errorf("hb-1 recorded %q after a refused delete, want running (nothing touched)", vm.State)
	}
	if st, _ := node.Virt.DomainState("hb-1"); st != "running" {
		t.Errorf("hb-1 domain %q after a refused delete, want running", st)
	}

	// The start is done: the delete goes through.
	health.ReleaseVMStartLease(ctx, node.DB, node.Name, "hb-1")
	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
		t.Fatalf("DeleteVM after the lease was released: %v", err)
	}
	if node.Virt.DomainExists("hb-1") {
		t.Fatal("hb-1's domain survived its delete")
	}
	// The delete gives its lease back.
	if holder, _, ok, err := health.ReadVMStartLease(ctx, node.DB, "hb-1"); err != nil || ok {
		t.Errorf("start lease after the delete: holder=%q present=%v err=%v; want none", holder, ok, err)
	}
}
