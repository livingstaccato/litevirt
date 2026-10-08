package grpcapi

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The executing host takes an admin's any-file replica only when the admin
// named it (req.Replica): a replica merely passed to it — chosen for the VM,
// or relayed by a name — must be the VM's own, by its record in the replica
// area or at the pool's top level.
func TestDoPromoteLocal_AnAdminsAnyFileOnlyWhenNamed(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	stray := "anything.qcow2"
	if err := qcow2.Create(filepath.Join(f.dr, stray), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	noop := func(*pb.PromoteReplicaProgress) error { return nil }
	err := f.s.doPromoteLocal(adminCtx(), &pb.PromoteReplicaRequest{VmName: "web", NewName: "unnamed", NoLocalize: true},
		vm, &disks[0], "dr", stray, false, noop)
	if status.Code(err) != codes.NotFound {
		t.Errorf("a file the admin did not name: got %v, want NotFound", err)
	}
	if err := f.s.doPromoteLocal(adminCtx(), &pb.PromoteReplicaRequest{VmName: "web", NewName: "named", NoLocalize: true, Replica: stray},
		vm, &disks[0], "dr", stray, false, noop); err != nil {
		t.Errorf("a file the admin named: %v", err)
	}
	f.assertBIntact(t)
}

// As on main, an admin's explicit replica promotes whatever file it names —
// even one another project owns alone (here project B's replica, which A's
// VM web disk 1 could never have written). It is not refused: it is logged
// and the VM's events name the owning project. A non-admin is still refused
// (TestPromoteReplica_CannotSelectAnotherProjectsFile).
func TestPromoteReplica_AnAdminMayNameAnotherProjectsFileAndIsWarned(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	err := f.s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", Replica: bReplicaQcow, NewName: "taken", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if err != nil {
		t.Fatalf("an admin naming another project's file: %v", err)
	}
	evs, err := corrosion.ListVMEvents(ctx, f.s.db, "web", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(evs, func(e corrosion.VMEventRecord) bool {
		return e.Type == "replica.foreign" && strings.Contains(e.Detail, bReplicaQcow) && strings.Contains(e.Detail, `project "b"`)
	}) {
		t.Errorf("no event names %s as project b's: %+v", bReplicaQcow, evs)
	}
	f.assertBIntact(t)
}
