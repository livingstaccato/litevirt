package health

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type recordingStackCleaner struct {
	failingStackCleaner
	vmReqs []*pb.DeleteVMRequest
}

func (c *recordingStackCleaner) DeleteVMForStackCleanup(_ context.Context, req *pb.DeleteVMRequest) (*emptypb.Empty, error) {
	c.vmReqs = append(c.vmReqs, req)
	return &emptypb.Empty{}, nil
}

// The reconciler deletes a member as the incarnation it listed: bound to
// the stack recorded on the row and the row's created_at, so the host that
// deletes it deletes nothing else of that name (a VM created on its own
// under a member's name after a failed deploy, or a re-created one).
func TestStackReconciler_DeletesBoundToTheListedIncarnation(t *testing.T) {
	db := seedDeletingStack(t, true, false)
	row, err := corrosion.GetVM(context.Background(), db, "app-web")
	if err != nil || row == nil || row.CreatedAt == "" {
		t.Fatalf("seeded row = %+v, %v", row, err)
	}
	c := &recordingStackCleaner{}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.reconcile(context.Background())
	if len(c.vmReqs) != 1 {
		t.Fatalf("VM deletes = %d, want 1", len(c.vmReqs))
	}
	got := c.vmReqs[0]
	if got.GetExpectedStack() != "app" || got.GetExpectedCreatedAt() != row.CreatedAt {
		t.Fatalf("delete of app-web bound to stack %q incarnation %q, want stack %q incarnation %q",
			got.GetExpectedStack(), got.GetExpectedCreatedAt(), "app", row.CreatedAt)
	}
}

// Review M-2, the background half: the reconciler keeps a stack network a
// VM the stack did not create still uses.
func TestStackReconciler_KeepsANetworkAForeignVMUses(t *testing.T) {
	db := seedDeletingStack(t, false, false)
	if err := corrosion.InsertVM(context.Background(), db,
		corrosion.VMRecord{Name: "ui-vm", HostName: "node-1", State: "running", Spec: "{}"},
		[]corrosion.InterfaceRecord{{VMName: "ui-vm", NetworkName: "app_lan", MAC: "52:54:00:00:00:02"}}, nil); err != nil {
		t.Fatal(err)
	}
	c := &recordingStackCleaner{}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.reconcile(context.Background())
	for _, n := range c.deprovisioned {
		if n == "app_lan" {
			t.Fatal("the reconciler deprovisioned app_lan under ui-vm, a VM the stack did not create")
		}
	}
}
