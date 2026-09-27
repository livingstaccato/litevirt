package health

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// failingStackCleaner fails the workload deletes a test names and records
// every call.
type failingStackCleaner struct {
	failVM, failCT bool
	deprovisioned  []string
	ctDeleted      []string
}

func (c *failingStackCleaner) DeleteVMForStackCleanup(context.Context, *pb.DeleteVMRequest) (*emptypb.Empty, error) {
	if c.failVM {
		return nil, errors.New("injected: vm delete failed")
	}
	return &emptypb.Empty{}, nil
}
func (c *failingStackCleaner) DeleteContainerForStackCleanup(_ context.Context, req *pb.DeleteContainerRequest) (*emptypb.Empty, error) {
	if c.failCT {
		return nil, errors.New("injected: container delete failed")
	}
	c.ctDeleted = append(c.ctDeleted, req.Name)
	return &emptypb.Empty{}, nil
}
func (c *failingStackCleaner) RemoveLBForStack(context.Context, string, []corrosion.VMRecord) {}
func (c *failingStackCleaner) DeprovisionNetworkByName(_ context.Context, name string) error {
	c.deprovisioned = append(c.deprovisioned, name)
	return nil
}
func (c *failingStackCleaner) ExternalNetworkNames(context.Context, string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func seedDeletingStack(t *testing.T, withVM, withCT bool) *corrosion.Client {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "app", ComposeYAML: "vms: {}\n", State: "deleting"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: "app_lan", StackName: "app", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if withVM {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "app-web", StackName: "app", HostName: "node-1", State: "running", Spec: "{}"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if withCT {
		if err := db.Execute(ctx,
			`INSERT INTO containers (name, host_name, state, labels, created_at, updated_at)
			 VALUES ('app-db', 'node-1', 'running', ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
			`{"`+corrosion.LabelStack+`":"app"}`); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// While a stack VM's delete keeps failing, the reconciler leaves the stack's
// networks alone: a tombstone would reach every host and tear the network
// down under the VM that is still there.
func TestStackReconciler_KeepsNetworksWhileAVMDeleteFails(t *testing.T) {
	db := seedDeletingStack(t, true, false)
	c := &failingStackCleaner{failVM: true}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.reconcile(context.Background())
	if len(c.deprovisioned) != 0 {
		t.Errorf("deprovisioned %v while the stack's VM delete failed", c.deprovisioned)
	}
	if st, _ := corrosion.GetStack(context.Background(), db, "app"); st == nil {
		t.Error("the stack was tombstoned with a VM left")
	}
}

// The reconciler deletes a stack's containers too, and while one of those
// deletes fails it leaves the networks alone as well.
func TestStackReconciler_DeletesContainersAndKeepsNetworksWhileOneFails(t *testing.T) {
	db := seedDeletingStack(t, false, true)
	c := &failingStackCleaner{failCT: true}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.reconcile(context.Background())
	if len(c.deprovisioned) != 0 {
		t.Errorf("deprovisioned %v while the stack's container delete failed", c.deprovisioned)
	}
	if st, _ := corrosion.GetStack(context.Background(), db, "app"); st == nil {
		t.Error("the stack was tombstoned with a container left")
	}

	c.failCT = false
	r.reconcile(context.Background())
	if len(c.ctDeleted) != 1 || c.ctDeleted[0] != "app-db" {
		t.Errorf("container deletes = %v, want app-db", c.ctDeleted)
	}
	if len(c.deprovisioned) != 1 || c.deprovisioned[0] != "app_lan" {
		t.Errorf("deprovisioned %v once the container delete succeeded, want app_lan", c.deprovisioned)
	}
}
