package health

import (
	"context"
	"errors"
	"testing"
	"time"

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
	namedKept      []string // NameStackTeardownKeptDisks: "<vm>: <why>"
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
func (c *failingStackCleaner) NameStackTeardownKeptDisks(_ context.Context, _ string, vm corrosion.VMRecord, why string) {
	c.namedKept = append(c.namedKept, vm.Name+": "+why)
}
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
	// A teardown begun long ago: not one in flight (stackTeardownGrace).
	setStackUpdatedAt(t, db, "app", time.Now().Add(-time.Hour))
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

// A stack the reconciler finishes takes its firewall rows and backup repos
// with it, as a DeleteStack that completes does. A `compose down` of a stack
// whose compose up failed part way leaves the stack 'deleting' (the file
// names a member that was never created), and the reconciler finishing it
// left the stack's security groups behind: the next deploy of the same file
// was refused, "security-group ... is already defined by stack" (lab 1 `web`,
// lab 2 `noicmp`).
//
// The teardown is one whose caller held sg.write at the cluster root (one
// without it is stack_firewall_hold_test.go).
//
// Mutation: drop the firewall tombstone from the reconciler's last step — the
// security group outlives the stack.
func TestStackReconciler_FinishedStackTakesItsFirewallAndRepos(t *testing.T) {
	db := seedDeletingStack(t, false, false)
	ctx := context.Background()
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.MarkStackDeleting(ctx, db, "app", false, true, "node-0"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg1", Name: "web", StackName: "app"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg2", Name: "admin", StackName: ""}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupRepo(ctx, db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/b", StackName: "app"}); err != nil {
		t.Fatal(err)
	}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(&failingStackCleaner{})
	r.SetClock(func() time.Time { return time.Now().Add(2 * stackTeardownGrace) })
	r.reconcile(ctx)
	if st, _ := corrosion.GetStack(ctx, db, "app"); st != nil {
		t.Fatalf("the stack was not finished: %+v", st)
	}
	if sgs, _ := corrosion.ListSecurityGroups(ctx, db, "app"); len(sgs) != 0 {
		t.Errorf("the finished stack's security groups are still live: %+v", sgs)
	}
	if sgs, _ := corrosion.ListSecurityGroups(ctx, db, ""); len(sgs) != 1 || sgs[0].Name != "admin" {
		t.Errorf("security groups of no stack = %+v, want admin kept", sgs)
	}
	repos, _ := corrosion.ListBackupRepos(ctx, db)
	for _, rp := range repos {
		if rp.StackName == "app" {
			t.Errorf("the finished stack's backup repo %s is still registered", rp.Name)
		}
	}
}
