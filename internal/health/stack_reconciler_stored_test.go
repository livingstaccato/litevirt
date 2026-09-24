package health

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type unreadableStackCleaner struct {
	deprovisioned []string
}

func (c *unreadableStackCleaner) DeleteVMForStackCleanup(context.Context, *pb.DeleteVMRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (c *unreadableStackCleaner) RemoveLBForStack(context.Context, string, []corrosion.VMRecord) {}
func (c *unreadableStackCleaner) DeprovisionNetworkByName(_ context.Context, name string) error {
	c.deprovisioned = append(c.deprovisioned, name)
	return nil
}
func (c *unreadableStackCleaner) ExternalNetworkNames(context.Context, string) (map[string]bool, error) {
	return nil, errors.New(`stored compose for stack "bad" cannot be read`)
}

// When the stored compose cannot be read, which of the stack's networks are
// external is unknown: the reconciler deprovisions none, and keeps the stack
// in "deleting" rather than tombstoning it with its networks unaccounted for.
func TestStackReconciler_UnreadableStoredComposeKeepsNetworksAndStack(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "bad", ComposeYAML: "vms: [a]\n", State: "deleting"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: "bad_lan", StackName: "bad", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	c := &unreadableStackCleaner{}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.reconcile(ctx)

	if len(c.deprovisioned) != 0 {
		t.Errorf("deprovisioned %v of a stack whose external networks are unknown", c.deprovisioned)
	}
	if st, _ := corrosion.GetStack(ctx, db, "bad"); st == nil {
		t.Error("the stack was tombstoned with its networks unaccounted for")
	}
}
