package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Lab 2: after `lv image rm X` on one node, a create naming X on another
// node — whose copy that rm kept, published within the delete margin — built
// the VM on the kept copy, with no pull. A deleted image is not usable by
// name: the create is refused wherever it lands, and a re-import of the name
// makes it usable again.
func TestFleet_ImageRm_ACreateOnAHostThatKeptItsCopyIsRefused(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	ctx := context.Background()
	n0, n1 := c.Nodes[0], c.Nodes[1]
	importImageOn(t, c, n0, "ubuntu")
	f1 := importImageOn(t, c, n1, "ubuntu")

	if _, err := c.SelfClient(n0).RemoveImage(ctx, &pb.RemoveImageRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !fileThere(f1) {
		t.Fatalf("%s did not keep its copy within the delete margin: the test's premise is gone", n1.Name)
	}
	eventually(t, 15*time.Second, n1.Name+" to apply the image's delete", func() bool {
		d, err := corrosion.ImageDeletedAt(ctx, n1.DB, "ubuntu")
		return err == nil && d != ""
	})

	spec := func() *pb.VMSpec {
		return &pb.VMSpec{Name: "web", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}
	}
	_, err := c.SelfClient(n0).CreateVM(ctx, &pb.CreateVMRequest{Spec: spec()})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("create on %s of the deleted image: %v, want FailedPrecondition naming it deleted", n1.Name, err)
	}
	for _, n := range c.Nodes {
		if vm, _ := corrosion.GetVM(ctx, n.DB, "web"); vm != nil {
			t.Errorf("the refused create left a row on %s", n.Name)
		}
	}
	if !fileThere(f1) {
		t.Error("the refusal removed the kept copy")
	}

	// A re-import revives the name, and the create goes ahead.
	importImageOn(t, c, n1, "ubuntu")
	if _, err := c.SelfClient(n0).CreateVM(ctx, &pb.CreateVMRequest{Spec: spec()}); err != nil {
		t.Fatalf("create after a re-import: %v", err)
	}
}
