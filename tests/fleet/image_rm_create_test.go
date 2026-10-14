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

// I-4: a deploy update that switches a VM to another image already removed
// with lv image rm — whose file this host still keeps inside the delete
// margin — is refused before the VM is deleted: a new use of a deleted name,
// which the re-create exemption (an rm landing during the operation) does
// not cover. The VM stays as it was, on its own image.
//
// Mutation: drop refuseSwitchToDeletedImage from the deploy update — the
// update tears the VM down and builds it on the deleted image: red.
func TestFleet_ImageRm_ADeployUpdateToADeletedImageIsRefusedBeforeTheDelete(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	c.WaitConverged(t, convergeTimeout)
	n0 := c.Nodes[0]
	ctx := context.Background()
	importImageOn(t, c, n0, "ubuntu")
	noble := importImageOn(t, c, n0, "noble")
	if p := errorPhaseFor(deployCollect(t, ctx, c.SelfClient(n0), strings.Replace(composeImageSwitch, "IMG", "ubuntu", 1)), "box"); p != nil {
		t.Fatalf("first deploy: %s", p.Error)
	}
	before, err := corrosion.GetVM(ctx, n0.DB, "box")
	if err != nil || before == nil {
		t.Fatalf("box after the first deploy: %v %v", before, err)
	}
	if _, err := c.SelfClient(n0).RemoveImage(ctx, &pb.RemoveImageRequest{Name: "noble"}); err != nil {
		t.Fatal(err)
	}
	if !fileThere(noble) {
		t.Fatal("noble's file was not kept within the delete margin: the test's premise is gone")
	}

	p := errorPhaseFor(deployCollect(t, ctx, c.SelfClient(n0), strings.Replace(composeImageSwitch, "IMG", "noble", 1)), "box")
	if p == nil || !strings.Contains(p.Error, "deleted") || !strings.Contains(p.Error, "nothing was deleted") {
		t.Fatalf("the update to the deleted image noble: %v, want it refused before the delete", p)
	}
	vm, err := corrosion.GetVM(ctx, n0.DB, "box")
	if err != nil || vm == nil || vm.CreatedAt != before.CreatedAt || !strings.Contains(vm.Spec, `"image":"ubuntu"`) {
		t.Errorf("box after the refused update: %+v (err %v); want the same VM, on ubuntu", vm, err)
	}
	if !n0.Virt.DomainExists("box") {
		t.Error("box's domain is gone")
	}
}
