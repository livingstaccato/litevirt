// compose down of a stack whose only VM failed to create (lab 2,
// 2026-10-16, createfail-cddb81e9 O4), over two nodes.

package fleet

import (
	"context"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_ComposeDownOfAStackWhoseVMFailedToCreate: a stack whose only VM
// failed to create is torn down by one compose down, over two nodes: the
// member is reported absent, not NotFound, and the stack does not linger in
// "deleting" for the reconciler.
//
// Mutation: drop the never-created case — the member is an error and the
// stack stays "deleting", red.
func TestFleet_ComposeDownOfAStackWhoseVMFailedToCreate(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	n := c.Nodes[0]
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, n.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2", SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}
	client := c.SelfClient(n)
	n.Virt.FailStartDomain = func(string) error { return errors.New("injected: qemu died") }
	if errorPhaseFor(deployCollect(t, ctx, client, composeFailOne), "hb-1") == nil {
		t.Fatal("hb-1 was created; the scenario needs its create to fail")
	}
	if got := stackState(t, ctx, n.DB, "hb"); got != "degraded" {
		t.Fatalf("stack hb is %q after the failed create, want degraded", got)
	}

	stream, err := client.DeleteStack(ctx, &pb.DeleteStackRequest{Name: "hb"})
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	absent := false
	for {
		p, err := stream.Recv()
		if err != nil {
			break
		}
		if p.GetStatus() == "error" {
			t.Errorf("compose down reported an error: %+v", p)
		}
		absent = absent || (p.GetVmName() == "hb-1" && p.GetStatus() == "absent")
	}
	if !absent {
		t.Error("hb-1 was not reported absent")
	}
	st, err := corrosion.GetStack(ctx, n.DB, "hb")
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Errorf("stack hb is %q after compose down, want it gone", st.State)
	}
}
