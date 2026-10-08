// Fleet scenario: compose down reaches a VM it has no row for (replication
// lag) through the peer fan-out, and the peer's VM of that name is not the
// stack's. main deleted it by name (fanoutDeleteVM → DeleteVM{Name} on the
// peer, stacks.go:1145 at 1c105363). The fan-out's inspect can be stale, so
// the delete itself carries the stack it is bound to, and the host that
// owns the VM checks its own row under the lock before it tears anything
// down. Only a real fleet reaches this: the teardown, the fan-out and the
// owner's delete are different daemons, and replication is held apart.
package fleet

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestFleet_StackDownFanOutLeavesAPeersVMTheStackDidNotCreate(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	n0, n1 := c.Nodes[0], c.Nodes[1]
	// n0 must not learn of n1's VM: the teardown on n0 then finds no row and
	// fans out.
	c.Partition(n0, n1)

	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 128})
	if err := corrosion.InsertVM(ctx, n1.DB, corrosion.VMRecord{
		Name: "web", HostName: n1.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 128,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	n1.Virt.SetState("web", "running")
	if err := corrosion.UpsertStack(ctx, n0.DB, corrosion.StackRecord{
		Name: "st", State: "active",
		ComposeYAML: "name: st\nvms:\n  web:\n    image: tiny\n    cpu: 1\n    memory: 128\n",
	}); err != nil {
		t.Fatal(err)
	}
	if vm, _ := corrosion.GetVM(ctx, n0.DB, "web"); vm != nil {
		t.Fatal("setup: n0 already has web's row; the fan-out would not be exercised")
	}
	// The inspect the fan-out makes first sees the VM as the stack's — a
	// stale view, or the name re-created in between. The delete must still
	// judge the row it would delete.
	n1.HookUnary("InspectVM", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		out, err := handler(ctx, req)
		if vm, ok := out.(*pb.VM); ok && err == nil {
			vm.StackName = "st"
		}
		return out, err
	})

	stream, err := c.SelfClient(n0).DeleteStack(ctx, &pb.DeleteStackRequest{Name: "st"})
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	var progress []*pb.DeleteProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("DeleteStack stream: %v", err)
		}
		progress = append(progress, p)
	}

	if vm, _ := corrosion.GetVM(ctx, n1.DB, "web"); vm == nil {
		t.Fatalf("compose down deleted n1's web, a VM the stack did not create; progress %v", progress)
	}
	if !n1.Virt.DomainExists("web") {
		t.Fatal("n1's web domain was torn down")
	}
	kept := false
	for _, p := range progress {
		if p.VmName == "web" && p.Status == "kept" {
			kept = true
		}
	}
	if !kept {
		t.Errorf("no progress reports web as kept: %v", progress)
	}
}
