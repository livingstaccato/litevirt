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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// Review M-1: a peer that answers the fan-out's inspect with
// PermissionDenied (a project-scoped caller judged by a peer that lacks the
// row) does not end the search: the next peer, which holds the stack's VM,
// still deletes it.
func TestFleet_StackDownFanOutGoesPastAPeerThatDeniesTheInspect(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.Partition(n0, n1)
	c.Partition(n0, n2)
	c.Partition(n1, n2)

	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 128, StackName: "st"})
	if err := corrosion.InsertVM(ctx, n2.DB, corrosion.VMRecord{
		Name: "web", StackName: "st", HostName: n2.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 128,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	n2.Virt.SetState("web", "running")
	if err := corrosion.UpsertStack(ctx, n0.DB, corrosion.StackRecord{
		Name: "st", State: "active",
		ComposeYAML: "name: st\nvms:\n  web:\n    image: tiny\n    cpu: 1\n    memory: 128\n",
	}); err != nil {
		t.Fatal(err)
	}
	n1.HookUnary("InspectVM", func(context.Context, any, grpc.UnaryHandler) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "permission denied: no grant on the VM's path")
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
	if vm, _ := corrosion.GetVM(ctx, n2.DB, "web"); vm != nil {
		t.Fatalf("the stack's web on n2 was not deleted: the search stopped at n1's denial; progress %v", progress)
	}
}

// Review M-4: the stack binding travels with the forwarded delete. n0's
// replica says web is the stack's (stack "st"), the owner n1's row says it
// is not; same incarnation, so only expected_stack tells them apart. n0
// forwards the delete to n1, which checks its own row and keeps the VM.
func TestFleet_StackDownForwardedDeleteCarriesTheStack(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	n0, n1 := c.Nodes[0], c.Nodes[1]
	c.Partition(n0, n1)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 128})
	for _, row := range []struct {
		n     *Node
		stack string
	}{{n0, "st"}, {n1, ""}} {
		if err := corrosion.InsertVM(ctx, row.n.DB, corrosion.VMRecord{
			Name: "web", StackName: row.stack, HostName: n1.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 128,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := row.n.DB.Execute(ctx, `UPDATE vms SET created_at = '2026-10-08T00:00:00.000000001Z' WHERE name = 'web'`); err != nil {
			t.Fatal(err)
		}
	}
	n1.Virt.SetState("web", "running")
	if err := corrosion.UpsertStack(ctx, n0.DB, corrosion.StackRecord{
		Name: "st", State: "active",
		ComposeYAML: "name: st\nvms:\n  web:\n    image: tiny\n    cpu: 1\n    memory: 128\n",
	}); err != nil {
		t.Fatal(err)
	}
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
	if vm, _ := corrosion.GetVM(ctx, n1.DB, "web"); vm == nil || !n1.Virt.DomainExists("web") {
		t.Fatalf("the owner deleted web, which its row says the stack did not create; progress %v", progress)
	}
}
