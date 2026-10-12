// lv compose down on a stack whose member was already deleted (lab 2 run b,
// finding 5), over the real multi-node spine: the entry node holds the
// member's tombstone, and every peer is asked over real gRPC + mTLS whether
// it has the VM.
package fleet

import (
	"context"
	"errors"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const goneMemberYAML = `name: fbm
vms:
  lbfbm:
    image: tiny
    cpu: 1
    memory: 256
`

// goneMemberCluster is three nodes; node-0 has stack fbm, whose one member
// lbfbm it deleted (lv rm --force). The peers never had it.
func goneMemberCluster(t *testing.T) (*Cluster, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 3})
	n := c.Nodes[0]
	ctx := context.Background()
	if err := corrosion.UpsertStack(ctx, n.DB, corrosion.StackRecord{Name: "fbm", State: "active", ComposeYAML: goneMemberYAML}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{Name: "lbfbm", StackName: "fbm", HostName: n.Name, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, n.DB, "lbfbm"); err != nil {
		t.Fatal(err)
	}
	return c, n
}

// composeDown runs DeleteStack fbm against client and returns the progress.
func composeDown(t *testing.T, client pb.LiteVirtClient) []*pb.DeleteProgress {
	t.Helper()
	stream, err := client.DeleteStack(context.Background(), &pb.DeleteStackRequest{Name: "fbm"})
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	var out []*pb.DeleteProgress
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("DeleteStack stream: %v", err)
		}
		out = append(out, msg)
	}
}

func goneStackState(t *testing.T, n *Node) string {
	t.Helper()
	st, err := corrosion.GetStack(context.Background(), n.DB, "fbm")
	if err != nil {
		t.Fatal(err)
	}
	if st == nil {
		return "(gone)"
	}
	return st.State
}

// Every peer is asked and answers NotFound: the member is reported deleted
// and the stack is torn down in the one call.
//
// Mutation: drop the already-deleted check — the member is an error and the
// stack stays "deleting", red.
func TestFleet_ComposeDown_AMemberAlreadyDeletedIsRemoved(t *testing.T) {
	c, n := goneMemberCluster(t)
	asked := map[string]bool{}
	for _, p := range c.Nodes[1:] {
		p := p
		p.HookUnary("InspectVM", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
			asked[p.Name] = true
			return handler(ctx, req)
		})
	}
	progress := composeDown(t, c.SelfClient(n))
	for _, p := range progress {
		if p.GetStatus() == "error" {
			t.Errorf("compose down reported an error: %+v", p)
		}
	}
	if got := goneStackState(t, n); got != "(gone)" {
		t.Errorf("stack fbm is %q after compose down, want it gone", got)
	}
	for _, p := range c.Nodes[1:] {
		if !asked[p.Name] {
			t.Errorf("peer %s was never asked whether it has lbfbm", p.Name)
		}
	}
}

// A draining peer is never asked — and still runs VMs — and a peer that
// answers PermissionDenied may hold the name in another project: either way
// the member is not proven gone, and compose down errors as on main.
//
// Mutations: skip a non-active peer without counting it — the draining case
// goes red; count PermissionDenied as "no VM" — the denied case goes red.
func TestFleet_ComposeDown_AMemberIsNotTakenAsGoneWhileAPeerCannotSay(t *testing.T) {
	t.Run("draining", func(t *testing.T) {
		c, n := goneMemberCluster(t)
		if err := corrosion.UpdateHostState(context.Background(), n.DB, c.Nodes[2].Name, "draining"); err != nil {
			t.Fatal(err)
		}
		composeDown(t, c.SelfClient(n))
		if got := goneStackState(t, n); got != "deleting" {
			t.Errorf("stack fbm is %q with a draining peer, want \"deleting\"", got)
		}
	})
	t.Run("permission denied", func(t *testing.T) {
		c, n := goneMemberCluster(t)
		c.Nodes[1].HookUnary("InspectVM", func(context.Context, any, grpc.UnaryHandler) (any, error) {
			return nil, status.Error(codes.PermissionDenied, "not in your project")
		})
		composeDown(t, c.SelfClient(n))
		if got := goneStackState(t, n); got != "deleting" {
			t.Errorf("stack fbm is %q with a peer that answered PermissionDenied, want \"deleting\"", got)
		}
	})
}
