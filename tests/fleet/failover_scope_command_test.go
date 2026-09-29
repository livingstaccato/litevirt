// Fleet scenario for the operator command behind region-scoped failover:
// SetFailoverScope over real gRPC, with a real health.Checker per node driving
// the failover_scope_v1 latch over real peer Pings, and the policy row
// travelling between independent replicas.
package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_FailoverScopeCommand_RefusesUntilLatchedAndReachable walks the two
// refusals and the success, in the order an operator meets them.
func TestFleet_FailoverScopeCommand_RefusesUntilLatchedAndReachable(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 265,
		RegionByIndex: []string{"east", "east", "west"}})
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		// The daemon's wiring (wireClusterPolicyGate), against this node's real checker.
		g := gates[n.Name]
		n.DB.SetClusterPolicyGate(func() bool { return g.DurablyLatched(capabilities.FailoverScopeV1) })
	}
	c.WaitConverged(t, convergeTimeout)
	a := c.Nodes[0]
	cli := c.SelfClient(a)

	// 1. Before the latch: refused, naming the token, and nothing written.
	st, err := cli.GetFailoverScope(ctx, &emptypb.Empty{})
	if err != nil || st.GetScope() != corrosion.FailoverScopeCluster || st.GetSettable() {
		t.Fatalf("before the latch: %+v err=%v, want cluster scope and not settable", st, err)
	}
	_, err = cli.SetFailoverScope(ctx, &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), capabilities.FailoverScopeV1) {
		t.Fatalf("SetFailoverScope before the latch: %v, want FailedPrecondition naming %s", err, capabilities.FailoverScopeV1)
	}
	for _, n := range c.Nodes {
		assertNoPolicyStatements(t, n)
	}

	// Every node runs this build, so the latch forms.
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) || !gates[n.Name].DurablyLatched(capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch on a uniform fleet", n.Name)
		}
	}

	// 2. Latched, but a's probes have seen no peer healthy (nothing in-process
	// runs the probe loop, and the reachability overlay is empty): refused,
	// naming who is out of reach.
	_, err = cli.SetFailoverScope(ctx, &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), c.Nodes[1].Name) ||
		!strings.Contains(err.Error(), c.Nodes[2].Name) {
		t.Fatalf("SetFailoverScope with no peer reachable: %v, want FailedPrecondition naming both peers", err)
	}

	// Only one of two peers back: still refused, naming the other.
	c.Nodes[1].Rejoin()
	_, err = cli.SetFailoverScope(ctx, &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot reach "+c.Nodes[2].Name+".") {
		t.Fatalf("SetFailoverScope with %s unreachable: %v", c.Nodes[2].Name, err)
	}
	for _, n := range c.Nodes {
		assertNoPolicyStatements(t, n)
	}

	// 3. Every voter reachable: the change is written and reaches every replica.
	c.Nodes[2].Rejoin()
	st, err = cli.SetFailoverScope(ctx, &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if err != nil || st.GetScope() != corrosion.FailoverScopeRegion || !st.GetSettable() {
		t.Fatalf("SetFailoverScope with every voter reachable: %+v err=%v", st, err)
	}
	var west *pb.FailoverScopeRegion
	for _, r := range st.GetRegions() {
		if r.GetName() == "west" {
			west = r
		}
	}
	if west == nil || west.GetVoters() != 1 || west.GetCanFenceOwn() {
		t.Fatalf("west in the report: %+v, want one voter and unable to fence its own", west)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if p, err := corrosion.GetFailoverScope(ctx, n.DB); err != nil || !p.Region() {
			t.Fatalf("%s reads %+v (err=%v) after the change replicated, want region", n.Name, p, err)
		}
	}
}

// assertNoPolicyStatements fails if n put a cluster_policies statement on its
// replication stream.
func assertNoPolicyStatements(t *testing.T, n *Node) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", n.Name, err)
	}
	for _, r := range rows {
		if strings.Contains(r.String("stmts"), "cluster_policies") {
			t.Fatalf("%s put a cluster_policies statement on its stream while the change was refused:\n%s",
				n.Name, r.String("stmts"))
		}
	}
}
