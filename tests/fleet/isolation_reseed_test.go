package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// isolationRegimeOn turns the regime on across the fleet: the config flag on
// every node (uniformity is what lets a token latch) plus a latched gate.
func isolationRegimeOn(t *testing.T, c *Cluster, on bool) {
	t.Helper()
	for _, n := range c.Nodes {
		n.Server.SetIsolationEpochEnforce(on)
		// A REAL health.Checker as the gate (gateFor), so the token latches the
		// production way — a fresh Ping per voting-eligible host over the
		// harness's real loopback mTLS — instead of a stub asserting it did.
		gateFor(t, c, n)
	}
}

// isolationOf reads a host's recorded isolation from a node's OWN DB — the
// point of the epoch is that PEERS can see it, so assertions read the peer.
func isolationOf(t *testing.T, n *Node, host string) (int64, string) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT isolation_epoch e, COALESCE(isolation_reason,'') r FROM hosts WHERE name = ?`, host)
	if err != nil {
		t.Fatalf("read %s isolation on %s: %v", host, n.Name, err)
	}
	if len(rows) == 0 {
		return 0, ""
	}
	return rows[0].Int64("e"), rows[0].String("r")
}

// TestFleet_IsolatedNodeIsRefusedByItsPeers is the scenario the roadmap names:
// a node is isolated, BOTH peers refuse its mutation pushes while continuing to
// replicate normally among themselves, and after a reseed its pushes are
// accepted again. Everything is asserted from the PEERS' own state — a
// self-muting node's own view is exactly what cannot be trusted.
func TestFleet_IsolatedNodeIsRefusedByItsPeers(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	bad, a, b := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	isolationRegimeOn(t, c, true)

	// A healthy peer records the isolation; it replicates to the other peer.
	if _, err := c.SelfClient(a).IsolateHost(ctx, &pb.IsolateHostRequest{
		Name: bad.Name, Reason: corrosion.IsolationRolledBackLatch,
	}); err != nil {
		t.Fatalf("isolate: %v", err)
	}
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, a, bad)
	for _, peer := range []*Node{a, b} {
		if epoch, reason := isolationOf(t, peer, bad.Name); epoch == 0 || reason != corrosion.IsolationRolledBackLatch {
			t.Fatalf("%s does not see the isolation: epoch=%d reason=%q", peer.Name, epoch, reason)
		}
	}

	// Both peers now REFUSE the isolated node's pushes.
	for _, peer := range []*Node{a, b} {
		_, err := c.PeerClient(bad, peer).PushMutations(ctx, &pb.ReplicateRequest{
			Sender: bad.Name, Entries: nil,
		})
		if err == nil {
			t.Fatalf("%s accepted a push from the isolated node", peer.Name)
		}
		if !strings.Contains(err.Error(), "isolated") {
			t.Fatalf("%s refusal must name the isolation, got: %v", peer.Name, err)
		}
	}

	// POSITIVE CONTROL: a healthy node is never refused — the gate must
	// discriminate, not just refuse everything once it is on.
	if _, err := c.PeerClient(a, b).PushMutations(ctx, &pb.ReplicateRequest{
		Sender: a.Name, Entries: nil,
	}); err != nil {
		t.Fatalf("a healthy peer's push must still be accepted: %v", err)
	}

	// Reseed, driven from a healthy node and forwarded to the isolated one.
	resp, err := c.SelfClient(a).ReseedHost(ctx, &pb.ReseedHostRequest{
		Name: bad.Name, Source: a.Name,
	})
	if err != nil {
		t.Fatalf("reseed: %v", err)
	}
	if resp.GetClearedEpoch() == 0 || resp.GetSource() != a.Name {
		t.Fatalf("reseed response: %+v", resp)
	}

	// The clear was written by the HEALTHY peer that drove the reseed (the
	// reseeded node's own writes are still refused at that instant, so a
	// self-written clear could never have reached anyone). It therefore
	// replicates OUTWARD from a: to the other peer, and back to the node.
	if epoch, _ := isolationOf(t, a, bad.Name); epoch != 0 {
		t.Fatalf("the driving peer must have cleared the epoch: %d", epoch)
	}
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, a, bad)
	if epoch, _ := isolationOf(t, bad, bad.Name); epoch != 0 {
		t.Fatalf("the reseeded node should learn its own clear by replication: epoch=%d", epoch)
	}
	for _, peer := range []*Node{a, b} {
		if epoch, _ := isolationOf(t, peer, bad.Name); epoch != 0 {
			t.Fatalf("%s still records the isolation after reseed: epoch=%d", peer.Name, epoch)
		}
		if _, err := c.PeerClient(bad, peer).PushMutations(ctx, &pb.ReplicateRequest{
			Sender: bad.Name, Entries: nil,
		}); err != nil {
			t.Fatalf("%s still refuses a reseeded node: %v", peer.Name, err)
		}
	}
}

// A node cannot record — or clear — its own quarantine, and reseed is not a
// general repair tool. These are the refusals that keep the regime meaningful.
func TestFleet_IsolationRefusals(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	isolationRegimeOn(t, c, true)

	// Self-isolation is refused: the observation must come from a peer.
	if _, err := c.SelfClient(a).IsolateHost(ctx, &pb.IsolateHostRequest{Name: a.Name}); err == nil {
		t.Fatal("a node must not isolate itself")
	}

	// Reseeding a node that is NOT isolated is refused — it discards state.
	if _, err := c.SelfClient(a).ReseedHost(ctx, &pb.ReseedHostRequest{Name: b.Name}); err == nil {
		t.Fatal("reseed of a healthy node must be refused")
	} else if !strings.Contains(err.Error(), "not isolated") {
		t.Fatalf("refusal should say why: %v", err)
	}

	// A running workload blocks a reseed: discarding replicated state under a
	// live VM is the one way this primitive could destroy something.
	if _, err := c.SelfClient(a).IsolateHost(ctx, &pb.IsolateHostRequest{Name: b.Name}); err != nil {
		t.Fatalf("isolate b: %v", err)
	}
	pumpMutations(t, c, a, b)
	if err := corrosion.InsertVM(ctx, b.DB, corrosion.VMRecord{
		Name: "live1", HostName: b.Name, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("seed running VM: %v", err)
	}
	_, err := c.SelfClient(a).ReseedHost(ctx, &pb.ReseedHostRequest{Name: b.Name, Source: a.Name})
	if err == nil {
		t.Fatal("reseed must refuse while the node runs workloads")
	}
	if !strings.Contains(err.Error(), "drain") {
		t.Fatalf("the refusal must tell the operator to drain: %v", err)
	}
	if epoch, _ := isolationOf(t, a, b.Name); epoch == 0 {
		t.Fatal("a refused reseed must leave the isolation in place")
	}

	// Aiming a reseed at the isolated node ITSELF is refused: a node cannot
	// clear its own quarantine, and its writes are refused anyway — so a
	// self-driven reseed would "succeed" into a cluster that never hears it.
	if _, err := c.SelfClient(b).ReseedHost(ctx, &pb.ReseedHostRequest{Name: b.Name}); err == nil {
		t.Fatal("a self-driven reseed must be refused")
	} else if !strings.Contains(err.Error(), "peer") {
		t.Fatalf("the refusal must point at a healthy peer: %v", err)
	}
}

// The regime is capability-gated: with the token off, nothing is refused, so a
// pre-latch cluster behaves exactly as it did before this shipped.
func TestFleet_IsolationIsCapabilityGated(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	// Record an isolation with the regime ON, then turn it OFF everywhere.
	isolationRegimeOn(t, c, true)
	if _, err := c.SelfClient(a).IsolateHost(ctx, &pb.IsolateHostRequest{Name: b.Name}); err != nil {
		t.Fatalf("isolate: %v", err)
	}
	if epoch, _ := isolationOf(t, a, b.Name); epoch == 0 {
		t.Fatal("precondition: the isolation must be recorded")
	}
	isolationRegimeOn(t, c, false)

	// The FACT stays recorded, but nothing is refused on it.
	if _, err := c.PeerClient(b, a).PushMutations(ctx, &pb.ReplicateRequest{
		Sender: b.Name, Entries: nil,
	}); err != nil {
		t.Fatalf("with the token off, an isolated node's push must NOT be refused: %v", err)
	}
}
