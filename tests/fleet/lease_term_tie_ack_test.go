package fleet

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// leaseTermsDigests returns every host's leader_lease_terms digest from one
// cluster-wide verification digest, as `lv cluster converge` reads it.
func leaseTermsDigests(t *testing.T, c *Cluster, via *Node) map[string]*pb.TableDigest {
	t.Helper()
	dig, err := c.SelfClient(via).GetClusterStateDigest(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStateDigest via %s: %v", via.Name, err)
	}
	if len(dig.GetUnreachable()) > 0 || len(dig.GetUnsupported()) > 0 {
		t.Fatalf("digest did not reach every host: unreachable=%v unsupported=%v",
			dig.GetUnreachable(), dig.GetUnsupported())
	}
	out := map[string]*pb.TableDigest{}
	for _, h := range dig.GetHosts() {
		for _, td := range h.GetTables() {
			if td.GetName() == "leader_lease_terms" {
				out[h.GetHostName()] = td
			}
		}
	}
	if len(out) != len(c.Nodes) {
		t.Fatalf("leader_lease_terms reported by %d hosts, want %d", len(out), len(c.Nodes))
	}
	return out
}

// TestFleet_LeaseTermTieAck_StaysAcknowledgedAndReadsConverged is the lab's
// fixture on five real daemons: one dual_run_detector term every node claimed,
// acknowledged by an operator on each host.
//
//   - The RPC still refuses a peer certificate.
//   - One acknowledgement per host holds against every peer, on every later
//     pass, and across a restart — although the register only ever names the
//     last peer met.
//   - Every host's verification digest says the tie is acknowledged and gives
//     the same residual, which is what `lv cluster converge` counts converged.
//   - A new claim for that term, met by one host, is live again there and
//     withdraws that host's residual, so converge goes back to SAFETY-FAULT.
func TestFleet_LeaseTermTieAck_StaysAcknowledgedAndReadsConverged(t *testing.T) {
	c := New(t, Options{Nodes: 5})
	ctx := context.Background()
	const key, term = "dual_run_detector", int64(2)
	for _, n := range c.Nodes {
		seedUnreplicatedLeaseTerm(t, n, key, term, n.Name)
	}
	pass := func(n *Node, db *corrosion.Client) {
		t.Helper()
		if !corrosion.NewAntiEntropy(db, n.PKIDir, 0).RunOnce(ctx) {
			t.Fatalf("%s: anti-entropy pass did not run", n.Name)
		}
	}
	for _, n := range c.Nodes {
		pass(n, n.DB)
		if got := n.DB.UnresolvedTieCount(); got != 1 {
			t.Fatalf("precondition: %s tracks %d live ties, want the contested term", n.Name, got)
		}
	}

	// Unacknowledged: every host's digest carries the tie and no residual.
	for h, d := range leaseTermsDigests(t, c, c.Nodes[0]) {
		if d.GetUnresolvedTies() != 1 || d.GetAcknowledgedTies() != 0 || d.GetAcknowledgedResidual() != "" {
			t.Fatalf("%s before acknowledgement: ties=%d acknowledged=%d residual=%q",
				h, d.GetUnresolvedTies(), d.GetAcknowledgedTies(), d.GetAcknowledgedResidual())
		}
	}

	// The operator acknowledges on each host, as the condition tells them to,
	// with a bearer. (The refusal of a PEER certificate is pinned in grpcapi,
	// TestAcknowledgeLeaseTermTie_RefusesAPeer: every fleet node dials from
	// loopback, where a host certificate classifies as the on-node root.)
	// One operator per host, minted there: the contested table never
	// converges, so waiting for a token to replicate would wait forever.
	for _, n := range c.Nodes {
		admin := c.SelfClient(n)
		user := "tieack-op-" + n.Name
		if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
			Username: user, Password: "tieack-pass", Role: "operator",
		}); err != nil {
			t.Fatalf("%s: CreateUser: %v", n.Name, err)
		}
		tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: user, Name: "ack"})
		if err != nil || tok.GetToken() == "" {
			t.Fatalf("%s: CreateToken: %+v %v", n.Name, tok, err)
		}
		resp, err := c.bearerClient(n, tok.GetToken()).AcknowledgeLeaseTermTie(ctx,
			&pb.AcknowledgeLeaseTermTieRequest{Key: key, Term: term})
		if err != nil || !resp.GetAcknowledged() {
			t.Fatalf("%s: acknowledge: %+v %v", n.Name, resp, err)
		}
	}

	// Every later pass meets every peer's claim again.
	for round := 0; round < 2; round++ {
		for _, n := range c.Nodes {
			pass(n, n.DB)
			if got := n.DB.UnresolvedTieCount(); got != 0 {
				t.Fatalf("round %d: %s re-raised the acknowledged term (live=%d): the "+
					"acknowledgement covered only the last peer met", round, n.Name, got)
			}
			if got := n.DB.TrackedTieCount(); got != 1 {
				t.Fatalf("round %d: %s tracks %d ties; the contested row must stay visible", round, n.Name, got)
			}
		}
	}

	// Converged apart from the acknowledged row, and the report can prove it.
	digests := leaseTermsDigests(t, c, c.Nodes[0])
	hashes, residuals := map[string]bool{}, map[string]bool{}
	for h, d := range digests {
		if d.GetUnresolvedTies() != 1 || d.GetAcknowledgedTies() != 1 {
			t.Errorf("%s: ties=%d acknowledged=%d, want 1/1", h, d.GetUnresolvedTies(), d.GetAcknowledgedTies())
		}
		if d.GetAcknowledgedResidual() == "" {
			t.Errorf("%s supplied no residual for a table whose only tie is acknowledged", h)
		}
		hashes[d.GetHash()] = true
		residuals[d.GetAcknowledgedResidual()] = true
	}
	if len(hashes) < 2 {
		t.Fatal("the table hashes agree across hosts; the residual is not being exercised")
	}
	if len(residuals) != 1 {
		t.Errorf("hosts disagree on the acknowledged residual (%d distinct) although the only "+
			"difference between them is the acknowledged term", len(residuals))
	}

	// A restart: a fresh daemon over each node's database, meeting its peers
	// from an empty register.
	for _, n := range c.Nodes {
		restarted, err := corrosion.NewSharedTestClient("fleet-"+n.Name, n.Name)
		if err != nil {
			t.Fatalf("%s: reopen: %v", n.Name, err)
		}
		if err := corrosion.InitSchema(ctx, restarted); err != nil {
			restarted.Close()
			t.Fatalf("%s: InitSchema: %v", n.Name, err)
		}
		restarted.MarkReplicaCaughtUpForTests("tieack-restart")
		// The same gossip view the running daemon has: the fleet joins no
		// memberlist, so a fresh client would otherwise see no peers at all.
		restarted.SetMembersForTests(n.DB.Members)
		pass(n, restarted)
		live, tracked := restarted.UnresolvedTieCount(), restarted.TrackedTieCount()
		restarted.Close()
		if live != 0 || tracked != 1 {
			t.Errorf("%s after a restart: live=%d tracked=%d, want 0/1: the acknowledgement did "+
				"not survive the restart", n.Name, live, tracked)
		}
	}

	// A sixth claim for the term, on node-1. node-2 meets it: new evidence.
	a, b := c.Nodes[0], c.Nodes[1]
	a.DB.Mu().Lock()
	_, err := a.DB.DB().Exec(`UPDATE leader_lease_terms SET holder = 'node-x' WHERE key = ? AND term = ?`, key, term)
	a.DB.Mu().Unlock()
	if err != nil {
		t.Fatalf("rewrite %s's claim: %v", a.Name, err)
	}
	pass(b, b.DB)
	if got := b.DB.UnresolvedTieCount(); got != 1 {
		t.Fatalf("%s met a claim nobody acknowledged and tracks %d live ties, want 1: new "+
			"evidence was silently covered by the old acknowledgement", b.Name, got)
	}
	d := leaseTermsDigests(t, c, a)[b.Name]
	if d.GetAcknowledgedTies() >= d.GetUnresolvedTies() || d.GetAcknowledgedResidual() != "" {
		t.Errorf("%s's digest after a new claim: ties=%d acknowledged=%d residual=%q; converge "+
			"would count the new claim as reviewed", b.Name, d.GetUnresolvedTies(),
			d.GetAcknowledgedTies(), d.GetAcknowledgedResidual())
	}
}
