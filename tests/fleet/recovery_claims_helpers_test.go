package fleet

// Helpers for the recovery-claim scenarios (docs/design/recovery-claims.md,
// colonelpanik/litevirt#250): an independent-replica fleet with an adopted
// voter generation and recovery_claim_v1 enforced on every node.

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// claimsGate is a server gate for a node on which split_brain_gate_v1 and
// recovery_claim_v1 have latched and quorum is present. Everything else a
// server consults answers "healthy", so the scenarios isolate the claim.
type claimsGate struct{}

func (claimsGate) ExecutionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (claimsGate) DecisionGate(context.Context) health.GateResult { return health.GateResult{OK: true} }
func (claimsGate) CapabilityActive(_ context.Context, tok string) (bool, string) {
	return claimsLatched(tok), ""
}
func (claimsGate) CapabilityActiveForHealth(_ context.Context, tok string) (bool, string) {
	return claimsLatched(tok), ""
}
func (claimsGate) Enforced(_ context.Context, tok string) bool { return claimsLatched(tok) }
func (claimsGate) Latched(tok string) bool                     { return claimsLatched(tok) }
func (claimsGate) DurablyLatched(tok string) bool              { return claimsLatched(tok) }
func (claimsGate) PeerSupportsFresh(context.Context, string, string) bool {
	return true
}
func (claimsGate) HealthyPeers(context.Context) []string { return nil }
func (claimsGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return health.QuorumYes, 2, 2
}

func claimsLatched(tok string) bool {
	return tok == capabilities.SplitBrainGateV1 || tok == capabilities.RecoveryClaimV1 ||
		tok == capabilities.VoterConfigV1
}

// enableRecoveryClaims turns recovery claims on for every node the way a
// latched cluster has them: the flag, the latch (claimsGate), and the
// claim_certificate emission gate the daemon wires to the durable latch.
func enableRecoveryClaims(t *testing.T, c *Cluster, nodes ...*Node) {
	t.Helper()
	if len(nodes) == 0 {
		nodes = c.Nodes
	}
	for _, n := range nodes {
		n.DB.SetRecoveryClaimGate(func() bool { return true })
		n.Server.SetRecoveryClaimEnforce(true)
		n.Server.SetGate(claimsGate{})
		if !n.Server.RecoveryClaimEnforced(context.Background()) {
			t.Fatalf("%s: recovery claims are not enforced after enabling them (no adopted voter generation?)", n.Name)
		}
	}
}

// genesisByTick writes voter generation 1 over every node WITHOUT a failover
// tick — genesis is the lease holder's job, and a scenario about two
// coordinators that each think they lead must not hand one of them the lease
// first.
func genesisByTick(t *testing.T, c *Cluster, by *Node) {
	t.Helper()
	openVoterConfigGates(c)
	by.Server.VoterGenesisTick(context.Background(), 0)
	if voterRow(t, by, 1) == nil {
		t.Fatal("automatic genesis wrote no generation on a clean cluster")
	}
	adoptAll(t, c, 1)
}

// claimReconciler is the destination's reconciler as the daemon wires it:
// the execution gate and the recovery-claim certificate check.
func claimReconciler(t *testing.T, n *Node) *health.Reconciler {
	t.Helper()
	rec := health.NewReconciler(n.Name, t.TempDir(), n.DB, n.Virt)
	rec.SetGate(epochGate{})
	rec.SetRecoveryClaimGate(n.Server.RecoveryClaimGateForPendingProof)
	return rec
}

// proofsNaming lists the ownership-transfer proofs n's replica holds for target
// whose destination is dest.
func proofsNaming(t *testing.T, n *Node, target, dest string) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT id FROM runtime_action_proofs WHERE target_name = ? AND dest_host = ? AND deleted_at IS NULL`,
		target, dest)
	if err != nil {
		t.Fatalf("%s: read proofs: %v", n.Name, err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("id"))
	}
	return out
}

// claimFleet is failedHostFleet with an adopted voter generation {a, b,
// victim} and recovery claims enforced everywhere, the victim then killed
// (replication, claim RPCs and owner probe all fail) and each survivor's
// failed probe of it replicated to the other.
func claimFleet(t *testing.T, clock *VirtualClock, seed int64, vms ...string) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	return claimFleetWith(t, clock, seed, func(_ *Cluster, a, _, victim *Node) {
		for _, vm := range vms {
			insertVM(t, a, vm, victim.Name)
		}
	})
}

// claimFleetWith is claimFleet with the workloads placed by setup, before the
// voter set is formed and the victim killed.
func claimFleetWith(t *testing.T, clock *VirtualClock, seed int64, setup func(c *Cluster, a, b, victim *Node)) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	setup(c, a, b, victim)
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)

	c.Kill(victim)
	c.SetLinkFaultBoth(a, b, slowLink)
	PublishHealth(t, a, victim.Name, 5, clock.Now())
	PublishHealth(t, b, victim.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)
	return c, a, b, victim
}

// voterState is one voter's recorded state for a key, read directly.
func voterState(t *testing.T, n *Node, key corrosion.ClaimKey) corrosion.ClaimVoterState {
	t.Helper()
	st, _, err := n.DB.ClaimState(context.Background(), key)
	if err != nil {
		t.Fatalf("%s: claim state %s: %v", n.Name, key, err)
	}
	return st
}
