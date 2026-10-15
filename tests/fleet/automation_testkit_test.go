package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// This evidence is intentionally constructed only in test source. It is not
// daemon readiness, Task5 cutover evidence, key custody, or runtime eligibility.
type AutomationFixture struct {
	ctx          context.Context
	cluster      *Cluster
	engines      []*automation.Engine
	ownerSession uint64
}

func NewAutomationFixture(t *testing.T, nodes int) *AutomationFixture {
	return newAutomationFixture(t, nodes, true)
}
func newAutomationFixture(t *testing.T, nodes int, initialize bool) *AutomationFixture {
	return newAutomationFixtureWith(t, nodes, initialize, nil)
}
func newAutomationFixtureWith(t *testing.T, nodes int, initialize bool, beforeGenesis func(*Cluster)) *AutomationFixture {
	t.Helper()
	c := New(t, Options{Nodes: nodes, IndependentReplicas: true, FaultSeed: 4102026})
	c.WaitConverged(t, convergeTimeout)
	if beforeGenesis != nil {
		beforeGenesis(c)
	}
	genesisByTick(t, c, c.Nodes[0])
	enableRecoveryClaims(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	f := &AutomationFixture{ctx: ctx, cluster: c}
	for _, n := range c.Nodes {
		cfg, err := corrosion.AdoptedVoterConfig(ctx, n.DB)
		if err != nil {
			t.Fatal(err)
		}
		incarnation, err := n.DB.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := localExec(ctx, n.DB, `INSERT INTO local_automation_authority (id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance) VALUES (1,?,?,?,?,?,?)`, cfg.Generation, corrosion.MembersHash(cfg.Members), incarnation, "fixture-bootstrap", "same-request", "test-only:authenticated-fleet-membership:4102026"); err != nil {
			t.Fatal(err)
		}
		e, err := n.Server.AutomationEngine()
		if err != nil {
			t.Fatal(err)
		}
		f.engines = append(f.engines, e)
	}
	if initialize {
		if _, err := f.Engine(0).Submit(ctx, f.Initialize("same-request")); err != nil {
			t.Fatal(err)
		}
		f.Converge(t)
	}
	return f
}
func (f *AutomationFixture) Context() context.Context           { return f.ctx }
func (f *AutomationFixture) Engine(node int) *automation.Engine { return f.engines[node] }
func (f *AutomationFixture) Initialize(request string) automation.Command {
	return automation.Command{Kind: "initialize_cluster", PrincipalID: "fixture-bootstrap", RequestID: request, Body: []byte(`{"version":1}`)}
}
func (f *AutomationFixture) Barrier(node int, request string) automation.Command {
	h, _ := f.cluster.Nodes[node].DB.AutomationHead(f.ctx)
	return automation.Command{Kind: "read_barrier", ClusterUID: h.ClusterUID, PrincipalID: f.cluster.Nodes[node].Name, RequestID: request, Body: []byte(`{"version":1}`)}
}
func (f *AutomationFixture) Isolate(node int) {
	for i, n := range f.cluster.Nodes {
		if i != node {
			f.cluster.SetLinkFaultBoth(f.cluster.Nodes[node], n, LinkFault{BlockAll: true})
		}
	}
}
func (f *AutomationFixture) Heal(node int) {
	for i, n := range f.cluster.Nodes {
		if i != node {
			f.cluster.SetLinkFaultBoth(f.cluster.Nodes[node], n, LinkFault{})
		}
	}
}
func (f *AutomationFixture) Head(t *testing.T, node int) corrosion.AutomationPrefix {
	t.Helper()
	h, e := f.cluster.Nodes[node].DB.AutomationHead(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func (f *AutomationFixture) Converge(t *testing.T) {
	t.Helper()
	// Catch-up calls production authenticated prefix RPCs. Barriers provide fresh
	// quorum authority; fetched heads remain hints until re-certified.
	for i := range f.engines {
		if err := f.Engine(i).Recover(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	want := f.Head(t, 0)
	for i := range f.engines {
		if h := f.Head(t, i); h != want {
			t.Fatalf("node %d head %+v, want %+v", i, h, want)
		}
	}
}

// certifyFixtureDecision sends a fixed test proposal to real acceptors. It is
// for testing hostile/replayed admitted facts, not an alternative engine or
// mutex-based decision model: quorum signatures come from committed production
// ClaimAccept calls, with production membership/prefix/schema checks intact.
func (f *AutomationFixture) certifyFixtureDecision(t *testing.T, d automation.Decision) corrosion.AutomationRecord {
	t.Helper()
	encoded, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: encoded}}
	key, err := corrosion.AutomationClaimKey(d.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	ballot := corrosion.Ballot{Round: 50, Coordinator: f.cluster.Nodes[0].Name, Nonce: []byte("fixture-direct-accept")}
	cfg, err := corrosion.AdoptedVoterConfig(f.ctx, f.cluster.Nodes[0].DB)
	if err != nil {
		t.Fatal(err)
	}
	cert := corrosion.ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: cfg.Generation, ValueDigest: value.MustDigest()}
	for _, n := range f.cluster.Nodes {
		signer, err := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
		if err != nil {
			t.Fatal(err)
		}
		r, err := n.DB.ClaimAccept(f.ctx, key, ballot, value, cfg.Generation, signer, nil)
		if err != nil || !r.Accepted || r.Accept == nil {
			t.Fatalf("fixture voter refused: %v %s", err, r.Refusal)
		}
		cert.Accepts = append(cert.Accepts, *r.Accept)
	}
	return corrosion.AutomationRecord{Value: value, Certificate: cert}
}
