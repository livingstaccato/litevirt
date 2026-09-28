// Fleet scenarios: the explicit voter set and the voter side of recovery
// claims (colonelpanik/litevirt#251 step 2; docs/design/recovery-claims.md
// §3–§4, §7.1).
//
// Every scenario here is multi-node by construction: a decision is a quorum of
// independent voters' durable promises, a generation is adopted by each node
// from its OWN replica once the certificate verifies, and seal-and-transfer
// moves claim state between generations over the claim RPCs. So they run over
// independent replicas and real gRPC, with LinkFault.BlockClaims to take
// individual voters out of a decision without touching replication.
package fleet

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// OpenVoterConfigGate is voter_config_v1 durably latching on every node: the
// daemon wires the gate to the durable marker, and a single-build fleet has
// nothing to wait for.
func openVoterConfigGates(c *Cluster) {
	for _, n := range c.Nodes {
		n.DB.SetVoterConfigGate(func() bool { return true })
	}
}

// adoptAll runs the adoption pass on every given node (all when none are
// given) until each has adopted generation gen — the daemon's adoption loop,
// driven by the scenario.
func adoptAll(t *testing.T, c *Cluster, gen int64, nodes ...*Node) {
	t.Helper()
	if len(nodes) == 0 {
		nodes = c.Nodes
	}
	ctx := context.Background()
	eventually(t, convergeTimeout, fmt.Sprintf("every node to adopt voter generation %d", gen), func() bool {
		for _, n := range nodes {
			got, _ := n.Server.AdoptVoterConfigs(ctx)
			if got < gen {
				return false
			}
		}
		return true
	})
}

func adoptedGen(t *testing.T, n *Node) int64 {
	t.Helper()
	g, err := corrosion.AdoptedVoterGeneration(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("%s: adopted generation: %v", n.Name, err)
	}
	return g
}

func voterNames(t *testing.T, n *Node) []string {
	t.Helper()
	vs, err := corrosion.VoterSet(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("%s: VoterSet: %v", n.Name, err)
	}
	var out []string
	for v := range vs {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func nodeNames(ns ...*Node) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return out
}

func voterRow(t *testing.T, n *Node, gen int64) *corrosion.VoterConfig {
	t.Helper()
	row, err := corrosion.GetVoterConfig(context.Background(), n.DB, gen)
	if err != nil {
		t.Fatalf("%s: voter_configs %d: %v", n.Name, gen, err)
	}
	return row
}

// runGenesis latches voter_config_v1 and lets node-0's coordinator, the lease
// holder, write generation 1 on a clean cluster.
func runGenesis(t *testing.T, c *Cluster) {
	t.Helper()
	openVoterConfigGates(c)
	cs := c.NewCoordinators(NewVirtualClock(time.Now().UTC()))
	cs.Tick(context.Background(), c.Nodes[0])
	if voterRow(t, c.Nodes[0], 1) == nil {
		t.Fatal("automatic genesis wrote no generation on a clean cluster")
	}
	adoptAll(t, c, 1)
}

func setHostState(t *testing.T, c *Cluster, host *Node, state string) {
	t.Helper()
	if err := corrosion.UpdateHostState(context.Background(), c.Nodes[0].DB, host.Name, state); err != nil {
		t.Fatalf("set %s %s: %v", host.Name, state, err)
	}
	eventually(t, convergeTimeout, fmt.Sprintf("%s to read %s everywhere", host.Name, state), func() bool {
		for _, n := range c.Nodes {
			h, err := corrosion.GetHost(context.Background(), n.DB, host.Name)
			if err != nil || h == nil || h.State != state {
				return false
			}
		}
		return true
	})
}

// blockClaimsInto takes n out of every other node's claims, leaving
// replication alone.
func blockClaimsInto(c *Cluster, n *Node) {
	for _, o := range c.Nodes {
		if o != n {
			c.SetLinkFault(o, n, LinkFault{BlockClaims: true})
		}
	}
}

func workloadClaimValue(key corrosion.ClaimKey, dest, id string) corrosion.ClaimValue {
	return corrosion.ClaimValue{
		Proof: &corrosion.ActionProof{ID: id, Action: "reschedule", TargetKind: key.TargetKind,
			TargetName: key.TargetName, DestHost: dest, Coordinator: dest,
			OwnerEpoch: fmt.Sprint(key.OwnerEpoch), LeaseKey: corrosion.LeaseKeyFailover},
		// No hosts row answers to it, so every voter's owner probe fails to
		// reach it, as it would a powered-off owner (§3.5.1).
		SourceHost: "powered-off-owner",
	}
}

// ── scenarios ───────────────────────────────────────────────────────────────

// TestFleet_VoterGenesis_WaitsForACleanCluster: with voter_config_v1 latched
// and node-4 in maintenance, automatic genesis writes nothing and
// ha.voter.genesis_pending names node-4; ending the maintenance writes
// generation 1 with all five members on the next tick, and every node adopts
// it.
//
// Mutation: drop the clean-cluster check in VoterGenesisTick — genesis writes
// four members while node-4 is away, and the test goes red.
func TestFleet_VoterGenesis_WaitsForACleanCluster(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 2511})
	c.WaitConverged(t, convergeTimeout)
	openVoterConfigGates(c)
	lead, away := c.Nodes[0], c.Nodes[4]
	setHostState(t, c, away, "maintenance")

	cs := c.NewCoordinators(NewVirtualClock(time.Now().UTC()))
	cs.Tick(ctx, lead)
	if empty, err := corrosion.VoterConfigsEmpty(ctx, lead.DB); err != nil || !empty {
		t.Fatalf("genesis wrote a generation while %s was in maintenance (err %v); members=%v",
			away.Name, err, voterRow(t, lead, 1).Names())
	}
	cond, found, err := corrosion.GetHealthCondition(ctx, lead.DB, "voter_config", "ha.voter.genesis_pending", "cluster", "voters")
	if err != nil || !found || cond.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("ha.voter.genesis_pending is not raised: %+v found=%v err=%v", cond, found, err)
	}
	if !slices.Contains(cond.Hosts, away.Name) || !strings.Contains(cond.Evidence, "maintenance") {
		t.Fatalf("the condition does not name %s and its state: hosts=%v evidence=%s", away.Name, cond.Hosts, cond.Evidence)
	}

	setHostState(t, c, away, "active")
	cs.Tick(ctx, lead)
	row := voterRow(t, lead, 1)
	if row == nil {
		t.Fatal("genesis did not run once the cluster was clean")
	}
	if got, want := row.Names(), nodeNames(c.Nodes...); !slices.Equal(got, want) {
		t.Fatalf("generation 1 members = %v, want every host %v", got, want)
	}
	adoptAll(t, c, 1)
	for _, n := range c.Nodes {
		if got := voterNames(t, n); !slices.Equal(got, nodeNames(c.Nodes...)) {
			t.Errorf("%s counts voters %v after adopting generation 1", n.Name, got)
		}
	}
	cond, _, _ = corrosion.GetHealthCondition(ctx, lead.DB, "voter_config", "ha.voter.genesis_pending", "cluster", "voters")
	if cond.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("ha.voter.genesis_pending stayed %s after genesis", cond.Lifecycle)
	}
}

// TestFleet_VoterGenesis_AcrossALeaseHandOff: two nodes that each believe
// they hold the leader lease — their replication is cut, so neither sees the
// other's lease row — both propose genesis. Exactly one generation-1 value is
// decided, and every node adopts it.
//
// Mutation: write generation 1 without the claim (each proposer writes its
// own value) — the two nodes hold different generation-1 rows and the test
// goes red.
func TestFleet_VoterGenesis_AcrossALeaseHandOff(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2512})
	c.WaitConverged(t, convergeTimeout)
	openVoterConfigGates(c)
	a, b := c.Nodes[0], c.Nodes[1]
	// Replication only: the claim RPCs are ordinary gRPC and still reach
	// every voter, which is what lets the two lease holders decide one value.
	c.Isolate(a)
	c.Isolate(b)
	cs := c.NewCoordinators(NewVirtualClock(time.Now().UTC()))
	cs.Tick(ctx, a, b)
	for _, n := range []*Node{a, b} {
		if cs.ByNode[n.Name].LeaseTerm() == 0 {
			t.Fatalf("%s did not take the lease; the scenario needs two lease holders", n.Name)
		}
	}
	c.ClearLinkFaults()
	adoptAll(t, c, 1)

	first := voterRow(t, c.Nodes[0], 1)
	for _, n := range c.Nodes {
		row := voterRow(t, n, 1)
		if row == nil || row.MembersHash != first.MembersHash || row.CreatedBy != first.CreatedBy ||
			row.CreatedAt != first.CreatedAt || row.Change != first.Change {
			t.Fatalf("%s holds a different generation-1 value: %+v vs %+v", n.Name, row, first)
		}
		if adoptedGen(t, n) != 1 {
			t.Fatalf("%s adopted generation %d", n.Name, adoptedGen(t, n))
		}
	}
	// Two proposers that completed one decision can hold two valid
	// certificates for it; anti-entropy settles on one.
	for _, x := range c.Nodes {
		for _, y := range c.Nodes {
			if x != y {
				if err := x.DB.MergeStateBytesLWW(y.DB.DumpStateBytes()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms"})
}

// TestFleet_VoterReset_DecidedAndSticky: after genesis, `lv cluster voter
// reset` with one voter unreachable is decided by the other four. Every node's
// VoterSet becomes derived at the same generation, and automatic genesis does
// not run again on later ticks.
//
// Mutations: adopt a reset on the deciding node only (the others keep the
// explicit set) — the nodes disagree on VoterSet; let automatic genesis run
// after a reset — a generation 3 appears.
func TestFleet_VoterReset_DecidedAndSticky(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 2513})
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	parked, unreachable := c.Nodes[3], c.Nodes[4]
	// A member in maintenance: the explicit set counts it, the derived set does
	// not, so the two are told apart.
	setHostState(t, c, parked, "maintenance")
	for _, n := range c.Nodes {
		if got := voterNames(t, n); !slices.Equal(got, nodeNames(c.Nodes...)) {
			t.Fatalf("%s: before the reset the explicit set counts %v", n.Name, got)
		}
	}
	blockClaimsInto(c, unreachable)
	resp, err := c.SelfClient(c.Nodes[0]).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "reset"})
	if err != nil {
		t.Fatalf("reset with four of five voters reachable: %v", err)
	}
	if resp.GetGeneration() != 2 || resp.GetChange() != corrosion.VoterChangeReset {
		t.Fatalf("reset decided %+v", resp)
	}
	adoptAll(t, c, 2)
	want := nodeNames(c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[4])
	for _, n := range c.Nodes {
		if g := adoptedGen(t, n); g != 2 {
			t.Errorf("%s adopted generation %d, want 2", n.Name, g)
		}
		if got := voterNames(t, n); !slices.Equal(got, want) {
			t.Errorf("%s counts %v after the reset, want the derived set %v", n.Name, got, want)
		}
	}
	c.ClearLinkFaults()
	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	for i := 0; i < 3; i++ {
		cs.Tick(ctx, c.Nodes[0])
		clock.Advance(10 * time.Second)
	}
	rows, err := corrosion.ListVoterConfigs(ctx, c.Nodes[0].DB)
	if err != nil || len(rows) != 2 {
		t.Fatalf("automatic genesis ran again after a reset: %d generations (err %v)", len(rows), err)
	}
}

// TestFleet_VoterSet_SurvivesTheKillSwitch: once a generation is adopted, the
// voter set is its members on every node whatever host state and flags say —
// two fenced members still count in the denominator, so the quorum a node
// needs is a majority of five, not of the three it can see. The
// enforcement.recovery_claim kill switch arrives with recovery_claim_v1
// (colonelpanik/litevirt#250); no flag in this build reaches VoterSet, and
// every enforcement flag is off here.
//
// Mutation: make VoterSet fall back to the derived set — the fenced members
// drop out and the needed quorum falls to 2.
func TestFleet_VoterSet_SurvivesTheKillSwitch(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 2514})
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	setHostState(t, c, c.Nodes[3], "fenced")
	setHostState(t, c, c.Nodes[4], "fenced")
	for _, n := range c.Nodes {
		n.Server.SetEnforcementConfig(false, false, false, false, false, false)
		if got := voterNames(t, n); !slices.Equal(got, nodeNames(c.Nodes...)) {
			t.Errorf("%s counts %v; a fenced member must stay in the voter set until `lv cluster voter rm`", n.Name, got)
		}
		_, _, needed := health.NewChecker(n.Name, n.PKIDir, n.DB).QuorumProof(ctx)
		if needed != 3 {
			t.Errorf("%s needs %d for quorum; the denominator must be the five members", n.Name, needed)
		}
	}
}

// TestFleet_VoterSet_SealAndTransferAfterTwoRemovals is §4.4's example: with
// {0,1,2,3,4} and a value chosen by {0,1,2}, remove node-0 and then node-1;
// {3,4} is a majority of {2,3,4} that never saw the value. It survives
// because each generation imports from a sealed majority of the one before,
// so a later proposer reaching only {3,4} still learns it.
//
// Mutation: skip the import (adopt without importing) — node-3's proposer
// decides its own value and the test goes red.
func TestFleet_VoterSet_SealAndTransferAfterTwoRemovals(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 2515})
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	n0, n1, n2, n3, n4 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-sealed", OwnerEpoch: 7}
	v := workloadClaimValue(key, n2.Name, "proof-chosen")

	// Chosen by {0,1,2} only.
	c.SetLinkFault(n0, n3, LinkFault{BlockClaims: true})
	c.SetLinkFault(n0, n4, LinkFault{BlockClaims: true})
	out, err := n0.Server.DecideRecoveryClaim(ctx, key, v, 1)
	if err != nil {
		t.Fatalf("decide under generation 1: %v", err)
	}
	if got := len(out.Certificate.Accepts); got != 3 {
		t.Fatalf("the value was accepted by %d voters, want exactly {0,1,2}", got)
	}
	c.ClearLinkFaults()

	for _, step := range []struct {
		via, host *Node
		gen       int64
	}{{n1, n0, 2}, {n2, n1, 3}} {
		resp, err := c.SelfClient(step.via).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: step.host.Name})
		if err != nil || resp.GetGeneration() != step.gen {
			t.Fatalf("rm %s: %+v %v", step.host.Name, resp, err)
		}
		adoptAll(t, c, step.gen)
	}
	if got := voterRow(t, n3, 3).Names(); !slices.Equal(got, nodeNames(n2, n3, n4)) {
		t.Fatalf("generation 3 = %v", got)
	}

	// A proposer that reaches only {3,4} — a majority of generation 3.
	c.SetLinkFault(n3, n2, LinkFault{BlockClaims: true})
	late, err := n3.Server.DecideRecoveryClaim(ctx, key, workloadClaimValue(key, n3.Name, "proof-late"), 1)
	if err != nil {
		t.Fatalf("decide under generation 3: %v", err)
	}
	if late.Digest != v.MustDigest() || late.Ours {
		t.Fatalf("after two removals a majority of generation 3 decided a second value for one key "+
			"(dest %s, ours=%v); the value chosen in generation 1 was lost", late.Value.Proof.DestHost, late.Ours)
	}
}

// TestFleet_Voter_ChangedIncarnationAbstains: a voter whose state.db was
// recreated abstains — it refuses to promise under its old member entry,
// `lv cluster voter ls` shows it, and the remaining majority still decides.
// `lv cluster voter rm` then `add` heals it (§3.11).
//
// Mutation: skip the incarnation comparison in the voter's membership check —
// the amnesiac voter's accept lands in the certificate.
func TestFleet_Voter_ChangedIncarnationAbstains(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2516})
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	n0, amnesiac := c.Nodes[0], c.Nodes[2]
	if _, err := amnesiac.DB.ReplaceVoterIncarnationForTest(ctx); err != nil {
		t.Fatal(err)
	}
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-amnesia", OwnerEpoch: 1}
	out, err := n0.Server.DecideRecoveryClaim(ctx, key, workloadClaimValue(key, n0.Name, "proof-a"), 1)
	if err != nil {
		t.Fatalf("the remaining majority could not decide: %v", err)
	}
	for _, a := range out.Certificate.Accepts {
		if a.Voter == amnesiac.Name {
			t.Fatalf("%s voted under an incarnation it no longer has", amnesiac.Name)
		}
	}
	got, err := c.SelfClient(amnesiac).GetRecoveryClaim(ctx, &pb.GetRecoveryClaimRequest{
		Key: &pb.RecoveryClaimKey{TargetKind: key.TargetKind, TargetName: key.TargetName, OwnerEpoch: key.OwnerEpoch}})
	if err != nil || got.GetLastRefusalReason() != corrosion.RefusalIncarnationMismatch {
		t.Fatalf("%s's refusal is not visible: %+v %v", amnesiac.Name, got, err)
	}
	ls, err := c.SelfClient(n0).GetVoterConfig(ctx, &pb.GetVoterConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ls.GetMembers() {
		if (m.GetName() == amnesiac.Name) != m.GetAbstaining() {
			t.Errorf("lv cluster voter ls: %s abstaining=%v", m.GetName(), m.GetAbstaining())
		}
	}

	for i, op := range []string{"rm", "add"} {
		if _, err := c.SelfClient(n0).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: op, Host: amnesiac.Name}); err != nil {
			t.Fatalf("heal: %s %s: %v", op, amnesiac.Name, err)
		}
		adoptAll(t, c, int64(i+2))
	}
	key2 := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-healed", OwnerEpoch: 1}
	c.SetLinkFault(n0, c.Nodes[1], LinkFault{BlockClaims: true})
	if _, err := n0.Server.DecideRecoveryClaim(ctx, key2, workloadClaimValue(key2, n0.Name, "proof-b"), 1); err != nil {
		t.Fatalf("after rm+add the healed voter still does not vote: %v", err)
	}
}

// TestFleet_Voter_DuellingProposersConverge: two coordinators claim one key
// concurrently over real gRPC, each for its own destination. Both return the
// same decided value, and exactly one of them decided its own.
//
// Mutation: make the proposer ignore accepted values in promises — both
// decide their own destination.
func TestFleet_Voter_DuellingProposersConverge(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2517})
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-duel", OwnerEpoch: 3}
	var wg sync.WaitGroup
	outs := make([]claims.Outcome, 2)
	errs := make([]error, 2)
	for i, n := range c.Nodes[:2] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], errs[i] = n.Server.DecideRecoveryClaim(ctx, key, workloadClaimValue(key, n.Name, "proof-"+n.Name), 1)
		}()
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("proposer %s: %v", c.Nodes[i].Name, errs[i])
		}
	}
	if outs[0].Digest != outs[1].Digest {
		t.Fatalf("duelling proposers decided %s and %s", outs[0].Value.Proof.DestHost, outs[1].Value.Proof.DestHost)
	}
	if outs[0].Ours == outs[1].Ours {
		t.Fatalf("exactly one proposer's own value should win (ours %v/%v)", outs[0].Ours, outs[1].Ours)
	}
}
