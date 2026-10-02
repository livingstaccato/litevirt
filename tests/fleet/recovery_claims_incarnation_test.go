// Fleet scenarios: a recovery claim belongs to ONE incarnation of a workload
// (docs/design/recovery-claims.md §3.1, §10 item 37).
//
// A claim used to be keyed by (kind, name, owner epoch, attempt). A workload
// deleted and re-created under the same name starts again at the same owner
// epoch, so its first recovery met the previous incarnation's decided value at
// the same key: Paxos made the coordinator re-propose it, and every voter whose
// row named the new owner refused it as a source mismatch. On the kvm003 lab
// (2026-10-01) the re-created VM was never recovered. The key now carries the
// incarnation — the row's created_at — so a re-created workload starts with a
// fresh claim history.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// incarnationFleet is five hosts, every one a voter, recovery claims enforced,
// and a's coordinator with its decision gate forced open, so what is under
// test is the claim and not the coordinator's health view.
func incarnationFleet(t *testing.T, seed int64, place func(c *Cluster, a, victim *Node)) (*Cluster, *Coordinators, *VirtualClock) {
	t.Helper()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: seed})
	place(c, c.Nodes[0], c.Nodes[4])
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, c.Nodes[0])
	enableRecoveryClaims(t, c)
	clock := NewVirtualClock(time.Now().UTC())
	return c, probeCoordinator(c, clock, c.Nodes[0]), clock
}

// failHost kills host and has every survivor publish its failed probe of it.
// It returns the survivors.
func failHost(t *testing.T, c *Cluster, clock *VirtualClock, dead map[string]bool, host *Node) []*Node {
	t.Helper()
	dead[host.Name] = true
	c.Kill(host)
	var alive []*Node
	for _, n := range c.Nodes {
		if !dead[n.Name] {
			alive = append(alive, n)
		}
	}
	for _, n := range alive {
		PublishHealth(t, n, host.Name, 5, clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	return alive
}

// otherThan is the first of nodes that is none of not.
func otherThan(t *testing.T, nodes []*Node, not ...*Node) *Node {
	t.Helper()
	skip := map[string]bool{}
	for _, n := range not {
		skip[n.Name] = true
	}
	for _, n := range nodes {
		if !skip[n.Name] {
			return n
		}
	}
	t.Fatalf("no node other than %v", skip)
	return nil
}

// TestFleet_RecoveryClaim_ARecreatedVMGetsAFreshClaim is the lab case. A VM is
// recovered once under a claim, deleted, re-created under the same name on
// another host at the same owner epoch, and that host dies too. The new VM
// must be recovered exactly once, through a claim of its own.
//
// Mutation: key the claim without the incarnation (Server.ClaimKeyFor returns
// the legacy key) — the coordinator meets the first VM's decided value at the
// shared key and must re-propose it; the voters that accepted it before
// re-accept it without a check, and the new VM is pointed at the first
// incarnation's spent proof, which never runs. (On the lab the voters that
// held it were too few, the rest refused it as a source mismatch, and the VM
// was never recovered at all.)
func TestFleet_RecoveryClaim_ARecreatedVMGetsAFreshClaim(t *testing.T) {
	ctx := context.Background()
	const name = "claimvm"
	c, cs, clock := incarnationFleet(t, 2561, func(_ *Cluster, a, victim *Node) {
		insertVM(t, a, name, victim.Name)
	})
	a := c.Nodes[0]
	dead := map[string]bool{}
	epoch := vmOn(t, a, name).OwnerEpoch

	// The first incarnation: its host dies, a claim decides, the destination
	// starts it.
	first := c.Nodes[4]
	alive := failHost(t, c, clock, dead, first)
	cs.Tick(ctx, a)
	vm := vmOn(t, a, name)
	if vm.PendingActionID == "" || vm.HostName == first.Name {
		t.Fatalf("the first incarnation was not recovered under a claim: %+v", vm)
	}
	firstProof := vm.PendingActionID
	dest1 := c.Node(vm.HostName)
	c.WaitConverged(t, convergeTimeout, alive...)
	claimReconciler(t, dest1).ReconcileOnce(ctx)
	c.WaitConverged(t, convergeTimeout, alive...)
	if st, _ := dest1.Virt.DomainState(name); st != string(libvirtfake.StateRunning) {
		t.Fatalf("the first incarnation is not running on %s after its recovery: %q", dest1.Name, st)
	}

	// Deleted, and re-created under the same name on a third host. It starts
	// at the epoch the first incarnation's claim was keyed at, which is the
	// collision the lab hit.
	mustDeleteVM(t, dest1, name)
	c.WaitConverged(t, convergeTimeout, alive...)
	second := otherThan(t, alive, a, dest1)
	insertVM(t, a, name, second.Name)
	c.WaitConverged(t, convergeTimeout, alive...)
	if got := vmOn(t, a, name).OwnerEpoch; got != epoch {
		t.Fatalf("the re-created VM starts at owner epoch %d, not %d; the scenario needs the collision", got, epoch)
	}

	// Its host dies too.
	alive = failHost(t, c, clock, dead, second)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	vm = vmOn(t, a, name)
	if vm.PendingActionID == "" || vm.HostName == second.Name {
		t.Fatalf("the re-created VM was not recovered: %+v (a previous incarnation's decision answered its claim?)", vm)
	}
	if vm.PendingActionID == firstProof {
		t.Fatalf("the re-created VM was pointed at the first incarnation's proof %s", firstProof)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, vm.PendingActionID)
	if err != nil || !ok || pr.ClaimCertificate == "" {
		t.Fatalf("the re-created VM's proof carries no certificate: ok=%v err=%v", ok, err)
	}
	dest2 := c.Node(vm.HostName)
	c.WaitConverged(t, convergeTimeout, alive...)
	claimReconciler(t, dest2).ReconcileOnce(ctx)

	owners := 0
	for _, n := range alive {
		if st, _ := n.Virt.DomainState(name); st == string(libvirtfake.StateRunning) {
			owners++
			if n != dest2 {
				t.Errorf("%s runs %s, but the claim decided %s", n.Name, name, dest2.Name)
			}
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners of the re-created VM after its recovery, want 1", owners)
	}
	assertFreshIncarnationClaim(t, a, pr.ActionProof, vmOn(t, a, name).CreatedAt)
}

// TestFleet_RecoveryClaim_ARecreatedContainerGetsAFreshClaim is the same for
// the container relocation path, which is keyed the same way.
//
// Mutation: as for the VM — key the claim without the incarnation, and the
// re-created container is re-keyed under the first incarnation's decision:
// its proof, its relocation token, its destination.
func TestFleet_RecoveryClaim_ARecreatedContainerGetsAFreshClaim(t *testing.T) {
	ctx := context.Background()
	const name = "claimct"
	upsert := func(n *Node, host string) {
		if err := corrosion.UpsertContainer(ctx, n.DB, corrosion.ContainerRecord{
			HostName: host, Name: name, Image: "docker.io/library/alpine:3.19",
			State: "running", OnHostFailure: "image-recreate", MemMiB: 512,
		}); err != nil {
			t.Fatalf("seed container on %s: %v", host, err)
		}
	}
	c, cs, clock := incarnationFleet(t, 2562, func(_ *Cluster, a, victim *Node) { upsert(a, victim.Name) })
	a := c.Nodes[0]
	dead := map[string]bool{}
	ct, err := corrosion.GetContainer(ctx, a.DB, c.Nodes[4].Name, name)
	if err != nil || ct == nil {
		t.Fatalf("read the container: %v %+v", err, ct)
	}
	epoch := ct.OwnerEpoch

	first := c.Nodes[4]
	alive := failHost(t, c, clock, dead, first)
	cs.Tick(ctx, a)
	hosts := liveContainerHosts(t, a, name)
	if len(hosts) != 1 || hosts[0] == first.Name {
		t.Fatalf("the first incarnation was not relocated under a claim: live on %v", hosts)
	}
	dest1 := c.Node(hosts[0])
	c.WaitConverged(t, convergeTimeout, alive...)
	moved, err := corrosion.GetContainer(ctx, a.DB, dest1.Name, name)
	if err != nil || moved == nil || moved.RelocateToken == "" {
		t.Fatalf("the first relocation carries no token: %v %+v", err, moved)
	}
	firstToken := moved.RelocateToken
	recreatedOn(t, c, dest1, name, alive)

	if err := corrosion.DeleteContainer(ctx, a.DB, dest1.Name, name); err != nil {
		t.Fatalf("delete the first incarnation: %v", err)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	second := otherThan(t, alive, a, dest1)
	upsert(a, second.Name)
	c.WaitConverged(t, convergeTimeout, alive...)
	ct, err = corrosion.GetContainer(ctx, a.DB, second.Name, name)
	if err != nil || ct == nil {
		t.Fatalf("read the re-created container: %v %+v", err, ct)
	}
	if ct.OwnerEpoch != epoch {
		t.Fatalf("the re-created container starts at owner epoch %d, not %d; the scenario needs the collision", ct.OwnerEpoch, epoch)
	}

	alive = failHost(t, c, clock, dead, second)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	hosts = liveContainerHosts(t, a, name)
	if len(hosts) != 1 || hosts[0] == second.Name {
		t.Fatalf("the re-created container was not relocated: live on %v (a previous incarnation's decision answered its claim?)", hosts)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	for _, n := range alive {
		if got := liveContainerHosts(t, n, name); len(got) != 1 || got[0] != hosts[0] {
			t.Errorf("%s's replica has the re-created container live on %v, want only %s", n.Name, got, hosts[0])
		}
	}
	moved, err = corrosion.GetContainer(ctx, a.DB, hosts[0], name)
	if err != nil || moved == nil {
		t.Fatalf("read the relocated container: %v", err)
	}
	if moved.RelocateToken == "" || moved.RelocateToken == firstToken {
		t.Fatalf("the re-created container was relocated under token %q, the first incarnation's was %q: "+
			"a previous incarnation's decision answered its claim", moved.RelocateToken, firstToken)
	}
	rows, err := a.DB.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE relocation_token = ? AND deleted_at IS NULL`, moved.RelocateToken)
	if err != nil || len(rows) != 1 {
		t.Fatalf("no single relocation proof carries the re-created container's token: %v %d", err, len(rows))
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, rows[0].String("id"))
	if err != nil || !ok {
		t.Fatalf("read the relocation proof: ok=%v err=%v", ok, err)
	}
	assertFreshIncarnationClaim(t, a, pr.ActionProof, ct.CreatedAt)
	recreatedOn(t, c, c.Node(hosts[0]), name, alive)
}

// recreatedOn runs dest's container checker, wired as the daemon wires it
// (claimContainerChecker), and requires it to have claimed the relocation
// proof under its certificate and recreated the container: a relocation the
// destination refuses leaves the row pending forever, its source already
// tombstoned.
func recreatedOn(t *testing.T, c *Cluster, dest *Node, name string, alive []*Node) {
	t.Helper()
	ctx := context.Background()
	var refused []string
	cc := claimContainerChecker(t, dest)
	cc.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })
	cc.SweepOnce(ctx)
	c.WaitConverged(t, convergeTimeout, alive...)
	row, err := corrosion.GetContainer(ctx, dest.DB, dest.Name, name)
	if err != nil || row == nil {
		t.Fatalf("%s: read %s: %v", dest.Name, name, err)
	}
	if !dest.CT.Exists(name) || row.StateDetail == corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("%s did not recreate %s from its relocation (refusals %v): row %+v", dest.Name, name, refused, row)
	}
	pr, ok, err := corrosion.GetActionProofByToken(ctx, dest.DB, row.RelocateToken)
	if err != nil || !ok || pr.ExecutorHost != dest.Name {
		t.Fatalf("%s: the relocation proof was not claimed here: ok=%v err=%v %+v", dest.Name, ok, err, pr)
	}
}

// assertFreshIncarnationClaim checks that the certificate on p decides p's
// own target at attempt 0 of the incarnation whose created_at is createdAt,
// and that no voter holds anything at that incarnation's later attempts: the
// re-created workload started with a fresh claim, not a superseded one.
func assertFreshIncarnationClaim(t *testing.T, n *Node, p corrosion.ActionProof, createdAt string) {
	t.Helper()
	cert, err := corrosion.DecodeClaimCertificate(p.ClaimCertificate)
	if err != nil {
		t.Fatalf("proof %s: %v", p.ID, err)
	}
	if createdAt == "" {
		t.Fatal("the re-created workload has no created_at; the scenario cannot name its incarnation")
	}
	want, err := corrosion.ClaimKeyForProof(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	want.Incarnation = createdAt
	if cert.Key != want {
		t.Fatalf("proof %s's certificate decides %s, want %s", p.ID, cert.Key, want)
	}
	next := want
	next.Attempt = 1
	for _, v := range n.cluster.Nodes {
		if st, found, err := v.DB.ClaimState(context.Background(), next); err == nil && found && !st.Promised.IsZero() {
			t.Errorf("%s holds state at %s: the claim moved past attempt 0", v.Name, next)
		}
	}
}

// preIncarnationGate is claimsGate on a node where claim_incarnation_v1 has
// not latched yet: claims enforced, keyed the legacy way.
type preIncarnationGate struct{ claimsGate }

func preIncarnationLatched(tok string) bool {
	return claimsLatched(tok) && tok != capabilities.ClaimIncarnationV1
}
func (preIncarnationGate) CapabilityActive(_ context.Context, tok string) (bool, string) {
	return preIncarnationLatched(tok), ""
}
func (preIncarnationGate) CapabilityActiveForHealth(_ context.Context, tok string) (bool, string) {
	return preIncarnationLatched(tok), ""
}
func (preIncarnationGate) Enforced(_ context.Context, tok string) bool {
	return preIncarnationLatched(tok)
}
func (preIncarnationGate) Latched(tok string) bool        { return preIncarnationLatched(tok) }
func (preIncarnationGate) DurablyLatched(tok string) bool { return preIncarnationLatched(tok) }

// latchIncarnation sets every node's gate: before claim_incarnation_v1 has
// latched (false) or after (true).
func latchIncarnation(c *Cluster, latched bool) {
	for _, n := range c.Nodes {
		latchIncarnationOn(n, latched)
	}
}

// latchIncarnationOn is latchIncarnation for one node: its server's gate, and
// the corrosion gate the daemon wires to the same durable latch.
func latchIncarnationOn(n *Node, latched bool) {
	if latched {
		n.Server.SetGate(claimsGate{})
	} else {
		n.Server.SetGate(preIncarnationGate{})
	}
	n.DB.SetClaimIncarnationGate(func() bool { return latched })
}

// TestFleet_RecoveryClaim_ALegacyDecisionIsCompletedAcrossTheLatch: a
// coordinator decided a recovery at the legacy key before
// claim_incarnation_v1 latched and died before it wrote the proof. Its
// successor, after the latch, claims the incarnation-scoped key: the voters'
// promises report the legacy decision, and the successor completes THAT
// recovery — the same proof, the same destination — rather than deciding a
// second one. The voters' legacy key is sealed from then on.
//
// Mutations: drop the AdoptLegacy block in the proposer — the successor
// decides its own proof; drop the legacy-key seal in the voter — the late
// legacy Prepare is promised.
func TestFleet_RecoveryClaim_ALegacyDecisionIsCompletedAcrossTheLatch(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2563, "vm-bridge")
	latchIncarnation(c, false)
	c.Kill(d)
	legacy := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-bridge"}
	p := corrosion.ActionProof{ID: "decided-before-the-latch", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-bridge", DestHost: b.Name, Coordinator: cc.Name, OwnerEpoch: "0"}
	if _, err := cc.Server.DecideRecoveryClaim(ctx, legacy, corrosion.ClaimValue{Proof: &p, SourceHost: d.Name}, 1, nil); err != nil {
		t.Fatalf("decide at the legacy key: %v", err)
	}

	// The latch forms; cc's coordinator is gone, a's takes over.
	latchIncarnation(c, true)
	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), a)
	cs.Tick(ctx, a)
	vm := vmOn(t, a, "vm-bridge")
	if vm.PendingActionID != p.ID || vm.HostName != b.Name {
		t.Fatalf("the successor did not complete the legacy decision (proof %s to %s): %+v", p.ID, b.Name, vm)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, p.ID)
	if err != nil || !ok {
		t.Fatalf("read the completed proof: ok=%v err=%v", ok, err)
	}
	cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
	if err != nil || cert.Key.Incarnation == "" || !cert.Key.SameDecision(legacy) {
		t.Fatalf("the completed proof's certificate decides %s (%v), want %s at its incarnation", cert.Key, err, legacy)
	}

	// A coordinator that has not latched yet tries the legacy key again.
	resp, err := c.PeerClient(cc, b).PrepareRecoveryClaim(ctx, &pb.PrepareRecoveryClaimRequest{
		Key: claimKeyPB(legacy), Ballot: &pb.ClaimBallot{Round: 99, Coordinator: cc.Name, BootNonce: []byte{7}},
		ConfigGeneration: 2})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetPromised() || resp.GetRefusalReason() != corrosion.RefusalLegacyKeySealed {
		t.Fatalf("a legacy Prepare after the scoped claim = %+v, want %s", resp, corrosion.RefusalLegacyKeySealed)
	}
}

// TestFleet_RecoveryClaim_APreviousIncarnationsLegacyDecisionIsLeftBehind is
// the lab case across an upgrade. The first VM's recovery was decided at the
// legacy key before claim_incarnation_v1 latched; the VM was deleted before it
// ran, re-created on another host at the same epoch, and that host died after
// the latch. The bridge reports the old decision; its destination shows from
// its own database that the proof never started and the new VM is not
// pending on it, and abandons it; the new VM is recovered through a fresh
// claim, and the old proof never runs.
//
// The "exclusion-unavailable" run is the same with the destination unable to
// answer the exclusion (an older build): ambiguity costs liveness, never a
// second decision — the old value is re-proposed, the voters refuse it,
// nothing is minted, and ha.claim.legacy_held names the workload. Once the
// destination answers, the next tick recovers it.
//
// Mutations: make legacyValueExcluded return false — the old value is
// re-proposed, refused, and the VM is never recovered; make it return true
// without the destination's word — the blocked run decides a fresh value
// beside a decision nobody excluded.
func TestFleet_RecoveryClaim_APreviousIncarnationsLegacyDecisionIsLeftBehind(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "excluded", true: "exclusion-unavailable"}[blocked], func(t *testing.T) {
			runPreviousIncarnationLeftBehind(t, blocked)
		})
	}
}

func runPreviousIncarnationLeftBehind(t *testing.T, blocked bool) {
	ctx := context.Background()
	const name = "claimvm"
	c, cs, clock := incarnationFleet(t, 2564, func(_ *Cluster, a, victim *Node) {
		insertVM(t, a, name, victim.Name)
		// a's capacity is full, so no placement picks the coordinator itself:
		// the decision's destination is a peer, whose exclusion goes over the
		// wire (and can be refused as an older build would).
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: "full-" + a.Name, HostName: a.Name,
			Spec: `{}`, State: "running", CPUActual: 64, MemActual: 262144}, nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	latchIncarnation(c, false)
	a := c.Nodes[0]
	dead := map[string]bool{}

	first := c.Nodes[4]
	alive := failHost(t, c, clock, dead, first)
	cs.Tick(ctx, a)
	vm := vmOn(t, a, name)
	if vm.PendingActionID == "" || vm.HostName == first.Name {
		t.Fatalf("the first incarnation was not recovered under a legacy claim: %+v", vm)
	}
	firstProof := vm.PendingActionID
	pr, _, err := corrosion.GetActionProof(ctx, a.DB, firstProof)
	if err != nil {
		t.Fatal(err)
	}
	if cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate); err != nil || cert.Key.Incarnation != "" {
		t.Fatalf("before the latch the claim was not at the legacy key: %s %v", cert.Key, err)
	}
	dest1 := c.Node(vm.HostName)
	c.WaitConverged(t, convergeTimeout, alive...)

	// Deleted before its destination ran it: the proof stays prepared, so
	// only its source tells the bridge it is a previous incarnation's.
	if err := corrosion.DeleteVM(ctx, a.DB, name); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	second := otherThan(t, alive, a, dest1)
	insertVM(t, a, name, second.Name)
	c.WaitConverged(t, convergeTimeout, alive...)

	latchIncarnation(c, true)
	alive = failHost(t, c, clock, dead, second)
	if blocked {
		if dest1 == a {
			t.Fatalf("the scenario needs the first decision's destination to be a peer of the coordinator, got %s", dest1.Name)
		}
		restore := dest1.DoNotImplement("AbandonRecoveryProof")
		clock.Advance(contentionPoll)
		cs.Tick(ctx, a)
		if v := vmOn(t, a, name); v.HostName != second.Name || v.PendingActionID != "" {
			t.Fatalf("a fresh value was decided beside a legacy decision nobody excluded: %+v", v)
		}
		// The condition is a replicated row: the lease holder's tick keeps it
		// while the workload is held, and every replica holds it.
		a.Server.RecoveryClaimHealthTick(ctx)
		c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms"}, alive...)
		for _, n := range alive {
			row, found, err := corrosion.GetHealthCondition(ctx, n.DB, "recovery_claim", "ha.claim.legacy_held", "vm", name)
			if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved ||
				!strings.Contains(row.Evidence, firstProof) || !strings.Contains(row.Evidence, "enforcement.recovery_claim") {
				t.Fatalf("%s: ha.claim.legacy_held does not name %s, proof %s and its escape: found=%v err=%v %+v",
					n.Name, name, firstProof, found, err, row)
			}
		}
		restore()
	}
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	vm = vmOn(t, a, name)
	if vm.PendingActionID == "" || vm.HostName == second.Name || vm.PendingActionID == firstProof {
		t.Fatalf("the re-created VM was not recovered through a fresh claim (first proof %s): %+v", firstProof, vm)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, vm.PendingActionID)
	if err != nil || !ok {
		t.Fatalf("read the new proof: ok=%v err=%v", ok, err)
	}
	assertFreshIncarnationClaim(t, a, pr.ActionProof, vm.CreatedAt)
	if blocked {
		a.Server.RecoveryClaimHealthTick(ctx)
		if row, found, _ := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.legacy_held", "vm", name); !found ||
			row.Lifecycle != corrosion.ConditionResolved {
			t.Fatalf("ha.claim.legacy_held did not resolve once the workload was recovered: %+v", row)
		}
	}
	if ok, _ := dest1.DB.ProofAbandoned(ctx, firstProof); !ok {
		t.Fatalf("%s decided a fresh value, but %s never abandoned the first decision %s", a.Name, dest1.Name, firstProof)
	}

	// `lv cluster claim vm/claimvm` tells the two keys apart: the scoped key
	// decided for the new destination, and the legacy key still holding the
	// previous incarnation's decision.
	insp, err := c.SelfClient(a).InspectRecoveryClaim(ctx, &pb.InspectRecoveryClaimRequest{Kind: "vm", Name: name})
	if err != nil {
		t.Fatalf("lv cluster claim: %v", err)
	}
	var scopedDest, legacyDest string
	for _, at := range insp.GetAttempts() {
		switch {
		case at.GetKey().GetIncarnation() == vm.CreatedAt && at.GetKey().GetAttempt() == 0:
			scopedDest = at.GetDecidedDest()
		case at.GetKey().GetIncarnation() == "" && at.GetKey().GetAttempt() == 0:
			// Some of the voters that accepted it are dead now, so read what
			// the reachable ones hold rather than whether a majority answers.
			for _, v := range at.GetVoters() {
				if v.GetDestHost() != "" {
					legacyDest = v.GetDestHost()
				}
			}
		}
	}
	if scopedDest != vm.HostName || legacyDest != dest1.Name {
		t.Fatalf("lv cluster claim shows the scoped key decided for %q and the legacy key for %q, want %s and %s",
			scopedDest, legacyDest, vm.HostName, dest1.Name)
	}
}

// TestFleet_RecoveryClaim_ACompletedLegacyDecisionIsReAdopted: a recovery
// decided at the legacy key before claim_incarnation_v1 latched has run and
// completed. A coordinator that still reads the epoch it left claims the
// scoped key after the latch. It must learn the completed decision — a no-op,
// its proof spent — and never decide a second value for the same epoch of the
// same incarnation, whose only remaining guard would be the destination's
// owner-epoch check.
//
// Mutations: drop the epoch check from AbandonForeignProof — the destination
// excludes this incarnation's own completed decision and the lagging claim
// decides its own value; exclude every legacy value without the
// destination's word — the same.
func TestFleet_RecoveryClaim_ACompletedLegacyDecisionIsReAdopted(t *testing.T) {
	ctx := context.Background()
	c, a, b, _, d := probeFleet(t, 2565, "vm-done")
	latchIncarnation(c, false)
	c.Kill(d)
	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), a)
	cs.Tick(ctx, a)
	vm := vmOn(t, a, "vm-done")
	if vm.PendingActionID == "" || vm.HostName == d.Name {
		t.Fatalf("the legacy claim did not decide: %+v", vm)
	}
	decided := vm.PendingActionID
	dest := c.Node(vm.HostName)
	alive := []*Node{a, b, c.Nodes[2]}
	c.WaitConverged(t, convergeTimeout, alive...)
	claimReconciler(t, dest).ReconcileOnce(ctx)
	c.WaitConverged(t, convergeTimeout, alive...)
	if pr, ok, _ := corrosion.GetActionProof(ctx, a.DB, decided); !ok || pr.Status != corrosion.ProofCompleted {
		t.Fatalf("the legacy decision did not complete: %+v", pr)
	}

	// After the latch, a claim at the epoch the VM has already left.
	latchIncarnation(c, true)
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-done", OwnerEpoch: 0,
		Incarnation: vmOn(t, a, "vm-done").CreatedAt}
	w := corrosion.ActionProof{ID: "lagging-second-value", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-done", DestHost: b.Name, Coordinator: a.Name, OwnerEpoch: "0"}
	if dest == b {
		w.DestHost = a.Name
	}
	out, err := a.Server.DecideRecoveryClaim(ctx, key, corrosion.ClaimValue{Proof: &w, SourceHost: d.Name}, 50, nil)
	if err != nil {
		t.Fatalf("the lagging scoped claim: %v", err)
	}
	if out.Ours || out.Value.Proof == nil || out.Value.Proof.ID != decided {
		t.Fatalf("the lagging claim decided %+v (ours=%v), want the completed legacy decision %s", out.Value.Proof, out.Ours, decided)
	}
}

// TestFleet_RecoveryClaim_ASpentDecisionOfAPreviousIncarnationDoesNotWedge:
// incarnation A was recovered under a legacy claim, and its proof ran and
// completed. A is deleted and B re-created at once, on the same host, at the
// same epoch, and that host fails after the latch. The legacy key still holds
// A's spent decision, and its source is B's owner too, so neither time nor
// source tells them apart. The destination that ran it does: B is still at
// the epoch there, so the completion did not move B. It excludes the
// decision, and B's claim decides afresh instead of re-adopting a proof that
// can never run again.
//
// Mutation: make AbandonForeignProof refuse every completed proof — the
// spent decision is adopted, and B waits behind it for good.
func TestFleet_RecoveryClaim_ASpentDecisionOfAPreviousIncarnationDoesNotWedge(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2566, "vm-spent")
	latchIncarnation(c, false)
	c.Kill(d)
	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), a)
	cs.Tick(ctx, a)
	vm := vmOn(t, a, "vm-spent")
	if vm.PendingActionID == "" || vm.HostName == d.Name {
		t.Fatalf("the legacy claim did not decide: %+v", vm)
	}
	spent := vm.PendingActionID
	dest := c.Node(vm.HostName)
	alive := []*Node{a, b, cc}
	c.WaitConverged(t, convergeTimeout, alive...)
	claimReconciler(t, dest).ReconcileOnce(ctx)
	c.WaitConverged(t, convergeTimeout, alive...)
	if pr, ok, _ := corrosion.GetActionProof(ctx, a.DB, spent); !ok || pr.Status != corrosion.ProofCompleted {
		t.Fatalf("A's decision did not complete: %+v", pr)
	}

	// A deleted; B re-created on d — dead, as it is about to be again — at
	// epoch 0.
	mustDeleteVM(t, dest, "vm-spent")
	c.WaitConverged(t, convergeTimeout, alive...)
	insertVM(t, a, "vm-spent", d.Name)
	c.WaitConverged(t, convergeTimeout, alive...)
	bRow := vmOn(t, a, "vm-spent")
	if bRow.OwnerEpoch != 0 {
		t.Fatalf("B starts at epoch %d; the scenario needs the collision at 0", bRow.OwnerEpoch)
	}

	latchIncarnation(c, true)
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-spent", OwnerEpoch: 0,
		Incarnation: bRow.CreatedAt}
	other := a
	if dest == a {
		other = b
	}
	w := corrosion.ActionProof{ID: "b-recovery", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-spent", DestHost: other.Name, Coordinator: a.Name, OwnerEpoch: "0"}
	out, err := a.Server.DecideRecoveryClaim(ctx, key, corrosion.ClaimValue{Proof: &w, SourceHost: d.Name}, 60, nil)
	if err != nil {
		t.Fatalf("B's claim: %v", err)
	}
	if !out.Ours || out.Value.Proof == nil || out.Value.Proof.ID != w.ID {
		t.Fatalf("B's claim decided %+v (ours=%v), not a fresh value: A's spent decision wedges it", out.Value.Proof, out.Ours)
	}
	if ok, _ := dest.DB.ProofAbandoned(ctx, spent); !ok {
		t.Fatalf("%s did not record that A's decision %s is excluded", dest.Name, spent)
	}
}

// TestFleet_RecoveryClaim_AnAdoptedSpentDecisionMovesOnOnceItsDestinationAnswers
// is the round-3 review sequence. Before the latch, A's recovery decision V
// ran and completed on D. A is deleted and B re-created on A's old source
// host S, at the same epoch. After the latch, S fails while D cannot answer
// the bridge's exclusion. V is adopted, and its voters re-accept it — same
// source, no probe — so V is DECIDED at B's scoped key. V can never run
// again, so:
//
//   - the coordinator does not point B at it (B would leave every later
//     recovery for a proof that never executes), and retries;
//   - ha.claim.legacy_held stays raised, though the key decided;
//   - once D answers, the next tick moves the claim to attempt 1 on D's
//     foreign abandonment, and B is recovered; the condition then resolves.
//
// Mutations: write a decided spent proof (drop the proofSpent refusal in
// claimRecovery) — B is pointed at V and never recovered; drop the spent arm
// of supersedeEvidence — B waits behind V for good; resolve the condition when
// the key decides — it clears while B is held.
func TestFleet_RecoveryClaim_AnAdoptedSpentDecisionMovesOnOnceItsDestinationAnswers(t *testing.T) {
	ctx := context.Background()
	const name = "claimvm"
	c, cs, clock := incarnationFleet(t, 2567, func(_ *Cluster, a, victim *Node) {
		insertVM(t, a, name, victim.Name)
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: "full-" + a.Name, HostName: a.Name,
			Spec: `{}`, State: "running", CPUActual: 64, MemActual: 262144}, nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	latchIncarnation(c, false)
	a, source := c.Nodes[0], c.Nodes[4]
	dead := map[string]bool{}

	// A: recovered from S under a legacy claim to D, and run there.
	alive := failHost(t, c, clock, dead, source)
	cs.Tick(ctx, a)
	vm := vmOn(t, a, name)
	if vm.PendingActionID == "" || vm.HostName == source.Name {
		t.Fatalf("A was not recovered under a legacy claim: %+v", vm)
	}
	spent := vm.PendingActionID
	d := c.Node(vm.HostName)
	if d == a {
		t.Fatalf("the scenario needs D to be a peer of the coordinator, got %s", d.Name)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	claimReconciler(t, d).ReconcileOnce(ctx)
	c.WaitConverged(t, convergeTimeout, alive...)
	if pr, ok, _ := corrosion.GetActionProof(ctx, a.DB, spent); !ok || pr.Status != corrosion.ProofCompleted {
		t.Fatalf("A's decision did not complete: %+v", pr)
	}

	// A deleted; S back; B re-created on S at the same epoch.
	mustDeleteVM(t, d, name)
	c.ClearLinkFaults()
	delete(dead, source.Name)
	if err := corrosion.UpdateHostState(ctx, a.DB, source.Name, "active"); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		PublishHealth(t, n, source.Name, 0, clock.Now())
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms", "health_conditions", "host_health"})
	insertVM(t, a, name, source.Name)
	c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms", "health_conditions", "host_health"})
	if got := vmOn(t, a, name).OwnerEpoch; got != 0 {
		t.Fatalf("B starts at epoch %d; the scenario needs the collision at 0", got)
	}

	// The latch forms; S fails again while D cannot answer the exclusion.
	latchIncarnation(c, true)
	// Past the coordinator's recent-fence window, so S's second failure is a
	// failure of its own rather than the first one's fence.
	clock.Advance(6 * time.Minute)
	alive = failHost(t, c, clock, dead, source)
	restore := d.DoNotImplement("AbandonRecoveryProof")
	cs2 := probeCoordinator(c, clock, a)
	clock.Advance(contentionPoll)
	cs2.Tick(ctx, a)
	b := vmOn(t, a, name)
	if b.HostName != source.Name || b.PendingActionID != "" {
		t.Fatalf("B was pointed at a decision that can never run: %+v", b)
	}
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: name, OwnerEpoch: 0, Incarnation: b.CreatedAt}
	if st := voterState(t, a, key); st.Value == nil || st.Value.Proof.ID != spent {
		t.Fatalf("the scenario needs V decided at B's scoped key; a holds %+v", st)
	}
	a.Server.RecoveryClaimHealthTick(ctx)
	if row, found, _ := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.legacy_held", "vm", name); !found ||
		row.Lifecycle == corrosion.ConditionResolved || !strings.Contains(row.Evidence, spent) {
		t.Fatalf("ha.claim.legacy_held is not raised while B is held behind the decided spent proof: %+v", row)
	}

	// D answers: the claim moves past V.
	restore()
	clock.Advance(contentionPoll)
	cs2.Tick(ctx, a)
	b = vmOn(t, a, name)
	if b.PendingActionID == "" || b.PendingActionID == spent || b.HostName == source.Name {
		t.Fatalf("B was not recovered once D answered: %+v", b)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, b.PendingActionID)
	if err != nil || !ok {
		t.Fatalf("read B's proof: %v", err)
	}
	cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
	if err != nil || cert.Key.Attempt != 1 || cert.Key.Incarnation != b.CreatedAt {
		t.Fatalf("B's certificate decides %s (%v), want attempt 1 of its incarnation", cert.Key, err)
	}
	a.Server.RecoveryClaimHealthTick(ctx)
	if row, found, _ := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.legacy_held", "vm", name); !found ||
		row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("ha.claim.legacy_held did not resolve once B was recovered: %+v", row)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	claimReconciler(t, c.Node(b.HostName)).ReconcileOnce(ctx)
	owners := 0
	for _, n := range alive {
		if st, _ := n.Virt.DomainState(name); st == string(libvirtfake.StateRunning) {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners of B after its recovery, want 1", owners)
	}
}
