// Fleet scenarios: the owner probe on recovery claims
// (docs/design/recovery-claims.md §3.5.1, §7.1 "The owner probe").
//
// Before a voter accepts a workload value it has not accepted before, it
// probes the value's source host itself over the peer transport and refuses if
// it can reach it. These scenarios run over independent replicas with a
// DIRECTED probe fault — SetLinkFault(voter, owner, LinkFault{BlockProbe:
// true}) makes the owner unreachable to that one voter and to nobody else —
// and force the coordinator's decision gate open with quorateGate, so what is
// under test is the voters' own check, not the coordinator's health view.
package fleet

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// probeFleet is four hosts a, b, c, d with voter generation 2 = {a, b, c}
// (genesis over all four, then d removed), recovery claims enforced, the VMs
// on d, and d ALIVE. Every voter's failed probe of d is published, so a
// coordinator judges d failed whatever the voters find.
func probeFleet(t *testing.T, seed int64, vms ...string) (c *Cluster, a, b, cc, d *Node) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: seed})
	a, b, cc, d = c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	for _, vm := range vms {
		insertVM(t, a, vm, d.Name)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	if _, err := c.SelfClient(a).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: d.Name}); err != nil {
		t.Fatalf("voter rm %s: %v", d.Name, err)
	}
	adoptAll(t, c, 2)
	enableRecoveryClaims(t, c, a, b, cc)
	clock := time.Now().UTC()
	for _, n := range []*Node{a, b, cc} {
		PublishHealth(t, n, d.Name, 5, clock)
	}
	c.WaitConverged(t, convergeTimeout, a, b, cc)
	return c, a, b, cc, d
}

// probeCoordinator is a's coordinator with its decision gate forced open.
func probeCoordinator(c *Cluster, clock *VirtualClock, on *Node) *Coordinators {
	cs := c.NewCoordinators(clock)
	cs.ByNode[on.Name].Gate = quorateGate{}
	return cs
}

func vmKey(name string, epoch int64) corrosion.ClaimKey {
	return corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: name, OwnerEpoch: epoch}
}

// lastRefusal is voter n's most recent refusal for key, as GetRecoveryClaim
// reports it to an operator.
func lastRefusal(t *testing.T, c *Cluster, n *Node, key corrosion.ClaimKey) (string, string) {
	t.Helper()
	resp, err := c.SelfClient(n).GetRecoveryClaim(context.Background(), &pb.GetRecoveryClaimRequest{
		Key: &pb.RecoveryClaimKey{TargetKind: key.TargetKind, TargetName: key.TargetName, OwnerEpoch: key.OwnerEpoch, Attempt: key.Attempt}})
	if err != nil {
		t.Fatalf("%s: GetRecoveryClaim: %v", n.Name, err)
	}
	return resp.GetLastRefusalReason(), resp.GetLastRefusalDetail()
}

// TestFleet_RecoveryClaim_OwnerReachableFromAMajority: d is alive and only a
// has lost sight of it. a's coordinator proposes; b and c reach d and refuse.
// No certificate forms, nothing is minted, the refusal names b and c and what
// each reached, and the next tick retries at the same round.
//
// Mutation: skip the probe in the Accept handler (checkClaimOwner returns ""
// before probing) — b and c accept, a certificate forms and a proof is minted.
func TestFleet_RecoveryClaim_OwnerReachableFromAMajority(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2501, "vm-live")
	c.SetLinkFault(a, d, LinkFault{BlockProbe: true})

	clock := NewVirtualClock(time.Now().UTC())
	cs := probeCoordinator(c, clock, a)
	var refused []string
	cs.ByNode[a.Name].SetGateRefusedObserver(func(_, r string) { refused = append(refused, r) })
	cs.Tick(ctx, a)

	if ids := proofsNaming(t, a, "vm-live", a.Name); len(ids) != 0 {
		t.Fatalf("a proof was minted while a majority of voters could reach the owner: %v", ids)
	}
	if vm := vmOn(t, a, "vm-live"); vm.HostName != d.Name || vm.PendingActionID != "" {
		t.Fatalf("the VM moved while its owner was reachable: %+v", vm)
	}
	found := false
	for _, r := range refused {
		found = found || r == "recovery_claim_owner_reachable"
	}
	if !found {
		t.Fatalf("the coordinator did not record recovery_claim_owner_reachable: %v", refused)
	}
	key := vmKey("vm-live", 0)
	for _, n := range []*Node{b, cc} {
		reason, detail := lastRefusal(t, c, n, key)
		want := fmt.Sprintf("%s still reaches %s", n.Name, d.Name)
		if reason != corrosion.RefusalOwnerReachable || !strings.Contains(detail, want) {
			t.Errorf("%s's refusal = %q %q, want %s naming %q", n.Name, reason, detail, corrosion.RefusalOwnerReachable, want)
		}
	}
	promised := voterState(t, b, key).Promised
	before := len(refused)

	// The next tick retries — the fenced host is otherwise processed once —
	// and at the SAME round: nothing is contending, the source is up.
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	if len(refused) == before {
		t.Fatal("the next tick did not retry the refused claim")
	}
	again := voterState(t, b, key).Promised
	if again.Round != promised.Round {
		t.Errorf("the retry moved the round from %d to %d", promised.Round, again.Round)
	}
	if ids := proofsNaming(t, a, "vm-live", a.Name); len(ids) != 0 {
		t.Fatalf("the retry minted a proof while the owner was still reachable: %v", ids)
	}
}

// TestFleet_RecoveryClaim_OwnerUpForEveryVoter_RetriesTheSameValue: when EVERY
// voter still reaches the owner nobody accepts anything, so Paxos gives the
// retry no value to adopt: the coordinator itself re-proposes the value the
// voters refused — same proof ID — which is what lets it keep its round.
//
// Mutation: drop the refused-proposal cache in claimRecovery — the retry
// proposes a fresh proof ID, the round is bound to the old value, and the
// proposer moves up.
func TestFleet_RecoveryClaim_OwnerUpForEveryVoter_RetriesTheSameValue(t *testing.T) {
	ctx := context.Background()
	c, a, b, _, _ := probeFleet(t, 2508, "vm-up")
	clock := NewVirtualClock(time.Now().UTC())
	cs := probeCoordinator(c, clock, a)
	cs.Tick(ctx, a)
	key := vmKey("vm-up", 0)
	first := voterState(t, b, key).Promised
	if first.IsZero() {
		t.Fatal("b never saw the claim; the rest is vacuous")
	}
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	if again := voterState(t, b, key).Promised; again.Round != first.Round {
		t.Fatalf("re-proposing the refused value moved the round from %d to %d", first.Round, again.Round)
	}
	if ids := proofsNaming(t, a, "vm-up", a.Name); len(ids) != 0 {
		t.Fatalf("a proof was minted while every voter reached the owner: %v", ids)
	}
}

// TestFleet_RecoveryClaim_OwnerReachableFromAMinority: a and b have lost
// sight of d, c has not. c refuses; a and b accept; the certificate forms and
// recovery proceeds with one owner.
//
// Mutation: probe the value's DESTINATION instead of its source — a and b
// reach the destination and refuse, and no certificate forms.
func TestFleet_RecoveryClaim_OwnerReachableFromAMinority(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2502, "vm-minority")
	c.SetLinkFault(a, d, LinkFault{BlockProbe: true})
	c.SetLinkFault(b, d, LinkFault{BlockProbe: true})

	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), a)
	cs.Tick(ctx, a)

	vm := vmOn(t, a, "vm-minority")
	if vm.PendingActionID == "" || vm.HostName == d.Name {
		t.Fatalf("a claim a majority could certify did not move the VM: %+v", vm)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, vm.PendingActionID)
	if err != nil || !ok || pr.ClaimCertificate == "" {
		t.Fatalf("the reschedule proof carries no certificate: ok=%v err=%v", ok, err)
	}
	if reason, _ := lastRefusal(t, c, cc, vmKey("vm-minority", 0)); reason != corrosion.RefusalOwnerReachable {
		t.Errorf("c, which still reaches d, did not refuse: %q", reason)
	}
	dest := c.Node(vm.HostName)
	c.WaitConverged(t, convergeTimeout, a, b, cc)
	claimReconciler(t, dest).ReconcileOnce(ctx)
	owners := 0
	for _, n := range []*Node{a, b, cc} {
		if st, _ := n.Virt.DomainState("vm-minority"); st == string(libvirtfake.StateRunning) {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners after a minority-reachable recovery, want 1", owners)
	}
}

// TestFleet_RecoveryClaim_ProofGradeFenceClearsTheProbe: the claim runs after
// the fence (§3.13 step 1). A fence that powers the owner off takes it out of
// every voter's reach, so the claim forms on the first tick and no voter
// records an owner-probe refusal.
//
// Mutation: run the recovery before the fence in failover() — the voters
// still reach d, refuse, and nothing is recovered on the first tick.
func TestFleet_RecoveryClaim_ProofGradeFenceClearsTheProbe(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2503, "vm-fenced")
	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), a)
	cs.ByNode[a.Name].SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		c.Kill(c.Node(h.Name)) // an IPMI power-off: nothing answers any more
		return fence.Result{Method: "ipmi", Success: true}
	})
	cs.Tick(ctx, a)

	if vm := vmOn(t, a, "vm-fenced"); vm.PendingActionID == "" || vm.HostName == d.Name {
		t.Fatalf("the claim did not form on the first tick after a proof-grade fence: %+v", vm)
	}
	key := vmKey("vm-fenced", 0)
	for _, n := range []*Node{a, b, cc} {
		if reason, detail := lastRefusal(t, c, n, key); reason == corrosion.RefusalOwnerReachable {
			t.Errorf("%s recorded an owner-probe refusal after the fence: %s", n.Name, detail)
		}
	}
}

// TestFleet_RecoveryClaim_ProbeBudget: twenty workloads on one slow owner cost
// each voter ONE probe, not twenty — every Accept naming the same source
// within claimProbeMaxAge reuses the result — and every claim completes.
//
// Mutation: drop the per-source result reuse in probeOwner — each voter
// probes d once per claim.
func TestFleet_RecoveryClaim_ProbeBudget(t *testing.T) {
	ctx := context.Background()
	var vms []string
	for i := 0; i < 20; i++ {
		vms = append(vms, fmt.Sprintf("vm-b%02d", i))
	}
	c, a, b, cc, d := probeFleet(t, 2504, vms...)
	for _, n := range []*Node{a, b, cc} {
		// Longer than claimProbeTimeout (2 s): each probe waits out its
		// timeout, reads not reached, and the voter accepts.
		c.SetLinkFault(n, d, LinkFault{ProbeDelay: 3 * time.Second})
	}
	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), a)
	start := time.Now()
	cs.Tick(ctx, a)
	took := time.Since(start)

	moved := 0
	for _, vm := range vms {
		if v := vmOn(t, a, vm); v.PendingActionID != "" && v.HostName != d.Name {
			moved++
		}
	}
	if moved != len(vms) {
		t.Fatalf("%d of %d claims completed in one tick (took %s)", moved, len(vms), took)
	}
	for _, n := range []*Node{a, b, cc} {
		if got := c.LinkStats(n, d).Pings; got != 1 {
			t.Errorf("%s probed %s %d times for %d workloads, want once", n.Name, d.Name, got, len(vms))
		}
	}
}

// TestFleet_RecoveryClaim_AVoterThatIsTheOldOwner: the victim is a voter, is
// alive, and has been wrongly declared failed. If it can answer an Accept it
// is up, and it must not count toward certifying its own eviction: it refuses
// "is the owner" without probing.
//
// Mutation: remove the source_host == me check, with the victim's probe of
// itself blocked — the victim accepts its own eviction.
func TestFleet_RecoveryClaim_AVoterThatIsTheOldOwner(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2505})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	insertVM(t, a, "vm-own", victim.Name)
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	for _, n := range []*Node{a, b, victim} {
		// Nobody's probe reaches the victim — not even its own — so only the
		// owner check can make it refuse.
		c.SetLinkFault(n, victim, LinkFault{BlockProbe: true})
	}
	PublishHealth(t, a, victim.Name, 5, time.Now().UTC())
	PublishHealth(t, b, victim.Name, 5, time.Now().UTC())
	c.WaitConverged(t, convergeTimeout, a, b)

	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), a)
	cs.Tick(ctx, a)

	key := vmKey("vm-own", 0)
	reason, detail := lastRefusal(t, c, victim, key)
	if reason != corrosion.RefusalOwnerReachable || !strings.Contains(detail, victim.Name+" is the owner") {
		t.Fatalf("the old owner's refusal = %q %q, want %s \"%s is the owner\"",
			reason, detail, corrosion.RefusalOwnerReachable, victim.Name)
	}
	if st := voterState(t, victim, key); !st.Accepted.IsZero() {
		t.Fatalf("the old owner accepted its own eviction at %s", st.Accepted)
	}
}

// rogueAccept sends one Accept from rogue straight to voter, with rogue's own
// host certificate, as a coordinator whose failure detector — or whose peer
// key — has been subverted would.
func rogueAccept(t *testing.T, c *Cluster, rogue, voter *Node, key corrosion.ClaimKey, source, dest string) *pb.AcceptRecoveryClaimResponse {
	t.Helper()
	return rogueAcceptAt(t, c, rogue, voter, key, source, dest, 2)
}

// rogueAcceptAt is rogueAccept under voter generation gen.
func rogueAcceptAt(t *testing.T, c *Cluster, rogue, voter *Node, key corrosion.ClaimKey, source, dest string, gen int64) *pb.AcceptRecoveryClaimResponse {
	t.Helper()
	resp, err := c.PeerClient(rogue, voter).AcceptRecoveryClaim(context.Background(), &pb.AcceptRecoveryClaimRequest{
		Key:              &pb.RecoveryClaimKey{TargetKind: key.TargetKind, TargetName: key.TargetName, OwnerEpoch: key.OwnerEpoch},
		Ballot:           &pb.ClaimBallot{Round: 7, Coordinator: rogue.Name, BootNonce: []byte{9}},
		ConfigGeneration: gen,
		Value: &pb.RecoveryClaimValue{Id: "rogue-" + source, Action: corrosion.ActionReschedule, TargetKind: key.TargetKind,
			TargetName: key.TargetName, DestHost: dest, Coordinator: rogue.Name,
			OwnerEpoch: fmt.Sprint(key.OwnerEpoch), SourceHost: source},
	})
	if err != nil {
		t.Fatalf("%s → %s Accept: %v", rogue.Name, voter.Name, err)
	}
	return resp
}

// TestFleet_RecoveryClaim_ARogueCoordinator: a host certificate is enough to
// send Accept, so a coordinator with a wrong failure detector — or a forged
// host_health row — can ask. It still cannot certify: a live source is
// reached and refused, and a dead host named as the source of a workload whose
// settled row names a live one is refused on the cross-check.
//
// Mutation: drop the source cross-check in checkClaimOwner — the dead-source
// case certifies (both voters accept).
func TestFleet_RecoveryClaim_ARogueCoordinator(t *testing.T) {
	c, a, b, cc, d := probeFleet(t, 2506, "vm-rogue")
	rogue := cc

	live := vmKey("vm-rogue", 0)
	for _, v := range []*Node{a, b} {
		resp := rogueAccept(t, c, rogue, v, live, d.Name, rogue.Name)
		if resp.GetAccepted() || resp.GetRefusalReason() != corrosion.RefusalOwnerReachable {
			t.Errorf("%s accepted the eviction of a live source: %+v", v.Name, resp)
		}
	}
	accepted := 0
	for _, v := range []*Node{a, b} {
		resp := rogueAccept(t, c, rogue, v, live, "ghost-host", rogue.Name)
		if resp.GetAccepted() {
			accepted++
		} else if resp.GetRefusalReason() != corrosion.RefusalSourceMismatch {
			t.Errorf("%s refused the wrong source for the wrong reason: %+v", v.Name, resp)
		}
	}
	if accepted >= 2 {
		t.Fatalf("a majority certified a dead host as the source of a workload whose settled row names %s", d.Name)
	}
}

// TestFleet_RecoveryClaim_OwnerReturnsAfterAValueWasChosen: a majority accepts
// a value while the owner is unreachable and the proposer dies before it
// writes anything; then the owner comes back. The successor's phase 1 learns
// the value, the voters that hold it re-accept it WITHOUT re-probing, and the
// certificate completes with the same proof ID (§3.5.1, §3.15).
//
// Mutation: re-probe an already-accepted value in ClaimAccept — a and b reach
// the returned owner and refuse, and the claim stalls.
func TestFleet_RecoveryClaim_OwnerReturnsAfterAValueWasChosen(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2507, "vm-return")
	for _, n := range []*Node{a, b} {
		c.SetLinkFault(n, d, LinkFault{BlockProbe: true})
	}
	key := vmKey("vm-return", 0)
	// The dead proposer: a majority (a, b) accepted its value, nobody wrote it.
	for _, v := range []*Node{a, b} {
		if resp := rogueAccept(t, c, cc, v, key, d.Name, b.Name); !resp.GetAccepted() {
			t.Fatalf("%s did not accept while the owner was unreachable: %+v", v.Name, resp)
		}
	}
	// The owner returns: every voter can reach it now. Wait out the probe
	// result's reuse window (claimProbeMaxAge, 5 s), so a voter that probed d
	// again would genuinely find it up rather than reuse "not reached".
	c.SetLinkFault(a, d, LinkFault{})
	c.SetLinkFault(b, d, LinkFault{})
	time.Sleep(5500 * time.Millisecond)

	cs := probeCoordinator(c, NewVirtualClock(time.Now().UTC()), b)
	cs.Tick(ctx, b)
	vm := vmOn(t, b, "vm-return")
	if vm.PendingActionID != "rogue-"+d.Name {
		t.Fatalf("the successor did not complete the chosen value (proof %q): %+v", "rogue-"+d.Name, vm)
	}
	pr, _, err := corrosion.GetActionProof(ctx, b.DB, vm.PendingActionID)
	if err != nil || pr.ClaimCertificate == "" {
		t.Fatalf("the completed proof carries no certificate: %v", err)
	}
}
