// Fleet scenarios: message faults on the recovery-claim RPCs
// (docs/design/recovery-claims.md §3.15, §7.1 "Claim-RPC faults"),
// colonelpanik/litevirt#250.
//
// The claim RPCs are ordinary gRPC between daemons, so the network can lose a
// Prepare or an Accept, lose the reply to one the voter committed, deliver one
// twice, or hold one back until after the sender's next — a newer round
// reaching the voter first. Paxos's answer to every one of these is the
// voter's ballot check and the idempotence of a repeated message (§3.5); these
// scenarios check that the implementation's answer is the same, with every
// fault injected on the receiving voter (claim_faults.go) and every safety
// property asserted over the votes actually cast (claim_invariants_test.go).
//
// A reply that arrives after the proposer has given up on the call is
// discarded by gRPC with the call, so to the proposer it is a lost reply
// (ClaimDropReply); what makes "late" matter is the voter side, where a late
// REQUEST lands after a newer round (ClaimHold).
package fleet

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// TestFleet_RecoveryClaimFaults_TwoCoordinatorsAcrossSeeds is the
// two-coordinator scenario (failover_two_coordinators_test.go) with every
// claim RPC between the coordinators faulted. Both survivors believe they
// lead — replication between them is blocked for the whole window — and both
// are voters, with the third voter the dead victim, so every decision needs
// the one message each way that the network is mangling.
//
// The schedule is seeded twice over: which coordinator ticks at each step,
// and the fate of every claim RPC on each link. Ticks are sequential, so a
// seed is a fixed interleaving: a message held on a→b is delivered after a's
// next claim RPC to b, which may be rounds — and the other coordinator's
// decision — later.
//
// Mutation: make Accept ignore the promise (corrosion.ClaimAccept accepts a
// ballot below row.Promised) — a held Accept from an older round is taken
// after a newer promise, which checkVoters reports.
func TestFleet_RecoveryClaimFaults_TwoCoordinatorsAcrossSeeds(t *testing.T) {
	kinds := []struct {
		name  string
		fault ClaimFault
	}{
		{"drop-request", ClaimFault{DropRequest: 0.4}},
		{"drop-reply", ClaimFault{DropReply: 0.4}},
		{"duplicate", ClaimFault{Duplicate: 0.6}},
		{"hold", ClaimFault{Hold: 0.5}},
		{"mixed", ClaimFault{DropRequest: 0.15, DropReply: 0.15, Duplicate: 0.2, Hold: 0.2}},
	}
	for _, latch := range claimFormats {
		for _, k := range kinds {
			for seed := int64(1); seed <= 3; seed++ {
				t.Run(fmt.Sprintf("%s/%s/seed-%d", latch.name, k.name, seed), func(t *testing.T) {
					runTwoCoordinatorClaimFaults(t, k.name, k.fault, 2700+seed*10+int64(len(k.name)), latch.a, latch.b)
				})
			}
		}
	}
}

// claimFormats runs a scenario under both claim key formats — before
// claim_incarnation_v1 has latched (legacy keys) and after (keys scoped to
// the workload's incarnation, docs/design/recovery-claims.md §10 item 37) —
// and with the two coordinators on opposite sides of the latch at once, as
// a rolling latch leaves them for a few seconds: a claims the scoped key, b
// the legacy one, for the same recovery.
var claimFormats = []struct {
	name string
	a, b bool
}{{"legacy-keys", false, false}, {"incarnation-keys", true, true}, {"split-latch", true, false}}

func runTwoCoordinatorClaimFaults(t *testing.T, kind string, fault ClaimFault, seed int64, latchA, latchB bool) {
	ctx := context.Background()
	vm := fmt.Sprintf("vm-cf-%s-%d", kind, seed)
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := claimFleet(t, clock, seed, vm)
	latchIncarnationOn(a, latchA)
	latchIncarnationOn(b, latchB)
	ledger := watchClaims(t, c)

	// The decision window: no replication between the coordinators, and
	// every claim RPC between them faulted.
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true, Claim: fault})
	cs := c.NewCoordinators(clock)
	for _, n := range []*Node{a, b} {
		cs.ByNode[n.Name].Gate = quorateGate{}
		cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ipmi", Success: true}
		})
	}

	order := rand.New(rand.NewPCG(uint64(seed), 0x6f72646572))
	decided := func(n *Node) bool {
		v := vmOn(t, n, vm)
		return v.PendingActionID != "" && v.HostName != victim.Name
	}
	var schedule []string
	const maxTicks = 40
	for step := 0; step < maxTicks && !(decided(a) && decided(b)); step++ {
		n := a
		if order.IntN(2) == 1 {
			n = b
		}
		schedule = append(schedule, n.Name)
		cs.Tick(ctx, n)
		// Each step is a tenth of a poll interval, so the whole schedule fits
		// inside one health-freshness window (30 s): replication between the
		// coordinators is blocked, so neither can refresh the other's
		// observation of the victim, and a stale one would drop the victim
		// from the fence candidates — and with it every retry of a refused
		// claim.
		clock.Advance(contentionPoll / 10)
	}
	if !decided(a) && !decided(b) {
		t.Fatalf("no coordinator decided in %d ticks (schedule %v; a→b %+v; b→a %+v)",
			maxTicks, schedule, c.ClaimStats(a, b), c.ClaimStats(b, a))
	}
	ab, ba := c.ClaimStats(a, b), c.ClaimStats(b, a)
	t.Logf("%d ticks %v; a→b %+v; b→a %+v", len(schedule), schedule, ab, ba)
	if faulted := ab.DroppedReq + ab.DroppedReply + ab.Duplicated + ab.Held +
		ba.DroppedReq + ba.DroppedReply + ba.Duplicated + ba.Held; faulted == 0 {
		t.Fatal("the schedule faulted no claim RPC; the seed proves nothing")
	}

	// Whatever the network still holds arrives now, after every newer round.
	c.ReleaseHeldClaims()
	// Heal, as failover_two_coordinators_test.go does; the victim stays dead.
	c.ClearLinkFaults()
	c.Kill(victim)
	for _, n := range []*Node{a, b} {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	// leader_lease_terms keeps both contested claims by design
	// (leader_lease_contest_test.go). health_conditions is NOT excepted: both
	// lease holders raise the same ha.voter.unavailable row in the window,
	// and the two raises must converge (health_condition_two_raisers_test.go).
	c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms", "health_conditions"}, a, b)
	for _, n := range []*Node{a, b} {
		claimReconciler(t, n).ReconcileOnce(ctx)
	}
	out := checkClaimSafety(t, ledger, a, vm, c.Nodes)
	// One certified value for the recovery, across the key's legacy and
	// scoped forms (each coordinator claims the form its own latch says).
	certified := map[string]bool{}
	for k, ds := range out.Certified {
		if k.SameDecision(vmKey(a, vm, 0)) {
			for d := range ds {
				certified[d] = true
			}
		}
	}
	if len(certified) != 1 {
		t.Errorf("certified values for %s across its key forms: %v, want exactly one", vm, keys(certified))
	}
	if latchA != (vmKey(a, vm, 0).Incarnation != "") || latchB != (vmKey(b, vm, 0).Incarnation != "") {
		t.Errorf("the coordinators' keys do not match their latches")
	}
	for _, n := range []*Node{a, b} {
		if v := vmOn(t, n, vm); out.Running != nil && v.HostName != out.Running[0] {
			t.Errorf("after the heal %s's replica says %s is on %s, want the one owner %s", n.Name, vm, v.HostName, out.Running[0])
		}
	}
}

// staleAccept is the script for TestFleet_RecoveryClaimFaults_StaleAcceptAfterNewerRound.
type staleAccept struct {
	x, a, b, cc *Node
	mu          sync.Mutex
	aPrepared   bool
}

func (s *staleAccept) script(m ClaimMsg) ClaimFate {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case m.From == s.x.Name && m.Method == "AcceptRecoveryClaim":
		switch m.To {
		case s.a.Name:
			return ClaimHold // x's Accept to a is stuck in the network
		case s.b.Name:
			return ClaimDeliver
		default:
			return ClaimDropRequest
		}
	case m.From == s.a.Name && m.To == s.b.Name && m.Method == "PrepareRecoveryClaim" && !s.aPrepared:
		// a's first Prepare to b — the one voter holding x's value — is
		// lost, so a never learns x's value and decides its own.
		s.aPrepared = true
		return ClaimDropRequest
	}
	return ClaimDefault
}

// TestFleet_RecoveryClaimFaults_StaleAcceptAfterNewerRound: an Accept from an
// older round arrives after a newer round was decided. x's Accept(b1, v1)
// reaches b and is held on the way to a; x gets no majority. a then runs a
// newer round b2 without learning v1 (its Prepare to b is lost), and decides
// its own v2 with c. Only then does the network deliver x's Accept(b1, v1) to
// a. a has promised b2, so it must refuse — accepting would put v1 on a
// majority {a, b} at b1, and v1 and v2 would both be chosen.
//
// Mutation: make Accept ignore the promise (drop the row.Promised > b
// refusal in corrosion.ClaimAccept) — a accepts the stale v1 and two values
// are chosen at one key.
func TestFleet_RecoveryClaimFaults_StaleAcceptAfterNewerRound(t *testing.T) {
	for _, latched := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-keys", true: "incarnation-keys"}[latched], func(t *testing.T) {
			runStaleAcceptAfterNewerRound(t, latched)
		})
	}
}

func runStaleAcceptAfterNewerRound(t *testing.T, latched bool) {
	ctx := context.Background()
	vm := "vm-cf-stale-accept"
	c, a, b, cc, x, d := crashFleet(t, 2801, vm)
	latchIncarnation(c, latched)
	voters := []*Node{a, b, cc}
	ledger := watchClaims(t, c)
	key := vmKey(a, vm, 0)
	s := &staleAccept{x: x, a: a, b: b, cc: cc}
	c.SetClaimScript(s.script)

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	for _, n := range []*Node{a, x} {
		cs.ByNode[n.Name].Gate = quorateGate{}
		cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ipmi", Success: true}
		})
	}
	cs.Tick(ctx, x)
	if st := c.ClaimStats(x, a); st.Held != 1 {
		t.Fatalf("x's Accept to a was not held: %+v", st)
	}
	xState := voterState(t, b, key)
	if xState.Value == nil || xState.Accepted.Coordinator != x.Name {
		t.Fatalf("b does not hold x's value: %+v", xState)
	}
	// x never ticks again. It is not crashed: replacing its links' faults
	// would hand the held Accept to a now, before the newer round.

	// Past x's lease. x's fence row and d's 'fenced' state replicate as one
	// entry, so a either resumes from them or, if they have not reached it,
	// fences d itself; the claim below is the same either way.
	clock.Advance(time.Minute)
	now := clock.Now()
	for _, n := range voters {
		PublishHealth(t, n, d.Name, 5, now)
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	for i := 0; i < 4 && vmOn(t, a, vm).PendingActionID == ""; i++ {
		cs.Tick(ctx, a)
		clock.Advance(contentionPoll)
	}
	decided := vmOn(t, a, vm)
	if decided.PendingActionID == "" || decided.PendingActionID == xState.Value.Proof.ID {
		t.Fatalf("a did not decide a value of its own (proof %q, x's %q)", decided.PendingActionID, xState.Value.Proof.ID)
	}

	// The stale Accept finally arrives.
	c.ReleaseHeldClaims()
	if st := c.ClaimStats(x, a); st.HeldDelivered != 1 {
		t.Fatalf("the held Accept was not delivered: %+v", st)
	}
	if st := voterState(t, a, key); st.Accepted.Coordinator == x.Name {
		t.Errorf("a took x's stale Accept after promising %s: now holds %s", st.Promised, st.Accepted)
	}

	c.WaitConverged(t, convergeTimeout, voters...)
	claimReconciler(t, c.Node(decided.HostName)).ReconcileOnce(ctx)
	out := checkClaimSafety(t, ledger, a, vm, c.Nodes)
	xDigest, _ := xState.Value.Digest()
	if out.Chosen[key][xDigest] {
		t.Errorf("x's value, which only b accepted before a newer round decided another, became chosen")
	}
}
