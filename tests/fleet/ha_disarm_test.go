package fleet

// Cluster-wide HA disarm across real daemons (docs/migration-failover.md,
// "Disarming HA for planned maintenance"): the SetHAPolicy handler's
// confirmation, the coordinator's L1 and L2, and the claim voters' L3, over
// real gRPC, real replication and the per-key apply filter (HoldPolicyKey).
//
// Each node runs its HA policy cache and a prober that asks every peer Ready
// every probeEvery, which is what the health checker does in the daemon; the
// peer answers it records are the ones the coordinator's veto reads.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

// haWindow is the scenarios' W_L2: the handler's wait after confirmation and
// the coordinators' answer window, shortened together.
const (
	haWindow   = 5 * time.Second
	probeEvery = 100 * time.Millisecond
)

type haFleet struct {
	c     *Cluster
	gates map[string]*health.Checker
	cs    *Coordinators
	clock *VirtualClock
}

// newHAFleet is a latched fleet (release token included) with every node's HA
// cache and prober running, every gate seeing every peer healthy, the arm
// gate's fence-candidate hook, and a coordinator on every node wired for the
// peer veto as the daemon wires it.
func newHAFleet(t *testing.T, opts Options) *haFleet {
	t.Helper()
	opts.IndependentReplicas = true
	c := New(t, opts)
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(context.Background(), capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	latchReleaseToken(t, c, gates)
	t.Cleanup(grpcapi.SetHAWaitsForTest(10*time.Second, 50*time.Millisecond, haWindow))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := NewVirtualClock(time.Now())
	f := &haFleet{c: c, gates: gates, clock: clock}
	for _, n := range c.Nodes {
		f.seedLive(n)
		go n.Server.RunHAPolicyCache(ctx)
		go f.probe(ctx, n)
		n := n
		n.Server.SetFenceCandidates(func(ctx context.Context) ([]string, error) {
			return failover.CurrentFenceCandidates(ctx, n.DB, n.Name, clock.Now(), 2*time.Minute)
		})
	}
	f.cs = c.NewCoordinators(clock)
	for _, n := range c.Nodes {
		n := n
		coord := f.cs.ByNode[n.Name]
		coord.PeerHAState = func(peer string) (failover.PeerHAAnswer, bool) {
			asked, known, disarmed, at, ok := n.Server.PeerHAAnswer(peer)
			return failover.PeerHAAnswer{Asked: asked, Known: known, Disarmed: disarmed, PolicyAt: at}, ok
		}
		coord.LiveVoters = gates[n.Name].LiveVoters
		coord.AnswerWindow = haWindow
	}
	return f
}

// seedLive makes n's gate count every other node live except down.
func (f *haFleet) seedLive(n *Node, down ...*Node) {
	peers := map[string]bool{}
	for _, o := range f.c.Nodes {
		if o != n {
			peers[o.Name] = true
		}
	}
	for _, d := range down {
		peers[d.Name] = false
	}
	f.gates[n.Name].SeedPeersForTests(peers)
}

// probe asks every peer Ready, as the health checker does.
func (f *haFleet) probe(ctx context.Context, n *Node) {
	t := time.NewTicker(probeEvery)
	defer t.Stop()
	for {
		for _, o := range f.c.Nodes {
			if o != n {
				pctx, cancel := context.WithTimeout(ctx, time.Second)
				_, _, _ = n.Server.PeerReady(pctx, o.Name, "")
				cancel()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// down publishes target as failing, seen by observers, and drops it from
// every gate's live set.
func (f *haFleet) down(t *testing.T, target *Node, observers ...*Node) {
	t.Helper()
	// target holds a workload that needs its fence: a host with nothing to
	// recover is not fenced at all, and every scenario here asks whether HA
	// lets a fence run.
	needsFenceOn(t, observers[0], target.Name)
	eventually(t, convergeTimeout, "the workload on "+target.Name+" to reach every observer", func() bool {
		for _, o := range observers {
			if vm, err := corrosion.GetVM(context.Background(), o.DB, "held-for-"+target.Name); err != nil || vm == nil {
				return false
			}
		}
		return true
	})
	now := f.clock.Now()
	for _, o := range observers {
		PublishHealthRun(t, o, target.Name, 5, now, now)
	}
	for _, n := range f.c.Nodes {
		if n != target {
			f.seedLive(n, target)
		}
		f.c.SetLinkFault(n, target, LinkFault{BlockReady: true})
	}
	for _, n := range f.c.Nodes {
		if n == target {
			continue
		}
		eventually(t, convergeTimeout, target.Name+"'s failure on "+n.Name, func() bool {
			rows, _ := n.DB.Query(context.Background(),
				`SELECT observer FROM host_health WHERE target = ? AND consecutive_failures >= 5`, target.Name)
			return len(rows) >= len(observers)
		})
	}
}

func (f *haFleet) set(n *Node, state string, fenceDown bool) (*pb.HAPolicyStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return f.c.SelfClient(n).SetHAPolicy(ctx, &pb.SetHAPolicyRequest{State: state, Reason: "fleet", FenceDownHosts: fenceDown})
}

func (f *haFleet) fencesOf(target string) int {
	n := 0
	for _, fc := range f.cs.Fences() {
		if fc.Target == target {
			n++
		}
	}
	return n
}

func haCondition(t *testing.T, n *Node, code string) corrosion.HealthCondition {
	t.Helper()
	row, _, err := corrosion.GetHealthCondition(context.Background(), n.DB, corrosion.HADisarmEvaluator, code, "host", n.Name)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// Disarm, then a host goes down: nothing is fenced, and every node says it is
// disarmed. Arm is refused while the host is down, names it, and with
// --fence-down-hosts the host is fenced and its VM recovered on the next
// cycle. The first use was paid in the background beforehand, without a
// policy row.
//
// Mutation: drop L1 (the candidate and fence re-reads) — the host is fenced
// while disarmed and this goes red.
func TestHADisarm_Fleet_DisarmHoldsArmFences(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 3, FaultSeed: 1501})
	a, b, x := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2]
	insertVM(t, a, "vm-x", x.Name)
	f.c.WaitConverged(t, convergeTimeout)

	// The first use, paid on the lease holder with no policy row.
	if err := failover.HADisarmPreRecord(ctx, f.gates[a.Name].WithFeature); err != nil {
		t.Fatalf("pre-record: %v", err)
	}
	info, _ := capabilities.LookupFeature(capabilities.FeatureHADisarm)
	for _, n := range f.c.Nodes {
		eventually(t, convergeTimeout, "the used record on "+n.Name, func() bool {
			present, acked, _ := corrosion.ReleaseFeatureState(ctx, n.DB, info.Token, string(capabilities.FeatureHADisarm))
			return present && acked
		})
		if p, _ := corrosion.GetHAPolicy(ctx, n.DB); p.UpdatedAt != "" {
			t.Fatalf("the pre-record wrote a policy row on %s: %+v", n.Name, p)
		}
	}

	if _, err := f.set(a, corrosion.HADisarmed, false); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	for _, n := range f.c.Nodes {
		eventually(t, convergeTimeout, "ha_disarmed on "+n.Name, func() bool {
			return haCondition(t, n, corrosion.CondHADisarmed).Lifecycle == corrosion.ConditionConfirmed
		})
	}
	f.down(t, x, a, b)
	f.cs.Tick(ctx, a)
	f.cs.Tick(ctx, a)
	if n := f.fencesOf(x.Name); n != 0 {
		t.Fatalf("%s fenced %d times while HA is disarmed", x.Name, n)
	}

	// The status lists exactly the host the lease holder then fences (m-4).
	st, err := f.c.SelfClient(b).GetHAPolicy(ctx, &emptypb.Empty{})
	if err != nil || len(st.GetWouldBeFenced()) != 1 || st.GetWouldBeFenced()[0] != x.Name {
		t.Fatalf("would-be-fenced on %s: %v %v, want exactly %s", b.Name, st.GetWouldBeFenced(), err, x.Name)
	}
	_, err = f.set(a, corrosion.HAArmed, false)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), x.Name) {
		t.Fatalf("arm with %s down: %v, want FailedPrecondition naming it", x.Name, err)
	}
	if _, err := f.set(a, corrosion.HAArmed, true); err != nil {
		t.Fatalf("arm --fence-down-hosts: %v", err)
	}
	f.cs.Tick(ctx, a)
	if n := f.fencesOf(x.Name); n != 1 {
		t.Fatalf("%s fenced %d times after the arm, want 1", x.Name, n)
	}
	if all := f.cs.Fences(); len(all) != 1 {
		t.Fatalf("fences after the arm: %+v, want exactly the listed host", all)
	}
	if vm := vmOn(t, a, "vm-x"); vm == nil || vm.HostName == x.Name {
		t.Fatalf("vm-x not recovered after the arm: %+v", vm)
	}
}

// A lease holder whose replica has not received the disarm is held back by
// the live voters' answers (L2, rule disarmed), and says so.
//
// Mutation: drop L2's disarmed rule — the lagging lease holder fences.
func TestHADisarm_Fleet_LaggingLeaseHolderIsVetoed(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 5, FaultSeed: 1502})
	a, b, e, x, d := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2], f.c.Nodes[3], f.c.Nodes[4]
	x.HoldPolicyKey(t, "ha")
	f.cs.Tick(ctx, x) // x takes the lease

	if _, err := f.set(a, corrosion.HADisarmed, false); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	if p, _ := corrosion.GetHAPolicy(ctx, x.DB); p.UpdatedAt != "" {
		t.Fatalf("%s holds the disarm through its filter", x.Name)
	}
	f.down(t, d, a, b, e, x)
	f.cs.Tick(ctx, x)
	if n := f.fencesOf(d.Name); n != 0 {
		t.Fatalf("a lease holder lagging the disarm fenced %s %d times", d.Name, n)
	}
	cond := haCondition(t, x, corrosion.CondHAPeerVeto)
	if cond.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(cond.Evidence, "disarmed") {
		t.Fatalf("%s raised no peer-veto condition naming the rule: %+v", x.Name, cond)
	}
}

// Case W (re-review 2 R2-m6): five voters; x leads and is held off the row; d
// is down. x's last answers from v1..v3 were SENT before the disarm was
// written. The disarm is confirmed by v1..v3, and the handler waits W_L2
// before it returns: x deciding right after the return reads those answers as
// stale, and vetoes.
//
// Mutation: drop the handler's W_L2 wait — x decides while its pre-disarm
// answers are still fresh, and fences d.
func TestHADisarm_Fleet_CaseW_TheWaitMakesOldAnswersStale(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 5, FaultSeed: 1503})
	x, v1, v2, v3, d := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2], f.c.Nodes[3], f.c.Nodes[4]
	if err := failover.HADisarmPreRecord(ctx, f.gates[x.Name].WithFeature); err != nil {
		t.Fatalf("pre-record: %v", err)
	}
	x.HoldPolicyKey(t, "ha")
	f.down(t, d, x, v1, v2, v3)
	for _, v := range []*Node{v1, v2, v3} {
		v := v
		eventually(t, convergeTimeout, x.Name+"'s answer from "+v.Name, func() bool {
			_, known, _, _, ok := x.Server.PeerHAAnswer(v.Name)
			return ok && known
		})
	}
	// x's probes of the intersection voters stop; they stay live for it.
	for _, v := range []*Node{v1, v2, v3} {
		f.c.SetLinkFault(x, v, LinkFault{BlockReady: true})
	}
	time.Sleep(3 * probeEvery)
	written := time.Now()

	if _, err := f.set(v1, corrosion.HADisarmed, false); err != nil {
		t.Fatalf("disarm through %s: %v", v1.Name, err)
	}
	for _, v := range []*Node{v1, v2, v3} {
		asked, _, disarmed, at, _ := x.Server.PeerHAAnswer(v.Name)
		if !asked.Before(written) || disarmed || at != "" {
			t.Fatalf("%s's recorded answer from %s does not predate the disarm (asked %s, written %s, at %q)",
				x.Name, v.Name, asked, written, at)
		}
	}
	f.cs.Tick(ctx, x)
	if n := f.fencesOf(d.Name); n != 0 {
		t.Fatalf("%s fenced %s right after a confirmed disarm returned", x.Name, d.Name)
	}
	if cond := haCondition(t, x, corrosion.CondHAPeerVeto); !strings.Contains(cond.Evidence, "stale") {
		t.Fatalf("the veto is not the stale rule: %+v", cond)
	}
}

// A voter that died with a disarmed answer on record does not hold HA off
// after a re-arm: it is not counted live, so it is not read.
func TestHADisarm_Fleet_DeadVoterDoesNotHoldHAOff(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 5, FaultSeed: 1504})
	a, b, e, x, d := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2], f.c.Nodes[3], f.c.Nodes[4]
	f.cs.Tick(ctx, x)
	if _, err := f.set(a, corrosion.HADisarmed, false); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	eventually(t, convergeTimeout, x.Name+" to record "+d.Name+"'s disarm", func() bool {
		_, _, disarmed, _, _ := x.Server.PeerHAAnswer(d.Name)
		return disarmed
	})
	f.down(t, d, a, b, e, x) // d dies with "disarmed" as its last answer
	if _, err := f.set(a, corrosion.HAArmed, true); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if _, _, disarmed, _, _ := x.Server.PeerHAAnswer(d.Name); !disarmed {
		t.Fatal("precondition: the dead voter's last answer should still say disarmed")
	}
	f.cs.Tick(ctx, x)
	if n := f.fencesOf(d.Name); n != 1 {
		t.Fatalf("after the re-arm %s was fenced %d times, want 1: a dead voter's disarm held HA off", d.Name, n)
	}
}

// Region scope: a region left unconfirmed fails the change, named, and the
// status reports it.
func TestHADisarm_Fleet_UnconfirmedRegionIsReported(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 4, FaultSeed: 1505, RegionByIndex: []string{"east", "east", "east", "west"}})
	a, w := f.c.Nodes[0], f.c.Nodes[3]
	if err := corrosion.SetFailoverScope(ctx, a.DB, corrosion.FailoverScopeRegion, "test"); err != nil {
		t.Fatal(err)
	}
	f.c.WaitConverged(t, convergeTimeout)
	// a cannot hear w's answers: west never confirms from a's point of view.
	f.c.SetLinkFault(a, w, LinkFault{BlockReady: true})
	_, err := f.set(a, corrosion.HADisarmed, false)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "west") || !strings.Contains(err.Error(), "may still take effect") {
		t.Fatalf("disarm with west unconfirmed: %v, want Unavailable naming west", err)
	}
	st, err := f.c.SelfClient(a).GetHAPolicy(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range st.GetRegions() {
		got[r.GetRegion()] = r.GetConfirmed()
	}
	if !got["east"] || got["west"] {
		t.Fatalf("region confirmation %v, want east confirmed and west not", got)
	}
}

// L3 (re-review C5): once a majority of voters holds a disarm, a coordinator
// whose replica lags it cannot decide an automatic recovery claim.
func TestHADisarm_Fleet_StaleCoordinatorCannotDecideAClaim(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 1506})
	a, b, e, x, v := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	insertVM(t, a, "vm-h", v.Name)
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	c.Kill(v)
	x.HoldPolicyKey(t, "ha")
	for _, n := range c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
	ts, err := corrosion.SetHAPolicy(ctx, a.DB, capabilities.GrantForTest(t, capabilities.FeatureHADisarm),
		corrosion.HADisarmed, "fleet", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{b, e} {
		n := n
		eventually(t, convergeTimeout, "the disarm on "+n.Name, func() bool {
			p, _ := corrosion.GetHAPolicy(ctx, n.DB)
			return p.UpdatedAt == ts
		})
	}
	p := corrosion.ActionProof{ID: "auto-vm-h", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm-h",
		DestHost: x.Name, Coordinator: x.Name, OwnerEpoch: "0"}
	_, err = x.Server.DecideRecoveryClaim(ctx, vmKey(x, "vm-h", 0), corrosion.ClaimValue{Proof: &p, SourceHost: v.Name}, 1, nil)
	var nm *claims.NoMajorityError
	if !errors.As(err, &nm) {
		t.Fatalf("a stale coordinator decided an automatic recovery while a majority holds a disarm: %v", err)
	}
	refused := 0
	for _, r := range nm.Refusals {
		if r.Reason == corrosion.RefusalHADisarmed {
			refused++
		}
	}
	if refused < 3 {
		t.Fatalf("refusals %+v, want a, b and e to refuse for the disarm", nm.Refusals)
	}
}

// A lagging voter's disarm, older than the arm this lease holder holds, does
// not veto: the re-arm case.
//
// Mutation: drop L2's timestamp rule — the lagging voter's old disarm vetoes
// and t is not fenced.
func TestHADisarm_Fleet_LaggingVoterDoesNotHoldHAOffAfterArm(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 6, FaultSeed: 1507})
	a, b, e, x, d, tgt := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2], f.c.Nodes[3], f.c.Nodes[4], f.c.Nodes[5]
	f.cs.Tick(ctx, x)
	if _, err := f.set(a, corrosion.HADisarmed, false); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	eventually(t, convergeTimeout, "the disarm on "+d.Name, func() bool {
		p, _ := corrosion.GetHAPolicy(ctx, d.DB)
		return p.State == corrosion.HADisarmed
	})
	d.HoldPolicyKey(t, "ha") // d will lag the arm
	f.down(t, tgt, a, b, e, x)
	if _, err := f.set(a, corrosion.HAArmed, true); err != nil {
		t.Fatalf("arm: %v", err)
	}
	eventually(t, convergeTimeout, x.Name+" to hear "+d.Name+"'s lagging disarm", func() bool {
		asked, _, disarmed, _, _ := x.Server.PeerHAAnswer(d.Name)
		return disarmed && time.Since(asked) < time.Second
	})
	f.cs.Tick(ctx, x)
	if n := f.fencesOf(tgt.Name); n != 1 {
		t.Fatalf("%s fenced %d times after the arm, want 1: a lagging voter's older disarm held HA off", tgt.Name, n)
	}
}

// R2-I1: with the lease row still valid, a lease holder that counts fewer
// than a majority of the voters live at the moment of decision decides
// nothing (no_quorum), armed or not, and raises no peer-veto condition.
//
// Mutation: drop the no_quorum check — x fences on a minority's view.
func TestHADisarm_Fleet_NoQuorumAtDecisionTime(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 5, FaultSeed: 1508})
	a, b, e, x, d := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2], f.c.Nodes[3], f.c.Nodes[4]
	if err := failover.HADisarmPreRecord(ctx, f.gates[x.Name].WithFeature); err != nil {
		t.Fatalf("pre-record: %v", err)
	}
	f.cs.Tick(ctx, x) // the lease, while x counts the majority
	f.down(t, d, a, b, e, x)
	// Mid-cycle drop: x now counts only itself and a live.
	f.gates[x.Name].SeedPeersForTests(map[string]bool{a.Name: true, b.Name: false, e.Name: false, d.Name: false})
	f.cs.Tick(ctx, x)
	if n := f.fencesOf(d.Name); n != 0 {
		t.Fatalf("%s fenced %s while it counted two of five voters live", x.Name, d.Name)
	}
	if cond := haCondition(t, x, corrosion.CondHAPeerVeto); cond.Lifecycle == corrosion.ConditionConfirmed {
		t.Fatalf("a loss of quorum raised the peer-veto condition: %+v", cond)
	}
}

// L1 on its own: the lease holder's replica holds a disarm its peers have not
// received (the change timed out unconfirmed, and its row stays). Their
// answers say armed, so only the lease holder's own re-read holds the fence.
//
// Mutation: drop L1 — no peer vetoes, and the host is fenced.
func TestHADisarm_Fleet_L1HoldsOnItsOwn(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 3, FaultSeed: 1509})
	a, b, x := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2]
	b.HoldPolicyKey(t, "ha")
	x.HoldPolicyKey(t, "ha")
	f.cs.Tick(ctx, a)
	if _, err := f.set(a, corrosion.HADisarmed, false); status.Code(err) != codes.Unavailable {
		t.Fatalf("disarm no peer can receive: %v, want Unavailable", err)
	}
	if p, _ := corrosion.GetHAPolicy(ctx, a.DB); p.State != corrosion.HADisarmed {
		t.Fatalf("the unconfirmed row did not stay on %s: %+v", a.Name, p)
	}
	f.down(t, x, a, b)
	f.cs.Tick(ctx, a)
	if n := f.fencesOf(x.Name); n != 0 {
		t.Fatalf("%s fenced %s while its own replica says disarmed", a.Name, x.Name)
	}
}

// Review I-1: a lease holder whose replica lacks both the ha row and the
// ha_disarm used record (a host absent at the first use, or added since) is
// still held back by the live voters' disarm.
//
// Mutation: put the whole-L2 gate on the used record back — x fences d.
func TestHADisarm_Fleet_CoordinatorWithoutTheUsedRecordIsVetoed(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 5, FaultSeed: 1510})
	a, b, e, x, d := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2], f.c.Nodes[3], f.c.Nodes[4]
	x.HoldPolicyKey(t, "ha")
	if _, err := f.set(a, corrosion.HADisarmed, false); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	info, _ := capabilities.LookupFeature(capabilities.FeatureHADisarm)
	used := "release_feature/" + info.Token + "/" + string(capabilities.FeatureHADisarm)
	x.HoldPolicyKey(t, "ha", used)
	if err := localExec(ctx, x.DB, `DELETE FROM cluster_policies WHERE key = ?`, used); err != nil {
		t.Fatal(err)
	}
	if present, _, _ := corrosion.ReleaseFeatureState(ctx, x.DB, info.Token, string(capabilities.FeatureHADisarm)); present {
		t.Fatalf("precondition: %s still holds the used record", x.Name)
	}
	f.down(t, d, a, b, e, x)
	f.cs.Tick(ctx, x)
	if n := f.fencesOf(d.Name); n != 0 {
		t.Fatalf("a lease holder without the used record fenced %s %d times during a confirmed disarm", d.Name, n)
	}
}

// F1 (lab 1, 3241dda4): a host that fails while HA is disarmed is held before
// any fence, so it stays recorded active — `lv host ls` keeps showing it
// active and `lv ls` its VM running, because nothing has decided otherwise.
// The lease holder's stall alert still names it, held by the disarm, once the
// hold has lasted recoveryStallAfter. The alert only reports: nothing is
// fenced, no host state is written on any replica, and the VM stays put.
//
// Mutation: drop heldBeforeFence from the stall pass (count only fenced and
// offline hosts, as before the fix) — no alert names x, and this goes red.
func TestHADisarm_Fleet_HostDownWhileDisarmedIsNamedHeld(t *testing.T) {
	ctx := context.Background()
	f := newHAFleet(t, Options{Nodes: 3, FaultSeed: 1511})
	a, b, x := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2]
	insertVM(t, a, "vm-x", x.Name)
	f.c.WaitConverged(t, convergeTimeout)
	if err := failover.HADisarmPreRecord(ctx, f.gates[a.Name].WithFeature); err != nil {
		t.Fatalf("pre-record: %v", err)
	}
	if _, err := f.set(a, corrosion.HADisarmed, false); err != nil {
		t.Fatalf("disarm: %v", err)
	}

	type alert struct {
		by, host, reason string
	}
	var mu sync.Mutex
	var alerts []alert
	for _, n := range f.c.Nodes {
		by := n.Name
		f.cs.ByNode[by].OnRecoveryStalled = func(host, _, reason string, _ int, _ time.Time) {
			mu.Lock()
			alerts = append(alerts, alert{by, host, reason})
			mu.Unlock()
		}
	}
	got := func() []alert {
		mu.Lock()
		defer mu.Unlock()
		return append([]alert(nil), alerts...)
	}

	runStart := f.clock.Now()
	f.down(t, x, a, b)
	f.cs.Tick(ctx, a)
	// Hold it past recoveryStallAfter (60 s), re-publishing the observers'
	// view inside the health freshness bound as the checkers would.
	for i := 0; i < 4; i++ {
		f.clock.Advance(20 * time.Second)
		now := f.clock.Now()
		PublishHealthRun(t, a, x.Name, 5+i, runStart, now)
		PublishHealthRun(t, b, x.Name, 5+i, runStart, now)
		eventually(t, convergeTimeout, b.Name+"'s refreshed view of "+x.Name+" on "+a.Name, func() bool {
			rows, _ := a.DB.Query(ctx, `SELECT updated_at FROM host_health WHERE observer = ? AND target = ?`, b.Name, x.Name)
			return len(rows) == 1 && rows[0].String("updated_at") == now.UTC().Format(time.RFC3339Nano)
		})
		f.cs.Tick(ctx, a)
	}

	var named []alert
	for _, al := range got() {
		if al.host == x.Name {
			named = append(named, al)
		}
	}
	if len(named) != 1 || named[0].by != a.Name || named[0].reason != "recovery held: HA disarmed; held: vm/held-for-node-2, vm/vm-x" {
		t.Fatalf("stall alerts naming %s: %+v, want one from the lease holder %s saying %q",
			x.Name, named, a.Name, "recovery held: HA disarmed; held: vm/held-for-node-2, vm/vm-x")
	}
	if fs := f.cs.Fences(); len(fs) != 0 {
		t.Fatalf("fences while HA is disarmed: %+v", fs)
	}
	for _, n := range f.c.Nodes {
		if n == x {
			continue
		}
		h, err := corrosion.GetHost(ctx, n.DB, x.Name)
		if err != nil || h == nil || h.State != "active" {
			t.Fatalf("%s's record of %s: %+v %v, want it still active (no state is written while disarmed)", n.Name, x.Name, h, err)
		}
		if vm := vmOn(t, n, "vm-x"); vm == nil || vm.HostName != x.Name {
			t.Fatalf("vm-x on %s's replica: %+v, want it still on %s", n.Name, vm, x.Name)
		}
		rows, _ := n.DB.Query(ctx, `SELECT id FROM fencing_log WHERE host_name = ?`, x.Name)
		if len(rows) != 0 {
			t.Fatalf("%s holds %d fencing_log rows for %s while HA is disarmed", n.Name, len(rows), x.Name)
		}
	}
}
