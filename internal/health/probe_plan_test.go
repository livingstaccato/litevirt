package health

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// planCluster names n hosts node-00..node-(n-1) and makes the first v of them
// voters.
func planCluster(n, v int) (names []string, voters map[string]bool) {
	voters = map[string]bool{}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("node-%02d", i)
		names = append(names, name)
		if i < v {
			voters[name] = true
		}
	}
	return names, voters
}

// without returns names minus self, the candidate list checkAllPeers hands
// the plan.
func without(names []string, self string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != self {
			out = append(out, n)
		}
	}
	return out
}

// planEdges is every observer→target edge the plan produces, cluster-wide.
func planEdges(names []string, voters map[string]bool, sample int) map[string]map[string]bool {
	observersOf := map[string]map[string]bool{}
	for _, self := range names {
		for target := range probePlan(self, without(names, self), voters, sample) {
			if observersOf[target] == nil {
				observersOf[target] = map[string]bool{}
			}
			observersOf[target][self] = true
		}
	}
	return observersOf
}

// A voter probes every other host. Its observations are the only ones the
// fence and recovery quorums count, so dropping any of them would shrink the
// number of voters that can ever vote on that target.
func TestProbePlan_VoterProbesEveryone(t *testing.T) {
	names, voters := planCluster(20, 5)
	for self := range voters {
		got := probePlan(self, without(names, self), voters, nonVoterProbeSample)
		if len(got) != len(names)-1 {
			t.Errorf("voter %s probes %d of %d peers; a voter must probe every peer", self, len(got), len(names)-1)
		}
	}
}

// Every target — voter or not — is observed by EVERY voter other than itself.
// This is the property that keeps fencing and recovery unchanged: both count
// fresh voter rows against len(voters)/2+1, and a target observed by fewer
// voters than that could never be fenced or recovered.
func TestProbePlan_EveryTargetIsObservedByEveryVoter(t *testing.T) {
	for _, tc := range []struct{ n, v int }{{5, 5}, {5, 3}, {20, 5}, {50, 5}, {50, 7}, {50, 1}} {
		names, voters := planCluster(tc.n, tc.v)
		obs := planEdges(names, voters, nonVoterProbeSample)
		for _, target := range names {
			for voter := range voters {
				if voter == target {
					continue
				}
				if !obs[target][voter] {
					t.Errorf("n=%d v=%d: voter %s does not observe %s", tc.n, tc.v, voter, target)
				}
			}
		}
	}
}

// A non-voter probes every voter — its own QuorumProof counts voters it has
// probed healthy, so sampling voters would let a non-voter lose quorum while
// the voters it skipped are fine — and at most nonVoterProbeSample other
// non-voters.
func TestProbePlan_NonVoterProbesAllVotersAndABoundedSample(t *testing.T) {
	names, voters := planCluster(50, 5)
	for _, self := range names {
		if voters[self] {
			continue
		}
		got := probePlan(self, without(names, self), voters, nonVoterProbeSample)
		nv := 0
		for target := range got {
			if !voters[target] {
				nv++
			}
		}
		for voter := range voters {
			if !got[voter] {
				t.Errorf("non-voter %s skips voter %s", self, voter)
			}
		}
		if nv != nonVoterProbeSample {
			t.Errorf("non-voter %s probes %d non-voters, want exactly %d", self, nv, nonVoterProbeSample)
		}
	}
}

// Each non-voter is observed by a bounded number of other non-voters, and by
// at least one while there are others: the sample is a ring, so nobody is
// left out and nobody is observed by everyone.
func TestProbePlan_EachNonVoterHasBoundedNonVoterObservers(t *testing.T) {
	for _, tc := range []struct{ n, v int }{{50, 5}, {20, 5}, {6, 3}, {5, 3}, {4, 3}} {
		names, voters := planCluster(tc.n, tc.v)
		obs := planEdges(names, voters, nonVoterProbeSample)
		nonVoters := tc.n - tc.v
		want := nonVoterProbeSample
		if nonVoters-1 < want {
			want = nonVoters - 1
		}
		for _, target := range names {
			if voters[target] {
				continue
			}
			nv := 0
			for o := range obs[target] {
				if !voters[o] {
					nv++
				}
			}
			if nv != want {
				t.Errorf("n=%d v=%d: non-voter %s has %d non-voter observers, want %d", tc.n, tc.v, target, nv, want)
			}
		}
	}
}

// No voter set (a read error, or none known yet) is the full mesh: the plan
// fails toward probing more, never toward starving a quorum.
func TestProbePlan_NoVoterSetProbesEveryone(t *testing.T) {
	names, _ := planCluster(20, 0)
	for _, voters := range []map[string]bool{nil, {}} {
		got := probePlan(names[3], without(names, names[3]), voters, nonVoterProbeSample)
		if len(got) != len(names)-1 {
			t.Errorf("voters=%v: probes %d of %d peers, want the full mesh", voters, len(got), len(names)-1)
		}
	}
}

// countingProbes is a readiness prober that answers ready and counts calls.
type countingProbes struct {
	mu    sync.Mutex
	calls map[string]map[string]int // observer → target → probes
}

func (p *countingProbes) forObserver(observer string) PeerReadiness {
	return func(_ context.Context, host, _ string) (bool, string, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.calls[observer] == nil {
			p.calls[observer] = map[string]int{}
		}
		p.calls[observer][host]++
		return true, "", nil
	}
}

func (p *countingProbes) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, m := range p.calls {
		for _, c := range m {
			n += c
		}
	}
	return n
}

// probesPerCycle runs one real probe cycle on every node of an n-node cluster
// whose voter set is the first v hosts (v == n: every host votes, today's
// full mesh) and returns how many probes the cluster issued.
func probesPerCycle(t *testing.T, n, v int) int {
	t.Helper()
	db := testCheckHostDB(t)
	ctx := context.Background()
	names, voters := planCluster(n, v)
	for i, name := range names {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: fmt.Sprintf("10.9.%d.%d", i/200, i%200+1), SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	probes := &countingProbes{calls: map[string]map[string]int{}}
	for _, name := range names {
		c := NewChecker(name, t.TempDir(), db)
		c.writeFn = func(context.Context, string, ...interface{}) error { return nil }
		c.voterSet = func(context.Context) (map[string]bool, error) { return voters, nil }
		c.SetPeerReadiness(probes.forObserver(name))
		if !c.checkAllPeers(ctx) {
			t.Fatalf("%s: probe cycle did not enumerate hosts", name)
		}
	}
	return probes.total()
}

// The measurement behind colonelpanik/litevirt#262 (b): probes per 2 s cycle,
// cluster-wide, before (every host a voter — the full mesh) and after (an
// explicit voter set of 5), counted from real probe cycles, not a formula.
//
// With every host voting nothing may change: that is today's VoterSet, and a
// plan that sampled there would be sampling the observations quorum counts.
func TestProbesPerCycle_Scale(t *testing.T) {
	for _, tc := range []struct{ n, v int }{{5, 3}, {20, 5}, {50, 5}} {
		n, v := tc.n, tc.v
		before := probesPerCycle(t, n, n)
		if before != n*(n-1) {
			t.Errorf("n=%d, all voting: %d probes per cycle, want the full mesh %d", n, before, n*(n-1))
		}
		after := probesPerCycle(t, n, v)
		nv := n - v
		sample := nonVoterProbeSample
		if nv-1 < sample {
			sample = max(nv-1, 0)
		}
		// Voters: the full row. Non-voters: every voter plus the sample.
		want := v*(n-1) + nv*(v+sample)
		if after != want {
			t.Errorf("n=%d v=%d: %d probes per cycle, want %d", n, v, after, want)
		}
		t.Logf("n=%d: full mesh %d probes/cycle (%.0f/s); voters=%d: %d probes/cycle (%.0f/s)",
			n, before, float64(before)/checkInterval.Seconds(), v, after, float64(after)/checkInterval.Seconds())
	}
}

// A voter set that cannot be read is the full mesh, not an empty plan and not
// a sample: without it the plan cannot tell which edges a quorum counts.
func TestCheckAllPeers_UnreadableVoterSetProbesEveryone(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	names, _ := planCluster(10, 0)
	for i, name := range names {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: fmt.Sprintf("10.9.0.%d", i+1), SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	probes := &countingProbes{calls: map[string]map[string]int{}}
	c := NewChecker(names[0], t.TempDir(), db)
	c.writeFn = func(context.Context, string, ...interface{}) error { return nil }
	c.voterSet = func(context.Context) (map[string]bool, error) { return nil, context.DeadlineExceeded }
	c.SetPeerReadiness(probes.forObserver(names[0]))
	c.checkAllPeers(ctx)
	if got := probes.total(); got != len(names)-1 {
		t.Errorf("%d probes with the voter set unreadable, want every peer (%d)", got, len(names)-1)
	}
}

// A non-voter that stops probing a peer must also stop reporting it: a peer
// state left behind from before the plan changed says "healthy" forever, and
// HealthyPeers would keep offering it as proven-live.
func TestCheckAllPeers_ForgetsAPeerItStoppedProbing(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	names, voters := planCluster(12, 3)
	for i, name := range names {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: fmt.Sprintf("10.9.0.%d", i+1), SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	self := names[len(names)-1] // a non-voter
	c := NewChecker(self, t.TempDir(), db)
	c.writeFn = func(context.Context, string, ...interface{}) error { return nil }
	c.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) { return true, "", nil })

	// Cycle one with every host voting: the full mesh.
	all := map[string]bool{}
	for _, n := range names {
		all[n] = true
	}
	c.voterSet = func(context.Context) (map[string]bool, error) { return all, nil }
	c.checkAllPeers(ctx)
	if got := len(c.HealthyPeers(ctx)); got != len(names)-1 {
		t.Fatalf("precondition: %d healthy peers after a full-mesh cycle, want %d", got, len(names)-1)
	}

	// Cycle two with three voters: this non-voter now probes 3 + sample.
	c.voterSet = func(context.Context) (map[string]bool, error) { return voters, nil }
	c.checkAllPeers(ctx)
	got := c.HealthyPeers(ctx)
	sort.Strings(got)
	plan := probePlan(self, without(names, self), voters, nonVoterProbeSample)
	if len(got) != len(plan) {
		t.Fatalf("HealthyPeers = %v (%d), want exactly the %d peers this node still probes", got, len(got), len(plan))
	}
	for _, p := range got {
		if !plan[p] {
			t.Errorf("HealthyPeers still reports %s, which this node no longer probes", p)
		}
	}
}

// PeerUp answers for a peer outside this node's plan by probing it then and
// there, never from absence. Absence from HealthyPeers used to mean "down";
// with a sampled plan it can simply mean "not mine to watch", and the callers
// that read it as down (a manual fence confirmation freeing a VIP) must not.
func TestPeerUp_ProbesAPeerOutsideThePlan(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	names, voters := planCluster(12, 3)
	for i, name := range names {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: fmt.Sprintf("10.9.0.%d", i+1), SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	self := names[len(names)-1]
	c := NewChecker(self, t.TempDir(), db)
	c.writeFn = func(context.Context, string, ...interface{}) error { return nil }
	c.voterSet = func(context.Context) (map[string]bool, error) { return voters, nil }
	up := map[string]bool{}
	for _, n := range names {
		up[n] = true
	}
	var mu sync.Mutex
	c.SetPeerReadiness(func(_ context.Context, host, _ string) (bool, string, error) {
		mu.Lock()
		defer mu.Unlock()
		if up[host] {
			return true, "", nil
		}
		return false, "", context.DeadlineExceeded
	})
	c.checkAllPeers(ctx)

	plan := probePlan(self, without(names, self), voters, nonVoterProbeSample)
	var outside string
	for _, n := range without(names, self) {
		if !plan[n] {
			outside = n
			break
		}
	}
	if outside == "" {
		t.Fatal("precondition: the plan covers every peer; nothing to test")
	}
	if !c.PeerUp(ctx, outside) {
		t.Errorf("PeerUp(%s) = false for a live peer this node does not probe; absence is not evidence of down", outside)
	}
	mu.Lock()
	up[outside] = false
	mu.Unlock()
	if c.PeerUp(ctx, outside) {
		t.Errorf("PeerUp(%s) = true for a dead peer outside the plan; it must be probed, not assumed", outside)
	}
	// Inside the plan the cached verdict is the answer, as HealthyPeers gives it.
	var inside string
	for p := range plan {
		inside = p
		break
	}
	if !c.PeerUp(ctx, inside) {
		t.Errorf("PeerUp(%s) = false for a peer probed healthy this cycle", inside)
	}
}
