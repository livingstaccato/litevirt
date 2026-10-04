package health

import (
	"context"
	"sort"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Probe plan: all-pairs among voters, sampled for non-voters
// (colonelpanik/litevirt#262 (b)).
//
// Every observation any quorum counts is a VOTER's:
//
//   - the failover coordinator's fence and recovery quorums count fresh
//     host_health rows whose observer is in corrosion.VoterSet, against
//     len(voters)/2+1, about ANY target — voter or not;
//   - QuorumProof counts voters this node has probed healthy itself.
//
// So the plan keeps every edge those read and samples only the rest:
//
//   - a voter probes every peer, so every target keeps every voter as an
//     observer, and a dead host of either kind reaches the fence quorum on the
//     same probe cycle a full mesh would;
//   - a non-voter probes every voter, so its own QuorumProof sees the same
//     voters it did before;
//   - a non-voter probes nonVoterProbeSample other non-voters: its successors
//     on a ring of the non-voters sorted by name. Each non-voter is therefore
//     observed by every voter plus exactly that many non-voters (fewer only
//     when there are not that many others), a bounded number in both
//     directions.
//
// Those non-voter→non-voter rows feed no quorum. They feed the operator's
// connectivity view and a non-voter's HealthyPeers, which is why PeerUp exists:
// a peer outside this node's plan is probed on demand, never read as down
// from its absence.
//
// Until a voter generation is adopted, VoterSet is derived and every active
// host is a voter, so the plan is the full mesh; the non-voters it samples are
// the offline and fenced hosts' own probes of each other, and the probes OF an
// offline or fenced host, which recovery counts, are all kept. Once a
// generation is adopted (colonelpanik/litevirt#251 step 2), the voters are its
// members whatever their state — a fenced member keeps probing all-pairs and
// being counted — and an active host outside it is sampled like any non-voter
// (TestProbePlan_ReadsTheAdoptedVoterSet).
//
// The ring is computed from each node's own view of the host table. Two nodes
// that briefly disagree about membership pick slightly different samples; since
// only non-voter→non-voter edges are sampled, no quorum depends on them
// agreeing.

// nonVoterProbeSample is how many other non-voters each non-voter probes, and
// so how many non-voters observe each non-voter.
const nonVoterProbeSample = 3

// probePlan returns the peers self probes, drawn from candidates (every probe
// target this cycle, self excluded). A nil or empty voter set is the full mesh:
// with no voter set to protect, the plan fails toward probing more.
func probePlan(self string, candidates []string, voters map[string]bool, sample int) map[string]bool {
	plan := make(map[string]bool, len(candidates))
	if len(voters) == 0 || voters[self] {
		for _, c := range candidates {
			plan[c] = true
		}
		return plan
	}
	ring := []string{self}
	for _, c := range candidates {
		if voters[c] {
			plan[c] = true
		} else {
			ring = append(ring, c)
		}
	}
	sort.Strings(ring)
	at := sort.SearchStrings(ring, self)
	for i := 1; i <= sample && i < len(ring); i++ {
		plan[ring[(at+i)%len(ring)]] = true
	}
	return plan
}

// planCandidates is every host an observer's checker considers probing: not
// itself, not in maintenance (checkAllPeers never probes a maintenance host).
func planCandidates(observer string, hosts []corrosion.HostRecord) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h.Name != observer && h.State != "maintenance" && h.State != corrosion.HostStateJoining {
			out = append(out, h.Name)
		}
	}
	return out
}

// ObserverPlan is the set of peers observer's checker probes, computed from
// hosts and voters the way that checker computes it from its own view. A
// reader of host_health uses it to tell an edge nobody probes any more, whose
// row is frozen at its last verdict, from a live one.
func ObserverPlan(observer string, hosts []corrosion.HostRecord, voters map[string]bool) map[string]bool {
	return probePlan(observer, planCandidates(observer, hosts), voters, nonVoterProbeSample)
}

// voters reads the voter set the plan protects: corrosion.VoterSet unless a
// test replaced it.
func (c *Checker) voters(ctx context.Context) (map[string]bool, error) {
	if c.voterSet != nil {
		return c.voterSet(ctx)
	}
	return corrosion.VoterSet(ctx, c.db)
}

// PeerUp reports whether host is up as far as this node can tell NOW, for the
// callers that act on "down": a voting-eligible peer probed healthy by this
// node, the HealthyPeers test.
//
// A peer outside this node's probe plan is not in HealthyPeers because nobody
// here watches it, not because it is down, so it is probed on the spot instead.
// Before the first plan exists the cached answer stands, as it always did.
func (c *Checker) PeerUp(ctx context.Context, host string) bool {
	c.mu.Lock()
	planned := c.planned
	c.mu.Unlock()
	if planned == nil || planned[host] {
		for _, h := range c.HealthyPeers(ctx) {
			if h == host {
				return true
			}
		}
		return false
	}
	rec, err := corrosion.GetHost(ctx, c.db, host)
	if err != nil || rec == nil || !VotingEligible(rec.State) {
		return false
	}
	return c.probeHost(ctx, rec.Name, corrosion.PeerTarget(rec.Address, rec.GRPCPort)) == probeReady
}
