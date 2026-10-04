package failover

// Region-scoped failover (colonelpanik/litevirt#265,
// docs/design/region-scoped-failover.md).
//
// With the cluster policy failover_scope = region, a host in region R is
// fenced, re-admitted and recovered only on the strength of R's own voters,
// and its workloads are recovered onto hosts in R. Everything here is inert
// under the default scope: quorumView.voters returns the whole voter set, the
// decide gate is the cluster-wide one, and no placement request carries a
// region.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// RegionGate is the region-scoped half of the decide gate, implemented by
// *health.Checker. It is a separate interface from FailoverGate so a gate that
// predates region scoping keeps compiling — and, under region scope, is
// refused rather than silently asked the cluster-wide question.
type RegionGate interface {
	// DecisionGateForRegion is DecisionGate over region's voters: this daemon
	// probed a live majority of them itself, and is coordinator-eligible.
	DecisionGateForRegion(ctx context.Context, region string) health.GateResult
	// RegionQuorumProof is the live/needed count behind it, recorded on the
	// proof.
	RegionQuorumProof(ctx context.Context, region string) (health.QuorumState, int, int)
}

// RegionScopedPromoter promotes a replica only if the host holding it is in
// region. Under region scope a Promoter that does not implement it is not
// asked to promote at all: the VM falls through to the reschedule, which is
// region-constrained.
type RegionScopedPromoter interface {
	AutoPromoteReplicaInRegion(ctx context.Context, vmName, fenceEpoch string, leaseTerm int64, region string) error
}

// errPromoterNotRegionScoped makes an out-of-region promote fall through to the
// reschedule path, exactly as any other promote error does.
var errPromoterNotRegionScoped = errors.New("replica promoter cannot keep a promotion in region")

// quorumView is one cycle's quorum rule, read once at the top of run so every
// decision in the cycle is made against the same policy and voter set.
type quorumView struct {
	region bool
	vr     corrosion.VoterRegionSets
}

// voters is the population whose observations count toward a decision about
// target: every voter, or target's region's voters.
func (q quorumView) voters(target string) map[string]bool {
	if !q.region {
		return q.vr.Voters
	}
	return q.vr.In(q.vr.Region(target))
}

// quorum is a majority of voters(target).
func (q quorumView) quorum(target string) int { return len(q.voters(target))/2 + 1 }

// graceScope is the quorum scope a fence of target rests on, for the
// quorum-regain grace: the cluster-wide quorum, or target's region's under
// region scope.
func (q quorumView) graceScope(target string) string {
	if !q.region {
		return health.QuorumScopeCluster
	}
	return health.RegionQuorumScope(q.vr.Region(target))
}

// regionOf is target's region.
func (q quorumView) regionOf(target string) string { return q.vr.Region(target) }

// decideGate is the recovery decide-site gate for a workload whose host is
// host: DecisionGate under the cluster scope, DecisionGateForRegion(host's
// region) under region scope. A gate that cannot answer the regional question
// refuses.
func (c *Coordinator) decideGate(ctx context.Context, host string) health.GateResult {
	if !c.scope.region {
		return c.Gate.DecisionGate(ctx)
	}
	rg, ok := c.Gate.(RegionGate)
	if !ok {
		return health.GateResult{Reason: health.ReasonNoQuorum}
	}
	return rg.DecisionGateForRegion(ctx, c.scope.regionOf(host))
}

// proofQuorum is the live/needed pair a proof records for a decision about
// host, from the same quorum decideGate checked.
func (c *Coordinator) proofQuorum(ctx context.Context, host string) (live, needed int) {
	if c.scope.region {
		if rg, ok := c.Gate.(RegionGate); ok {
			_, live, needed = rg.RegionQuorumProof(ctx, c.scope.regionOf(host))
			return live, needed
		}
	}
	_, live, needed = c.Gate.QuorumProof(ctx)
	return live, needed
}

// vmRecoveryRegion is the region a VM fenced off host must be recovered into:
// host's region under region scope, "" (anywhere) otherwise, and "" for a VM
// that opted out with corrosion.LabelFailoverAnyRegion. The opt-out widens
// where the VM may go, never who decides: the fence that authorised the
// recovery was still host's region's quorum.
func (c *Coordinator) vmRecoveryRegion(host string, vm corrosion.VMRecord) string {
	if !c.scope.region || vmAllowsAnyRegion(vm) {
		return ""
	}
	return c.scope.regionOf(host)
}

// containerRecoveryRegion is vmRecoveryRegion for a container. There is no
// opt-out for containers.
func (c *Coordinator) containerRecoveryRegion(host string) string {
	if !c.scope.region {
		return ""
	}
	return c.scope.regionOf(host)
}

// vmAllowsAnyRegion reports whether the VM's spec carries
// LabelFailoverAnyRegion=true.
func vmAllowsAnyRegion(vm corrosion.VMRecord) bool {
	var spec struct {
		Labels map[string]string `json:"labels"`
	}
	if vm.Spec != "" {
		_ = json.Unmarshal([]byte(vm.Spec), &spec)
	}
	return spec.Labels[corrosion.LabelFailoverAnyRegion] == "true"
}

// autoPromote runs the replica promotion for vm, kept in region when the
// scope requires it.
func (c *Coordinator) autoPromote(ctx context.Context, h *corrosion.HostRecord, vm corrosion.VMRecord, fenceEpoch string, leaseTerm int64) error {
	region := c.vmRecoveryRegion(h.Name, vm)
	if region == "" {
		return c.Promoter.AutoPromoteReplica(ctx, vm.Name, fenceEpoch, leaseTerm)
	}
	rp, ok := c.Promoter.(RegionScopedPromoter)
	if !ok {
		return errPromoterNotRegionScoped
	}
	return rp.AutoPromoteReplicaInRegion(ctx, vm.Name, fenceEpoch, leaseTerm, region)
}

// noteRegionDeclined reports a host that the cluster-wide count would have
// fenced and the region-scoped count does not. Two different conditions, told
// apart because they need different things from an operator:
//
//   - region_too_small: the host's region has fewer than MinRegionVoters
//     voters, so it can never fence one of its own. Its hosts have no
//     automatic failover while the policy is on. Add voters (a witness counts)
//     or accept it.
//   - region_scoped: the region is large enough, but the observations come
//     from other regions' voters. A site partition looks exactly like this,
//     and declining is the point of the policy.
//
// The counter moves every cycle; the log line only when a host's class
// changes, so an hours-long partition is one line per host rather than one
// every poll.
func (c *Coordinator) noteRegionDeclined(q quorumView, target string, clusterObservers, regionObservers int) {
	class := ErrRegionScoped
	if len(q.voters(target)) < corrosion.MinRegionVoters {
		class = ErrRegionTooSmall
	}
	c.mAttempt(PhaseQuorum, ResultRefused, class)
	if c.regionDeclined == nil {
		c.regionDeclined = map[string]string{}
	}
	if c.regionDeclined[target] == class {
		return
	}
	c.regionDeclined[target] = class
	region := q.regionOf(target)
	if class == ErrRegionTooSmall {
		slog.Error("failover: region-scoped failover cannot fence this host — its region has too few voters to form a quorum of its own; NOT widening to the cluster",
			"host", target, "region", region, "region_voters", len(q.voters(target)),
			"min_region_voters", corrosion.MinRegionVoters, "cluster_observers", clusterObservers,
			"hint", "add voters to region "+region+" (a witness counts), or run 'lv cluster failover-scope' to review")
		return
	}
	slog.Warn("failover: host reported down only by voters outside its region — region-scoped failover leaves it to its own region",
		"host", target, "region", region, "region_observers", regionObservers,
		"region_quorum", q.quorum(target), "cluster_observers", clusterObservers)
}

// clearRegionDeclined forgets the logged class of hosts no longer declined.
func (c *Coordinator) clearRegionDeclined(still map[string]bool) {
	for h := range c.regionDeclined {
		if !still[h] {
			delete(c.regionDeclined, h)
		}
	}
}

// publishRegionsWithoutQuorum sets the gauge of regions that hold a worker but
// cannot fence their own hosts. 0 under the cluster scope, where no region
// needs a quorum of its own.
func (c *Coordinator) publishRegionsWithoutQuorum(ctx context.Context, q quorumView) {
	if !q.region {
		c.mRegionsWithoutQuorum(0)
		return
	}
	report, err := corrosion.RegionQuorumReport(ctx, c.db)
	if err != nil {
		// Leave the last measured value: 0 would clear an alert on a number
		// nobody read.
		slog.Warn("failover: region quorum report", "error", err)
		return
	}
	n := 0
	for _, r := range report {
		if r.Workers > 0 && !r.CanFenceOwn() {
			n++
		}
	}
	c.mRegionsWithoutQuorum(n)
}
