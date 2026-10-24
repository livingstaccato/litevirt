package failover

import (
	"context"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// HealthObservation is one host_health row a fence decision may count: an
// observer's failing verdict of a target, as the coordinator's query selects
// it (at or past the failure threshold, not unready, not about the deciding
// node itself).
type HealthObservation struct {
	Target, Observer string
	Failures         int
	LastSeen         string
	UpdatedAt        string
}

// CandidateInputs is everything the fence-candidate decision reads, gathered
// by the caller. Nothing in it is a handle: FenceCandidates is a pure function
// of it, so any goroutine on any node can ask it.
type CandidateInputs struct {
	// Self is the deciding node; its own verdicts were never selected.
	Self string
	// RegionScope is failover_scope = region; Voters the voter set with every
	// host's region.
	RegionScope bool
	Voters      corrosion.VoterRegionSets
	Now         time.Time
	// Observations are the failing verdicts (candidateObservations).
	Observations []HealthObservation
	// ActiveSince is when each host last turned active, nil when it could not
	// be read (then observations are judged as before activation was known).
	ActiveSince map[string]time.Time
	// FenceTimes are the fencing_log timestamps of each host the
	// inherited-run grace needs them for (fenceTimesNeeded).
	FenceTimes map[string][]time.Time
	// UpgradingTimeout is the allowance a host fenced inside a failing run it
	// has since come back from gets (inheritedRunGraceFrom), and the restart
	// allowance UpgradingLives extends.
	UpgradingTimeout time.Duration
	// UpgradingLives is, per host, the last span the deciding node saw it
	// recorded 'upgrading' (upgradingLifeGrace). nil: none.
	UpgradingLives map[string]UpgradingLife
}

// UpgradingLife is a span a host was recorded 'upgrading', as the deciding
// coordinator saw it: from its 'upgrading' write (Start) to the activation
// that ended it (End; zero while it lasts).
type UpgradingLife struct {
	Start, End time.Time
}

// FenceCandidate is a host enough fresh voters report down.
type FenceCandidate struct {
	Target    string
	Observers int
}

// RegionDecline is a host the cluster-wide count would have fenced and its
// region's count does not (region scope only).
type RegionDecline struct {
	Target                            string
	ClusterObservers, RegionObservers int
}

// quorumView is the scope rule of the inputs.
func (in CandidateInputs) quorumView() quorumView {
	return quorumView{region: in.RegionScope, vr: in.Voters}
}

// observationInstant is an observation's updated_at as a wall instant, and
// whether it is fresh and not future-dated relative to now.
func observationInstant(o HealthObservation, now time.Time) (inst time.Time, fresh, future bool) {
	inst, ok := corrosion.ParseUpdatedAt(o.UpdatedAt)
	if !ok || !inst.After(now.Add(-healthFreshness)) {
		return inst, false, false
	}
	if inst.After(now.Add(healthFreshness)) {
		return inst, false, true
	}
	return inst, true, false
}

// FenceCandidates is the fence decision's quorum count: every host enough
// fresh voters of its scope report down, sorted by name, and under region
// scope the hosts the cluster-wide count would have fenced and the region
// count does not. It applies the freshness bounds (an observation older than
// healthFreshness, or stamped further ahead than that, does not count),
// countedSinceActive with the inherited-run grace, and the scope's quorum.
//
// It is PURE: it reads only in, and touches no coordinator, metric, gauge or
// log. The coordinator's cycle acts on what it returns (run), and the HA arm
// handler lists the same hosts from inputs it gathers itself
// (CurrentFenceCandidates), so the two cannot disagree.
func FenceCandidates(in CandidateInputs) (cands []FenceCandidate, declined []RegionDecline) {
	q := in.quorumView()
	clusterQuorum := len(in.Voters.Voters)/2 + 1
	fresh, cluster := countVoters(in)
	for t, obs := range fresh {
		if len(obs) >= q.quorum(t) {
			cands = append(cands, FenceCandidate{Target: t, Observers: len(obs)})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Target < cands[j].Target })
	for t, obs := range cluster {
		if len(obs) >= clusterQuorum && len(fresh[t]) < q.quorum(t) {
			declined = append(declined, RegionDecline{Target: t, ClusterObservers: len(obs), RegionObservers: len(fresh[t])})
		}
	}
	sort.Slice(declined, func(i, j int) bool { return declined[i].Target < declined[j].Target })
	return cands, declined
}

// countVoters is FenceCandidates' count: per target, the fresh voters of its
// scope that report it down, and under region scope the cluster-wide voters.
func countVoters(in CandidateInputs) (fresh, cluster map[string]map[string]struct{}) {
	q := in.quorumView()
	fresh = map[string]map[string]struct{}{}
	cluster = map[string]map[string]struct{}{}
	for _, o := range in.Observations {
		inst, ok, _ := observationInstant(o, in.Now)
		if !ok {
			continue
		}
		if since, has := in.ActiveSince[o.Target]; has && !countedSinceActiveWithin(o.Failures, o.LastSeen, inst, since,
			longerGrace(inheritedRunGraceFrom(in.FenceTimes[o.Target], since, in.UpgradingTimeout),
				upgradingLifeGrace(in.UpgradingLives[o.Target], since, in.UpgradingTimeout))) {
			continue
		}
		if q.region && countsAsVote(in.Voters.Voters, o.Observer, o.Target) {
			if cluster[o.Target] == nil {
				cluster[o.Target] = map[string]struct{}{}
			}
			cluster[o.Target][o.Observer] = struct{}{}
		}
		if !countsAsVote(q.voters(o.Target), o.Observer, o.Target) {
			continue
		}
		if fresh[o.Target] == nil {
			fresh[o.Target] = map[string]struct{}{}
		}
		fresh[o.Target][o.Observer] = struct{}{}
	}
	return fresh, cluster
}

// freshVoterCounts is, per target, the number of fresh voters of its scope
// that report it down, counted exactly as FenceCandidates counts them,
// including targets short of a quorum. Pure, like FenceCandidates.
func freshVoterCounts(in CandidateInputs) map[string]int {
	fresh, _ := countVoters(in)
	out := make(map[string]int, len(fresh))
	for t, obs := range fresh {
		out[t] = len(obs)
	}
	return out
}

// inheritedRunGraceFrom is the inherited-run grace (see fence_incarnation.go)
// over fence times already read.
func inheritedRunGraceFrom(times []time.Time, since time.Time, upgrading time.Duration) func(time.Time) time.Duration {
	return func(runStart time.Time) time.Duration {
		from := runStart.Add(-fenceSkewMargin)
		for _, ts := range times {
			if !ts.Before(from) && ts.Before(since) {
				if upgrading > afreshRun {
					return upgrading
				}
				return afreshRun
			}
		}
		return afreshRun
	}
}

// upgradingLifeGrace is the allowance of a failing run that began while the
// host was recorded 'upgrading', when the activation at `since` is the one that
// ended that life: the rest of the restart allowance (upgrading, from the
// 'upgrading' write), and never less than afreshRun. Any other run gets
// afreshRun.
//
// Only the host records itself active once it serves, and its observers'
// runs then break. Anything else that records it active mid-restart — an
// operator's undrain handled by a node without the serving check — would
// otherwise leave it afreshRun before a fence on the failing run left from
// its stop (lab 1, 2026-10-17: fenced 19 s after the undrain, 0.4 s after its
// gRPC server listened). It is never fenced later than it would have been
// had it stayed 'upgrading': once Start+upgrading has passed, a host that
// still does not answer is fenced as one stuck 'upgrading' is.
func upgradingLifeGrace(life UpgradingLife, since time.Time, upgrading time.Duration) func(time.Time) time.Duration {
	return func(runStart time.Time) time.Duration {
		if life.Start.IsZero() || !life.End.Equal(since) || runStart.Before(life.Start.Add(-fenceSkewMargin)) {
			return afreshRun
		}
		if left := life.Start.Add(upgrading).Sub(since); left > afreshRun {
			return left
		}
		return afreshRun
	}
}

// longerGrace is the longer of two run allowances.
func longerGrace(a, b func(time.Time) time.Duration) func(time.Time) time.Duration {
	return func(runStart time.Time) time.Duration {
		return max(a(runStart), b(runStart))
	}
}

// fenceTimesNeeded lists the hosts whose fencing_log the inherited-run grace
// reads: one with a fresh observation published since it turned active whose
// failing run began before that. No other host's log is read, as before.
func fenceTimesNeeded(obs []HealthObservation, activeSince map[string]time.Time, now time.Time) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range obs {
		since, has := activeSince[o.Target]
		if !has || seen[o.Target] {
			continue
		}
		inst, ok, _ := observationInstant(o, now)
		if !ok || inst.Before(since) || !observerRunStart(o.Failures, o.LastSeen, inst).Before(since) {
			continue
		}
		seen[o.Target] = true
		out = append(out, o.Target)
	}
	return out
}

// candidateObservations reads the failing verdicts a fence decision counts.
func candidateObservations(ctx context.Context, db *corrosion.Client, self string) ([]HealthObservation, error) {
	rows, err := db.Query(ctx,
		`SELECT target, observer, consecutive_failures, last_seen, updated_at
		 FROM host_health
		 WHERE target != ?
		   AND consecutive_failures >= ?
		   AND status != ?`,
		self, offlineThreshold, health.StatusUnready)
	if err != nil {
		return nil, err
	}
	out := make([]HealthObservation, 0, len(rows))
	for _, r := range rows {
		out = append(out, HealthObservation{Target: r.String("target"), Observer: r.String("observer"),
			Failures: int(r.Int("consecutive_failures")), LastSeen: r.String("last_seen"), UpdatedAt: r.String("updated_at")})
	}
	return out, nil
}

// readFenceTimes fills in the fencing_log timestamps fenceTimesNeeded names.
func readFenceTimes(ctx context.Context, db *corrosion.Client, in *CandidateInputs) {
	in.FenceTimes = map[string][]time.Time{}
	for _, h := range fenceTimesNeeded(in.Observations, in.ActiveSince, in.Now) {
		in.FenceTimes[h] = fenceAttemptTimesIn(ctx, db, h)
	}
}

// CurrentFenceCandidates gathers fresh inputs from db — the failover scope
// and voter regions through a new health.DecisionPolicy, the host_health
// rows, when each host turned active, and the fence log the grace needs — and
// returns the hosts FenceCandidates names. It is the coordinator's own
// decision, safe from any goroutine on any node, lease holder or not; the HA
// arm handler lists down hosts with it. A read error is returned: the caller
// must not read an empty list as "nothing is down".
func CurrentFenceCandidates(ctx context.Context, db *corrosion.Client, self string, now time.Time, upgrading time.Duration) ([]string, error) {
	pol := health.NewDecisionPolicy(db)
	vr, err := pol.VoterRegions(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := pol.Scope(ctx)
	if err != nil {
		return nil, err
	}
	obs, err := candidateObservations(ctx, db, self)
	if err != nil {
		return nil, err
	}
	active, err := corrosion.HostsActiveSince(ctx, db)
	if err != nil {
		active = nil
	}
	in := CandidateInputs{Self: self, RegionScope: scope.Region(), Voters: vr, Now: now,
		Observations: obs, ActiveSince: active, UpgradingTimeout: upgrading}
	readFenceTimes(ctx, db, &in)
	cands, _ := FenceCandidates(in)
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.Target)
	}
	return out, nil
}
