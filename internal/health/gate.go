package health

import (
	"context"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Split-brain safety gate (Phase 1).
//
// Every dangerous runtime-ownership action must fail closed without quorum. The
// gate is composed of two independent checks so per-host and coordinator-driven
// actions aren't wrongly subjected to leader-only rules:
//
//   - DecisionGate  — QuorumProof.Yes && the local host is COORDINATOR-eligible
//     (fully in service to *initiate* failover). Witnesses pass (they vote and
//     may decide/forward) but an upgrading/draining/warming host does not.
//   - ExecutionGate — QuorumProof.Yes && the local host is an ACTIVE WORKER
//     (localHostIsActiveWorker; witnesses never execute a workload).
//
// Callers in internal/failover additionally require holdLease() at the *decide*
// site. The lease alone is never sufficient: a CRDT lease can be "held" on both
// sides of a partition, so decide-site safety is holdLease() && DecisionGate.OK.
//
// QuorumProof is derived from THIS daemon's own probe results (c.peers), not from
// arbitrary replicated host_health rows, which freeze-but-look-fresh for a probe
// window after a partition and would let both sides believe they have quorum.

// QuorumState is the tri-state result of a local quorum computation.
type QuorumState int

const (
	// QuorumUnknown means the daemon has not completed its first probe cycle and
	// the startup grace has not elapsed: neither positive proof nor confirmed
	// loss. Callers must neither claim/act nor (for Phase 2) demote on Unknown.
	QuorumUnknown QuorumState = iota
	// QuorumNo means quorum is not currently held (fail closed).
	QuorumNo
	// QuorumYes means a live voting majority is reachable from this daemon.
	QuorumYes
)

// startupGrace bounds the QuorumUnknown warmup window. After it elapses without a
// completed probe cycle, Unknown is treated as No (fail closed).
const startupGrace = 20 * time.Second

// Gate refusal reasons — a CLOSED vocabulary shared with the
// litevirt_runtime_action_refused_total{reason} metric (wired in Phase 1 gate
// insertion). This is the plan's closed reason set PLUS the Phase-1/2 additions that
// postdate the plan's original list, each kept distinct for observability:
//   - ReasonWarmup — QuorumProof is Unknown (the tri-state warmup window): "can't
//     confirm quorum YET", kept separate from a confirmed no_quorum.
//   - ReasonProofClaimError — a TRANSIENT DB error while claiming a proof, distinct
//     from a spent/terminal proof (proof_terminal).
//   - ReasonSelfFenced — this node has self-fenced and refuses all decide/execute
//     during the fence-timeout window (doomed, waiting to reboot).
//
// Adding a reason here is safe (the metric CounterVec accepts any label value); keep
// this list and the documented plan vocabulary in sync.
const (
	ReasonNoQuorum              = "no_quorum"
	ReasonMissingWitness        = "missing_witness"
	ReasonLeaseLost             = "lease_lost"
	ReasonLocalNotActiveWorker  = "local_not_active_worker"
	ReasonNotCoordinatorElig    = "not_coordinator_eligible"
	ReasonPeerUnreachable       = "peer_unreachable"
	ReasonActivationUnconfirm   = "activation_unconfirmed"
	ReasonUnsupportedCapability = "unsupported_capability"
	ReasonProofMissing          = "proof_missing"
	ReasonProofInProgress       = "proof_in_progress"
	ReasonProofTerminal         = "proof_terminal"
	ReasonProofConflict         = "proof_conflict"
	ReasonProofClaimError       = "proof_claim_error" // transient DB error claiming a proof (not a spent/terminal proof)
	ReasonStaleEpoch            = "stale_epoch"       // Phase 5 (fence/owner epoch staleness)
	// ReasonStaleLeaseTerm: FENCED. The proof's lease term is below the
	// quorum-observed high-water mark for its key, or its coordinator is not
	// the holder this node recorded at that term.
	ReasonStaleLeaseTerm = "stale_lease_term"
	// ReasonLeaseTermUnconfirmed: NOT fenced — could not establish WHETHER it
	// was fenced. Quorum was unreachable, or a ledger read failed. Kept
	// distinct from ReasonStaleLeaseTerm because the first is the mechanism
	// working and the second is the mechanism degraded; collapsing them loses
	// the only signal that tells an operator which one is happening.
	ReasonLeaseTermUnconfirmed  = "lease_term_unconfirmed"
	ReasonFenceUnproven         = "fence_unproven"
	ReasonDemotionFailed        = "demotion_failed"
	ReasonVIPReleaseUnconfirmed = "vip_release_unconfirmed"
	ReasonStorageUnverified     = "storage_unverified"
	ReasonWarmup                = "warmup"
	ReasonSelfFenced            = "self_fenced"       // this node self-fenced; refuses decide/execute until it reboots
	ReasonOwnershipDispute      = "ownership_dispute" // the workload has an active ownership condition; automated recovery must not add a holder
	ReasonHardwareBlocked       = "hardware_blocked"  // hardware_v2 pre-start refused an automated (re)start (blocked adoption / unacquirable passthrough)

	// Recovery claims (docs/design/recovery-claims.md §5.4). The destination
	// refuses with ReasonClaimUnproven; the coordinator with the other four,
	// which say why no certificate formed.
	//
	// ReasonClaimUnproven: an ownership-transfer proof reached its executor
	// without a certificate that verifies — absent, for another value, from a
	// generation this node has not adopted or a forced one replaced, or with
	// too few valid signed accepts. The row stays pending; replication lag on
	// voter_configs or cluster_crl clears on a later tick.
	ReasonClaimUnproven = "recovery_claim_unproven"
	// ReasonClaimLost: another value was decided for the key; this coordinator
	// completed or deferred to it and minted nothing of its own.
	ReasonClaimLost = "recovery_claim_lost"
	// ReasonClaimNoMajority: no majority of the voter generation promised or
	// accepted — unreachable voters, or ballots that kept losing.
	ReasonClaimNoMajority = "recovery_claim_no_majority"
	// ReasonClaimOwnerReachable: voters could still reach the recorded owner
	// and refused to certify its eviction (§3.5.1).
	ReasonClaimOwnerReachable = "recovery_claim_owner_reachable"
	// ReasonClaimSourceMismatch: voters whose settled row names a different
	// owner refused the named source (§3.5.1).
	ReasonClaimSourceMismatch = "recovery_claim_source_mismatch"
)

// GateResult is the outcome of a gate check. Reason is set (from the closed
// vocabulary above) only when !OK.
type GateResult struct {
	OK     bool
	Reason string
}

func gateOK() GateResult         { return GateResult{OK: true} }
func gateNo(r string) GateResult { return GateResult{OK: false, Reason: r} }

// VotingEligible is corrosion.VotingEligible, the one definition of a voting
// member: a host votes iff its state is not offline/maintenance/fenced
// (witnesses included). The failover coordinator's fence and recovery quorums
// use the same rule through corrosion.VoterSet, so the self-count here, the
// quorum denominator and the observers whose votes count cannot skew.
//
// Exported because callers outside this package need "is this host live" and
// must not invent a fourth answer to it. The NetBox cluster-name uniformity
// check is one: it compares each live host's published configuration, and a
// host that is down, in maintenance or fenced must not be able to stop the
// inventory mirror forever by holding a stale value. It deliberately does NOT
// use HealthyPeers for that, which additionally requires a successful probe
// THIS run — that answer differs per node and is empty on a freshly started
// daemon, so two nodes would disagree about who is live and a restart would
// briefly count nobody. This predicate is cluster STATE, so every node
// computes the same set.
func VotingEligible(state string) bool { return corrosion.VotingEligible(state) }

// QuorumProof computes whether this daemon currently sees a live voting majority,
// using its OWN probe results. Returns the tri-state plus the live/needed counts
// for observability. `needed = liveVotingHosts/2 + 1`; `live` counts self (if
// voting-eligible) plus each voting-eligible peer this daemon has probed healthy.
//
// It is CLUSTER-WIDE whatever the failover scope says. Its consumers outside
// the failover path — VIP self-demotion, the lease-term barrier, dual-run
// resolution — decide things a region's quorum does not own (see
// docs/design/region-scoped-failover.md §2.4). The region-scoped counts are
// RegionQuorumProof, ExecutionGate and DecisionGateForRegion.
func (c *Checker) QuorumProof(ctx context.Context) (state QuorumState, live, needed int) {
	voters, err := corrosion.VoterSet(ctx, c.db)
	if err != nil {
		// Can't read the host table → UNKNOWN, not No. For gates this still fails closed
		// (Unknown refuses). But the VIPDemoter treats sustained No as a TRIGGER to demote
		// local VIPs (and, only if that demote can't be confirmed on a node with a verified
		// watchdog, to self-fence); mapping a transient local DB error (e.g. anti-entropy
		// lock contention) to No would stand a healthy, quorum-holding node's VIP down.
		// Unknown = "neither proof nor loss" → no action, no loss-clock.
		return QuorumUnknown, 0, 0
	}
	state, live, needed = c.quorumOver(voters)
	c.noteQuorum(QuorumScopeCluster, state)
	return state, live, needed
}

// QuorumRegainGrace is how long after this daemon regained a quorum its
// coordinator decides no new fence on that quorum: StallGrace, the time a
// fence verdict takes to build. A node that was itself cut off holds failure
// rows its peers wrote DURING the cut — about every host, after a fleet-wide
// blip — and replication delivers them in the seconds after the heal, before
// the observers' first successful probes overwrite them. Deciding on them
// would fence hosts that are answering (docs/design/partition-pause.md §7 F7).
const QuorumRegainGrace = StallGrace

// Quorum scopes the regain grace is tracked per. The grace for a decision is
// the grace of the quorum that decision rests on: the cluster-wide one under
// the cluster scope, the region's under region-scoped failover — never the
// cluster-wide quorum for a regional decision, which a region majority cut off
// from the rest of the cluster legitimately lacks for as long as the cut
// lasts.
const QuorumScopeCluster = "cluster"

// RegionQuorumScope is the regain-grace scope of region's voters.
func RegionQuorumScope(region string) string { return regionScopePrefix + region }

const regionScopePrefix = "region:"

// noteQuorum records one reading of scope's quorum: a No marks it lost, and the
// first Yes after that is its No→Yes transition. Unknown changes nothing. The
// grace runs from the TRANSITION, not from the last No, so a consumer that
// keeps re-reading a quorum that stays lost does not keep re-arming it.
func (c *Checker) noteQuorum(scope string, st QuorumState) {
	if st == QuorumUnknown {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.quorumLost == nil {
		c.quorumLost = map[string]bool{}
		c.quorumRegainedAt = map[string]time.Time{}
	}
	switch st {
	case QuorumNo:
		c.quorumLost[scope] = true
	case QuorumYes:
		if c.quorumLost[scope] {
			c.quorumLost[scope] = false
			c.quorumRegainedAt[scope] = c.now()
		}
	}
}

// InQuorumRegainGraceFor reports whether the failover coordinator should defer
// a new fence decided on scope's quorum: that quorum is lost now (this node is
// on the minority side of it), or it was regained within QuorumRegainGrace. A
// scope this daemon never saw lost is never in it, so a majority that kept its
// quorum through a partition fences as before.
//
// "Lost now" is read fresh, never taken from the last recorded reading. The
// daemon's own scope is re-read every tick by the partition pauser, but a
// remote region's quorum is read only by a fence decision about one of its
// hosts — which this grace runs ahead of. Trusting the recorded No would defer
// that region's fences for as long as nothing else re-read it: forever. So a
// scope recorded lost is re-evaluated here; a Yes is its No→Yes transition and
// opens the grace from now, a No or an unreadable quorum keeps it closed.
func (c *Checker) InQuorumRegainGraceFor(ctx context.Context, scope string) bool {
	c.mu.Lock()
	lost := c.quorumLost[scope]
	c.mu.Unlock()
	if lost {
		if region, ok := strings.CutPrefix(scope, regionScopePrefix); ok {
			c.RegionQuorumProof(ctx, region)
		} else {
			c.QuorumProof(ctx)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.quorumLost[scope] {
		return true
	}
	at, ok := c.quorumRegainedAt[scope]
	return ok && c.now().Sub(at) < QuorumRegainGrace
}

// RegionQuorumProof is QuorumProof over one region's voters: the members of
// the voter set whose hosts.region is region, counted from THIS daemon's own
// probes. A region with no voters has nothing to prove and reports No. A read
// error is Unknown, as for QuorumProof.
func (c *Checker) RegionQuorumProof(ctx context.Context, region string) (state QuorumState, live, needed int) {
	vr, err := corrosion.VoterRegions(ctx, c.db)
	if err != nil {
		return QuorumUnknown, 0, 0
	}
	state, live, needed = c.quorumOver(vr.In(region))
	c.noteQuorum(RegionQuorumScope(region), state)
	return state, live, needed
}

// quorumOver counts this daemon's fresh probe results over voters: live is
// self (when a member) plus each member probed healthy this run, needed is a
// majority of voters.
func (c *Checker) quorumOver(voters map[string]bool) (state QuorumState, live, needed int) {
	// A peer this node last saw healthy BEFORE its own most recent stall is not
	// proven live: the stall is exactly the window in which it may have died,
	// and the failures that would have said so were withheld (stall.go). It
	// counts again after one successful probe. This is the fail-closed half of
	// the stall guard — without it, withholding failures would leave a node that
	// resumed into a partition claiming quorum for longer than before.
	stallAt, _ := c.beat(c.now())

	c.mu.Lock()
	probed := c.probedOnce
	started := c.startedAt
	healthy := make(map[string]bool, len(c.peers))
	for name, ps := range c.peers {
		// Count a peer toward quorum ONLY on a restart-local fresh probe success.
		// peerState is no longer seeded from the host_health DB row at bootstrap
		// (checker.go stopped doing that, in both directions), but this guard is
		// not redundant: lastHealthyAt is a local monotonic anchor, zero until
		// THIS run probes the peer healthy at least once, so a peer can never be
		// credited toward quorum on anything but a fresh probe of our own —
		// whatever a future bootstrap decides to pre-populate.
		healthy[name] = ps.status == "healthy" && !ps.lastHealthyAt.IsZero() &&
			!ps.lastHealthyAt.Before(stallAt)
	}
	c.mu.Unlock()

	// The denominator is the voter set, the same one the failover
	// coordinator's fence and recovery quorums count over; only its members
	// count toward live.
	needed = len(voters)/2 + 1
	for name := range voters {
		if name == c.hostName || healthy[name] {
			live++
		}
	}

	// Warmup: before the first probe cycle, c.peers is empty/partial, so a
	// multi-node cluster would read as No purely from missing probes. Report
	// Unknown (neither proof nor loss) until a probe cycle completes or the
	// startup grace elapses (then fall through to the fail-closed Yes/No count).
	if !probed && time.Since(started) < startupGrace {
		return QuorumUnknown, live, needed
	}
	if live >= needed {
		return QuorumYes, live, needed
	}
	return QuorumNo, live, needed
}

// executionQuorum is the quorum ExecutionGate requires: cluster-wide, or this
// host's own region's under region-scoped failover. A policy this build cannot
// read, or does not know, is No: the gate refuses with no_quorum rather than
// guessing a scope, and does not read as the startup warmup.
//
// Region scope REPLACES the cluster-wide count here rather than adding to it.
// A host cut off from its own region's majority is exactly the host that
// majority may fence and recover, so it must stop even if it can still reach
// a cluster-wide majority through other regions; and a region's own majority
// is enough, because nothing outside the region may recover its workloads.
func (c *Checker) executionQuorum(ctx context.Context) QuorumState {
	scope, err := corrosion.GetFailoverScope(ctx, c.db)
	if err != nil {
		return QuorumNo
	}
	if !scope.Region() {
		st, _, _ := c.QuorumProof(ctx)
		return st
	}
	vr, err := corrosion.VoterRegions(ctx, c.db)
	if err != nil {
		return QuorumUnknown
	}
	st, _, _ := c.quorumOver(vr.In(vr.Region(c.hostName)))
	return st
}

// ExecutionGate is the universal runtime gate: quorum held AND this host is an
// active worker (never a witness). Used at execute sites (startPendingVM,
// doPromoteLocal, container re-key, ApplyLB, owner-assert).
//
// The quorum is cluster-wide, or this host's own region's when failover is
// region-scoped (executionQuorum).
func (c *Checker) ExecutionGate(ctx context.Context) GateResult {
	if c.isSelfFenced() {
		return gateNo(ReasonSelfFenced)
	}
	switch c.executionQuorum(ctx) {
	case QuorumUnknown:
		return gateNo(ReasonWarmup)
	case QuorumNo:
		return gateNo(ReasonNoQuorum)
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return gateNo(ReasonNoQuorum)
	}
	if !localHostIsActiveWorker(hosts, c.hostName) {
		return gateNo(ReasonLocalNotActiveWorker)
	}
	return gateOK()
}

// DecisionGate is the coordinator gate: quorum held AND this host is
// coordinator-eligible (fully in service to initiate failover — active, warmed;
// witnesses allowed). For a TWO-worker cluster with no live witness and no adopted
// voter generation, HA decisions are blocked (a 1-1 split can't be safely arbitrated
// over a voter set derived from host state). With a generation adopted the voter
// majority governs. Callers must also hold the failover lease.
func (c *Checker) DecisionGate(ctx context.Context) GateResult {
	return c.decisionGate(ctx, func() QuorumState {
		st, _, _ := c.QuorumProof(ctx)
		return st
	})
}

// DecisionGateForRegion is DecisionGate with the quorum of one region's voters
// in place of the cluster-wide one: the failover coordinator's decide gate for
// a host in region when failover is region-scoped. The daemon must itself have
// probed a live majority of THAT region, whichever region it is in, and must
// be coordinator-eligible exactly as for DecisionGate. It refuses outright when
// the policy cannot be read or is not region scope: a caller asking for a
// region's quorum under any other scope has read a different policy from the
// one this daemon holds, and must not act on the difference.
func (c *Checker) DecisionGateForRegion(ctx context.Context, region string) GateResult {
	scope, err := corrosion.GetFailoverScope(ctx, c.db)
	if err != nil || !scope.Region() {
		return gateNo(ReasonNoQuorum)
	}
	return c.decisionGate(ctx, func() QuorumState {
		st, _, _ := c.RegionQuorumProof(ctx, region)
		return st
	})
}

func (c *Checker) decisionGate(ctx context.Context, quorum func() QuorumState) GateResult {
	if c.isSelfFenced() {
		return gateNo(ReasonSelfFenced)
	}
	switch quorum() {
	case QuorumUnknown:
		return gateNo(ReasonWarmup)
	case QuorumNo:
		return gateNo(ReasonNoQuorum)
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return gateNo(ReasonNoQuorum)
	}

	// Coordinator-eligible: local host present + state=="active" (stricter than the
	// voting predicate — a draining/upgrading/maintenance host votes but must not
	// initiate ownership changes) + past warmup.
	var self *corrosion.HostRecord
	for i := range hosts {
		if hosts[i].Name == c.hostName {
			self = &hosts[i]
			break
		}
	}
	c.mu.Lock()
	probed := c.probedOnce
	c.mu.Unlock()
	if self == nil || self.State != "active" || !probed {
		return gateNo(ReasonNotCoordinatorElig)
	}

	// Two workers, no live witness → block automated HA (a 1-1 split is unarbitrable). This
	// is scoped to EXACTLY two workers, not any even count: for 4/6/… workers quorum math
	// already disambiguates a clean split (a 2-2 of four needs 3 to act, so neither side
	// does), so a broader `workers%2==0` block adds NO safety there while permanently
	// stopping the rebalance executor (decideGate) on a healthy even cluster.
	workers, witnesses := 0, 0
	for i := range hosts {
		if !VotingEligible(hosts[i].State) {
			continue
		}
		if hosts[i].IsWitness() {
			witnesses++
		} else {
			workers++
		}
	}
	if workers == 2 && witnesses == 0 {
		// The rule stands in for a fixed denominator. A voter set DERIVED
		// from replicated host state can shrink on one side of a split, so
		// two workers are refused outright. An ADOPTED generation changes only
		// by a decided change or a forced one, and the quorum read above
		// already counted its majority: a 1-1 split of two voters is 1 of 2
		// on each side and refused there. So with a generation adopted, the
		// voter majority governs. Drill 6 on main-b3368d7c forced {node-1,
		// node-2} after the other three were lost and fence-confirmed, and
		// nothing they held could be recovered until a third host joined.
		cfg, err := corrosion.AdoptedVoterConfig(ctx, c.db)
		if err != nil || !cfg.Explicit() {
			return gateNo(ReasonMissingWitness)
		}
	}
	return gateOK()
}

// ExecutionQuorum is executionQuorum with the live/needed counts: the quorum
// that may fence this host and recover its workloads — cluster-wide, or this
// host's region's under region-scoped failover. The partition pauser runs on
// it (docs/design/partition-pause.md §3.1).
func (c *Checker) ExecutionQuorum(ctx context.Context) (QuorumState, int, int) {
	scope, err := corrosion.GetFailoverScope(ctx, c.db)
	if err != nil {
		return QuorumNo, 0, 0
	}
	if !scope.Region() {
		return c.QuorumProof(ctx)
	}
	vr, err := corrosion.VoterRegions(ctx, c.db)
	if err != nil {
		return QuorumUnknown, 0, 0
	}
	region := vr.Region(c.hostName)
	st, live, needed := c.quorumOver(vr.In(region))
	c.noteQuorum(RegionQuorumScope(region), st)
	return st, live, needed
}

// SeedPeersForTests sets this checker's probe results as one completed probe
// cycle would — healthy[peer] true for a peer probed healthy now, false for one
// probed failing — and ends its warmup. Test seam for scenarios (tests/fleet)
// that need a real Checker's quorum arithmetic without running its probe loop;
// production never calls it.
func (c *Checker) SeedPeersForTests(healthy map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probedOnce = true
	c.startedAt = time.Now().Add(-time.Hour)
	mono := c.now()
	for name, ok := range healthy {
		ps := &peerState{}
		if ok {
			ps.status, ps.lastHealthyAt = "healthy", mono
		} else {
			ps.status, ps.lastFailureAt = "suspect", mono
		}
		c.peers[name] = ps
	}
}

// LastContact reports when this daemon last probed host healthy, on its local
// monotonic clock (false: not this run). The failover coordinator anchors a
// partition-pause deadline on the later of this and its decision.
func (c *Checker) LastContact(host string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ps, ok := c.peers[host]
	if !ok || ps.lastHealthyAt.IsZero() {
		return time.Time{}, false
	}
	return ps.lastHealthyAt, true
}
