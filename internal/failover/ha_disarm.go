package failover

// Cluster-wide HA disarm (docs/migration-failover.md, "Disarming HA for
// planned maintenance"). While the cluster_policies row `ha` says disarmed, no
// coordinator decides a new fence or mints a recovery. Fencing and recovery
// are CREATED here, by the lease holder, so this is where the guarantee is
// enforced:
//
//   - L1: the cycle reads the policy once, and every Held action re-reads it
//     immediately before it runs (haHold): each fence, each resume of a
//     recorded fence, and each proof-mint site. Disarmed or unreadable holds
//     the action; a read error decides nothing.
//   - L2: at the same sites, the latest Ready answer of every OTHER voter this
//     node counts live for the decision's scope (the set its quorum counts)
//     can veto it (haPeerVeto). That closes the replication-lag gap: a
//     confirmed disarm is held by a majority, and any live majority this node
//     can count intersects it.
//
// Kept while disarmed: health probes, recoverHosts, relay health, partition
// pause, and operator actions.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// PeerHAAnswer is a peer's latest answer to the health probe about the cluster
// HA policy (ReadyResponse.ha_known, ha_disarmed, ha_policy_at).
type PeerHAAnswer struct {
	Asked    time.Time // when the probe that carried it was sent, on this node's monotonic clock
	Known    bool
	Disarmed bool
	PolicyAt string // the policy row's updated_at as the peer stores it; "" when it has none
}

// PeerAnswerWindow (W_L2) is health.PeerAnswerWindow: how old, from its
// probe's send time, a live voter's answer may be and still be read as what it
// says. An older answer from a voter still counted live vetoes (rule stale),
// which only ever delays a fence.
const PeerAnswerWindow = health.PeerAnswerWindow

// Peer-veto rules, as ha_disarm_peer_veto and `lv cluster ha` name them.
const (
	VetoNoQuorum = "no_quorum" // fewer than a majority of the scope's voters counted live
	VetoStale    = "stale"     // a live voter's answer is older than PeerAnswerWindow
	VetoUnknown  = "unknown"   // a live voter has not loaded the policy (ha_known=false)
	VetoDisarmed = "disarmed"  // a live voter holds a disarm not older than this node's row
)

// haVeto is one voter's veto of one decision.
type haVeto struct {
	Voter, Rule, PolicyAt string
}

// haDisarmState is the coordinator's HA-disarm memory. Only the poll
// goroutine touches it, except holding (read by the pre-record).
type haDisarmState struct {
	// loggedDisarm names the hosts already logged as held this disarm
	// episode; cleared once a cycle reads armed.
	loggedDisarm map[string]bool
	// loggedVeto is the last veto logged per host; cleared once a cycle
	// passes without one.
	loggedVeto map[string]string
	// heldRecovery names hosts whose recovery a hold interrupted after its
	// fence; resumed from the fence loop once the hold lifts.
	heldRecovery map[string]bool
	// cycleVetoes are this cycle's peer vetoes (no_quorum excluded), by voter.
	cycleVetoes map[string]haVeto
	vetoCond    *health.HACondition
	// featureUsed latches once this replica holds the ha_disarm used record.
	featureUsed atomic.Bool
	// holding is whether the last cycle held the failover lease.
	holding atomic.Bool
	// beforeHold, when set, runs before each Held action's re-read with the
	// site's name; read, when set, replaces the policy read. Tests only.
	beforeHold func(site string)
	read       func(ctx context.Context) (corrosion.HAPolicy, error)
}

// haRead reads the policy from this node's replica.
func (c *Coordinator) haRead(ctx context.Context) (corrosion.HAPolicy, error) {
	if c.ha.read != nil {
		return c.ha.read(ctx)
	}
	return corrosion.GetHAPolicy(ctx, c.db)
}

// Held-action sites, as the re-read hook and the logs name them.
const (
	haSiteCandidate  = "candidate"
	haSiteFence      = "fence"
	haSiteRecovery   = "recovery"
	haSiteReschedule = "reschedule"
	haSitePromote    = "promote"
	haSiteRekey      = "rekey"
	haSiteRelocate   = "relocate"
	haSiteRecreate   = "recreate"
)

// HoldsLease reports whether this coordinator's last cycle held the failover
// lease.
func (c *Coordinator) HoldsLease() bool { return c.ha.holding.Load() }

// haCycleRead is the cycle's one read of the policy. A read error is returned;
// an unreadable policy is not (it reads disarmed).
func (c *Coordinator) haCycleRead(ctx context.Context) (corrosion.HAPolicy, error) {
	p, err := c.haRead(ctx)
	if err != nil && !errors.Is(err, corrosion.ErrUnreadableHAPolicy) {
		return p, err
	}
	if !p.Disarmed() {
		c.ha.loggedDisarm = nil
	}
	c.ha.cycleVetoes = nil
	return p, nil
}

// haHold reports whether the Held action at site about target (a host; "" for
// a cluster-wide pass) must not run now. It re-reads the policy (L1) and
// applies the peer veto (L2), records why, and counts the skip.
func (c *Coordinator) haHold(ctx context.Context, target, site string) bool {
	if c.ha.beforeHold != nil {
		c.ha.beforeHold(site)
	}
	p, err := c.haRead(ctx)
	if err != nil && !errors.Is(err, corrosion.ErrUnreadableHAPolicy) {
		slog.Warn("failover: could not read the HA policy; holding", "host", target, "site", site, "error", err)
		c.mAttempt(PhaseSkip, ResultSkipped, ErrDBError)
		c.noteHAHold(target, "recovery held: the HA policy could not be read")
		return true
	}
	if p.Disarmed() {
		c.mAttempt(PhaseSkip, ResultSkipped, ErrHADisarmed)
		c.noteHAHold(target, "recovery held: HA disarmed")
		if c.ha.loggedDisarm == nil {
			c.ha.loggedDisarm = map[string]bool{}
		}
		if !c.ha.loggedDisarm[target] {
			c.ha.loggedDisarm[target] = true
			if site == haSiteCandidate || site == haSiteFence {
				slog.Warn("failover: HA disarmed; not fencing " + target + " (quorum reports it down)")
			} else {
				slog.Warn("failover: HA disarmed; not recovering the workloads of "+target, "site", site,
					"unreadable", p.Unreadable, "set_by", p.SetBy, "reason", p.Reason)
			}
		}
		return true
	}
	vetoes := c.haPeerVeto(ctx, target, p)
	if len(vetoes) == 0 {
		delete(c.ha.loggedVeto, target)
		return false
	}
	if vetoes[0].Rule == VetoNoQuorum {
		c.mAttempt(PhaseQuorum, ResultRefused, ErrNoQuorum)
		c.noteHAHold(target, "held: fewer than a majority of the voters for this decision are counted live (lv cluster ha shows which are not)")
	} else {
		c.mAttempt(PhaseSkip, ResultSkipped, ErrHAPeerVeto)
		c.noteHAHold(target, "recovery held: HA disarmed on a live voter ("+describeVetoes(vetoes)+")")
		if c.ha.cycleVetoes == nil {
			c.ha.cycleVetoes = map[string]haVeto{}
		}
		for _, v := range vetoes {
			c.ha.cycleVetoes[v.Voter] = v
		}
	}
	if c.ha.loggedVeto == nil {
		c.ha.loggedVeto = map[string]string{}
	}
	if d := describeVetoes(vetoes); c.ha.loggedVeto[target] != d {
		c.ha.loggedVeto[target] = d
		slog.Warn("failover: a live voter's answer holds this decision back", "host", target, "site", site, "vetoes", d,
			"own_policy_at", p.UpdatedAt)
	}
	return true
}

// noteHAHold records the stall alert's reason for a held host.
func (c *Coordinator) noteHAHold(target, why string) {
	if target != "" {
		c.noteHold(target, why)
	}
}

// noteHAHeldRecovery remembers that host's recovery was held after its fence,
// so the fence loop resumes it once the hold lifts.
func (c *Coordinator) noteHAHeldRecovery(host string) {
	if c.ha.heldRecovery == nil {
		c.ha.heldRecovery = map[string]bool{}
	}
	c.ha.heldRecovery[host] = true
}

// resumeHAHeldRecovery takes up a recovery a hold interrupted after its
// fence, and reports whether it handled the host this cycle. Called from the
// fence loop only once haHold has passed for the host. The fence it stood on
// may be hours old: it is judged as every resume from a recorded fence is
// (resumeActionFor) — resumed while it still stands and is fresh, fenced
// again when a verified fence has aged, declined when it no longer stands.
// Without a recorded successful fence (an operator's confirmation, a
// best-effort fence that proceeded) it resumes only while the newest fence
// attempt still stands.
//
// The held mark is dropped only on a final outcome: a resume, a re-fence that
// ran (its success recovers, its failure is the operator's), or a decline
// judged on rows that were read. A re-fence that did not run (a local stall,
// the lease floor, a new hold at the fence site) and every read error keep it,
// so the host is judged again next cycle rather than left cached in c.fenced.
func (c *Coordinator) resumeHAHeldRecovery(ctx context.Context, host string, observers int) bool {
	if !c.ha.heldRecovery[host] {
		return false
	}
	if _, waiting := c.pauseWaits[host]; waiting {
		// A pause wait is still owed: it runs first, and recovers from there.
		return false
	}
	h, err := corrosion.GetHost(ctx, c.db, host)
	if err != nil {
		return true
	}
	if h == nil {
		delete(c.ha.heldRecovery, host)
		return true
	}
	// The health rows every judgement below rests on must be readable.
	if c.readHostHealth(ctx, host).err != nil {
		c.noteHold(host, "recovery held by an HA disarm; its host's health rows could not be read, retrying")
		return true
	}
	if rec, at, ok := c.recordedFence(ctx, h); ok {
		switch act, why := c.resumeActionFor(ctx, host, rec, at); act {
		case resumeFromRecord:
			delete(c.ha.heldRecovery, host)
			slog.Info("failover: HA armed again; resuming the recovery it held", "host", host, "fence_id", rec.ID)
			c.mAttempt(PhaseRecovery, ResultOK, ErrRecoveryResumed)
			c.noteFencedOn(host, rec.ID)
			c.recoverFenced(ctx, h, fence.Result{Success: true, Method: rec.Method, Detail: rec.Detail}, "", c.fenceStateLatched(ctx))
		case resumeAfterRefence:
			slog.Info("failover: HA armed again; the fence the held recovery stood on has aged, fencing again", "host", host, "fence_id", rec.ID)
			before := c.lastFenceAt[host]
			delete(c.ha.heldRecovery, host)
			c.refence(ctx, h, rec, observers)
			if c.lastFenceAt[host].Equal(before) {
				// No fence ran: judged again next cycle.
				c.noteHAHeldRecovery(host)
			}
		default:
			if c.readHostHealth(ctx, host).err != nil {
				return true
			}
			delete(c.ha.heldRecovery, host)
			c.noteResumeDeclined(host, rec, why)
			c.noteHold(host, "recovery held by an HA disarm, and its fence no longer stands: "+why)
		}
		return true
	}
	_, at, ok, err := c.readNewestFenceAttempt(ctx, host)
	if err != nil {
		c.noteHold(host, "recovery held by an HA disarm; the fence log could not be read, retrying")
		return true
	}
	if !ok {
		delete(c.ha.heldRecovery, host)
		c.noteHold(host, "recovery held by an HA disarm, and no fence of the host is on record")
		return true
	}
	hr := c.readHostHealth(ctx, host)
	if hr.err != nil {
		return true
	}
	if why, _, stands := c.fenceStillStandsIn(hr, host, at); !stands {
		delete(c.ha.heldRecovery, host)
		c.noteHold(host, "recovery held by an HA disarm, and its fence no longer stands: "+why)
		return true
	}
	delete(c.ha.heldRecovery, host)
	slog.Info("failover: HA armed again; resuming the recovery it held", "host", host)
	c.mAttempt(PhaseRecovery, ResultOK, ErrRecoveryResumed)
	c.recoverWorkloads(ctx, h)
	return true
}

func describeVetoes(vs []haVeto) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		if v.Rule == VetoNoQuorum {
			parts = append(parts, v.Rule)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s (ha_policy_at %q)", v.Voter, v.Rule, v.PolicyAt))
	}
	return strings.Join(parts, "; ")
}

// haFeatureUsed reports whether this replica holds the ha_disarm used record.
// Until it does, the peer veto's fail-safe rules (no_quorum, stale, unknown)
// are not applied, which keeps a rolling upgrade INTO this build, whose older
// peers answer without the HA fields, from holding every fence back. The
// disarmed rule does not wait for it (haPeerVeto). It latches.
func (c *Coordinator) haFeatureUsed(ctx context.Context) bool {
	if c.ha.featureUsed.Load() {
		return true
	}
	info, ok := capabilities.LookupFeature(capabilities.FeatureHADisarm)
	if !ok {
		return true
	}
	present, _, err := corrosion.ReleaseFeatureState(ctx, c.db, info.Token, string(capabilities.FeatureHADisarm))
	if err != nil {
		// Unknown is not "unused": apply the veto.
		return true
	}
	if present {
		c.ha.featureUsed.Store(true)
	}
	return present
}

// haPeerVeto is L2: the vetoes of the decision about target ("" for the
// cluster) by the voters this node counts live for its scope. own is this
// node's policy row (armed, or L1 would have held). nil: no veto.
func (c *Coordinator) haPeerVeto(ctx context.Context, target string, own corrosion.HAPolicy) []haVeto {
	if c.PeerHAState == nil {
		return nil
	}
	// The disarmed rule always applies: only a build with the feature that
	// holds a row can answer disarmed, so it cannot veto falsely during a
	// rolling upgrade, and a coordinator whose replica lacks the used record
	// (absent at the first use, or added since) is exactly the lagging one
	// it exists for. The fail-safe rules — no_quorum, stale, unknown — wait
	// for the used record: before it, older peers answer without the fields.
	failSafe := c.haFeatureUsed(ctx)
	voters := c.scope.vr.Voters
	if target != "" {
		voters = c.scope.voters(target)
	}
	needed := len(voters)/2 + 1
	var live map[string]bool
	if c.LiveVoters != nil {
		live = c.LiveVoters(voters, c.scope.vr.Uncounted)
	}
	if failSafe && len(live) < needed {
		return []haVeto{{Rule: VetoNoQuorum}}
	}
	names := make([]string, 0, len(live))
	for v := range live {
		names = append(names, v)
	}
	sort.Strings(names)
	now := c.mono()
	window := PeerAnswerWindow
	if c.AnswerWindow > 0 {
		window = c.AnswerWindow
	}
	var out []haVeto
	for _, v := range names {
		if v == c.hostName {
			// No answer from itself exists; its own replica is L1's input.
			continue
		}
		a, ok := c.PeerHAState(v)
		switch {
		case ok && a.Known && a.Disarmed && !(own.UpdatedAt != "" && corrosion.LWWNewer(own.UpdatedAt, a.PolicyAt)):
			// A disarm not older than this node's row: no row here, a newer
			// disarm, or the same timestamp with another state. Read
			// whatever its age: an old disarm only holds back.
			out = append(out, haVeto{Voter: v, Rule: VetoDisarmed, PolicyAt: a.PolicyAt})
		case !failSafe:
		case !ok || now.Sub(a.Asked) > window:
			out = append(out, haVeto{Voter: v, Rule: VetoStale, PolicyAt: a.PolicyAt})
		case !a.Known:
			out = append(out, haVeto{Voter: v, Rule: VetoUnknown, PolicyAt: a.PolicyAt})
		}
	}
	return out
}

// syncHAVeto keeps ha_disarm_peer_veto and litevirt_ha_peer_veto in line with
// this cycle's peer vetoes. A no_quorum veto is an ordinary loss of quorum,
// counted as one, and never raises them.
func (c *Coordinator) syncHAVeto(ctx context.Context) {
	if c.ha.vetoCond == nil {
		c.ha.vetoCond = &health.HACondition{DB: c.db, Host: c.hostName, Code: corrosion.CondHAPeerVeto,
			Severity: corrosion.SeverityWarning, Now: c.Now}
	}
	vs := make([]haVeto, 0, len(c.ha.cycleVetoes))
	for _, v := range c.ha.cycleVetoes {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Voter < vs[j].Voter })
	open := len(vs) > 0
	evidence := ""
	if open {
		evidence = "this node's replica says HA is armed, and live voters' answers held a fence or recovery back: " +
			describeVetoes(vs) + ". It resolves once no live voter vetoes; check lv cluster ha"
	}
	c.ha.vetoCond.Sync(ctx, open, evidence)
	if c.HAPeerVetoGauge != nil {
		c.HAPeerVetoGauge(open)
	}
}

// haPassHeld is L1 alone, re-read for a cluster-wide recovery pass: disarmed,
// unreadable or unread holds it. Each proof the pass would mint re-checks at
// its own site, peer veto included.
func (c *Coordinator) haPassHeld(ctx context.Context) bool {
	if c.ha.beforeHold != nil {
		c.ha.beforeHold("pass")
	}
	p, err := c.haRead(ctx)
	return (err != nil && !errors.Is(err, corrosion.ErrUnreadableHAPolicy)) || p.Disarmed()
}
