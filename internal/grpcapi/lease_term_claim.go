package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Single-claimant lease terms (capabilities.LeaseTermClaimV1).
//
// The quorum high-water read in LeaseMintClearance establishes that no peer
// has seen the term a node is about to record. It cannot establish that no
// peer is about to record it too: two nodes whose polls line up both read the
// same high water, both clear, and both record the next term. Both then act
// as the lease's holder, and the two ledger rows are an immutable conflict
// that stays until `lv cluster acknowledge-lease-term`.
//
// So the clearance also DECIDES the term: a single-decree claim at key
// (lease_term, <lease key>, term, 0) among the adopted voter generation,
// proposing this node as the holder. A voter keeps one promise and one
// accepted value per key, durably, so two claimants for one term cannot both
// collect a majority; at an equal ballot round the lower-sorting name ranks
// higher (corrosion.CompareBallots), the same rule the lease contest keeps. A
// claimant records the term only when the decided value names it. One that
// learns another holder records nothing and keeps the decision
// (corrosion.Client.NoteLeaseTermDecided).
//
// WHEN. Whenever this node has adopted a voter generation with members — not
// only once its own lease_term_claim_v1 latch has formed. Each node forms its
// latch from its own sweep, at its own moment, and a node that minted
// unclaimed while its peers claimed is the second holder they exclude: at the
// end of every roll, on every joiner, and for as long as one node cannot
// reach a member. So the claim does not wait for the latch. The ONE fallback
// is to a voter majority that does not know the claim type at all — a
// rolling upgrade, where those voters' own builds mint unclaimed anyway — and
// only before this node's latch has formed: a latched token proves every host
// answers lease-term claims, so after it no refusal is read as an older
// build. An unreachable voter is never a reason to fall back. No majority, no
// term: the node retries on its next poll.
//
// Clocks play no part in the decision — ballots are ordered by round and name
// — so skew cannot produce a second holder, and a minority side of a
// partition cannot decide anything.

// leaseTermClaimBudget bounds one term's claim. A phase that reaches its
// quorum returns at once (claims.Spec.ReturnAtQuorum); one that does not waits
// out a voter that does not answer, one claims.DefaultCallTimeout.
const leaseTermClaimBudget = 10 * time.Second

// leaseClaimYieldBase is how long a claimant outbid by another claimant of the
// same term lets it finish before going above it (leaseClaimYield). A
// claimant with its quorum decides in two round trips to the voters — tens of
// milliseconds — so this is many decisions' worth, and a few yields still fit
// leaseTermClaimBudget.
const leaseClaimYieldBase = 250 * time.Millisecond

// leaseClaimYield is the pause before self outbids stale, another claimant's
// ballot. Every claimant of a dead holder's lease polls on the same tick and
// proposes at round 1. Outbidding at once pre-empts the leader between its
// two phases, and with several claimants that repeats round after round: five
// claimants against a dead voter reached round 39 on the lab and took the
// lease over a TTL late. Waiting instead lets the leader decide; the retry,
// one round up, then finds the decided value in a promise and completes it,
// learning the holder. A claimant defers longer to a lower-sorting name —
// the one the tie rule prefers at an equal round — and the jitter keeps the
// rest from retrying together. Safety does not rest on any of this: the
// ballots decide, whatever the timing.
func leaseClaimYield(self string) func(int, corrosion.Ballot) time.Duration {
	return func(_ int, stale corrosion.Ballot) time.Duration {
		d := leaseClaimYieldBase + time.Duration(rand.Int64N(int64(leaseClaimYieldBase)))
		if stale.Coordinator < self {
			d += leaseClaimYieldBase
		}
		return d
	}
}

// condLeaseClaimNoMajority is raised while a lease cannot get a claim
// majority for longer than one of its TTLs, and resolved when it can.
const (
	condLeaseClaimNoMajority = "ha.lease.claim_no_majority"
	leaseClaimEvaluator      = "lease_term_claim"
)

// leaseClaimMode is how a mint is cleared by lease-term claims.
type leaseClaimMode int

const (
	// leaseClaimOff: no member voter generation exists to decide anything.
	// The quorum high-water read alone clears.
	leaseClaimOff leaseClaimMode = iota
	// leaseClaimOn: the term must be decided for this node.
	leaseClaimOn
	// leaseClaimClosed: this node cannot tell which electorate decides, so it
	// records nothing.
	leaseClaimClosed
)

// leaseClaimStall tracks, per lease key, since when this node's claims for it
// have had no majority, and whether it raised the condition for that.
type leaseClaimStall struct {
	mu    sync.Mutex
	since map[string]time.Time
}

// leaseTermClaimMode decides whether a mint must be claimed, and under which
// voter generation.
//
// The claim is required whenever this node has adopted a generation with
// members. With none adopted (genesis pending, or after `lv cluster voter
// reset`) there is no fixed majority, and terms are cleared from the read
// alone. A generation with members that this replica holds but has not
// adopted yet is closed: its peers may already claim under it, so an
// unclaimed term here could be the second holder they exclude. A read error
// is closed too.
func (s *Server) leaseTermClaimMode(ctx context.Context) (leaseClaimMode, *corrosion.VoterConfig, string) {
	if s.leaseClaimsAsOlderBuild.Load() {
		return leaseClaimOff, nil, ""
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return leaseClaimClosed, nil, "cannot read this node's adopted voter generation, so it cannot claim the term: " + err.Error()
	}
	if cfg.Explicit() {
		return leaseClaimOn, cfg, ""
	}
	all, err := corrosion.ListVoterConfigs(ctx, s.db)
	if err != nil {
		return leaseClaimClosed, nil, "cannot read the voter generations, so it cannot tell whether the term must be claimed: " + err.Error()
	}
	adopted := int64(0)
	if cfg != nil {
		adopted = cfg.Generation
	}
	for _, v := range all {
		if v.Generation > adopted && v.Explicit() {
			return leaseClaimClosed, nil, fmt.Sprintf("voter generation %d has members but this node has not "+
				"adopted it yet, so it cannot claim the term under it; retries once it has", v.Generation)
		}
	}
	return leaseClaimOff, nil, ""
}

// leaseClaimLatched reports whether this node's lease_term_claim_v1 latch has
// durably formed: every host it replicates to answers lease-term claims.
func (s *Server) leaseClaimLatched() bool {
	g := s.gateV()
	return g != nil && g.DurablyLatched(capabilities.LeaseTermClaimV1)
}

// claimLeaseTerm decides req.Term of req.Key under cfg, proposing req.Holder.
// ok only when the decided value names req.Holder, or — before the latch —
// when so many voters refuse the claim as an unknown claim type (older
// builds) that the rest of the generation cannot form a majority. A term decided for another node is recorded with the corrosion
// client, so the next poll neither claims it again nor takes the lease over
// before that node could have recorded it.
//
// started is when the clearance began, so the decision's learned-at instant
// counts the sweep and the claim, not only the classification.
func (s *Server) claimLeaseTerm(ctx context.Context, cfg *corrosion.VoterConfig, req corrosion.LeaseMintRequest, started time.Time) (bool, string) {
	self := req.Holder
	if self == "" {
		self = s.hostName
	}
	if !corrosion.ValidLeaseKey(req.Key) {
		return false, fmt.Sprintf("cannot claim a term of %q: not a lease this build holds", req.Key)
	}
	key := corrosion.LeaseTermClaimKey(req.Key, req.Term)
	if err := key.Validate(); err != nil {
		return false, "cannot claim the term: " + err.Error()
	}
	names := cfg.Names()
	q := corrosion.MajorityOf(len(names))
	spec := leaseTermClaimSpec(key, cfg.Generation, names, req, self)
	cctx, cancel := context.WithTimeout(ctx, leaseTermClaimBudget)
	defer cancel()
	p := s.claimProposer()
	out, err := p.Decide(cctx, spec)
	// The decision is learned now, not when the lease was classified: the
	// winner may have classified, and so started its TTL, after this node did.
	learned := clearanceInstant(req, started)
	if err != nil {
		if !s.leaseClaimLatched() && olderBuildsBlockAMajority(err, names, q) {
			slog.Info("leader lease: so many voters run a build without lease-term claims that the rest "+
				"cannot form a majority; clearing the term on the quorum read alone until they are upgraded",
				"lease", req.Key, "term", req.Term)
			s.noteLeaseClaimDecided(ctx, req.Key)
			return true, ""
		}
		why := fmt.Sprintf("no majority of voter generation %d decided term %d: %v", cfg.Generation, req.Term, err)
		if majorityAnswered(err, names, q) {
			// A duel lost to another claimant of the term, with a majority
			// there to decide it: not a stall, and not counted.
			slog.Debug("leader lease: another claimant of the term outranked this one; retries next poll",
				"lease", req.Key, "term", req.Term, "reason", why)
			s.noteLeaseClaimContended(req.Key)
			return false, why
		}
		s.noteLeaseNoMajority(ctx, req.Key, req.TTL, learned, why)
		return false, why
	}
	s.noteLeaseClaimDecided(ctx, req.Key)
	p.ForgetBelow(corrosion.ClaimKindLeaseTerm, req.Key, req.Term)
	s.forgetClaimRefusalsBelow(corrosion.ClaimKindLeaseTerm, req.Key, req.Term)
	won := out.Value.LeaseTerm
	if won == nil || won.Key != req.Key || won.Term != req.Term || won.Holder == "" {
		return false, fmt.Sprintf("the claim for term %d decided a value that is not that lease term", req.Term)
	}
	if won.Holder == self {
		return true, ""
	}
	s.db.NoteLeaseTermDecided(req.Key, req.Term, won.Holder, learned)
	return false, fmt.Sprintf("term %d was decided for %s; this node records nothing and waits for that "+
		"node's lease (or for it to lapse, then claims the next term)", req.Term, won.Holder)
}

// leaseTermClaimSpec is the claim for req's term among names, the members of
// voter generation gen, proposing self as the holder.
func leaseTermClaimSpec(key corrosion.ClaimKey, gen int64, names []string, req corrosion.LeaseMintRequest, self string) claims.Spec {
	q := corrosion.MajorityOf(len(names))
	proposal := corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: req.Key, Term: req.Term, Holder: self}}
	return claims.Spec{
		Key: key, Generation: gen, Voters: names, PrepareQuorum: q,
		Electorate: func(corrosion.ClaimValue) ([]string, int) { return names, q },
		Propose:    func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return proposal, nil },
		StartRound: 1,
		// A dead voter must not cost each phase the call timeout, and an
		// outbid claimant lets the leader finish: together they keep a
		// takeover by many claimants to about one decision's time.
		ReturnAtQuorum: true,
		Yield:          leaseClaimYield(self),
	}
}

// olderBuildsBlockAMajority reports whether err is a claim that failed in
// phase 1 because the members of the generation that refused it as an unknown
// claim type — older builds — are so many that the rest of the generation,
// every other member, answering or not, cannot form a majority of q.
// Unreachable voters, other refusals and promises all count as voters that
// could still accept: a voter that does not answer must never make the
// fallback easier to reach.
func olderBuildsBlockAMajority(err error, names []string, q int) bool {
	var nm *claims.NoMajorityError
	if !errors.As(err, &nm) || nm.Phase != "prepare" {
		return false
	}
	member := make(map[string]bool, len(names))
	for _, v := range names {
		member[v] = true
	}
	old := map[string]bool{}
	for _, r := range nm.Refusals {
		if !member[r.Voter] {
			continue
		}
		switch r.Reason {
		case corrosion.RefusalWrongGeneration, corrosion.RefusalNotMember, corrosion.RefusalSealed:
			// This claimant's generation is stale: a newer one has been
			// decided, and under it the upgraded voters may well be a
			// majority deciding this very term. An older build answers
			// "unknown kind" whatever generation it is asked under, so the
			// count below would be the stale generation's. Retry under the
			// current one instead.
			return false
		}
		if r.Reason == corrosion.RefusalInvalidValue && strings.Contains(r.Detail, olderBuildRefusal) {
			old[r.Voter] = true
		}
	}
	return len(names)-len(old) < q
}

// majorityAnswered reports whether err is a claim that a majority of the
// generation was there to decide: the members that promised or accepted, plus
// those that refused only because another claimant's ballot outranked this
// one's, are a majority. That is a duel lost, not a stall. Anything else —
// unreachable members, refusals no higher ballot can change, an error that is
// not a claim's answer at all — leaves no majority this node could reach.
func majorityAnswered(err error, names []string, q int) bool {
	var nm *claims.NoMajorityError
	if !errors.As(err, &nm) {
		return false
	}
	member := make(map[string]bool, len(names))
	for _, v := range names {
		member[v] = true
	}
	outbid := map[string]bool{}
	for _, r := range nm.Refusals {
		if member[r.Voter] && (r.Reason == corrosion.RefusalBallotStale || r.Reason == corrosion.RefusalValueConflict) {
			outbid[r.Voter] = true
		}
	}
	return nm.Got+len(outbid) >= q
}

// olderBuildRefusal is how a build without lease-term claims refuses one:
// ClaimKey.Validate's answer for a target kind it does not know. It mirrors
// the default branch of ClaimKey.Validate in the release before
// lease_term_claim_v1 (base f2a5b25a), byte for byte; a later wording change
// there does not change what an older build answers.
var olderBuildRefusal = fmt.Sprintf("unknown claim target kind %q", corrosion.ClaimKindLeaseTerm)

// NoteLeaseNoMajority is corrosion's report (SetLeaseNoMajorityObserver) of
// a lease poll that stood down for want of the voter majority, over a lease
// this node sees no live holder of: a takeover that cannot happen. With
// ev.Live the lease was live as this node sees it: no takeover is due, so the
// stall start is forgotten and nothing is counted or written.
func (s *Server) NoteLeaseNoMajority(ctx context.Context, ev corrosion.LeaseNoMajority) {
	if ev.Live {
		s.noteLeaseClaimContended(ev.Key)
		return
	}
	s.noteLeaseNoMajority(ctx, ev.Key, ev.TTL, ev.Now, ev.Why)
}

// noteLeaseNoMajority counts one poll on which this node would take key over
// and cannot, because no voter majority is available to it — the health
// voter quorum is lost, the quorum high-water read found no quorum, or the
// term's claim reached no majority — and raises ha.lease.claim_no_majority
// once the lease has had none for one TTL.
func (s *Server) noteLeaseNoMajority(ctx context.Context, key string, ttl time.Duration, now time.Time, why string) {
	if s.onLeaseClaimNoMajority != nil {
		s.onLeaseClaimNoMajority(key)
	}
	st := &s.leaseClaimStall
	st.mu.Lock()
	if st.since == nil {
		st.since = map[string]time.Time{}
	}
	since, ok := st.since[key]
	if !ok {
		st.since[key], since = now, now
	}
	st.mu.Unlock()
	if ttl <= 0 || now.Sub(since) < ttl {
		return
	}
	line := fmt.Sprintf("lease %s has had no takeover since %s: %s. A takeover needs a majority of the "+
		"voters that can vote, and so does every voter change, so `lv cluster voter rm/add/reset` may not "+
		"be able to run either. Restore the lost voter, or fence proof-grade every member that cannot vote, "+
		"abstaining ones included, and run `lv cluster voter force-reconfigure --lost <host>[,<host>...]` "+
		"(docs/design/recovery-claims.md §4.6). "+
		"Repair a voter while ha.voter.unavailable names it, before it is needed. "+
		"`lv cluster voter reset` returns lease takeovers to the two-holder race.",
		key, since.UTC().Format(time.RFC3339), why)
	s.applyClusterCondition(ctx, leaseClaimEvaluator, condLeaseClaimNoMajority, key,
		map[string]string{key: line}, []string{s.hostName}, "")
}

// noteLeaseClaimContended ends this node's no-majority stall for key without
// touching the condition row: a duel showed a majority there to decide, or a
// node standing down at the gate saw the lease live.
func (s *Server) noteLeaseClaimContended(key string) {
	st := &s.leaseClaimStall
	st.mu.Lock()
	delete(st.since, key)
	st.mu.Unlock()
}

// noteLeaseClaimDecided ends a no-majority stall for key: a claim for it was
// decided, whoever it names, or the term was cleared by the older-build
// fallback.
func (s *Server) noteLeaseClaimDecided(ctx context.Context, key string) {
	st := &s.leaseClaimStall
	st.mu.Lock()
	delete(st.since, key)
	st.mu.Unlock()
	s.applyClusterCondition(ctx, leaseClaimEvaluator, condLeaseClaimNoMajority, key, nil, nil, "")
}

// NoteLeaseLive is told, by corrosion's lease path, that the lease key has a
// live holder as this node sees it: a peer's live lease, or this node's own
// renewal or mint. The lease is no longer contested, whoever holds it — the
// dead holder back, a takeover by any node, a term recorded with no claim
// (no generation adopted, a fallback). It ends this node's no-majority stall
// and resolves ha.lease.claim_no_majority.
//
// It runs on every lease poll that finds a holder, and costs one indexed read
// of the condition row when nothing is raised. Not throttled: the row can be
// raised by ANOTHER node at any moment, and a throttle keyed on this node's
// last read left a fresh raise standing for the whole window.
func (s *Server) NoteLeaseLive(ctx context.Context, key string) {
	st := &s.leaseClaimStall
	st.mu.Lock()
	delete(st.since, key)
	st.mu.Unlock()
	s.applyClusterCondition(ctx, leaseClaimEvaluator, condLeaseClaimNoMajority, key, nil, nil, "")
}

// forgetClaimRefusalsBelow drops the diagnostic last-refusal entries for keys
// of kind and name below epoch.
func (s *Server) forgetClaimRefusalsBelow(kind, name string, epoch int64) {
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.refusals {
		if k.TargetKind == kind && k.TargetName == name && k.OwnerEpoch < epoch {
			delete(c.refusals, k)
		}
	}
}

// SetLeaseClaimNoMajorityObserver wires the no-majority metric hook (nil-safe).
func (s *Server) SetLeaseClaimNoMajorityObserver(fn func(lease string)) {
	s.onLeaseClaimNoMajority = fn
}

// SetLeaseClaimsAsAnOlderBuildForTest makes this node behave, for lease-term
// claims only, like a build without them: it refuses them as an unknown claim
// type, and records terms on the quorum read alone.
func (s *Server) SetLeaseClaimsAsAnOlderBuildForTest(v bool) { s.leaseClaimsAsOlderBuild.Store(v) }

// olderBuildLeaseClaimRefusal is the refusal SetLeaseClaimsAsAnOlderBuildForTest
// answers a lease-term Prepare or Accept with, or "" to answer normally.
func (s *Server) olderBuildLeaseClaimRefusal(key corrosion.ClaimKey) string {
	if !s.leaseClaimsAsOlderBuild.Load() || !key.IsLeaseTerm() {
		return ""
	}
	return olderBuildRefusal
}
