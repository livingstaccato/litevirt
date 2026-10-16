package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// leaseTermClaimBudget bounds one term's claim. A voter that does not answer
// costs one claims.DefaultCallTimeout per phase; a duel costs a few rounds of
// milliseconds.
const leaseTermClaimBudget = 10 * time.Second

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
// when a majority of the voters that answered run a build without lease-term
// claims. A term decided for another node is recorded with the corrosion
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
	proposal := corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: req.Key, Term: req.Term, Holder: self}}
	spec := claims.Spec{
		Key: key, Generation: cfg.Generation, Voters: names, PrepareQuorum: q,
		Electorate: func(corrosion.ClaimValue) ([]string, int) { return names, q },
		Propose:    func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return proposal, nil },
		StartRound: 1,
	}
	cctx, cancel := context.WithTimeout(ctx, leaseTermClaimBudget)
	defer cancel()
	p := s.claimProposer()
	out, err := p.Decide(cctx, spec)
	// The decision is learned now, not when the lease was classified: the
	// winner may have classified, and so started its TTL, after this node did.
	learned := started
	if at, perr := time.Parse(time.RFC3339, req.Now); perr == nil {
		learned = at
	}
	learned = learned.Add(time.Since(started))
	if err != nil {
		if !s.leaseClaimLatched() && olderBuildMajority(err) {
			slog.Info("leader lease: a majority of the voters run a build without lease-term claims; "+
				"clearing the term on the quorum read alone until every host is upgraded",
				"lease", req.Key, "term", req.Term)
			return true, ""
		}
		why := fmt.Sprintf("no majority of voter generation %d decided term %d: %v", cfg.Generation, req.Term, err)
		s.noteLeaseClaimNoMajority(ctx, req, learned, why)
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

// olderBuildMajority reports whether err is a claim that failed because a
// majority of the voters that answered do not know the lease_term claim type
// — an older build's answer. Unreachable voters are not counted either way.
func olderBuildMajority(err error) bool {
	var nm *claims.NoMajorityError
	if !errors.As(err, &nm) || nm.Phase != "prepare" {
		return false
	}
	unknown, reached := 0, nm.Got
	for _, r := range nm.Refusals {
		if r.Reason == claims.ReasonUnreachable {
			continue
		}
		reached++
		if r.Reason == corrosion.RefusalInvalidValue && strings.Contains(r.Detail, olderBuildRefusal) {
			unknown++
		}
	}
	return reached > 0 && 2*unknown > reached
}

// olderBuildRefusal is how a build without lease-term claims refuses one:
// ClaimKey.Validate's answer for a target kind it does not know.
var olderBuildRefusal = fmt.Sprintf("unknown claim target kind %q", corrosion.ClaimKindLeaseTerm)

// noteLeaseClaimNoMajority counts a claim with no majority and raises
// ha.lease.claim_no_majority once the lease has had none for one TTL.
func (s *Server) noteLeaseClaimNoMajority(ctx context.Context, req corrosion.LeaseMintRequest, now time.Time, why string) {
	if s.onLeaseClaimNoMajority != nil {
		s.onLeaseClaimNoMajority(req.Key)
	}
	st := &s.leaseClaimStall
	st.mu.Lock()
	if st.since == nil {
		st.since = map[string]time.Time{}
	}
	since, ok := st.since[req.Key]
	if !ok {
		st.since[req.Key], since = now, now
	}
	st.mu.Unlock()
	if req.TTL <= 0 || now.Sub(since) < req.TTL {
		return
	}
	line := fmt.Sprintf("lease %s has had no takeover since %s: %s. A takeover needs a majority of the "+
		"voters that can vote; `lv cluster voter ls` shows them. Repair an abstaining voter with "+
		"`lv cluster voter rm <host>` then `lv cluster voter add <host>`, or return to the derived voter set "+
		"with `lv cluster voter reset`, which also ends recovery-claim protection.",
		req.Key, since.UTC().Format(time.RFC3339), why)
	s.applyClusterCondition(ctx, leaseClaimEvaluator, condLeaseClaimNoMajority, req.Key,
		map[string]string{req.Key: line}, []string{s.hostName}, "")
}

// noteLeaseClaimDecided ends a no-majority stall for key: a claim for it was
// decided, whoever it names.
func (s *Server) noteLeaseClaimDecided(ctx context.Context, key string) {
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
