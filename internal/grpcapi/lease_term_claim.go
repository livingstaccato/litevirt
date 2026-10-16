package grpcapi

import (
	"context"
	"fmt"
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
// So once the token has latched, the clearance also DECIDES the term: a
// single-decree claim at key (lease_term, <lease key>, term, 0) among the
// adopted voter generation, proposing this node as the holder. A voter keeps
// one promise and one accepted value per key, durably, so two claimants for
// one term cannot both collect a majority; at an equal ballot round the
// lower-sorting name ranks higher (corrosion.CompareBallots), the same rule
// the lease contest keeps. A claimant records the term only when the decided
// value names it. One that learns another holder records nothing and keeps
// the decision (corrosion.Client.NoteLeaseTermDecided).
//
// Fail closed: no majority, no term. Clocks play no part in the decision —
// ballots are ordered by round and name — so skew cannot produce a second
// holder, and a minority side of a partition cannot decide anything.

// leaseTermClaimBudget bounds one term's claim. A voter that does not answer
// costs one claims.DefaultCallTimeout; a duel costs a few rounds of
// milliseconds.
const leaseTermClaimBudget = 10 * time.Second

// leaseClaimMode is how a mint is cleared by lease-term claims.
type leaseClaimMode int

const (
	// leaseClaimOff: the token has not latched, or no member voter generation
	// exists to decide anything. The quorum high-water read alone clears.
	leaseClaimOff leaseClaimMode = iota
	// leaseClaimOn: the term must be decided for this node.
	leaseClaimOn
	// leaseClaimClosed: this node cannot tell which electorate decides, so it
	// records nothing.
	leaseClaimClosed
)

// leaseTermClaimMode decides whether a mint must be claimed, and under which
// voter generation.
//
// The claim is in force once lease_term_claim_v1 has DURABLY latched — the
// latch is monotone and survives a restart, so a node cannot fall back to
// unclaimed terms by restarting during a partition — and this node has
// adopted a generation with members. With none adopted (genesis pending, or
// after `lv cluster voter reset`) there is no fixed majority, and every node
// is in that position together: terms are cleared as before.
//
// One case is not together: a generation with members that this replica holds
// but has not adopted yet. Its peers may already claim under it, so recording
// an unclaimed term here could be the second holder they exclude. Closed,
// until the adoption pass catches up. A read error is closed too.
func (s *Server) leaseTermClaimMode(ctx context.Context) (leaseClaimMode, *corrosion.VoterConfig, string) {
	g := s.gateV()
	if g == nil || !g.DurablyLatched(capabilities.LeaseTermClaimV1) {
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

// claimLeaseTerm decides req.Term of req.Key under cfg, proposing req.Holder.
// ok only when the decided value names req.Holder. A term decided for another
// node is recorded with the corrosion client, so the next poll neither claims
// it again nor takes the lease over before that node could have recorded it.
func (s *Server) claimLeaseTerm(ctx context.Context, cfg *corrosion.VoterConfig, req corrosion.LeaseMintRequest) (bool, string) {
	self := req.Holder
	if self == "" {
		self = s.hostName
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
	out, err := s.claimProposer().Decide(cctx, spec)
	if err != nil {
		return false, fmt.Sprintf("no majority of voter generation %d decided term %d: %v", cfg.Generation, req.Term, err)
	}
	won := out.Value.LeaseTerm
	if won == nil || won.Key != req.Key || won.Term != req.Term || won.Holder == "" {
		return false, fmt.Sprintf("the claim for term %d decided a value that is not that lease term", req.Term)
	}
	if won.Holder == self {
		return true, ""
	}
	at, perr := time.Parse(time.RFC3339, req.Now)
	if perr != nil {
		at = time.Now()
	}
	s.db.NoteLeaseTermDecided(req.Key, req.Term, won.Holder, at)
	return false, fmt.Sprintf("term %d was decided for %s; this node records nothing and waits for that "+
		"node's lease (or for it to lapse, then claims the next term)", req.Term, won.Holder)
}
