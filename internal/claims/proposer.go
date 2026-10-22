// Package claims is the proposer side of single-decree recovery claims
// (docs/design/recovery-claims.md §3.13): phase 1 to a set of voters, adopt the
// highest-ballot accepted value any promise reports, phase 2, and a
// certificate once a quorum of signed accepts is in.
//
// It knows nothing about transport or storage. The voter's rules live in
// internal/corrosion; the server supplies a Transport that reaches each voter
// (its own voter locally, peers over the claim RPCs). Its callers are the
// voter-config changes and, under recovery_claim_v1
// (colonelpanik/litevirt#250), every recovery the failover coordinator
// authorizes.
package claims

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Transport reaches one voter. An error is "no answer": the voter counts toward
// neither side.
type Transport interface {
	// Prepare carries ev, the supersede evidence a key at attempt > 0 needs
	// (docs/design/recovery-claims.md §3.12); nil otherwise.
	Prepare(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, gen int64, ev *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error)
	Accept(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error)
}

// Spec is one decision to drive.
type Spec struct {
	Key        corrosion.ClaimKey
	Generation int64
	// Voters are the phase-1 targets; PrepareQuorum promises are needed.
	Voters        []string
	PrepareQuorum int
	// Electorate returns the phase-2 targets and quorum for the value about to
	// be proposed. For a generation decided by its own members (genesis) that
	// is the value's members; otherwise it is the generation's members.
	Electorate func(v corrosion.ClaimValue) (voters []string, quorum int)
	// Propose builds this proposer's own value, from the promises, when no
	// promise reports an accepted value.
	Propose func(promises map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error)
	// BeforeAccept prepares provenance for the EXACT selected phase-two value.
	// It runs after highest-accepted selection and ballot binding, never changes
	// the value/quorum, and its accepted votes still have to pass normal fanout.
	// A stale promise lets Decide retry at a higher ballot in the usual way.
	BeforeAccept func(context.Context, corrosion.Ballot, corrosion.ClaimValue) (corrosion.Ballot, error)
	// StartRound seeds the first ballot's round (the lease term, §3.2). 0 → 1.
	StartRound uint64
	// MaxRounds bounds how many ballots one Decide tries. 0 → 8.
	MaxRounds int
	// ReuseRound lets the FIRST ballot reuse StartRound even though this
	// process has used it for the key before — as long as the value it ends up
	// sending in phase 2 is the one it sent at that round last time (the
	// per-round binding below refuses anything else and raises the round).
	// It is how a coordinator retries a claim the voters refused because the
	// owner was still reachable without raising its round: nothing was
	// contending, so nothing should have to outrank it (§3.13 step 6).
	ReuseRound bool
	// Supersede is the evidence, sent with every Prepare, that the value
	// decided at Key.Attempt-1 will never execute. Required at attempt > 0.
	Supersede *corrosion.SupersedeEvidence
	// AdoptLegacy bridges an incarnation-scoped key (Key.Incarnation != "")
	// to its LEGACY form, which coordinators claimed until
	// claim_incarnation_v1 latched (docs/design/recovery-claims.md §10 item
	// 37). Every promise at the scoped key reports what that voter accepted at
	// the legacy key and seals it there, so a majority of promises holds
	// everything the legacy key can ever decide. When no promise reports a
	// value at the scoped key itself, the highest-ballot legacy value is
	// re-proposed — a recovery decided across the upgrade is completed, not
	// decided twice — unless AdoptLegacy returns false, which it may do only
	// for a value PROVEN to be another incarnation's and never to run (the
	// server asks the value's destination; grpcapi
	// Server.legacyValueExcluded). Then Propose builds a fresh value. Nil
	// adopts nothing.
	AdoptLegacy func(v corrosion.ClaimValue) bool
	// ReturnAtQuorum ends each phase as soon as a quorum of the voters has
	// promised (phase 1) or accepted (phase 2), and cancels the calls still
	// outstanding, instead of waiting for every voter. Any quorum of promises
	// holds every value a quorum can have accepted, so this decides the same
	// values; it only stops a voter that does not answer from costing the
	// whole call timeout on every phase of a claim that already has its
	// quorum. A phase that does not reach a quorum still waits for every
	// voter, so its refusals are complete. Lease-term claims set it.
	ReturnAtQuorum bool
	// Yield, when set, replaces the short random pause before a retry after
	// ANOTHER proposer's ballot outranked this one (stale names it): how long
	// to let that proposer finish before going above it. Outbidding it at
	// once can only pre-empt it between its phases, so several claimants of
	// one key would outbid each other round after round; one that waits finds
	// its value accepted and completes it. A ballot this process used itself
	// (an earlier Decide's) is no competitor and gets the short pause.
	Yield func(attempt int, stale corrosion.Ballot) time.Duration
}

// Outcome is a decided value and the certificate that proves it.
type Outcome struct {
	Value       corrosion.ClaimValue
	Digest      string
	Certificate corrosion.ClaimCertificate
	// Ours reports whether the decided value is one Propose built during this
	// Decide — in the deciding round, or in an earlier round whose phase 2
	// reached a voter before a higher ballot outranked it, so the value came
	// back in a promise. When it is not, another proposer's value was chosen
	// and this call completed it.
	Ours bool
}

// Refusal is one voter's answer that did not count.
type Refusal struct {
	Voter, Reason, Detail string
}

// NoMajorityError is returned when no ballot collected a quorum.
type NoMajorityError struct {
	Phase    string // prepare | accept
	Got      int
	Need     int
	Refusals []Refusal // one per voter, the last seen
}

func (e *NoMajorityError) Error() string {
	var parts []string
	for _, r := range e.Refusals {
		if r.Detail != "" {
			parts = append(parts, fmt.Sprintf("%s: %s (%s)", r.Voter, r.Reason, r.Detail))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", r.Voter, r.Reason))
		}
	}
	return fmt.Sprintf("no majority in %s: %d of %d needed [%s]", e.Phase, e.Got, e.Need, strings.Join(parts, "; "))
}

// ReasonUnreachable marks a voter that did not answer.
const ReasonUnreachable = "unreachable"

// Proposer drives decisions. One per process: its boot nonce makes every
// incarnation's ballots distinct, and its round allocator guarantees that
// within the process one ballot is never used with two values, even by two
// concurrent Decide calls on one key (§3.2).
type Proposer struct {
	Self      string
	Transport Transport
	// CallTimeout bounds each voter RPC. 0 → DefaultCallTimeout.
	CallTimeout time.Duration
	// Backoff is how long to wait before retrying after a ballot was refused
	// as stale. Nil → a random 0–50ms, which is what breaks a duel.
	Backoff func(attempt int) time.Duration

	nonce []byte
	mu    sync.Mutex
	used  map[corrosion.ClaimKey]uint64
	// bound is the value digest this process has sent in phase 2 at each
	// (key, round). A ballot is bound to one value (§3.2): a second value at a
	// bound round is refused before it is sent, and the proposer moves up.
	bound map[corrosion.ClaimKey]map[uint64]string
}

// NewProposer draws the process's boot nonce.
func NewProposer(self string, t Transport) *Proposer {
	return &Proposer{Self: self, Transport: t, nonce: corrosion.NewBootNonce(), used: map[corrosion.ClaimKey]uint64{},
		bound: map[corrosion.ClaimKey]map[uint64]string{}}
}

// ForgetBelow drops this process's ballot bookkeeping for keys of kind and
// name whose owner epoch is below epoch: decisions it will never propose at
// again (a lease's past terms). Without it the bookkeeping grows by one key
// per decision for the life of the process.
func (p *Proposer) ForgetBelow(kind, name string, epoch int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.used {
		if k.TargetKind == kind && k.TargetName == name && k.OwnerEpoch < epoch {
			delete(p.used, k)
			delete(p.bound, k)
		}
	}
	for k := range p.bound {
		if k.TargetKind == kind && k.TargetName == name && k.OwnerEpoch < epoch {
			delete(p.bound, k)
		}
	}
}

// Nonce is this process's boot nonce.
func (p *Proposer) Nonce() []byte { return append([]byte(nil), p.nonce...) }

// ballot allocates a round at or above want that this process has not used for
// key before — or, with reuse, want itself when it is exactly the last round
// used for key; bind then guarantees the reused round carries the same value.
func (p *Proposer) ballot(key corrosion.ClaimKey, want uint64, reuse bool) corrosion.Ballot {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := want
	last := p.used[key]
	switch {
	case reuse && want > 0 && want == last:
	case r <= last:
		r = last + 1
	}
	p.used[key] = r
	return corrosion.Ballot{Round: r, Coordinator: p.Self, Nonce: append([]byte(nil), p.nonce...)}
}

// bind records that phase 2 at (key, round) carries digest, and refuses a
// different digest at a round already bound. It is what makes reusing a round
// safe: one ballot, one value, across calls as well as within one.
func (p *Proposer) bind(key corrosion.ClaimKey, round uint64, digest string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bound == nil {
		p.bound = map[corrosion.ClaimKey]map[uint64]string{}
	}
	byRound := p.bound[key]
	if byRound == nil {
		byRound = map[uint64]string{}
		p.bound[key] = byRound
	}
	if d, ok := byRound[round]; ok && d != digest {
		return false
	}
	byRound[round] = digest
	return true
}

// errBallotBound is try's answer when the round it holds was bound to another
// value in this process; Decide moves to a higher round.
var errBallotBound = errors.New("claims: ballot already bound to another value in this process")

// DefaultCallTimeout bounds each voter RPC when CallTimeout is 0. The owner
// probe's timing is budgeted against it (grpcapi claimProbeRefreshAge).
const DefaultCallTimeout = 3 * time.Second

func (p *Proposer) callTimeout() time.Duration {
	if p.CallTimeout > 0 {
		return p.CallTimeout
	}
	return DefaultCallTimeout
}

func (p *Proposer) backoff(attempt int) time.Duration {
	if p.Backoff != nil {
		return p.Backoff(attempt)
	}
	return time.Duration(rand.Int64N(int64(50 * time.Millisecond)))
}

// ErrNoValue is returned when Propose has nothing to propose.
var ErrNoValue = errors.New("claims: nothing to propose")

// Decide drives spec to a decision or gives up.
//
// It never falls back to an uncertified value: without a quorum it returns
// the refusals and the caller retries later (§3.13 step 6).
func (p *Proposer) Decide(ctx context.Context, spec Spec) (Outcome, error) {
	maxRounds := spec.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 8
	}
	round := spec.StartRound
	if round == 0 {
		round = 1
	}
	var lastErr error
	// own is every value digest Propose built during this Decide, so a value
	// re-learned from a promise can be recognised as this call's own.
	own := map[string]bool{}
	for attempt := 0; attempt < maxRounds; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return Outcome{}, lastErr
			}
			return Outcome{}, err
		}
		b := p.ballot(spec.Key, round, spec.ReuseRound && attempt == 0)
		out, stale, err := p.try(ctx, spec, b, own)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if stale.IsZero() {
			return Outcome{}, err // refused for a reason a higher ballot cannot fix
		}
		// A voter has promised above us: go above it, after a short random
		// pause so two duelling proposers stop alternating (§6) — or, with
		// spec.Yield, after letting the other proposer finish.
		round = stale.Round + 1
		pause := p.backoff(attempt)
		if spec.Yield != nil && stale.Coordinator != p.Self {
			pause = spec.Yield(attempt, stale)
		}
		select {
		case <-ctx.Done():
			return Outcome{}, lastErr
		case <-time.After(pause):
		}
	}
	return Outcome{}, lastErr
}

// Learn runs phase 1 only, at a fresh ballot, and returns the accepted value
// with the highest ballot that any promise of a quorum reports — a value some
// proposer has PROPOSED at the key, chosen or not — or found=false when no
// promise of the quorum reports one. It decides nothing; its promises only
// make a lower-ballot proposer at the key retry higher.
func (p *Proposer) Learn(ctx context.Context, spec Spec) (value *corrosion.ClaimValue, found bool, err error) {
	maxRounds := spec.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 8
	}
	round := spec.StartRound
	if round == 0 {
		round = 1
	}
	var lastErr error
	for attempt := 0; attempt < maxRounds; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, false, lastErr
			}
			return nil, false, err
		}
		b := p.ballot(spec.Key, round, false)
		promises, refusals := p.prepareAll(ctx, spec, b)
		var stale corrosion.Ballot
		for _, r := range refusals {
			if r.reason == corrosion.RefusalBallotStale && corrosion.CompareBallots(r.promised, stale) > 0 {
				stale = r.promised
			}
		}
		if len(promises) >= spec.PrepareQuorum {
			var best corrosion.Ballot
			for _, pr := range promises {
				if pr.State.Value != nil && !pr.State.Accepted.IsZero() && corrosion.CompareBallots(pr.State.Accepted, best) > 0 {
					best, value = pr.State.Accepted, pr.State.Value
				}
			}
			return value, value != nil, nil
		}
		lastErr = &NoMajorityError{Phase: "prepare", Got: len(promises), Need: spec.PrepareQuorum,
			Refusals: publicRefusals(refusals)}
		if stale.IsZero() {
			return nil, false, lastErr
		}
		round = stale.Round + 1
		select {
		case <-ctx.Done():
			return nil, false, lastErr
		case <-time.After(p.backoff(attempt)):
		}
	}
	return nil, false, lastErr
}

// try runs both phases at one ballot. stale is the highest promise a voter
// refused us with, zero when no refusal was about the ballot.
func (p *Proposer) try(ctx context.Context, spec Spec, b corrosion.Ballot, own map[string]bool) (Outcome, corrosion.Ballot, error) {
	var stale corrosion.Ballot
	noteStale := func(reason string, promised corrosion.Ballot) {
		if reason == corrosion.RefusalBallotStale && corrosion.CompareBallots(promised, stale) > 0 {
			stale = promised
		}
	}

	// Phase 1.
	promises, refusals := p.prepareAll(ctx, spec, b)
	for _, r := range refusals {
		noteStale(r.reason, r.promised)
	}
	if len(promises) < spec.PrepareQuorum {
		return Outcome{}, stale, &NoMajorityError{Phase: "prepare", Got: len(promises), Need: spec.PrepareQuorum,
			Refusals: publicRefusals(refusals)}
	}

	// A value that might have been chosen must be re-proposed: the accepted
	// value with the highest ballot any promise reports (§3.16).
	var value *corrosion.ClaimValue
	var best corrosion.Ballot
	for _, pr := range promises {
		if pr.State.Value != nil && !pr.State.Accepted.IsZero() && corrosion.CompareBallots(pr.State.Accepted, best) > 0 {
			best, value = pr.State.Accepted, pr.State.Value
		}
	}
	if value == nil && spec.AdoptLegacy != nil && spec.Key.Incarnation != "" {
		var legacy *corrosion.ClaimValue
		var lbest corrosion.Ballot
		for _, pr := range promises {
			if l := pr.Legacy; l != nil && l.Value != nil && !l.Accepted.IsZero() && corrosion.CompareBallots(l.Accepted, lbest) > 0 {
				lbest, legacy = l.Accepted, l.Value
			}
		}
		if legacy != nil && spec.AdoptLegacy(*legacy) {
			value = legacy
		}
	}
	ours := false
	if value == nil {
		if spec.Propose == nil {
			return Outcome{}, corrosion.Ballot{}, ErrNoValue
		}
		v, err := spec.Propose(promises)
		if err != nil {
			return Outcome{}, corrosion.Ballot{}, err
		}
		value, ours = &v, true
	}
	digest, err := value.Digest()
	if err != nil {
		return Outcome{}, corrosion.Ballot{}, err
	}
	if ours {
		own[digest] = true
	} else {
		ours = own[digest]
	}
	if !p.bind(spec.Key, b.Round, digest) {
		// A reused round that would carry another value: move above it.
		return Outcome{}, b, errBallotBound
	}

	// Phase 2.
	targets, quorum := spec.Voters, spec.PrepareQuorum
	if spec.Electorate != nil {
		targets, quorum = spec.Electorate(*value)
	}
	if spec.BeforeAccept != nil {
		if promised, err := spec.BeforeAccept(ctx, b, *value); err != nil {
			return Outcome{}, promised, err
		}
	}
	accepts, arefusals := p.acceptAll(ctx, spec, b, *value, targets, quorum)
	for _, r := range arefusals {
		noteStale(r.reason, r.promised)
	}
	if len(accepts) < quorum {
		return Outcome{}, stale, &NoMajorityError{Phase: "accept", Got: len(accepts), Need: quorum,
			Refusals: publicRefusals(arefusals)}
	}
	cert := corrosion.ClaimCertificate{Key: spec.Key, ConfigGeneration: spec.Generation, Ballot: b,
		ValueDigest: digest, SourceHost: value.SourceHost}
	for _, a := range accepts {
		cert.Accepts = append(cert.Accepts, a)
	}
	sort.Slice(cert.Accepts, func(i, j int) bool { return cert.Accepts[i].Voter < cert.Accepts[j].Voter })
	return Outcome{Value: *value, Digest: digest, Certificate: cert, Ours: ours}, corrosion.Ballot{}, nil
}

type refusal struct {
	voter, reason, detail string
	promised              corrosion.Ballot
}

func publicRefusals(rs []refusal) []Refusal {
	out := make([]Refusal, 0, len(rs))
	for _, r := range rs {
		out = append(out, Refusal{Voter: r.voter, Reason: r.reason, Detail: r.detail})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Voter < out[j].Voter })
	return out
}

func (p *Proposer) prepareAll(ctx context.Context, spec Spec, b corrosion.Ballot) (map[string]corrosion.PrepareResult, []refusal) {
	type answer struct {
		voter string
		res   corrosion.PrepareResult
		err   error
	}
	voters := dedup(spec.Voters)
	// Cancelled on return: with ReturnAtQuorum, the calls still outstanding.
	actx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	// Buffered for every voter, so a call that answers after an early return
	// never blocks.
	answers := make(chan answer, len(voters))
	for _, v := range voters {
		go func(voter string) {
			cctx, cancel := context.WithTimeout(actx, p.callTimeout())
			defer cancel()
			res, err := p.Transport.Prepare(cctx, voter, spec.Key, b, spec.Generation, spec.Supersede)
			answers <- answer{voter: voter, res: res, err: err}
		}(v)
	}
	promises := map[string]corrosion.PrepareResult{}
	var refusals []refusal
	for range voters {
		a := <-answers
		switch {
		case a.err != nil:
			refusals = append(refusals, refusal{voter: a.voter, reason: ReasonUnreachable, detail: a.err.Error()})
		case a.res.Promised:
			promises[a.voter] = a.res
		default:
			refusals = append(refusals, refusal{voter: a.voter, reason: a.res.Refusal, detail: a.res.Detail, promised: a.res.PromisedBallot})
		}
		if spec.ReturnAtQuorum && spec.PrepareQuorum > 0 && len(promises) >= spec.PrepareQuorum {
			break
		}
	}
	return promises, refusals
}

func (p *Proposer) acceptAll(ctx context.Context, spec Spec, b corrosion.Ballot, v corrosion.ClaimValue, targets []string, quorum int) (map[string]corrosion.ClaimAccept, []refusal) {
	type answer struct {
		voter string
		res   corrosion.AcceptResult
		err   error
	}
	voters := dedup(targets)
	actx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	answers := make(chan answer, len(voters))
	for _, t := range voters {
		go func(voter string) {
			cctx, cancel := context.WithTimeout(actx, p.callTimeout())
			defer cancel()
			res, err := p.Transport.Accept(cctx, voter, spec.Key, b, v, spec.Generation)
			answers <- answer{voter: voter, res: res, err: err}
		}(t)
	}
	accepts := map[string]corrosion.ClaimAccept{}
	var refusals []refusal
	for range voters {
		a := <-answers
		voter, res := a.voter, a.res
		switch {
		case a.err != nil:
			refusals = append(refusals, refusal{voter: voter, reason: ReasonUnreachable, detail: a.err.Error()})
		case res.Accepted && res.Accept != nil && res.Accept.Voter == voter && res.Accept.Key == spec.Key:
			// An accept counts only for the key it signs. A voter on an
			// older build drops a key's incarnation and signs the legacy
			// key, and its accept certifies nothing here.
			accepts[voter] = *res.Accept
		default:
			refusals = append(refusals, refusal{voter: voter, reason: res.Refusal, detail: res.Detail, promised: res.PromisedBallot})
		}
		if spec.ReturnAtQuorum && quorum > 0 && len(accepts) >= quorum {
			break
		}
	}
	return accepts, refusals
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
