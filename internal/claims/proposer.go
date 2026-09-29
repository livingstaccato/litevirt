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
}

// Outcome is a decided value and the certificate that proves it.
type Outcome struct {
	Value       corrosion.ClaimValue
	Digest      string
	Certificate corrosion.ClaimCertificate
	// Ours reports whether the decided value is the one Propose built. When it
	// is not, another proposer's value was chosen and this call completed it.
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
	// CallTimeout bounds each voter RPC. 0 → 3s.
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

func (p *Proposer) callTimeout() time.Duration {
	if p.CallTimeout > 0 {
		return p.CallTimeout
	}
	return 3 * time.Second
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
	for attempt := 0; attempt < maxRounds; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return Outcome{}, lastErr
			}
			return Outcome{}, err
		}
		b := p.ballot(spec.Key, round, spec.ReuseRound && attempt == 0)
		out, stale, err := p.try(ctx, spec, b)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if stale.IsZero() {
			return Outcome{}, err // refused for a reason a higher ballot cannot fix
		}
		// A voter has promised above us: go above it, after a short random
		// pause so two duelling proposers stop alternating (§6).
		round = stale.Round + 1
		select {
		case <-ctx.Done():
			return Outcome{}, lastErr
		case <-time.After(p.backoff(attempt)):
		}
	}
	return Outcome{}, lastErr
}

// try runs both phases at one ballot. stale is the highest promise a voter
// refused us with, zero when no refusal was about the ballot.
func (p *Proposer) try(ctx context.Context, spec Spec, b corrosion.Ballot) (Outcome, corrosion.Ballot, error) {
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
	if !p.bind(spec.Key, b.Round, digest) {
		// A reused round that would carry another value: move above it.
		return Outcome{}, b, errBallotBound
	}

	// Phase 2.
	targets, quorum := spec.Voters, spec.PrepareQuorum
	if spec.Electorate != nil {
		targets, quorum = spec.Electorate(*value)
	}
	accepts, arefusals := p.acceptAll(ctx, spec, b, *value, targets)
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
	var mu sync.Mutex
	var wg sync.WaitGroup
	promises := map[string]corrosion.PrepareResult{}
	var refusals []refusal
	for _, v := range dedup(spec.Voters) {
		wg.Add(1)
		go func(voter string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, p.callTimeout())
			defer cancel()
			res, err := p.Transport.Prepare(cctx, voter, spec.Key, b, spec.Generation, spec.Supersede)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				refusals = append(refusals, refusal{voter: voter, reason: ReasonUnreachable, detail: err.Error()})
			case res.Promised:
				promises[voter] = res
			default:
				refusals = append(refusals, refusal{voter: voter, reason: res.Refusal, detail: res.Detail, promised: res.PromisedBallot})
			}
		}(v)
	}
	wg.Wait()
	return promises, refusals
}

func (p *Proposer) acceptAll(ctx context.Context, spec Spec, b corrosion.Ballot, v corrosion.ClaimValue, targets []string) (map[string]corrosion.ClaimAccept, []refusal) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	accepts := map[string]corrosion.ClaimAccept{}
	var refusals []refusal
	for _, t := range dedup(targets) {
		wg.Add(1)
		go func(voter string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, p.callTimeout())
			defer cancel()
			res, err := p.Transport.Accept(cctx, voter, spec.Key, b, v, spec.Generation)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				refusals = append(refusals, refusal{voter: voter, reason: ReasonUnreachable, detail: err.Error()})
			case res.Accepted && res.Accept != nil && res.Accept.Voter == voter:
				accepts[voter] = *res.Accept
			default:
				refusals = append(refusals, refusal{voter: voter, reason: res.Refusal, detail: res.Detail, promised: res.PromisedBallot})
			}
		}(t)
	}
	wg.Wait()
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
