package automation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"time"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Transport's prefix methods move one bounded certified record. They convey no
// trust roots, caller-provided membership or readiness assertions.
type Transport interface {
	claims.Transport
	Fetch(context.Context, string, uint64) (corrosion.AutomationRecord, bool, error)
	Install(context.Context, string, corrosion.AutomationRecord) error
}

type Engine struct {
	self      string
	db        *corrosion.Client
	verifier  *corrosion.ClaimVerifier
	transport Transport
	lock      chan struct{}
}

func NewEngine(self string, db *corrosion.Client, v *corrosion.ClaimVerifier, t Transport) *Engine {
	return &Engine{self: self, db: db, verifier: v, transport: t, lock: make(chan struct{}, 1)}
}
func (e *Engine) enter(ctx context.Context) error {
	select {
	case e.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fail(CodeUnavailable)
	}
}
func (e *Engine) leave() { <-e.lock }
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("automation entropy unavailable")
	}
	return hex.EncodeToString(b[:])
}

// Each call uses fresh ballot nonce and bounded rounds; no proposer retains
// per-slot maps for the lifetime of an unbounded stream.
func (e *Engine) decide(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64, proposal *corrosion.ClaimValue) (claims.Outcome, error) {
	key, err := corrosion.AutomationClaimKey(seq)
	if err != nil {
		return claims.Outcome{}, err
	}
	p := claims.NewProposer(e.self, e.transport)
	p.CallTimeout = 750 * time.Millisecond
	spec := claims.Spec{Key: key, Generation: cfg.Generation, Voters: cfg.Names(), PrepareQuorum: corrosion.MajorityOf(len(cfg.Members)), MaxRounds: 8}
	if proposal != nil {
		spec.Propose = func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return *proposal, nil }
	}
	return p.Decide(ctx, spec)
}
func (e *Engine) Submit(ctx context.Context, c Command) (Receipt, error) {
	if err := validateCommand(c); err != nil {
		return Receipt{}, err
	}
	if c.Kind == "read_barrier" && c.PrincipalID != e.self {
		return Receipt{}, fail(CodeOwnershipConflict)
	}
	if err := e.enter(ctx); err != nil {
		return Receipt{}, err
	}
	defer e.leave()
	return e.submit(ctx, c)
}
func (e *Engine) submit(ctx context.Context, c Command) (Receipt, error) {
	if err := e.recover(ctx); err != nil && !(c.Kind == "initialize_cluster" && errors.Is(err, claims.ErrNoValue)) {
		return Receipt{}, fmt.Errorf("recover automation: %w", fail(CodeUnavailable))
	}
	identity, err := CanonicalCommand(c)
	if err != nil {
		return Receipt{}, err
	}
	a := assignment{Version: 1, OperationID: randomID(), RecordedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if c.Kind == "initialize_cluster" {
		a.ClusterUID = randomID()
	} else {
		a.ClusterUID = c.ClusterUID
	}
	assigned, _ := json.Marshal(a)
	// Bounded work per call; a retry resumes from durable applied progress.
	for range 128 {
		if ctx.Err() != nil {
			return Receipt{}, fail(CodeUnavailable)
		}
		h, err := e.db.AutomationHead(ctx)
		if err != nil {
			return Receipt{}, err
		}
		existing, err := e.db.AutomationRequest(ctx, corrosion.AutomationScope(Decision{Command: c}), c.RequestID)
		if err != nil {
			return Receipt{}, err
		}
		// Initialization already has a permanent receipt. It is local certified
		// authority, but recovery above still verifies membership/lookup eligibility.
		if existing != nil {
			if !equalBytes(identity, existing.Identity) {
				return Receipt{}, fail(CodeIdempotencyConflict)
			}
			if existing.Receipt.Code != "" {
				return existing.Receipt, fail(existing.Receipt.Code)
			}
			return existing.Receipt, nil
		}
		if c.Kind == "initialize_cluster" && h.Sequence != 0 {
			return Receipt{}, fail(CodeOwnershipConflict)
		}
		if c.Kind != "initialize_cluster" && c.ClusterUID != h.ClusterUID {
			return Receipt{}, fail(CodeValidation)
		}
		cfg, err := e.db.AutomationMembership(ctx)
		if err != nil {
			return Receipt{}, fail(CodeUnavailable)
		}
		e.distribute(ctx, cfg, h.Sequence)
		d := Decision{Sequence: h.Sequence + 1, ParentDigest: h.Digest, Command: c, Assignment: assigned}
		encoded, err := contractEncode(d)
		if err != nil {
			return Receipt{}, err
		}
		value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: encoded}}
		out, err := e.decide(ctx, cfg, d.Sequence, &value)
		if err != nil {
			return Receipt{}, fail(CodeUnavailable)
		}
		rec := corrosion.AutomationRecord{Value: out.Value, Certificate: out.Certificate}
		if _, err = e.db.AutomationApply(ctx, rec, e.verifier, reduce); err != nil {
			return Receipt{}, fmt.Errorf("apply automation: %w", err)
		}
		e.distribute(ctx, cfg, d.Sequence)
		select {
		case <-ctx.Done():
			return Receipt{}, fail(CodeUnavailable)
		case <-time.After(time.Duration(mathrand.IntN(5)) * time.Millisecond):
		}
	}
	return Receipt{}, fail(CodeUnavailable)
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (e *Engine) distribute(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64) {
	if seq == 0 {
		return
	}
	r, ok, err := e.db.AutomationRecord(ctx, seq)
	if err != nil || !ok {
		return
	}
	e.distributeRecord(ctx, cfg, r)
}
func (e *Engine) distributeRecord(ctx context.Context, cfg *corrosion.VoterConfig, r corrosion.AutomationRecord) {
	for _, v := range cfg.Names() {
		if v == e.self {
			continue
		}
		call, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		_ = e.transport.Install(call, v, r)
		cancel()
	}
}
func (e *Engine) Recover(ctx context.Context) error {
	if err := e.enter(ctx); err != nil {
		return err
	}
	defer e.leave()
	err := e.recover(ctx)
	if errors.Is(err, claims.ErrNoValue) {
		return fail(CodeUnavailable)
	}
	return err
}
func (e *Engine) recover(ctx context.Context) error {
	if err := e.db.AutomationReplay(ctx, reduce, 256); err != nil {
		return err
	}
	cfg, err := e.db.AutomationMembership(ctx)
	if err != nil {
		return err
	}
	pending, err := e.db.AutomationRecoveryPending(ctx)
	if err != nil {
		return err
	}
	if pending {
		if err = e.resumeRecovery(ctx, cfg); err != nil {
			return err
		}
	}
	h, err := e.db.AutomationHead(ctx)
	if err != nil {
		return err
	}
	target, lowest := h.Sequence, h.Sequence
	answers := 0
	for _, v := range cfg.Names() {
		if v == e.self {
			continue
		}
		call, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		r, ok, err := e.transport.Fetch(call, v, 0)
		cancel()
		if err != nil {
			continue
		}
		answers++
		if !ok {
			lowest = 0
			continue
		}
		d, err := contractDecode(r.Value)
		if err == nil {
			if d.Sequence > target {
				target = d.Sequence
			}
			if d.Sequence < lowest {
				lowest = d.Sequence
			}
		}
	}
	if h.Sequence == 0 && answers < corrosion.MajorityOf(len(cfg.Members))-1 {
		return fail(CodeUnavailable)
	}
	if target == 0 && h.Sequence == 0 {
		// No head hint can exist when the genesis proposer died before publishing
		// its certificate. Decide without a proposal completes accepted bytes only;
		// ErrNoValue authorizes neither absence nor identity assignment.
		out, err := e.decide(ctx, cfg, 1, nil)
		if err != nil {
			return err
		}
		record := corrosion.AutomationRecord{Value: out.Value, Certificate: out.Certificate}
		if _, err = e.db.AutomationApply(ctx, record, e.verifier, reduce); err != nil {
			return err
		}
		e.distribute(ctx, cfg, 1)
		return nil
	}
	if target <= h.Sequence && lowest >= target {
		return nil
	}
	// Peer head is a hint. Existing Prepare/Accept re-certify the unchanged value
	// under current locally authorized membership before backward staging.
	out, err := e.decide(ctx, cfg, target, nil)
	if err != nil {
		if lowest < target {
			return e.recoverIntermediate(ctx, cfg, lowest, target)
		}
		return err
	}
	record := corrosion.AutomationRecord{Value: out.Value, Certificate: out.Certificate}
	if err = e.db.AutomationBeginRecovery(ctx, record, e.verifier); err != nil {
		return err
	}
	if err = e.resumeRecovery(ctx, cfg); err != nil {
		return err
	}
	// Forward the renewed certificate, rather than reloading the original
	// stored certificate whose leaf may have expired.
	e.distributeRecord(ctx, cfg, record)
	return nil
}

// A current quorum may contain a voter unable to promise the highest slot
// until its predecessor is applied. Recover exact accepted intermediate values
// with no new proposal, verify them normally, and yield after bounded work.
// Head hints only select work: they never grant authority or relax expiry.
func (e *Engine) recoverIntermediate(ctx context.Context, cfg *corrosion.VoterConfig, lowest, target uint64) error {
	for steps, seq := 0, lowest+1; steps < 16 && seq <= target; steps, seq = steps+1, seq+1 {
		out, err := e.decide(ctx, cfg, seq, nil)
		if err != nil {
			return err
		}
		record := corrosion.AutomationRecord{Value: out.Value, Certificate: out.Certificate}
		if _, err = e.db.AutomationApply(ctx, record, e.verifier, reduce); err != nil {
			return err
		}
		e.distributeRecord(ctx, cfg, record)
		if seq == target {
			return nil
		}
	}
	return fail(CodeUnavailable)
}

func (e *Engine) resumeRecovery(ctx context.Context, cfg *corrosion.VoterConfig) error {
	for range 256 {
		next, err := e.db.AutomationRecoveryNext(ctx)
		if err != nil {
			return err
		}
		if next == 0 {
			return e.db.AutomationFinishRecovery(ctx, reduce, 256)
		}
		found := false
		for _, v := range cfg.Names() {
			call, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			r, ok, err := e.transport.Fetch(call, v, next)
			cancel()
			if err == nil && ok {
				if err = e.db.AutomationStagePredecessor(ctx, r); err == nil {
					found = true
					break
				}
			}
		}
		if !found {
			return fail(CodeUnavailable)
		}
	}
	return fail(CodeUnavailable)
}

// Install applies contiguous records directly; a certified ahead head supplies
// a fresh anchor for bounded backward catch-up outside all DB transactions.
func (e *Engine) Install(ctx context.Context, r corrosion.AutomationRecord) error {
	if _, err := e.db.AutomationApply(ctx, r, e.verifier, reduce); err == nil {
		return nil
	}
	if err := e.db.AutomationBeginRecovery(ctx, r, e.verifier); err != nil {
		return err
	}
	cfg, err := e.db.AutomationMembership(ctx)
	if err != nil {
		return err
	}
	return e.resumeRecovery(ctx, cfg)
}
