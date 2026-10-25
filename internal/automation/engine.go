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

	"github.com/litevirt/litevirt/internal/automation/contract"
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
	return e.decideOwner(ctx, cfg, seq, proposal, nil)
}

type ownerPhase2Transport interface {
	PrepareOwnerPhase2(context.Context, corrosion.ClaimKey, corrosion.Ballot, corrosion.ClaimValue, *corrosion.VoterConfig, *corrosion.AutomationOwnerSubmission) (corrosion.Ballot, error)
}

func (e *Engine) decideOwner(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64, proposal *corrosion.ClaimValue, owner *corrosion.AutomationOwnerSubmission) (claims.Outcome, error) {
	return e.decidePrepared(ctx, cfg, seq, proposal, owner, nil)
}
func (e *Engine) decidePrepared(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64, proposal *corrosion.ClaimValue, owner *corrosion.AutomationOwnerSubmission, continuity *corrosion.AutomationIdentityContinuity) (claims.Outcome, error) {
	return e.decidePreparedUsing(ctx, cfg, seq, proposal, owner, continuity, nil)
}
func (e *Engine) decidePreparedUsing(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64, proposal *corrosion.ClaimValue, owner *corrosion.AutomationOwnerSubmission, continuity *corrosion.AutomationIdentityContinuity, p *claims.Proposer) (claims.Outcome, error) {
	key, err := corrosion.AutomationClaimKey(seq)
	if err != nil {
		return claims.Outcome{}, err
	}
	var propose func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error)
	if proposal != nil {
		propose = func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return *proposal, nil }
	}
	beforeAccept := func(ctx context.Context, b corrosion.Ballot, selected corrosion.ClaimValue) (corrosion.Ballot, error) {
		d, err := contractDecode(selected)
		if err != nil {
			return corrosion.Ballot{}, err
		}
		if d.Command.Kind == contract.IdentityContinuityCommand {
			t, ok := e.transport.(continuityPhase2Transport)
			if !ok {
				return corrosion.Ballot{}, fail(CodeUnavailable)
			}
			native := continuity
			if proposal == nil || selected.MustDigest() != proposal.MustDigest() {
				native = nil
			}
			return t.PrepareContinuityPhase2(ctx, key, b, selected, cfg, native)
		}
		if !corrosion.IsAutomationOwnerKind(d.Command.Kind) {
			return e.prepareSelectedAutomationPhase2(ctx, key, b, selected, cfg)
		}
		t, ok := e.transport.(ownerPhase2Transport)
		if !ok {
			return corrosion.Ballot{}, fail(CodeUnavailable)
		}
		native := owner
		if proposal == nil || selected.MustDigest() != proposal.MustDigest() {
			native = nil
		}
		return t.PrepareOwnerPhase2(ctx, key, b, selected, cfg, native)
	}

	return e.decideAutomationUsing(ctx, cfg, seq, p, propose, beforeAccept)
}
func (e *Engine) decideAutomationUsing(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64, p *claims.Proposer, propose func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error), beforeAccept func(context.Context, corrosion.Ballot, corrosion.ClaimValue) (corrosion.Ballot, error)) (claims.Outcome, error) {
	key, err := corrosion.AutomationClaimKey(seq)
	if err != nil {
		return claims.Outcome{}, err
	}
	if p == nil {
		p = claims.NewProposer(e.self, e.transport)
	}
	p.CallTimeout = callTimeout(ctx)
	spec := claims.Spec{Key: key, Generation: cfg.Generation, Voters: cfg.Names(), PrepareQuorum: corrosion.MajorityOf(len(cfg.Members)), MaxRounds: 8, Propose: propose, BeforeAccept: beforeAccept}
	return p.Decide(ctx, spec)
}

// SubmitOwner preserves the original command encoding and carries its target
// assignment separately. It is available only with a genuine local credential
// submission; neither generic Submit nor a peer can manufacture native authority.
func (e *Engine) SubmitOwner(ctx context.Context, owner *corrosion.AutomationOwnerSubmission) (Receipt, error) {
	if owner == nil || !owner.UsesClient(e.db) {
		return Receipt{}, fail(CodeUnavailable)
	}
	if err := e.enter(ctx); err != nil {
		return Receipt{}, err
	}
	defer e.leave()
	if err := owner.Authorize(ctx); err != nil {
		return Receipt{}, err
	}
	return e.submitOwner(ctx, owner.Command(), owner)
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
	return e.submitOwner(ctx, c, nil)
}
func (e *Engine) submitOwner(ctx context.Context, c Command, owner *corrosion.AutomationOwnerSubmission) (Receipt, error) {
	return e.submitPrepared(ctx, c, owner, nil)
}
func (e *Engine) submitPrepared(ctx context.Context, c Command, owner *corrosion.AutomationOwnerSubmission, continuity *corrosion.AutomationIdentityContinuity) (Receipt, error) {
	return e.submitPreparedFresh(ctx, c, owner, continuity, nil, nil)
}
func (e *Engine) submitPreparedFresh(ctx context.Context, c Command, owner *corrosion.AutomationOwnerSubmission, continuity *corrosion.AutomationIdentityContinuity, fresh func(context.Context, Decision) (*automationFreshValue, error), result *Decision) (Receipt, error) {
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
	if owner != nil && owner.TargetSessionID() != "" {
		a.Owner = &contract.OwnerAssignment{SessionID: owner.TargetSessionID()}
	}
	if continuity != nil {
		facts := continuity.Facts()
		a.Continuity = &facts
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
			if owner != nil {
				if _, err := owner.Original(ctx, existing.Receipt); err != nil {
					return Receipt{}, err
				}
			}
			if continuity != nil {
				if err := e.confirmContinuityOriginal(ctx, continuity, existing.Receipt); err != nil {
					return Receipt{}, err
				}
			}

			if result != nil {
				original, found, err := e.db.AutomationRecord(ctx, existing.Receipt.Sequence)
				if err != nil || !found {
					return Receipt{}, fail(CodeUnavailable)
				}
				decoded, err := contractDecode(original.Value)
				if err != nil || decoded.Command.RequestID != c.RequestID {
					return Receipt{}, fail(CodeUnavailable)
				}
				*result = decoded
			}
			if existing.Receipt.Code != "" {
				return existing.Receipt, fail(existing.Receipt.Code)
			}
			return existing.Receipt, nil
		}
		if owner != nil && c.Kind == "handoff_session" && owner.TargetSessionID() == c.SessionID {
			return Receipt{}, fail(CodeValidation)
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
		var out claims.Outcome
		if fresh != nil {
			out, err = e.decideFreshAutomationUsing(ctx, cfg, d.Sequence, nil, func(call context.Context) (*automationFreshValue, error) { return fresh(call, d) })
		} else {
			encoded, encodeErr := contractEncode(d)
			if encodeErr != nil {
				return Receipt{}, encodeErr
			}
			value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: encoded}}
			out, err = e.decidePrepared(ctx, cfg, d.Sequence, &value, owner, continuity)
		}
		if err != nil {
			if owner != nil || fresh != nil {
				return Receipt{}, err
			}
			return Receipt{}, fail(CodeUnavailable)
		}
		rec := corrosion.AutomationRecord{Value: out.Value, Certificate: out.Certificate}
		out.Value = corrosion.ClaimValue{}
		out.Certificate = corrosion.ClaimCertificate{}
		sequence := d.Sequence
		d = Decision{}
		applied, err := e.db.AutomationApplyOwned(ctx, &rec, e.verifier, reduce)
		if err != nil {
			return Receipt{}, fmt.Errorf("apply automation: %w", err)
		}
		e.distribute(ctx, cfg, sequence)
		// Read the actual selected result only after the owned apply. No full
		// decoded alias survives across the durable recovery owner above.
		if fresh != nil && result != nil && c.Kind == "activate_key_epoch" {
			original, found, err := e.db.AutomationRecord(ctx, applied.Sequence)
			if err != nil || !found {
				return Receipt{}, fail(CodeUnavailable)
			}
			selected, err := contractDecode(original.Value)
			if err != nil {
				return Receipt{}, err
			}
			if selected.Command.Kind == "activate_key_epoch" {
				*result = selected
				if applied.Code != "" {
					return applied, fail(applied.Code)
				}
				return applied, nil
			}
		}
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
		out.Value = corrosion.ClaimValue{}
		out.Certificate = corrosion.ClaimCertificate{}
		if _, err = e.db.AutomationApplyOwned(ctx, &record, e.verifier, reduce); err != nil {
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
	out.Value = corrosion.ClaimValue{}
	out.Certificate = corrosion.ClaimCertificate{}
	if err = e.db.AutomationBeginRecovery(ctx, record, e.verifier); err != nil {
		return err
	}
	// The durable recovery owner now holds the authenticated value. Retain only
	// its bounded certificate/identity while FinishRecovery opens originals;
	// this Engine ancestor must not keep the current raw envelope reachable.
	renewed := record.Certificate
	record = corrosion.AutomationRecord{}
	if err = e.resumeRecovery(ctx, cfg); err != nil {
		return err
	}
	var found bool
	record, found, err = e.db.AutomationRecord(ctx, target)
	if err != nil {
		return err
	}
	if !found {
		return fail(CodeUnavailable)
	}
	digest, err := record.Value.Digest()
	if err != nil || digest != renewed.ValueDigest {
		return fail(CodeUnavailable)
	}
	// Forward the intended renewed certificate; the exact durable value may
	// already have existed with an older certificate whose leaf has expired.
	record.Certificate = renewed
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
		out.Value = corrosion.ClaimValue{}
		out.Certificate = corrosion.ClaimCertificate{}
		if _, err = e.db.AutomationApplyOwned(ctx, &record, e.verifier, reduce); err != nil {
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
	return e.stagePredecessors(ctx, cfg.Names())
}

// stagePredecessors fetches each predecessor the pending staged job needs
// from any of voters, stages it, and applies the job once it connects to the
// local prefix.
func (e *Engine) stagePredecessors(ctx context.Context, voters []string) error {
	for range 256 {
		next, err := e.db.AutomationRecoveryNext(ctx)
		if err != nil {
			return err
		}
		if next == 0 {
			return e.db.AutomationFinishRecovery(ctx, reduce, 256)
		}
		found := false
		for _, v := range voters {
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
	if _, err := e.db.AutomationApplyOwned(ctx, &r, e.verifier, reduce); err == nil {
		return nil
	} else if r.Value.Automation == nil {
		// The actual matching durable handoff consumed this record. Preserve its
		// error and pending authenticated job for normal recovery on retry.
		return err
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
