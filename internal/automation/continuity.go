package automation

import (
	"context"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type continuityPhase2Transport interface {
	PrepareContinuityPhase2(context.Context, corrosion.ClaimKey, corrosion.Ballot, corrosion.ClaimValue, *corrosion.VoterConfig, *corrosion.AutomationIdentityContinuity) (corrosion.Ballot, error)
}

func (e *Engine) CertifyIdentityContinuity(ctx context.Context, native *corrosion.AutomationIdentityContinuity) (Receipt, error) {
	if !native.UsesClient(e.db) {
		return Receipt{}, fail(CodeUnavailable)
	}
	if err := e.enter(ctx); err != nil {
		return Receipt{}, err
	}
	defer e.leave()
	if err := native.Authorize(ctx); err != nil {
		return Receipt{}, err
	}
	return e.submitPrepared(ctx, native.Command(), nil, native)
}

// A nonempty local head is not a live decision quorum. Re-decide the exact
// original slot with a fresh request-bound ballot and verify/apply that actual
// certificate. Missing voters cannot turn an old receipt into current success.
func (e *Engine) confirmContinuityOriginal(ctx context.Context, native *corrosion.AutomationIdentityContinuity, receipt Receipt) error {
	original, found, err := e.db.AutomationRecord(ctx, receipt.Sequence)
	if err != nil {
		return err
	}
	if !found {
		return fail(CodeUnavailable)
	}
	cfg, err := e.db.AutomationMembership(ctx)
	if err != nil {
		return fail(CodeUnavailable)
	}
	out, err := e.decidePrepared(ctx, cfg, receipt.Sequence, nil, nil, nil)
	if err != nil {
		return fail(CodeUnavailable)
	}
	if out.Value.MustDigest() != original.Value.MustDigest() {
		return fail(CodeIdempotencyConflict)
	}
	record := corrosion.AutomationRecord{Value: out.Value, Certificate: out.Certificate}
	if _, err = e.db.AutomationApplyOwned(ctx, &record, e.verifier, reduce); err != nil {
		return err
	}
	_, err = native.Original(ctx, receipt, record)
	return err
}
