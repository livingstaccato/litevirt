package automation

import (
	"context"
	"errors"
	"math"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

var errAbsent = errors.New("automation: authoritatively absent")

func IsAbsent(err error) bool                   { return errors.Is(err, errAbsent) }
func contractEncode(d Decision) ([]byte, error) { return contract.EncodeDecision(d) }
func contractDecode(v corrosion.ClaimValue) (Decision, error) {
	if v.Automation == nil {
		return Decision{}, fail(CodeValidation)
	}
	return contract.DecodeDecision(v.Automation.Envelope)
}
func (e *Engine) barrier(ctx context.Context, min uint64) error {
	if min > math.MaxInt64 {
		return fail(CodeValidation)
	}
	if err := e.recover(ctx); err != nil {
		return fail(CodeUnavailable)
	}
	h, err := e.db.AutomationHead(ctx)
	if err != nil {
		return err
	}
	if h.Sequence == 0 || min > h.Sequence+128 {
		return fail(CodeUnavailable)
	}
	r, err := e.submit(ctx, Command{Kind: "read_barrier", ClusterUID: h.ClusterUID, PrincipalID: e.self, RequestID: randomID(), Body: []byte(`{"version":1}`)})
	if err != nil {
		return err
	}
	if r.Sequence < min {
		return fail(CodeUnavailable)
	}
	return nil
}
func (e *Engine) Observe(ctx context.Context, uid string, min uint64) (View, error) {
	if err := e.enter(ctx); err != nil {
		return View{}, err
	}
	defer e.leave()
	if err := e.barrier(ctx, min); err != nil {
		return View{}, err
	}
	// Identity/VM projections are added by their owning semantic handlers. A
	// certified barrier makes absence explicit in this staged empty projection.
	return View{}, errAbsent
}
func (e *Engine) Operation(ctx context.Context, id string) (Receipt, error) {
	if err := e.enter(ctx); err != nil {
		return Receipt{}, err
	}
	defer e.leave()
	if err := e.barrier(ctx, 0); err != nil {
		return Receipt{}, err
	}
	r, ok, err := e.db.AutomationOperation(ctx, id)
	if err != nil {
		return Receipt{}, err
	}
	if !ok {
		return Receipt{}, errAbsent
	}
	return r, nil
}
