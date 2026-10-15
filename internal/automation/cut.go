package automation

import "context"

// FreezeMembershipCut preserves audited local content while this node is
// sealed in generation. The returned opaque ID is not a signed transfer or
// adoption/readiness authority; no peer handler exposes these unpublished cuts.
func (e *Engine) FreezeMembershipCut(ctx context.Context, generation int64) (string, error) {
	if err := e.enter(ctx); err != nil {
		return "", err
	}
	defer e.leave()
	return e.db.FreezeAutomationCut(ctx, generation, reduce)
}
