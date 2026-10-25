package automation

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ImportPrefix stages and applies the certified prefix up to target for a
// voter new to the automation electorate at gen (F1 Task 5G). The tip is
// fetched from a source that attested it, verified against the electorate
// that certified it (corrosion.AutomationBeginImport), and every predecessor
// down to the local head is fetched from any source and checked by the parent
// digest chain, then applied with this engine's reducer. It confers no
// authority: corrosion.AutomationGrantImportedAuthority does, afterwards.
func (e *Engine) ImportPrefix(ctx context.Context, grant capabilities.FeatureGrant, gen int64, target corrosion.AutomationPrefix, sources []string) error {
	if err := e.enter(ctx); err != nil {
		return err
	}
	defer e.leave()
	head, err := e.db.AutomationHead(ctx)
	if err != nil {
		return err
	}
	if head.Sequence < target.Sequence {
		var tip *corrosion.AutomationRecord
		for _, v := range sources {
			call, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			r, ok, err := e.transport.Fetch(call, v, target.Sequence)
			cancel()
			if err != nil || !ok {
				continue
			}
			if digest, err := r.Value.Digest(); err == nil && digest == target.Digest {
				tip = &r
				break
			}
		}
		if tip == nil {
			return fail(CodeUnavailable)
		}
		if err := e.db.AutomationBeginImport(ctx, grant, *tip, e.verifier, gen); err != nil {
			return err
		}
	}
	pending, err := e.db.AutomationRecoveryPending(ctx)
	if err != nil || !pending {
		return err
	}
	return e.stagePredecessors(ctx, sources)
}
