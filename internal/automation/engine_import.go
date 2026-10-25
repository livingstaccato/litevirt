package automation

import (
	"context"
	"errors"
	"fmt"
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
		// Try every source serving the attested tip: one whose certificate
		// does not verify (forged, or signed by a since-revoked key) must not
		// block an import that another source can serve.
		var refused error = fail(CodeUnavailable)
		begun := false
		for _, v := range sources {
			call, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			r, ok, err := e.transport.Fetch(call, v, target.Sequence)
			cancel()
			if err != nil || !ok {
				continue
			}
			if digest, err := r.Value.Digest(); err != nil || digest != target.Digest {
				continue
			}
			if err := e.db.AutomationBeginImport(ctx, grant, r, e.verifier, gen); err != nil {
				if errors.Is(err, corrosion.ErrAutomationImportIneligible) || ctx.Err() != nil {
					return err
				}
				refused = fmt.Errorf("tip from %s: %w", v, err)
				continue
			}
			begun = true
			break
		}
		if !begun {
			return refused
		}
	}
	pending, err := e.db.AutomationRecoveryPending(ctx)
	if err != nil || !pending {
		return err
	}
	return e.stagePredecessors(ctx, sources)
}
