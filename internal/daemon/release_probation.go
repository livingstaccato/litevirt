package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// releaseProbationInterval is how often a node in release probation asks a
// voter majority again.
const releaseProbationInterval = 5 * time.Second

// kickReleaseProbation wakes runReleaseProbation now (non-blocking).
func (d *Daemon) kickReleaseProbation() {
	select {
	case d.releaseProbationKick <- struct{}{}:
	default:
	}
}

// runReleaseProbation lifts this node's release probation once a voter
// majority has been asked and holds no use of a feature this build cannot keep
// (corrosion.AntiEntropy.VerifyReleaseProbation). A use found there
// quarantines the node for good instead.
func (d *Daemon) runReleaseProbation(ctx context.Context, ae *corrosion.AntiEntropy) {
	t := time.NewTicker(releaseProbationInterval)
	defer t.Stop()
	for {
		if len(d.db.ReleaseProbation()) > 0 {
			if lifted, err := ae.VerifyReleaseProbation(ctx); err != nil {
				slog.Warn("release probation: check failed; staying in probation", "error", err)
			} else if lifted {
				slog.Info("release probation lifted")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.releaseProbationKick:
		}
	}
}
