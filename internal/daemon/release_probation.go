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

// runReleaseProbation lifts the release probation preflightRollback put this
// node in at boot, once a voter majority has been asked and holds no use of a
// feature this build cannot keep (corrosion.AntiEntropy.VerifyReleaseProbation).
// A use found there quarantines the node for good instead. It returns once
// there is no probation: probation is entered only at boot.
func (d *Daemon) runReleaseProbation(ctx context.Context, ae *corrosion.AntiEntropy) {
	t := time.NewTicker(releaseProbationInterval)
	defer t.Stop()
	for len(d.db.ReleaseProbation()) > 0 {
		if lifted, err := ae.VerifyReleaseProbation(ctx); err != nil {
			slog.Warn("release probation: check failed; staying in probation", "error", err)
		} else if lifted && len(d.db.ReleaseProbation()) == 0 {
			slog.Info("release probation lifted")
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
