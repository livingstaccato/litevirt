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

// BootRollbackCheck is the daemon's startup rollback check: it runs
// preflightRollback against db's replicated used records, puts db in release
// probation for every token that passed only on this replica's word, and
// returns the tokens that quarantine this node. One function so the daemon and
// the fleet harness boot the same way.
func BootRollbackCheck(ctx context.Context, dataDir string, db *corrosion.Client) []string {
	toks, probation := preflightRollback(dataDir, releaseFeatureUseReader(ctx, db))
	db.EnterReleaseProbation(probation)
	return toks
}

// RunReleaseProbation lifts the release probation BootRollbackCheck put db in,
// once a voter majority has been asked and holds no use of a feature this build
// cannot keep (corrosion.AntiEntropy.VerifyReleaseProbation). A use found there
// quarantines the node for good instead. It returns once there is no
// probation: probation is entered only at boot. While it lasts the node emits
// no replicated writes and applies nothing a peer pushes or anti-entropy
// offers; only the probation pull itself is merged.
func RunReleaseProbation(ctx context.Context, db *corrosion.Client, ae *corrosion.AntiEntropy) {
	t := time.NewTicker(releaseProbationInterval)
	defer t.Stop()
	for len(db.ReleaseProbation()) > 0 {
		if lifted, err := ae.VerifyReleaseProbation(ctx); err != nil {
			slog.Warn("release probation: check failed; staying in probation", "error", err)
		} else if lifted {
			// Nothing is remembered: the next boot below the marker is a
			// probation again (I-R3-1).
			if len(db.ReleaseProbation()) == 0 {
				slog.Info("release probation lifted")
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
