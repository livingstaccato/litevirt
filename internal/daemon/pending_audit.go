package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// pendingAuditFoldInterval is how often the daemon folds the pending-audit
// journal after its first pass at start.
//
// Start alone is not enough. `lv user reset-admin` falls back to the journal
// whenever it cannot reach the daemon's gRPC port, and that includes the window
// in which the daemon is running but not listening yet — startup opens the
// database long before it serves. An entry journalled then would otherwise wait
// for the NEXT restart. Thirty seconds bounds that, and a pass with no journal
// is one failed open.
const pendingAuditFoldInterval = 30 * time.Second

// runPendingAuditFold folds the journal now and then every
// pendingAuditFoldInterval. It must start after the audit keyring is wired, so
// the rows it folds are signed like every other row this host writes.
func (d *Daemon) runPendingAuditFold(ctx context.Context) {
	t := time.NewTicker(pendingAuditFoldInterval)
	defer t.Stop()
	for {
		d.foldPendingAuditOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (d *Daemon) foldPendingAuditOnce(ctx context.Context) {
	n, err := corrosion.FoldPendingAudit(ctx, d.db, d.cfg.DataDir, d.cfg.HostName)
	if err != nil {
		slog.Error("pending-audit journal: fold failed; the entries stay journalled and are retried",
			"error", err, "folded", n)
		return
	}
	if n > 0 {
		slog.Info("pending-audit journal: folded actions taken while the daemon was down into the audit log",
			"rows", n)
	}
}
