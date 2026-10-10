package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
)

// reverseReplicationAfterMove switches the direction of a workload's replication
// after it moved from oldHost to newHost (corrosion.ReverseReplicationOnMove):
// called wherever this daemon commits an ownership change: a replica promotion,
// a live or cold migrate, a drain move, a container relocation or migrate. It
// never fails the move: a problem is logged, and a schedule that could not be
// re-pointed is reported as a warning notification, because it leaves the workload
// replicating onto its own host.
func (s *Server) reverseReplicationAfterMove(ctx context.Context, kind, name, project, oldHost, newHost string) {
	ctx = context.WithoutCancel(ctx)
	revs, err := corrosion.ReverseReplicationOnMove(ctx, s.db, kind, name, project, oldHost, newHost)
	if err != nil {
		slog.Warn("replication: could not switch direction after a move", "kind", kind, "workload", name, "from", oldHost, "to", newHost, "error", err)
	}
	for _, r := range revs {
		if r.Skipped != "" {
			detail := fmt.Sprintf("%s %s moved %s -> %s onto its own replica target, which could not be switched to replicate back: %s; its replica now protects nothing",
				r.Kind, r.Workload, oldHost, newHost, r.Skipped)
			slog.Warn("replication: " + detail)
			s.audit(ctx, "replication.reverse", r.Workload, detail, "skipped")
			s.notify(ctx, notify.Notification{Kind: "replication.reverse_skipped", Severity: notify.SevWarn, Subject: r.Workload, Detail: detail})
			continue
		}
		detail := fmt.Sprintf("%s %s moved %s -> %s: replication now runs %s -> %s (%s)", r.Kind, r.Workload, oldHost, newHost, newHost, r.ToHost, r.Repo)
		s.audit(ctx, "replication.reverse", r.Workload, detail, "ok")
		if kind == "vm" {
			s.recordVMEvent(ctx, r.Workload, "replication.reversed", "ok", detail)
		}
		s.notify(ctx, notify.Notification{Kind: "replication.reversed", Severity: notify.SevInfo, Subject: r.Workload, Detail: detail})
	}
}
