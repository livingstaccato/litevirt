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
// a live or cold migrate, a drain move, an owner repair, a container migrate.
// (The failover coordinator and the health checker use
// corrosion.ReverseReplicationAudited.) It
// never fails the move: a problem is logged, and a schedule that could not be
// re-pointed is reported as a warning notification, because it leaves the workload
// replicating onto its own host.
func (s *Server) reverseReplicationAfterMove(ctx context.Context, kind, name, project, oldHost, newHost string) {
	ctx = context.WithoutCancel(ctx)
	// The compare-and-set of target_host alone is a statement shape a host on a
	// previous release does not know (it would back-pressure this host's whole
	// stream to it): it is used once every host runs a release that has it, the
	// container_replication release feature. Until then the switch re-reads the
	// row and re-upserts it (ReverseOptions).
	gateErr := s.containerReplicationGate(ctx)
	if kind == "container" && gateErr != nil {
		// Container replication, its reversal included, is the
		// container_replication release feature: with it closed no container
		// schedule can have been made here to switch.
		return
	}
	opts := corrosion.ReverseOptions{TargetOnly: gateErr == nil}
	revs, err := corrosion.ReverseReplicationOnMove(ctx, s.db, kind, name, project, oldHost, newHost, opts)
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
