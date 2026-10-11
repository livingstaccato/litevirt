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
	// stream to it): a VM's switch uses it once the release token has latched
	// (repointReady), and re-reads and re-upserts the row until then
	// (ReverseOptions). A container's schedule is container_replication's
	// data: its switch goes through this node's release-feature gate and is
	// always the compare-and-set (corrosion.RepointContainerReplicationTarget).
	opts := corrosion.ReverseOptions{Ready: func() bool { return s.repointReady(ctx) }}
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

// The compare-and-set switch (corrosion.RepointReplicationTarget), and the
// placement mint of the same kind (corrosion.MintContainerPlacement), are
// statement shapes a host on an earlier build does not know, and an unknown
// shape back-pressures the sender's whole replication stream to it. So they are
// emitted only once the release token has DURABLY latched here: the latch is
// replication-gated, so every host this one replicates to advertised a build
// that has them, and it is monotone, so it never re-opens. This reads the latch
// locally and asks no peer (ReleaseTokenLatched), and records no use: these
// statements are a better form of a write main already makes, not release
// feature data, so a cluster that never replicates a container still rolls back
// below the release without a quarantine.
//
// A member rolled back below the release after the latch can still be sent
// one of these statements: it refuses it, and replication from the sender to
// it stops there (back-pressure) until it runs the release again; nothing is
// applied in part (docs/backups.md, "If a member is rolled back"). A member
// that had latched the token itself is also WAL-quarantined by the earlier
// build's rollback preflight, which does not know the token's marker.
func (s *Server) wireReplicationReleaseGates() {
	if s.db != nil {
		s.db.SetRepointReady(s.repointReady)
		s.db.SetReleaseFeatureGate(s.WithReleaseFeature)
	}
}

func (s *Server) repointReady(context.Context) bool {
	return s.ReleaseTokenLatched()
}
