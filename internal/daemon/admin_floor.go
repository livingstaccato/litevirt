package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// adminFloorInterval is how often the daemon checks the admin floor. A check
// with an admin alive is one indexed read.
const adminFloorInterval = 15 * time.Second

// runAdminFloor checks corrosion.EnsureAdminFloor every adminFloorInterval. A
// zero must persist for corrosion.AdminFloorSettle on a caught-up replica
// before a check acts, so a node reinstates within about a minute of the race
// (colonelpanik/litevirt#228).
func (d *Daemon) runAdminFloor(ctx context.Context) {
	t := time.NewTicker(adminFloorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.checkAdminFloor(ctx, corrosion.AdminFloorSettle)
	}
}

// checkAdminFloor is one tick: it logs and audits a reinstatement, which
// brings back an account an operator deleted and so must never be quiet.
func (d *Daemon) checkAdminFloor(ctx context.Context, settle time.Duration) {
	who, err := d.db.EnsureAdminFloor(ctx, settle)
	if err != nil {
		slog.Warn("admin floor: check failed", "error", err)
		return
	}
	if who == "" {
		return
	}
	slog.Warn("the cluster had no live admin account (admins deleted at once on different "+
		"nodes); the most recently deleted admin was reinstated", "reinstated", who)
	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		ID:       randid.New(),
		Username: "system",
		HostName: d.cfg.HostName,
		Action:   "user.admin_reinstated",
		Target:   who,
		Detail:   "no live admin remained after concurrent deletes",
		Result:   "ok",
	}); err != nil {
		slog.Warn("audit log insert failed", "action", "user.admin_reinstated", "error", err)
	}
}
