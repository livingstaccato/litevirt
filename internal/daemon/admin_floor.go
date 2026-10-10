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
	d.reportUsableAdmin(ctx)
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

// Health condition for a cluster with no admin that can log in.
const (
	adminFloorEvaluator = "auth"
	// CondNoUnrestrictedAdmin is raised by each node while its replica holds no
	// live admin account that is enabled and unexpired, and the floor had no
	// usable deleted admin to bring back. The floor never re-enables a
	// disabled admin itself — that would undo a deliberate disable of a
	// compromised account (t1-auth-review I4) — so this names the recovery
	// paths instead.
	CondNoUnrestrictedAdmin = "no_unrestricted_admin"
)

// reportUsableAdmin raises or resolves no_unrestricted_admin about this node's
// replica.
func (d *Daemon) reportUsableAdmin(ctx context.Context) {
	usable, err := corrosion.UsableAdminExists(ctx, d.db)
	if err != nil {
		slog.Warn("admin floor: could not check for a usable admin", "error", err)
		return
	}
	if ok, _ := d.db.ReplicaCaughtUp(); !ok && !usable {
		return // cannot tell "none" from "none yet"
	}
	if !usable {
		slog.Error("no admin account can log in: every live admin is disabled or expired. Recover as " +
			"root on a node: `lv user reset-admin` re-enables the admin account, or `sudo lv user enable <admin>` " +
			"with credentials.json moved aside")
	}
	d.writeSelfConditionAs(ctx, adminFloorEvaluator, CondNoUnrestrictedAdmin, !usable, corrosion.SeverityCritical,
		map[string]any{"recovery": "lv user reset-admin; or as root: lv user enable <admin>, lv user expire <admin> never"})
}
