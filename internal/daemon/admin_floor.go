package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
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
	who, err := d.db.EnsureAdminFloor(ctx, settle, d.loginPolicyRun())
	if err != nil {
		slog.Warn("admin floor: check failed", "error", err)
		return
	}
	d.reportUsableAdmin(ctx)
	d.reportHeldSecondFactors(ctx)
	if who == "" {
		return
	}
	note := corrosion.AdminReinstatementNote(ctx, d.db, who)
	slog.Warn("the cluster had no live admin account (admins deleted at once on different "+
		"nodes); the most recently deleted admin was "+note, "reinstated", who)
	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		ID:       randid.New(),
		Username: "system",
		HostName: d.cfg.HostName,
		Action:   "user.admin_reinstated",
		Target:   who,
		Detail:   "no live admin remained after concurrent deletes; " + note,
		Result:   "ok",
	}); err != nil {
		slog.Warn("audit log insert failed", "action", "user.admin_reinstated", "error", err)
	}
}

// Health condition for a cluster with no admin that can log in.
const (
	adminFloorEvaluator = "auth"
	// CondNoUnrestrictedAdmin is raised by each node while its replica holds no
	// admin account anyone can log in as: none enabled and unexpired (and the
	// floor had no usable deleted admin to bring back), or only a
	// case-duplicate pair, or only an account the floor reinstated that has no
	// credential yet. The floor never re-enables a disabled admin itself —
	// that would undo a deliberate disable of a compromised account
	// (t1-auth-review I4) — so this names the recovery paths instead.
	CondNoUnrestrictedAdmin = "no_unrestricted_admin"
	// CondHeldSecondFactor is raised by each node while its replica holds an
	// account whose second factors are held (corrosion.ListHeldUser2FA): an
	// account re-created under the name of one a lagging node gave a factor.
	// None of them is accepted, and the account cannot log in on them.
	CondHeldSecondFactor = "held_second_factor"
)

// reportUsableAdmin raises or resolves no_unrestricted_admin about this node's
// replica. It is raised while no admin can actually log in, and its evidence
// names, for each admin root can bring back, the command that does it
// (re-review 3, I1a): a case-duplicate admin pair, which the floor counts as
// present rather than reinstate a deleted account beside it, and an account
// the floor reinstated without its old password.
func (d *Daemon) reportUsableAdmin(ctx context.Context) {
	rep, err := corrosion.AdminLoginState(ctx, d.db)
	if err != nil {
		slog.Warn("admin floor: could not check for a usable admin", "error", err)
		return
	}
	if ok, _ := d.db.ReplicaCaughtUp(); !ok && !rep.Loggable {
		return // cannot tell "none" from "none yet"
	}
	recovery := []string{}
	for _, name := range rep.AwaitingCredential {
		recovery = append(recovery, fmt.Sprintf("as root on a node: lv user reset-admin --user %s "+
			"(the admin floor reinstated %s without its old password)", name, name))
	}
	for _, name := range rep.HeldSecondFactor {
		held, _ := corrosion.ListHeldUser2FA(ctx, d.db, name) // none: the text names the form
		recovery = append(recovery, "as another admin: "+corrosion.HeldSecondFactorRecovery(name, held)+
			"; or as root on a node: lv user reset-admin --user "+name+" --clear-2fa")
	}
	for _, norm := range rep.Ambiguous {
		recovery = append(recovery, fmt.Sprintf("as root on a node, with credentials.json moved aside: "+
			"lv user delete --exact %s (lists the duplicate admin accounts and their ids), then "+
			"lv user delete --exact %s --id <ID> for the one to remove", norm, norm))
	}
	if len(recovery) == 0 {
		recovery = append(recovery, "lv user reset-admin; or as root: lv user enable <admin>, lv user expire <admin> never")
	}
	if !rep.Loggable {
		slog.Error("no admin account can log in. Recover as root on a node: " + strings.Join(recovery, "; or "))
	}
	d.writeSelfConditionAs(ctx, adminFloorEvaluator, CondNoUnrestrictedAdmin, !rep.Loggable, corrosion.SeverityCritical,
		map[string]any{"recovery": strings.Join(recovery, "; or ")})
}

// reportHeldSecondFactors raises or resolves held_second_factor, naming each
// account whose second factors are held and how an admin recovers it.
func (d *Daemon) reportHeldSecondFactors(ctx context.Context) {
	names, err := corrosion.HeldSecondFactorAccounts(ctx, d.db)
	if err != nil {
		slog.Warn("could not check for held second factors", "error", err)
		return
	}
	recovery := make([]string, 0, len(names))
	for _, name := range names {
		held, err := corrosion.ListHeldUser2FA(ctx, d.db, name)
		if err != nil {
			slog.Warn("could not list held second factors", "user", name, "error", err)
		}
		recovery = append(recovery, corrosion.HeldSecondFactorRecovery(name, held))
	}
	d.writeSelfConditionAs(ctx, adminFloorEvaluator, CondHeldSecondFactor, len(names) > 0, corrosion.SeverityWarning,
		map[string]any{"accounts": names, "recovery": strings.Join(recovery, "; ")})
}

// loginPolicyRun opens the login rules' release feature for the floor's
// reinstatement through this node's checker, best effort: the reinstatement
// is what the previous release does too, so it is never refused for the
// feature's sake, and carries the durable cut-offs only when the gate passes
// (grpcapi.LoginPolicyIfAvailable). No checker: the zero grant.
func (d *Daemon) loginPolicyRun() corrosion.FeatureRun {
	if d.checker == nil {
		return nil
	}
	return func(ctx context.Context, write func(context.Context, capabilities.FeatureGrant) error) error {
		return grpcapi.LoginPolicyIfAvailable(ctx, d.checker, write)
	}
}
