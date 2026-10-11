package corrosion

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// ErrNoLiveAdmin is ResetAdminPassword's refusal: there is no live admin
// account in this node's database to reset.
var ErrNoLiveAdmin = errors.New("no live admin account in this node's local database — " +
	"reset-admin resets an existing credential, it does not create one. " +
	"On a node that has joined a cluster the admin credential replicates in; " +
	"wait for this node to converge and try again. On a brand-new cluster the " +
	"founder's `lv host init` mints it. If the admin account was deliberately " +
	"deleted, it stays deleted; name another admin-role account with " +
	"`lv user reset-admin --user <name>` (the one the admin floor reinstated, " +
	"if it did)")

// ResetAdminPassword replaces the local admin account's password hash. It is
// the one write behind `lv user reset-admin`, shared by the daemon's local-root
// RPC and the CLI's daemon-down fallback so the two cannot drift.
//
// It RESETS only. It used to create an admin when GetUser returned nil, and that
// was two bugs at once:
//
//   - GetUser filters `deleted_at IS NULL`, so a deliberately deleted admin read
//     as absent — and InsertUser reactivates a soft-deleted row rather than
//     inserting, so the "create" silently un-deleted a revoked account, gave it a
//     fresh password and replicated it to every peer.
//
//   - On a node that has joined but not yet converged, `users` is legitimately
//     empty. Minting there produces a row with a current updated_at that wins LWW
//     and replaces the cluster's real admin credential — the same failure the
//     daemon's own seed guard exists to prevent, reached through the CLI. It is
//     the path an operator is pushed down, because a joining node deliberately
//     writes no password file and this is the documented recovery command.
//
// Nothing is lost by refusing: founding a cluster mints the admin through
// `lv host init` and the daemon's founder path, and a joined node receives it by
// replication.
//
// clearTwoFactor (`--clear-2fa`) also removes every second factor and recovery
// code of the account: the way back in for a sole admin who lost both under a
// mandatory second-factor policy. It is part of the login rules, so it needs
// the release feature capabilities.FeatureLoginPolicy, like every other write
// they make.
//
// Everything — the lifecycle re-enable, the factor clear and the password — is
// ONE batch (t1-auth-review m4): a reset that half-lands would leave the
// account re-enabled with its old password, or with a new password it still
// cannot use.
//
// run opens the release feature, and is asked to only when the reset writes
// the login rules' data (--clear-2fa, or an admin that is disabled or has an
// expiry): a plain password reset stays what it was before the release, and
// does not mark the feature used. A nil run (reset-admin with litevirtd down,
// which has no release-feature gate) writes none of that data and refuses a
// reset that needs it.
func ResetAdminPassword(ctx context.Context, c *Client, run FeatureRun, passwordHash string, clearTwoFactor bool) error {
	return ResetAdminPasswordFor(ctx, c, run, "admin", passwordHash, clearTwoFactor)
}

// ErrNotAnAdmin is ResetAdminPasswordFor's refusal of an account whose role is
// not admin: reset-admin recovers administrators, it is not a way for root to
// set any user's password.
var ErrNotAnAdmin = errors.New("not an admin-role account; reset-admin resets an administrator's password only")

// ResetAdminPasswordFor is ResetAdminPassword for the admin-role account named
// username (`lv user reset-admin --user`; "" is "admin"). It is how root gives
// an account the admin floor reinstated its first credential: the floor never
// brings back a deleted account's old password (re-review 3, I1a).
func ResetAdminPasswordFor(ctx context.Context, c *Client, run FeatureRun, username, passwordHash string, clearTwoFactor bool) error {
	if username == "" {
		username = "admin"
	}
	existing, err := GetUser(ctx, c, username)
	if errors.Is(err, ErrAmbiguousUsername) {
		return fmt.Errorf("%w. Two accounts are named like %q, and reset-admin cannot choose. As root, with "+
			"credentials.json moved aside, run `lv user delete --exact %s` to list them with their ids, "+
			"then `lv user delete --exact %s --id <ID>` for the one to remove, and run reset-admin again",
			err, username, username, username)
	}
	if err != nil {
		// A read that fails must not read as absence.
		return fmt.Errorf("look up the account %q: %w", username, err)
	}
	if existing == nil {
		if username != "admin" {
			return fmt.Errorf("%w (no live account named %q)", ErrNoLiveAdmin, username)
		}
		return ErrNoLiveAdmin
	}
	if existing.Role != "admin" {
		return fmt.Errorf("%q is %w", existing.Username, ErrNotAnAdmin)
	}
	name := existing.Username
	// The recovery path must also recover an admin that cannot log in for a
	// reason other than its password: a disable or an expiry (user_lifecycle).
	// Without this, disabling or expiring every administrator — which the
	// SetUserAccount guard refuses, but two admins on two nodes can still
	// race into — would leave the cluster with no supported way back in.
	life, err := GetUserLifecycle(ctx, c, name)
	if err != nil {
		return fmt.Errorf("read the admin account's lifecycle: %w", err)
	}
	write := func(ctx context.Context, g capabilities.FeatureGrant) error {
		stmts, err := resetAdminStatements(ctx, c, g, name, life, passwordHash, clearTwoFactor)
		if err != nil {
			return err
		}
		if err := c.ExecuteBatch(ctx, stmts); err != nil {
			return fmt.Errorf("reset the admin account: %w", err)
		}
		return nil
	}
	if !clearTwoFactor && life.Unrestricted() {
		if !cutoffsAhead(life, time.Now()) {
			return write(ctx, capabilities.FeatureGrant{})
		}
		// Only the forward-dated cut-off's correction needs the release
		// feature (re-review 4, m-2). A gate that does not open must not
		// cost root the plain password reset it had before: reset without
		// the correction, which the login's refusal still names.
		wrote := false
		err := run.run(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
			wrote = true
			return write(ctx, g)
		})
		if err != nil && !wrote {
			slog.Warn("reset-admin could not open the login_policy feature to correct a cut-off dated in the future; "+
				"resetting the password only", "user", name, "error", err)
			return write(ctx, capabilities.FeatureGrant{})
		}
		return err
	}
	return run.run(ctx, write)
}

// resetAdminStatements is ResetAdminPasswordFor's batch for name, whose
// lifecycle is life. The login rules' part of it — the factor clear and the
// re-enable — needs a grant for capabilities.FeatureLoginPolicy; without one
// a reset that needs it is refused, wrapping ErrLoginPolicyGateClosed, and
// nothing is changed.
func resetAdminStatements(ctx context.Context, c *Client, g capabilities.FeatureGrant, name string, life UserLifecycle,
	passwordHash string, clearTwoFactor bool) ([]Statement, error) {
	granted := g.Check(capabilities.FeatureLoginPolicy) == nil
	now := c.NowTS()
	nowT := time.Now()
	var stmts []Statement
	if clearTwoFactor {
		if !granted {
			return nil, fmt.Errorf("%w: --clear-2fa needs the login_policy feature of %s, which this process "+
				"cannot open (litevirtd is not running here, or the cluster upgrade has not finished); "+
				"nothing was changed. Run it again with litevirtd running", ErrLoginPolicyGateClosed, capabilities.ReleaseToken)
		}
		stmts = append(stmts, clearSecondFactorStatements(name, nowRFC3339(), now)...)
	}
	if !life.Unrestricted() {
		enable := enableUserStatements(g, name, "user.reset-admin", now)
		if enable == nil {
			// A row exists, so the feature is in use somewhere, but this
			// process cannot open it: litevirtd is down, or this node's own
			// latch has not formed yet. Writing without it would be the one
			// write the gate exists to stop.
			state := life.InactiveReason(time.Now().UTC())
			if state == "" {
				state = "set to expire at " + life.ExpiresAt
			}
			return nil, fmt.Errorf("%w: the admin account %q is restricted (%s), and this process cannot "+
				"clear that (litevirtd is not running here, or its release feature gate has not opened); "+
				"run reset-admin again with litevirtd running, or run `lv user enable %s` and "+
				"`lv user expire %s never` from a node where it is",
				ErrLoginPolicyGateClosed, name, state, name, name)
		}
		stmts = append(stmts, enable...)
		// A re-enable is a session cut-off here as in SetUserLifecycle
		// (rereview-2 m-3): nothing minted before it — on a node the disable
		// had not reached — revives with it. Set back by the skew margin, as
		// a re-create's is (ResetUserLifecycle), so the operator's login
		// right after the reset works at once.
		//
		// It never moves the stored cut-off backwards (re-review 3, m-5): a
		// disable written in the last few seconds, or by a node whose clock
		// runs a little ahead, keeps its later cut-off, and the operator's
		// login waits out that margin instead. One dated further ahead than
		// the margin is clock error, and is replaced (resetCutoff).
		stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
			Params: []interface{}{name, UserAttrSessionsNotBefore, resetCutoff(life.SessionsNotBefore, nowT),
				"user.reset-admin", now}})
	} else if granted && CutoffAhead(life.SessionsNotBefore, nowT) {
		stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
			Params: []interface{}{name, UserAttrSessionsNotBefore, setBackCutoff(), "user.reset-admin", now}})
	}
	// A cut-off further ahead than the skew margin was written by a node
	// whose clock runs ahead and refuses the admin's logins (or new tokens)
	// until that time; every other write keeps it. Root replaces it here
	// (re-review 4, m-2). Without the grant (litevirtd down, or its gate not
	// open) the password is still reset, as before the login rules.
	if granted && CutoffAhead(life.TokensNotBefore, nowT) {
		stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
			Params: []interface{}{name, UserAttrTokensNotBefore, setBackCutoff(), "user.reset-admin", now}})
	}
	if granted && cutoffsAhead(life, nowT) {
		slog.Warn("reset-admin replaced a cut-off dated in the future: a node's clock ran ahead when it was written",
			"user", name, "sessions_not_before", life.SessionsNotBefore, "tokens_not_before", life.TokensNotBefore)
	}
	pw, err := updateUserPasswordStatements(ctx, c, name, passwordHash, now)
	if err != nil {
		return nil, fmt.Errorf("update password: %w", err)
	}
	stmts = append(stmts, pw...)
	return stmts, nil
}

// cutoffsAhead reports whether either of life's cut-offs is dated further
// ahead than the skew margin (CutoffAhead).
func cutoffsAhead(life UserLifecycle, now time.Time) bool {
	return CutoffAhead(life.SessionsNotBefore, now) || CutoffAhead(life.TokensNotBefore, now)
}

// ResetAdminAuditDetail is the detail of a user.reset-admin row, shared with the
// CLI's daemon-down journal entry so both paths record the same shape.
//
// os_user is what the CLI reports (SUDO_USER, else the login name), so it is a
// claim, and it is squeezed to a safe token: it lands in a signed, replicated,
// append-only row.
func ResetAdminAuditDetail(via, osUser string) string {
	return "via=" + via + " os_user=" + sanitizeAuditToken(osUser)
}

func sanitizeAuditToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('?')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
