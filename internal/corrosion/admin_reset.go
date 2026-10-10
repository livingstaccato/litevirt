package corrosion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoLiveAdmin is ResetAdminPassword's refusal: there is no live admin
// account in this node's database to reset.
var ErrNoLiveAdmin = errors.New("no live admin account in this node's local database — " +
	"reset-admin resets an existing credential, it does not create one. " +
	"On a node that has joined a cluster the admin credential replicates in; " +
	"wait for this node to converge and try again. On a brand-new cluster the " +
	"founder's `lv host init` mints it. If the admin account was deliberately " +
	"deleted, it stays deleted")

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
// mandatory second-factor policy. It needs login_policy_v1 latched here, like
// every other write the login rules make.
//
// Everything — the lifecycle re-enable, the factor clear and the password — is
// ONE batch (t1-auth-review m4): a reset that half-lands would leave the
// account re-enabled with its old password, or with a new password it still
// cannot use.
func ResetAdminPassword(ctx context.Context, c *Client, passwordHash string, clearTwoFactor bool) error {
	existing, err := GetUser(ctx, c, "admin")
	if err != nil {
		// A read that fails must not read as absence.
		return fmt.Errorf("look up the admin account: %w", err)
	}
	if existing == nil {
		return ErrNoLiveAdmin
	}
	name := existing.Username
	now := c.NowTS()
	var stmts []Statement
	if clearTwoFactor {
		if !c.MayWriteLoginPolicy() {
			return fmt.Errorf("--clear-2fa is refused until login_policy_v1 has latched on this node; " +
				"nothing was changed")
		}
		stmts = append(stmts, clearSecondFactorStatements(name, nowRFC3339(), now)...)
	}
	// The recovery path must also recover an admin that cannot log in for a
	// reason other than its password: a disable or an expiry (user_lifecycle).
	// Without this, disabling or expiring every administrator — which the
	// SetUserAccount guard refuses, but two admins on two nodes can still
	// race into — would leave the cluster with no supported way back in.
	life, err := GetUserLifecycle(ctx, c, name)
	if err != nil {
		return fmt.Errorf("read the admin account's lifecycle: %w", err)
	}
	if !life.Unrestricted() {
		enable := enableUserStatements(c, name, "user.reset-admin", now)
		if enable == nil {
			// A row exists, so some node has latched login_policy_v1, but this
			// one has not durably latched it yet. Its own latch follows within a
			// capability sweep; writing before it would be the one write this
			// node's gate exists to stop.
			state := life.InactiveReason(time.Now().UTC())
			if state == "" {
				state = "set to expire at " + life.ExpiresAt
			}
			return fmt.Errorf("the admin account is restricted (%s), and this node cannot clear that "+
				"until login_policy_v1 has latched here; retry in a minute, or run `lv user enable admin` "+
				"and `lv user expire admin never` from a node where it has", state)
		}
		stmts = append(stmts, enable...)
	}
	pw, err := updateUserPasswordStatements(ctx, c, name, passwordHash, now)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	stmts = append(stmts, pw...)
	if err := c.ExecuteBatch(ctx, stmts); err != nil {
		return fmt.Errorf("reset the admin account: %w", err)
	}
	return nil
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
