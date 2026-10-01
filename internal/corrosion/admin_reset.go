package corrosion

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
func ResetAdminPassword(ctx context.Context, c *Client, passwordHash string) error {
	existing, err := GetUser(ctx, c, "admin")
	if err != nil {
		// A read that fails must not read as absence.
		return fmt.Errorf("look up the admin account: %w", err)
	}
	if existing == nil {
		return ErrNoLiveAdmin
	}
	if err := UpdateUserPassword(ctx, c, "admin", passwordHash); err != nil {
		return fmt.Errorf("update password: %w", err)
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
