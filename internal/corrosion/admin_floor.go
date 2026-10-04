package corrosion

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// The admin floor: every replica restores "at least one live admin" on its own
// (colonelpanik/litevirt#228).
//
// DeleteUser refuses the last live admin, but its check and its delete are two
// operations against replicated state, and nothing makes the pair atomic across
// LWW replicas. Two admins, one delete on each of two nodes: each check sees the
// other admin alive, both deletes land, and once the tombstones cross the
// cluster has no administrator. The repair DeleteUser runs beside its own
// delete cannot see this — it runs before the peer's tombstone arrives — so the
// floor is checked here, by every node, against its own replica, after the
// fact.
//
// The rule is ReinstateAdminIfNoneRemain's: with zero live admins, undo the
// newest admin tombstone, username breaking a tie. Every replica holding the
// same rows picks the same account, so the nodes that act all reinstate the one
// row, and their writes converge under LWW to one admin.
//
// It is periodic and not run on apply, on purpose. Apply order across origins
// is not the order things happened in: a replica can apply "delete alice"
// (made on a node that had already seen bob created) before it applies "create
// bob". On apply it would see zero admins for that instant and reinstate alice,
// cluster-wide — resurrecting an administrator the operator revoked while a
// live one exists. So a node acts only when
//
//   - its replica has caught up with a peer since it last had reason to doubt
//     it (ReplicaCaughtUp), and
//   - it saw zero live admins on an earlier check at least `settle` ago, and
//     still does now.
//
// A transient zero from reordering resolves within a push; a real one persists.

// adminFloor is the per-process state of the check: when this node first saw
// zero live admins, zero meaning it has not.
type adminFloor struct {
	mu        sync.Mutex
	zeroSince time.Time
}

// AdminFloorSettle is how long zero live admins must persist on a caught-up
// replica before the daemon's periodic check reinstates one.
const AdminFloorSettle = 30 * time.Second

// EnsureAdminFloor is one check of the admin floor. It reports the account it
// reinstated, "" when it did not act. See the block comment above.
func (c *Client) EnsureAdminFloor(ctx context.Context, settle time.Duration) (string, error) {
	f := &c.adminFloor
	f.mu.Lock()
	defer f.mu.Unlock()

	live, err := c.Query(ctx,
		`SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL LIMIT 1`)
	if err != nil {
		return "", err
	}
	if len(live) > 0 {
		f.zeroSince = time.Time{}
		return "", nil
	}
	if ok, why := c.ReplicaCaughtUp(); !ok {
		// A replica that may be missing rows cannot tell "no admin" from "no
		// admin YET". It also does not start the clock.
		f.zeroSince = time.Time{}
		slog.Debug("admin floor: zero live admins, but the replica is not caught up; not acting", "why", why)
		return "", nil
	}
	now := time.Now()
	if f.zeroSince.IsZero() {
		f.zeroSince = now
		slog.Warn("admin floor: this replica holds no live admin account; reinstating one if that persists",
			"settle", settle.String())
		return "", nil
	}
	if now.Sub(f.zeroSince) < settle {
		return "", nil
	}
	who, err := ReinstateAdminIfNoneRemain(ctx, c)
	if err != nil {
		return "", err
	}
	f.zeroSince = time.Time{}
	return who, nil
}
