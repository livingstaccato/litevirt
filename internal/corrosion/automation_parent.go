package corrosion

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// ErrAutomationProjectParentUnavailable is retryable until the project owner
// reports an unambiguous, adopted live lifetime.
var ErrAutomationProjectParentUnavailable = fmt.Errorf("automation project parent unavailable: %w", ErrAutomationLifecycleUnavailable)

// readAutomationParentLifetimeTx consumes the caller's transaction under c.mu.
// It reads current owner facts, not originating evidence or a certified identity.
// The existing user verdict takes the holds lock after the client lock; no
// public client query or independent snapshot belongs inside this boundary.
func readAutomationParentLifetimeTx(ctx context.Context, c *Client, tx *sql.Tx, kind, alias string) (contract.ParentLifetime, error) {
	var parent contract.ParentLifetime
	if kind == "project" {
		birth, verdict, err := projectParentIncarnationTx(ctx, tx, alias)
		if err != nil {
			return parent, err
		}
		if verdict != projectParentCurrent || birth == "" {
			return parent, ErrAutomationProjectParentUnavailable
		}
		// The implicit default has no stored row or private origin. Give its
		// empty supported spelling the owner's public name only.
		if alias == "" {
			alias = DefaultProject
		}
		return contract.ParentLifetime{Kind: kind, Alias: alias, Birth: birth}, nil
	}
	if kind != "principal" || !c.UserIncarnationOn() {
		return parent, ErrAutomationLifecycleUnavailable
	}
	rows, err := tx.QueryContext(ctx, `SELECT u.username,u.realm,u.created_at FROM users u WHERE `+usernameNormSQL+` = ? AND u.deleted_at IS NULL`, NormalizeUsername(alias))
	if err != nil {
		return contract.ParentLifetime{}, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if err := rows.Scan(&parent.Alias, &parent.Realm, &parent.Birth); err != nil {
			return contract.ParentLifetime{}, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return contract.ParentLifetime{}, err
	}
	if err := rows.Close(); err != nil {
		return contract.ParentLifetime{}, err
	}
	if count != 1 || parent.Alias == "" || parent.Realm != "local" || parent.Birth == "" {
		return contract.ParentLifetime{}, ErrAutomationLifecycleUnavailable
	}
	verdict, err := c.userGuardVerdictOf(ctx, tx, &MutationGuard{
		Protocol: userIncarnationGuardV1, ResourceKind: userGuardLive,
		ResourceID: parent.Alias, Incarnation: parent.Birth,
	})
	if err != nil {
		return contract.ParentLifetime{}, err
	}
	if verdict != userVerdictApply {
		return contract.ParentLifetime{}, ErrAutomationLifecycleUnavailable
	}
	parent.Kind = kind
	return parent, nil
}
