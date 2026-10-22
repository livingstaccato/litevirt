package corrosion

// Fleet fault injection only: remove authority by rolling back a signed
// valued transaction. This seam cannot grant or skip authentication.
import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
)

// FailAutomationValuedCommitForTest must be installed while the client's test
// operation is quiescent and restored only after all its calls have joined.
// It fails every signed valued write at this one key until restoration, so a
// proposer retry cannot silently turn an injected rollback into success.
func (c *Client) FailAutomationValuedCommitForTest(key ClaimKey) (restore func(), fired func() bool) {
	var seen atomic.Bool
	c.mu.Lock()
	previous := c.automationSeams
	c.automationSeams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		row, found, err := loadClaimRowTx(context.Background(), &LocalTx{tx: tx}, key)
		if err != nil {
			return err
		}
		if found && row.Accept != nil && row.Value != nil {
			seen.Store(true)
			return errors.New("test: native owner signed value commit rollback")
		}
		return nil
	}}
	c.mu.Unlock()
	return func() { c.mu.Lock(); c.automationSeams = previous; c.mu.Unlock() }, seen.Load
}
