// Package localwrites exercises the ExecuteLocal check: a LocalTx.Exec whose
// target is a node-local claim table passes, anything else is a gap.
package localwrites

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const localSQL = `INSERT OR IGNORE INTO local_voter_adoption (generation, imported_from, adopted_at) VALUES (?, ?, ?)`

func Local(ctx context.Context, c *corrosion.Client) error {
	return c.ExecuteLocal(ctx, func(tx *corrosion.LocalTx) error {
		_, err := tx.Exec(ctx, localSQL, 1, "", "t") // want: ok
		return err
	})
}

func Replicated(ctx context.Context, c *corrosion.Client) error {
	return c.ExecuteLocal(ctx, func(tx *corrosion.LocalTx) error {
		_, err := tx.Exec(ctx, `UPDATE hosts SET state = ? WHERE name = ?`, "fenced", "x") // want: gap
		return err
	})
}

func Dynamic(ctx context.Context, c *corrosion.Client, q string) error {
	return c.ExecuteLocal(ctx, func(tx *corrosion.LocalTx) error {
		_, err := tx.Exec(ctx, q) // want: gap (not a constant)
		return err
	})
}
