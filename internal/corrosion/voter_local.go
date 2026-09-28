package corrosion

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// Node-local writes for the voter side of recovery claims
// (docs/design/recovery-claims.md §3.6–§3.8).
//
// A voter's promises and accepts are statements about what THIS voter did, so
// they must never be relayed, repaired or merged: a promise a peer could write
// is not a promise. ExecuteLocal is the one path that writes them. It runs one
// SQLite transaction under the client mutex, writes nothing to mutation_log,
// and refuses a statement on any table that is not registered node-local — so
// "local" is a property the client checks, not a convention a caller keeps.
// stmtshapecheck makes the same check statically at every call site.

// nodeLocalClaimTables are the tables ExecuteLocal may write. Each is absent
// from tableNames and sensitiveTableNames (TestNodeLocalClaimTablesAreNotReplicated).
var nodeLocalClaimTables = map[string]bool{
	"local_recovery_claims":   true,
	"local_voter_incarnation": true,
	"local_voter_adoption":    true,
}

// IsNodeLocalClaimTable reports whether ExecuteLocal may write table. Exported
// for stmtshapecheck, which refuses any other target statically.
func IsNodeLocalClaimTable(table string) bool { return nodeLocalClaimTables[table] }

// IsReplicatedTable reports whether table is repaired by either anti-entropy
// lane. Exported for stmtshapecheck.
func IsReplicatedTable(table string) bool {
	for _, n := range tableNames {
		if n == table {
			return true
		}
	}
	for _, n := range sensitiveTableNames {
		if n == table {
			return true
		}
	}
	return false
}

// LocalTx is the transaction ExecuteLocal hands its callback. Reads are
// unrestricted (a voter's membership check reads the replicated voter_configs
// row in the same transaction as its write); writes are restricted to the
// node-local claim tables.
type LocalTx struct {
	tx *sql.Tx
}

// Exec runs one write. A statement whose target is not a node-local claim table
// is refused before it reaches SQLite, and so is one that does not parse: the
// check fails closed.
func (t *LocalTx) Exec(ctx context.Context, sqlStr string, params ...interface{}) (sql.Result, error) {
	sh, err := parseStmtShape(sqlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("ExecuteLocal refuses a statement it cannot parse (it could be a write "+
			"to a replicated table): %w", err)
	}
	if !nodeLocalClaimTables[sh.Table] {
		return nil, fmt.Errorf("ExecuteLocal refuses a write to %q: only node-local claim tables may be "+
			"written without relaying, and a replicated (or unregistered) table written here would "+
			"diverge from every peer silently", sh.Table)
	}
	return t.tx.ExecContext(ctx, sqlStr, params...)
}

// Query runs one read inside the transaction.
func (t *LocalTx) Query(ctx context.Context, sqlStr string, params ...interface{}) ([]Row, error) {
	rows, err := t.tx.QueryContext(ctx, sqlStr, params...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []Row
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				// BLOB columns (the ballot nonces) keep their bytes; the Row
				// accessors read them back through Bytes.
				vals[i] = append([]byte(nil), b...)
			}
		}
		out = append(out, Row{Columns: cols, Values: vals})
	}
	return out, rows.Err()
}

// ExecuteLocal runs fn in one local transaction and commits it before
// returning. Nothing is written to mutation_log and the replicator is not
// woken. The caller must build any reply that depends on the write only after
// ExecuteLocal returns nil: the commit is what makes a promise durable (§3.7).
func (c *Client) ExecuteLocal(ctx context.Context, fn func(tx *LocalTx) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin local tx: %w", err)
	}
	if err := fn(&LocalTx{tx: tx}); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit local tx: %w", err)
	}
	return nil
}

// mintVoterIncarnationSQL creates the row once. INSERT OR IGNORE, never
// REPLACE: the incarnation is the identity of this database's claim state, and
// re-minting it on a restart would make every voter abstain after every
// restart (and, worse, would not be detectable as the amnesia it pretends to
// be).
const mintVoterIncarnationSQL = `INSERT OR IGNORE INTO local_voter_incarnation (id, incarnation, created_at)
	VALUES (1, ?, ?)`

// mintVoterIncarnation is called by InitSchema after the tables exist.
func (c *Client) mintVoterIncarnation(ctx context.Context) error {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("mint voter incarnation: %w", err)
	}
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := tx.Exec(ctx, mintVoterIncarnationSQL, hex.EncodeToString(b), time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
}

// VoterIncarnation returns this state.db's voter incarnation (§3.11).
func (c *Client) VoterIncarnation(ctx context.Context) (string, error) {
	rows, err := c.Query(ctx, `SELECT incarnation FROM local_voter_incarnation WHERE id = 1`)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 || rows[0].String("incarnation") == "" {
		return "", fmt.Errorf("no voter incarnation recorded (schema not initialized)")
	}
	return rows[0].String("incarnation"), nil
}

// SynchronousFull is SQLite's PRAGMA synchronous value for FULL: with it, a WAL
// commit is fsynced before COMMIT returns.
const SynchronousFull = 2

// SynchronousLevel reads PRAGMA synchronous on one of the pool's connections.
// Every connection is opened from the same DSN, so one answers for all.
func (c *Client) SynchronousLevel(ctx context.Context) (int, error) {
	rows, err := c.Query(ctx, `PRAGMA synchronous`)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 || len(rows[0].Values) == 0 {
		return 0, fmt.Errorf("PRAGMA synchronous returned nothing")
	}
	switch v := rows[0].Values[0].(type) {
	case int64:
		return int(v), nil
	case int:
		return v, nil
	default:
		return 0, fmt.Errorf("PRAGMA synchronous returned %T", v)
	}
}

// StatementTable is the table a write statement targets, from the structural
// parse. Exported for stmtshapecheck's ExecuteLocal check.
func StatementTable(sqlStr string) (string, error) {
	sh, err := parseStmtShape(sqlStr, nil)
	if err != nil {
		return "", err
	}
	return sh.Table, nil
}
