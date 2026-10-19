package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// StackRecord represents a deployed compose stack.
type StackRecord struct {
	Name        string
	ComposeHash string
	ComposeYAML string
	State       string
	CreatedAt   string
	UpdatedAt   string
}

// stackUpsertSQL writes a stack's whole row: every column but created_at,
// which only an insert sets.
const stackUpsertSQL = `INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   compose_hash = excluded.compose_hash,
		   compose_yaml = excluded.compose_yaml,
		   state        = excluded.state,
		   updated_at   = excluded.updated_at,
		   deleted_at   = NULL`

// UpsertStack creates or updates a stack record.
func UpsertStack(ctx context.Context, c *Client, s StackRecord) error {
	now := c.NowTS()
	return c.Execute(ctx, stackUpsertSQL,
		s.Name, s.ComposeHash, s.ComposeYAML, s.State, nowRFC3339(), now,
	)
}

// GetStack returns a stack by name, or nil if not found.
func GetStack(ctx context.Context, c *Client, name string) (*StackRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, compose_hash, compose_yaml, state, created_at, updated_at
		 FROM stacks WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &StackRecord{
		Name:        r.String("name"),
		ComposeHash: r.String("compose_hash"),
		ComposeYAML: r.String("compose_yaml"),
		State:       r.String("state"),
		CreatedAt:   r.String("created_at"),
		UpdatedAt:   r.String("updated_at"),
	}, nil
}

// ListStacks returns all active stacks.
func ListStacks(ctx context.Context, c *Client) ([]StackRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, compose_hash, compose_yaml, state, created_at, updated_at
		 FROM stacks WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	stacks := make([]StackRecord, len(rows))
	for i, r := range rows {
		stacks[i] = StackRecord{
			Name:        r.String("name"),
			ComposeHash: r.String("compose_hash"),
			ComposeYAML: r.String("compose_yaml"),
			State:       r.String("state"),
			CreatedAt:   r.String("created_at"),
			UpdatedAt:   r.String("updated_at"),
		}
	}
	return stacks, nil
}

// stackSetStateSQL sets a live stack's state and stamps its LWW key. It is
// written only for a stack this node holds no live row of: over a row, it
// would leave the row's other columns as this node last saw them
// (stackRowRead).
const stackSetStateSQL = `UPDATE stacks SET state = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`

// stackTombstoneSQL tombstones a stack.
const stackTombstoneSQL = `UPDATE stacks SET deleted_at = ?, updated_at = ?, state = 'deleted' WHERE name = ?`

// stackRowRead is a stack's row as a state write read it, to write it back
// WHOLE. A write of state and updated_at alone that is newer than a redeploy
// this node has not seen yet wins last-write-wins on every peer, which takes
// its state and keeps the redeploy's compose_yaml and compose_hash, while
// this node skips the redeploy as older and keeps its own: the replicas hold
// different rows under one updated_at for good. Written whole, the newer
// write is the same row everywhere. The write is guarded on the row still
// reading as it did (stillReads) and retried when it does not
// (retryStackRowWrite).
type stackRowRead struct {
	row   StackRecord
	found bool
	gone  bool // tombstoned
}

const stackRowReadSQL = `SELECT compose_hash, compose_yaml, state, created_at, updated_at, deleted_at IS NOT NULL AS gone
	FROM stacks WHERE name = ?`

func readStackRowForWrite(ctx context.Context, c *Client, name string) (stackRowRead, error) {
	rows, err := c.Query(ctx, stackRowReadSQL, name)
	if err != nil || len(rows) == 0 {
		return stackRowRead{}, err
	}
	r := rows[0]
	return stackRowRead{found: true, gone: r.Int("gone") != 0, row: StackRecord{
		Name: name, ComposeHash: r.String("compose_hash"), ComposeYAML: r.String("compose_yaml"),
		State: r.String("state"), CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at")}}, nil
}

// live reports whether the read found a live row.
func (rd stackRowRead) live() bool { return rd.found && !rd.gone }

// stillReads is the write's guard: the stack's row, inside the write's
// transaction, is still the one read, or still absent.
func (rd stackRowRead) stillReads(ctx context.Context, name string) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var got stackRowRead
		got.row.Name = name
		err := tx.QueryRowContext(ctx, stackRowReadSQL, name).Scan(&got.row.ComposeHash, &got.row.ComposeYAML,
			&got.row.State, &got.row.CreatedAt, &got.row.UpdatedAt, &got.gone)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return !rd.found, nil
		case err != nil:
			return false, err
		}
		got.found = true
		return got == rd, nil
	}
}

// stackRowSQL writes the row rd read whole, as state at updatedAt.
func stackRowSQL(rd stackRowRead, state, updatedAt string) Statement {
	r := rd.row
	return Statement{SQL: stackUpsertSQL, Params: []interface{}{
		r.Name, r.ComposeHash, r.ComposeYAML, state, r.CreatedAt, updatedAt}}
}

// retryStackRowWrite runs write, a guarded stack row write, until it applies.
func retryStackRowWrite(name string, write func() (bool, error)) error {
	for attempt := 0; attempt < 5; attempt++ {
		if applied, err := write(); err != nil || applied {
			return err
		}
	}
	return fmt.Errorf("stack %q: its row kept changing while it was written", name)
}

// SetStackState sets a live stack's state (e.g. "active" → "deleting"),
// with its whole row (stackRowRead).
func SetStackState(ctx context.Context, c *Client, name, state string) error {
	return retryStackRowWrite(name, func() (bool, error) {
		rd, err := readStackRowForWrite(ctx, c, name)
		if err != nil {
			return false, err
		}
		now := c.NowTS()
		stmts := []Statement{{SQL: stackSetStateSQL, Params: []interface{}{state, now, name}}}
		if rd.live() {
			stmts = []Statement{stackRowSQL(rd, state, now)}
		}
		return c.ExecuteBatchGuarded(ctx, rd.stillReads(ctx, name), stmts)
	})
}

// stackTeardownKeyPrefix keys, in cluster_policies, what a stack's teardown
// may do with its VMs' disks (stackTeardownRecord).
const stackTeardownKeyPrefix = "stack_teardown/"

// stackTeardownRecord is a teardown's disk choice: Teardown is the stack
// row's updated_at the "deleting" write stamped, so the record speaks for
// that teardown only.
type stackTeardownRecord struct {
	Teardown  string `json:"teardown"`
	KeepDisks bool   `json:"keep_disks"`
}

// MarkStackDeleting marks a stack "deleting", as SetStackState does, and
// records in the same replicated write whether the teardown keeps its VMs'
// disks (DeleteStackRequest.keep_disks), so the stack reconciler that finishes it
// does as the operator asked. The record goes in cluster_policies: a stacks
// column would stall a previous release's replication stream. Where
// cluster_policies may not be written yet (failover_scope_v1 not durably
// latched), only the state is written, and a reconciler keeps the disks
// (StackTeardownDeletesDisks).
//
// The state is written with the stack's whole row (stackRowRead).
func MarkStackDeleting(ctx context.Context, c *Client, name string, keepDisks bool, setBy string) error {
	return retryStackRowWrite(name, func() (bool, error) {
		rd, err := readStackRowForWrite(ctx, c, name)
		if err != nil {
			return false, err
		}
		now := c.NowTS()
		stmts := []Statement{{SQL: stackSetStateSQL, Params: []interface{}{"deleting", now, name}}}
		if rd.live() {
			stmts = []Statement{stackRowSQL(rd, "deleting", now)}
		}
		if c.MayWriteClusterPolicy() {
			v, err := json.Marshal(stackTeardownRecord{Teardown: now, KeepDisks: keepDisks})
			if err != nil {
				return false, err
			}
			stmts = append(stmts, Statement{SQL: clusterPolicyUpsertSQL,
				Params: []interface{}{stackTeardownKeyPrefix + name, string(v), setBy, now}})
		}
		return c.ExecuteBatchGuarded(ctx, rd.stillReads(ctx, name), stmts)
	})
}

// StackTeardownDeletesDisks reports whether the teardown of st (a stack in
// "deleting") may delete its VMs' disks: only when the teardown's own record
// says it does not keep them. proven is whether the record speaks for this
// teardown (it deletes them, or the operator asked to keep them). No record,
// a record of another teardown (its stamp is not st's updated_at), one this
// build cannot read, or a read that fails is not proven: the disks are kept —
// the operator may have asked to keep them, and a kept disk can still be
// removed by hand where a deleted one is gone. why says why they are kept.
func StackTeardownDeletesDisks(ctx context.Context, c *Client, st StackRecord) (deletes, proven bool, why string) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, stackTeardownKeyPrefix+st.Name)
	switch {
	case err != nil:
		return false, false, "the teardown's disk choice cannot be read: " + err.Error()
	case len(rows) == 0:
		return false, false, "the teardown recorded no disk choice (begun by an older build, or before cluster_policies could be written)"
	}
	var rec stackTeardownRecord
	if err := json.Unmarshal([]byte(rows[0].String("value")), &rec); err != nil || rec.Teardown == "" {
		return false, false, "the teardown's disk choice cannot be read"
	}
	if rec.Teardown != st.UpdatedAt {
		return false, false, "the disk choice recorded is another teardown's (the stack was re-stamped since)"
	}
	if rec.KeepDisks {
		return false, true, "the teardown keeps disks (keep_disks)"
	}
	return true, true, ""
}

// ListDeletingStacks returns stacks that are mid-deletion (state = 'deleting').
func ListDeletingStacks(ctx context.Context, c *Client) ([]StackRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, compose_hash, compose_yaml, state, created_at, updated_at
		 FROM stacks WHERE state = 'deleting' AND deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	stacks := make([]StackRecord, len(rows))
	for i, r := range rows {
		stacks[i] = StackRecord{
			Name:        r.String("name"),
			ComposeHash: r.String("compose_hash"),
			ComposeYAML: r.String("compose_yaml"),
			State:       r.String("state"),
			CreatedAt:   r.String("created_at"),
			UpdatedAt:   r.String("updated_at"),
		}
	}
	return stacks, nil
}

// DeleteStackRecord tombstones a stack. Where this node holds its row, the
// row is first written whole, at an earlier stamp of the same write, so the
// tombstone is the same row everywhere (stackRowRead).
func DeleteStackRecord(ctx context.Context, c *Client, name string) error {
	return retryStackRowWrite(name, func() (bool, error) {
		rd, err := readStackRowForWrite(ctx, c, name)
		if err != nil {
			return false, err
		}
		var stmts []Statement
		if rd.found {
			stmts = append(stmts, stackRowSQL(rd, "deleted", c.NowTS()))
		}
		stmts = append(stmts, Statement{SQL: stackTombstoneSQL, Params: []interface{}{nowRFC3339(), c.NowTS(), name}})
		return c.ExecuteBatchGuarded(ctx, rd.stillReads(ctx, name), stmts)
	})
}
