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

// stackRowInterleaveHook is a TEST-ONLY seam between a stack row write's read
// and its guarded write. Production leaves it nil.
var stackRowInterleaveHook func()

func readStackRowForWrite(ctx context.Context, c *Client, name string) (stackRowRead, error) {
	if stackRowInterleaveHook != nil {
		defer stackRowInterleaveHook()
	}
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

// SetStackState marks a live stack "deleting" with its whole row
// (stackRowRead), as MarkStackDeleting does without the teardown's disk
// choice. It refuses any other state: a whole-row write of a lagging node
// brings back a row whose tombstone it has not seen, which is harmless only
// for "deleting" (a reconciler finishes it and tombstones it again).
func SetStackState(ctx context.Context, c *Client, name, state string) error {
	if state != "deleting" {
		return fmt.Errorf("stack %q: SetStackState writes only \"deleting\", not %q", name, state)
	}
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
// may do with its VMs' disks and its firewall (stackTeardownRecord).
const stackTeardownKeyPrefix = "stack_teardown/"

// stackTeardownRecord is a teardown's disk choice and firewall authority:
// Teardown is the stack row's updated_at the "deleting" write stamped, so the
// record speaks for that teardown only. Firewall is set when the caller that
// began it held sg.write at the cluster root. A false one is omitted, so the
// record of a teardown without that authority is the one a previous release
// writes, and a previous release's record reads as one without it.
type stackTeardownRecord struct {
	Teardown  string `json:"teardown"`
	KeepDisks bool   `json:"keep_disks"`
	Firewall  bool   `json:"firewall,omitempty"`
}

// MarkStackDeleting marks a stack "deleting", as SetStackState does, and
// records in the same replicated write whether the teardown keeps its VMs'
// disks (DeleteStackRequest.keep_disks), so the stack reconciler that finishes it
// does as the operator asked, and whether its caller held sg.write at the
// cluster root (removesFirewall), so a reconciler removes the stack's
// firewall only for a teardown that may (StackTeardownRemovesFirewall). The
// record goes in cluster_policies: a stacks column would stall a previous
// release's replication stream. Where cluster_policies may not be written yet
// (failover_scope_v1 not durably latched), only the state is written, and a
// reconciler keeps the disks (StackTeardownDeletesDisks) and any firewall it
// holds of the stack. A teardown with sg.write also clears the stack's
// firewall intent.
//
// The state is written with the stack's whole row (stackRowRead).
func MarkStackDeleting(ctx context.Context, c *Client, name string, keepDisks, removesFirewall bool, setBy string) error {
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
			v, err := json.Marshal(stackTeardownRecord{Teardown: now, KeepDisks: keepDisks, Firewall: removesFirewall})
			if err != nil {
				return false, err
			}
			stmts = append(stmts, Statement{SQL: clusterPolicyUpsertSQL,
				Params: []interface{}{stackTeardownKeyPrefix + name, string(v), setBy, now}})
			// A teardown with sg.write at the root ends what the stack declared
			// (StackFirewallIntent), at its own stamp: an Admin redeploy that
			// began after it records anew, and wins. One without leaves it.
			if removesFirewall {
				clear, err := stackFirewallIntentStatement(name, StackFirewallIntent{}, setBy, now)
				if err != nil {
					return false, err
				}
				stmts = append(stmts, clear)
			}
		}
		return c.ExecuteBatchGuarded(ctx, rd.stillReads(ctx, name), stmts)
	})
}

// stackTeardown reads the record of st's teardown, or says why there is none
// that speaks for it (of what, the part of it the caller wants): no record, a
// record of another teardown (its stamp is not st's updated_at), one this
// build cannot read, or a read that fails.
func stackTeardown(ctx context.Context, c *Client, st StackRecord, what string) (*stackTeardownRecord, string) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, stackTeardownKeyPrefix+st.Name)
	switch {
	case err != nil:
		return nil, "the teardown's " + what + " cannot be read: " + err.Error()
	case len(rows) == 0:
		return nil, "the teardown recorded no " + what + " (begun by an older build, or before cluster_policies could be written)"
	}
	var rec stackTeardownRecord
	if err := json.Unmarshal([]byte(rows[0].String("value")), &rec); err != nil || rec.Teardown == "" {
		return nil, "the teardown's " + what + " cannot be read"
	}
	if rec.Teardown != st.UpdatedAt {
		return nil, "the " + what + " recorded is another teardown's (the stack was re-stamped since)"
	}
	return &rec, ""
}

// StackTeardownDeletesDisks reports whether the teardown of st (a stack in
// "deleting") may delete its VMs' disks: only when the teardown's own record
// says it does not keep them. proven is whether the record speaks for this
// teardown (it deletes them, or the operator asked to keep them). No record
// that speaks for it (stackTeardown) is not proven: the disks are kept — the
// operator may have asked to keep them, and a kept disk can still be removed
// by hand where a deleted one is gone. why says why they are kept.
func StackTeardownDeletesDisks(ctx context.Context, c *Client, st StackRecord) (deletes, proven bool, why string) {
	rec, why := stackTeardown(ctx, c, st, "disk choice")
	if rec == nil {
		return false, false, why
	}
	if rec.KeepDisks {
		return false, true, "the teardown keeps disks (keep_disks)"
	}
	return true, true, ""
}

// StackTeardownRemovesFirewall reports whether the teardown of st (a stack in
// "deleting") was begun by a caller holding sg.write at the cluster root, so
// that it may remove the stack's firewall whatever this host holds of it.
// Any other teardown was authorized by a node that saw no firewall for the
// stack, and that node's replica may have lagged this one: such a teardown
// leaves whatever firewall this host holds. No record that speaks for it
// (stackTeardown), a previous release's included, is such a teardown. why
// says why it does not.
func StackTeardownRemovesFirewall(ctx context.Context, c *Client, st StackRecord) (removes bool, why string) {
	rec, why := stackTeardown(ctx, c, st, "firewall authority")
	switch {
	case rec == nil:
		return false, why
	case !rec.Firewall:
		return false, "it was begun by a caller without sg.write at the cluster root"
	}
	return true, ""
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
