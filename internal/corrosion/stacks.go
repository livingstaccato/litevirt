package corrosion

import (
	"context"
	"encoding/json"
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

// UpsertStack creates or updates a stack record.
func UpsertStack(ctx context.Context, c *Client, s StackRecord) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   compose_hash = excluded.compose_hash,
		   compose_yaml = excluded.compose_yaml,
		   state        = excluded.state,
		   updated_at   = excluded.updated_at,
		   deleted_at   = NULL`,
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

// stackSetStateSQL sets a live stack's state and stamps its LWW key.
const stackSetStateSQL = `UPDATE stacks SET state = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`

// SetStackState updates the state column of a stack (e.g. "active" → "deleting").
func SetStackState(ctx context.Context, c *Client, name, state string) error {
	now := c.NowTS()
	return c.Execute(ctx, stackSetStateSQL, state, now, name)
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
// holds of the stack.
func MarkStackDeleting(ctx context.Context, c *Client, name string, keepDisks, removesFirewall bool, setBy string) error {
	now := c.NowTS()
	stmts := []Statement{{SQL: stackSetStateSQL, Params: []interface{}{"deleting", now, name}}}
	if c.MayWriteClusterPolicy() {
		v, err := json.Marshal(stackTeardownRecord{Teardown: now, KeepDisks: keepDisks, Firewall: removesFirewall})
		if err != nil {
			return err
		}
		stmts = append(stmts, Statement{SQL: clusterPolicyUpsertSQL,
			Params: []interface{}{stackTeardownKeyPrefix + name, string(v), setBy, now}})
	}
	return c.ExecuteBatch(ctx, stmts)
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

// DeleteStackRecord tombstones a stack.
func DeleteStackRecord(ctx context.Context, c *Client, name string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE stacks SET deleted_at = ?, updated_at = ?, state = 'deleted' WHERE name = ?`,
		nowRFC3339(), now, name,
	)
}
