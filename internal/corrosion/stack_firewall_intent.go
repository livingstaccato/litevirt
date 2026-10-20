package corrosion

import (
	"context"
	"encoding/json"
	"strings"
)

// The condition the stack reconciler raises for firewall state of a stack
// that a caller without sg.write at the cluster root could not remove or
// withdraw (internal/health/stack_firewall_hold.go). Named here so a deploy
// refused while it is open can say so.
const (
	StackFirewallHoldEvaluator = "stack_reconciler"
	StackFirewallHoldCode      = "stack.firewall_teardown_held"
	StackFirewallHoldKind      = "stack"
)

// StackFirewallHeld reports whether stack.firewall_teardown_held is open for
// stack on this replica.
func StackFirewallHeld(ctx context.Context, c *Client, stack string) (bool, error) {
	row, found, err := GetHealthCondition(ctx, c, StackFirewallHoldEvaluator, StackFirewallHoldCode, StackFirewallHoldKind, stack)
	if err != nil {
		return false, err
	}
	return found && row.Lifecycle != ConditionResolved, nil
}

// stackFirewallKeyPrefix keys, in cluster_policies, a stack's firewall
// intent (StackFirewallIntent).
const stackFirewallKeyPrefix = "stack_firewall/"

// StackFirewallIntent is what the last deploy of a stack by a caller holding
// sg.write at the cluster root declared of the firewall: whether its file
// declares one (security groups, ip sets or a firewall block) and whether it
// asks for the cluster default-deny.
//
// Only a caller with that authority changes it: a deploy records what its
// file declares, and a teardown clears it (in MarkStackDeleting's batch, at
// the teardown's own stamp, so an Admin redeploy that began after the
// teardown wins it). A deploy or teardown without it, from a node whose
// replica may hold an older file or none of this record, leaves it as it
// is. So what a stack declared stands, for the stack's name, until an Admin
// deploys or tears it down: it still counts while the stack is being torn
// down, after a teardown without sg.write tombstoned it, and after a deploy
// without sg.write replaced its file. A first deploy records it only once it
// has recorded the stack, so one that fails leaves none.
//
// It is written only where cluster_policies may be written
// (failover_scope_v1), and a previous release neither writes nor reads it:
// with no record, the stack's file alone says (as before). A previous
// release's teardown leaves it as it is (docs/upgrades.md).
type StackFirewallIntent struct {
	Firewall    bool `json:"firewall"`
	DefaultDeny bool `json:"default_deny"`
}

// Declares reports whether the intent declares any firewall.
func (in StackFirewallIntent) Declares() bool { return in.Firewall || in.DefaultDeny }

// stackFirewallIntentStatement is the write of in as stack's intent at stamp.
func stackFirewallIntentStatement(stack string, in StackFirewallIntent, setBy, stamp string) (Statement, error) {
	v, err := json.Marshal(in)
	if err != nil {
		return Statement{}, err
	}
	return Statement{SQL: clusterPolicyUpsertSQL, Params: []interface{}{stackFirewallKeyPrefix + stack, string(v), setBy, stamp}}, nil
}

// SetStackFirewallIntent records the firewall intent of st, the stack's
// record as the deploy holds it. Callers write it only for a caller holding
// sg.write at the cluster root, with what the deploy's file declares. A no-op
// where cluster_policies may not be written yet, or for a stack with no
// record (a first deploy records it once its record is written).
func SetStackFirewallIntent(ctx context.Context, c *Client, st *StackRecord, firewall, defaultDeny bool, setBy string) error {
	if st == nil || st.Name == "" || !c.MayWriteClusterPolicy() {
		return nil
	}
	v, err := json.Marshal(StackFirewallIntent{Firewall: firewall, DefaultDeny: defaultDeny})
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, stackFirewallKeyPrefix+st.Name, string(v), setBy, c.NowTS())
}

// UpsertStackWithFirewallIntent writes a stack's record, as UpsertStack
// does, and the firewall intent of its file in the same replicated write, for
// a deploy by a caller holding sg.write at the cluster root, the intent
// first: no replica sees the new record without the intent, so no re-assert
// there can act on a record the intent no longer asks for. Where cluster_policies may not be
// written yet, only the record is.
func UpsertStackWithFirewallIntent(ctx context.Context, c *Client, s StackRecord, firewall, defaultDeny bool, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return UpsertStack(ctx, c, s)
	}
	now := c.NowTS()
	intent, err := stackFirewallIntentStatement(s.Name, StackFirewallIntent{Firewall: firewall, DefaultDeny: defaultDeny}, setBy, now)
	if err != nil {
		return err
	}
	return c.ExecuteBatch(ctx, []Statement{
		intent,
		{SQL: stackUpsertSQL, Params: []interface{}{s.Name, s.ComposeHash, s.ComposeYAML, s.State, nowRFC3339(), now}},
	})
}

// GetStackFirewallIntent reads the firewall intent recorded for stack: found
// is false when there is none. One this build cannot read declares a firewall
// and asks for the default-deny (fail closed: a deny is never withdrawn, and a
// firewall never removed, on a guess).
func GetStackFirewallIntent(ctx context.Context, c *Client, stack string) (in StackFirewallIntent, found bool, err error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, stackFirewallKeyPrefix+stack)
	if err != nil || len(rows) == 0 {
		return StackFirewallIntent{}, false, err
	}
	return decodeStackFirewallIntent(rows[0].String("value")), true, nil
}

// StackFirewallIntentOf reads the firewall intent that stands for st's name:
// applies is false when none is recorded, or it declares nothing.
func StackFirewallIntentOf(ctx context.Context, c *Client, st StackRecord) (in StackFirewallIntent, applies bool, err error) {
	in, found, err := GetStackFirewallIntent(ctx, c, st.Name)
	if err != nil || !found || !in.Declares() {
		return StackFirewallIntent{}, false, err
	}
	return in, true, nil
}

// StackFirewallIntents reads every stack name's standing firewall intent that
// declares a firewall, by name, whatever the stack's state: live, being torn
// down, torn down, or not recorded here yet.
func StackFirewallIntents(ctx context.Context, c *Client) (map[string]StackFirewallIntent, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key LIKE 'stack\_firewall/%' ESCAPE '\' AND deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]StackFirewallIntent, len(rows))
	for _, r := range rows {
		if in := decodeStackFirewallIntent(r.String("value")); in.Declares() {
			out[strings.TrimPrefix(r.String("key"), stackFirewallKeyPrefix)] = in
		}
	}
	return out, nil
}

// stackFirewallIntentStamps reads every stack name's recorded firewall
// intent, declaring or not, with the stamp it was written at.
func stackFirewallIntentStamps(ctx context.Context, c *Client) (map[string]stampedIntent, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value, updated_at FROM cluster_policies WHERE key LIKE 'stack\_firewall/%' ESCAPE '\' AND deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]stampedIntent, len(rows))
	for _, r := range rows {
		out[strings.TrimPrefix(r.String("key"), stackFirewallKeyPrefix)] = stampedIntent{
			StackFirewallIntent: decodeStackFirewallIntent(r.String("value")), at: r.String("updated_at")}
	}
	return out, nil
}

type stampedIntent struct {
	StackFirewallIntent
	at string
}

// standingDenyAsk reports whether stack's standing firewall intent asks for
// the cluster default-deny (StackFirewallIntent): it is an heir of the deny
// whatever its state, until an Admin's deploy or teardown changes it.
func standingDenyAsk(ctx context.Context, c *Client, stack string) (bool, error) {
	in, found, err := GetStackFirewallIntent(ctx, c, stack)
	return found && in.DefaultDeny, err
}

func decodeStackFirewallIntent(v string) StackFirewallIntent {
	var in StackFirewallIntent
	if err := json.Unmarshal([]byte(v), &in); err != nil {
		return StackFirewallIntent{Firewall: true, DefaultDeny: true}
	}
	return in
}
