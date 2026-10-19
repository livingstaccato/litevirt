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
// asks for the cluster default-deny. A deploy without that authority never
// writes it, so a deploy from a node whose replica holds an older file
// cannot withdraw what a newer one declared: the stack's file is replaced on
// every peer, and this record still says what the stack asks for.
//
// It is written only where cluster_policies may be written
// (failover_scope_v1), and a previous release neither writes nor reads it:
// with no record, the stack's file alone says (as before).
type StackFirewallIntent struct {
	Firewall    bool `json:"firewall"`
	DefaultDeny bool `json:"default_deny"`
}

// SetStackFirewallIntent records the firewall intent of stack. Callers write
// it only for a caller holding sg.write at the cluster root: a deploy, with
// what its file declares, and a teardown that removes the stack's firewall,
// with none. A no-op where cluster_policies may not be written yet.
func SetStackFirewallIntent(ctx context.Context, c *Client, stack string, in StackFirewallIntent, setBy string) error {
	if stack == "" || !c.MayWriteClusterPolicy() {
		return nil
	}
	v, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, stackFirewallKeyPrefix+stack, string(v), setBy, c.NowTS())
}

// GetStackFirewallIntent reads the firewall intent of stack: found is false
// when there is none. One this build cannot read declares a firewall and
// asks for the default-deny (fail closed: a deny is never withdrawn, and a
// firewall never removed, on a guess).
func GetStackFirewallIntent(ctx context.Context, c *Client, stack string) (in StackFirewallIntent, found bool, err error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, stackFirewallKeyPrefix+stack)
	if err != nil || len(rows) == 0 {
		return StackFirewallIntent{}, false, err
	}
	return decodeStackFirewallIntent(rows[0].String("value")), true, nil
}

// StackFirewallIntents reads every stack's firewall intent, by stack name.
func StackFirewallIntents(ctx context.Context, c *Client) (map[string]StackFirewallIntent, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key LIKE 'stack\_firewall/%' ESCAPE '\' AND deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]StackFirewallIntent, len(rows))
	for _, r := range rows {
		out[strings.TrimPrefix(r.String("key"), stackFirewallKeyPrefix)] = decodeStackFirewallIntent(r.String("value"))
	}
	return out, nil
}

func decodeStackFirewallIntent(v string) StackFirewallIntent {
	var in StackFirewallIntent
	if err := json.Unmarshal([]byte(v), &in); err != nil {
		return StackFirewallIntent{Firewall: true, DefaultDeny: true}
	}
	return in
}
