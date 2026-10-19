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
// It speaks for one deployment of the stack: the one since the stack's last
// teardown began (Teardown, that teardown's stamp in stack_teardown/<name>,
// "" for none), a cluster_policies row every replica holds alike. It is not
// bound to the stack record's created_at: that differs between replicas
// that each inserted the name (UpsertStack keeps it on conflict). A first
// deploy writes it only once it has recorded the stack, so one that fails
// leaves none; a teardown by this build re-stamps the stack, so a later
// deploy of the name does not inherit it (stackFirewallIntentApplies). A
// teardown on a previous release writes no stamp, and the intent then still
// applies to the name until an Admin's down or deploy (docs/upgrades.md).
//
// It is written only where cluster_policies may be written
// (failover_scope_v1), and a previous release neither writes nor reads it:
// with no record, the stack's file alone says (as before).
type StackFirewallIntent struct {
	Firewall    bool   `json:"firewall"`
	DefaultDeny bool   `json:"default_deny"`
	Teardown    string `json:"teardown,omitempty"`

	// unreadable: a value this build cannot decode, which applies to every
	// deployment, declaring a firewall and asking for the default-deny.
	unreadable bool
}

// SetStackFirewallIntent records the firewall intent of st, the stack's
// record as the deploy holds it, bound to that deployment. Callers write it
// only for a caller holding sg.write at the cluster root, with what the
// deploy's file declares. A no-op where cluster_policies may not be written
// yet, or for a stack with no record (a first deploy records it once its
// record is written).
func SetStackFirewallIntent(ctx context.Context, c *Client, st *StackRecord, firewall, defaultDeny bool, setBy string) error {
	if st == nil || st.Name == "" || !c.MayWriteClusterPolicy() {
		return nil
	}
	td, err := stackTeardownStamp(ctx, c, st.Name)
	if err != nil {
		return err
	}
	v, err := json.Marshal(StackFirewallIntent{Firewall: firewall, DefaultDeny: defaultDeny, Teardown: td})
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, stackFirewallKeyPrefix+st.Name, string(v), setBy, c.NowTS())
}

// GetStackFirewallIntent reads the firewall intent recorded for stack,
// whichever deployment it speaks for: found is false when there is none.
func GetStackFirewallIntent(ctx context.Context, c *Client, stack string) (in StackFirewallIntent, found bool, err error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, stackFirewallKeyPrefix+stack)
	if err != nil || len(rows) == 0 {
		return StackFirewallIntent{}, false, err
	}
	return decodeStackFirewallIntent(rows[0].String("value")), true, nil
}

// StackFirewallIntentOf reads the firewall intent of st's deployment:
// applies is false when none is recorded for it.
func StackFirewallIntentOf(ctx context.Context, c *Client, st StackRecord) (in StackFirewallIntent, applies bool, err error) {
	in, found, err := GetStackFirewallIntent(ctx, c, st.Name)
	if err != nil || !found {
		return StackFirewallIntent{}, false, err
	}
	td, err := stackTeardownStamp(ctx, c, st.Name)
	if err != nil {
		return StackFirewallIntent{}, false, err
	}
	if !stackFirewallIntentApplies(in, st, td) {
		return StackFirewallIntent{}, false, nil
	}
	return in, true, nil
}

// StackFirewallIntents reads the firewall intent of each live stack's
// deployment, by stack name; a stack with none recorded is absent.
func StackFirewallIntents(ctx context.Context, c *Client) (map[string]StackFirewallIntent, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key LIKE 'stack\_firewall/%' ESCAPE '\' AND deleted_at IS NULL`)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	stacks, err := ListStacks(ctx, c)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]StackRecord, len(stacks))
	for _, st := range stacks {
		byName[st.Name] = st
	}
	out := make(map[string]StackFirewallIntent, len(rows))
	for _, r := range rows {
		name := strings.TrimPrefix(r.String("key"), stackFirewallKeyPrefix)
		st, ok := byName[name]
		if !ok {
			continue
		}
		td, err := stackTeardownStamp(ctx, c, name)
		if err != nil {
			return nil, err
		}
		if in := decodeStackFirewallIntent(r.String("value")); stackFirewallIntentApplies(in, st, td) {
			out[name] = in
		}
	}
	return out, nil
}

// stackFirewallIntentApplies reports whether in speaks for st's deployment,
// whose last teardown's stamp is teardown: it was written since that
// teardown began. While st is "deleting", the
// teardown under way began after the intent was written, and the intent
// still speaks for what is being torn down. One this build cannot read
// applies to every deployment.
func stackFirewallIntentApplies(in StackFirewallIntent, st StackRecord, teardown string) bool {
	if in.unreadable {
		return true
	}
	return in.Teardown == teardown || st.State == "deleting"
}

// stackTeardownStamp is the stamp of stack's last teardown, from its
// teardown record (stackTeardownRecord), or "" when there is none. A record
// this build cannot read is its own stamp: it is still another teardown's.
func stackTeardownStamp(ctx context.Context, c *Client, stack string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, stackTeardownKeyPrefix+stack)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	v := rows[0].String("value")
	var rec stackTeardownRecord
	if json.Unmarshal([]byte(v), &rec) != nil || rec.Teardown == "" {
		return v, nil
	}
	return rec.Teardown, nil
}

func decodeStackFirewallIntent(v string) StackFirewallIntent {
	var in StackFirewallIntent
	if err := json.Unmarshal([]byte(v), &in); err != nil {
		return StackFirewallIntent{Firewall: true, DefaultDeny: true, unreadable: true}
	}
	return in
}
