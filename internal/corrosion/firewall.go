package corrosion

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// FirewallRule is a cluster- or host-tier firewall rule — the two policy
// planes that apply beyond a single NIC. The per-NIC tier lives in
// security_groups + sg_rules; this is the cluster_default / host_overrides
// chains the renderer emits. HostName is set only for host-tier rules.
type FirewallRule struct {
	ID        string
	HostName  string // host_firewall_rules only; empty for cluster rules
	Direction string
	Proto     string
	PortRange string
	CIDR      string
	Action    string
	Priority  int
	Comment   string
	StackName string // set when the rule came from a compose file
}

// IPSet is a named CIDR list, rendered as an nftables set object. Rules
// reference one with cidr = "@<name>".
type IPSet struct {
	ID        string
	Name      string
	CIDRs     []string
	StackName string
}

// FirewallDefault is the default-deny policy for one scope ('cluster' or a
// host name).
type FirewallDefault struct {
	Scope       string
	DefaultDeny bool
	StackName   string
}

// normRule applies the same field defaults the renderer/security-group path
// uses.
func normRule(r *FirewallRule) error {
	if r.Proto == "" {
		r.Proto = "all"
	}
	if r.Action == "" {
		r.Action = "accept"
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	return nil
}

// ── IP sets ──────────────────────────────────────────────────────────────

// InsertIPSet creates a named CIDR list of IPv4 elements; one with an IPv6
// element needs InsertIPSetWithGrant.
func InsertIPSet(ctx context.Context, c *Client, s IPSet) error {
	return InsertIPSetWithGrant(ctx, c, capabilities.FeatureGrant{}, s)
}

// InsertIPSetWithGrant creates a named CIDR list. An IPv6 element is the
// release feature firewall_ipv6: g must be its grant.
func InsertIPSetWithGrant(ctx context.Context, c *Client, g capabilities.FeatureGrant, s IPSet) error {
	// The name and elements are written into every host's nft script as text.
	// An element holding commas is stored as the elements it lists.
	s.CIDRs = rulefield.NormaliseSetElements(s.CIDRs)
	if err := rulefield.IPSet(s.Name, s.CIDRs); err != nil {
		return err
	}
	if err := IPSetCompanionClash(ctx, c, "", []IPSet{s}); err != nil {
		return err
	}
	v6, err := ipSetFamily(s.CIDRs)
	if err != nil {
		return err
	}
	if v6 {
		if err := g.Check(capabilities.FeatureFirewallIPv6); err != nil {
			return noIPv6Grant(err)
		}
	}
	cidrs, err := encodeSGs(s.CIDRs) // reuse the []string→JSON helper
	if err != nil {
		return err
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.Name, cidrs, s.StackName, nowRFC3339(), now,
	)
}

// IPSetCompanionClash refuses sets that, beside the live ones, would make
// every host refuse its ruleset: a set named <x>_v6 while a set x holds IPv6
// elements, or the reverse (rulefield.CompanionClash). The live rows of stack
// (when not "") are left out of the comparison: a deploy replaces them.
func IPSetCompanionClash(ctx context.Context, c *Client, stack string, sets []IPSet) error {
	live, err := ListIPSets(ctx, c)
	if err != nil {
		return err
	}
	byName := map[string][]string{}
	for _, l := range live {
		if stack == "" || l.StackName != stack {
			byName[l.Name] = append(byName[l.Name], l.CIDRs...)
		}
	}
	for _, s := range sets {
		byName[s.Name] = append(byName[s.Name], s.CIDRs...)
	}
	for _, s := range sets {
		if err := rulefield.CompanionClash(byName, s.Name); err != nil {
			return err
		}
	}
	return nil
}

// ListIPSets returns every live ip set (cluster-wide — the renderer scopes
// them by reference, not by host).
func ListIPSets(ctx context.Context, c *Client) ([]IPSet, error) {
	rows, err := c.Query(ctx,
		`SELECT id, name, COALESCE(cidrs, '[]') AS cidrs, stack_name
		 FROM ip_sets WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]IPSet, len(rows))
	for i, r := range rows {
		out[i] = IPSet{
			ID:        r.String("id"),
			Name:      r.String("name"),
			CIDRs:     decodeSGs(r.String("cidrs")),
			StackName: r.String("stack_name"),
		}
	}
	return out, nil
}

// DeleteIPSet tombstones an ip set by id.
func DeleteIPSet(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE ip_sets SET deleted_at = ?, updated_at = ? WHERE id = ?`, nowRFC3339(), now, id)
}

// ── Cluster-tier rules ─────────────────────────────────────────────────────

// InsertClusterFirewallRule adds an IPv4 rule to the cluster_default chain;
// one that needs a release feature needs InsertClusterFirewallRuleWithGrant.
func InsertClusterFirewallRule(ctx context.Context, c *Client, r FirewallRule) error {
	return InsertClusterFirewallRuleWithGrant(ctx, c, capabilities.FeatureGrant{}, capabilities.FeatureGrant{}, capabilities.FeatureGrant{}, r)
}

// InsertClusterFirewallRuleWithGrant adds a rule to the cluster_default
// chain. An IPv6 rule is the release feature firewall_ipv6, a logged one
// firewall_log and one matching a tag group firewall_tag_groups: g, gLog and
// gTag must be their grants (FirewallRowFeatures). A row whose fields fail the
// grammar the renderer writes into an nft script is refused before any grant
// is checked.
func InsertClusterFirewallRuleWithGrant(ctx context.Context, c *Client, g, gLog, gTag capabilities.FeatureGrant, r FirewallRule) error {
	r.Proto, r.PortRange, r.Action = rulefield.NormaliseRule(r.Proto, r.PortRange, r.Action)
	if err := rulefield.StoredRule(r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Comment); err != nil {
		return err
	}
	need, err := firewallRowFeatures(r.CIDR, r.Proto, r.Action)
	if err != nil {
		return err
	}
	// One grant per feature the row needs; each writer checks every one
	// itself (release_guard_test.go writerTakesGrant).
	if slices.Contains(need, capabilities.FeatureFirewallIPv6) {
		if err := g.Check(capabilities.FeatureFirewallIPv6); err != nil {
			return noIPv6Grant(err)
		}
	}
	if slices.Contains(need, capabilities.FeatureFirewallLog) {
		if err := gLog.Check(capabilities.FeatureFirewallLog); err != nil {
			return noLogGrant(err)
		}
	}
	if slices.Contains(need, capabilities.FeatureFirewallTagGroups) {
		if err := gTag.Check(capabilities.FeatureFirewallTagGroups); err != nil {
			return noTagGrant(err)
		}
	}
	if err := normRule(&r); err != nil {
		return err
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO cluster_firewall_rules
		   (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Priority, r.Comment, r.StackName, nowRFC3339(), now,
	)
}

// ListClusterFirewallRules returns every live cluster-tier rule, in priority
// order (the order the renderer emits them within the chain).
func ListClusterFirewallRules(ctx context.Context, c *Client) ([]FirewallRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, direction, proto, port_range, cidr, action, priority, COALESCE(comment,'') AS comment, stack_name
		 FROM cluster_firewall_rules WHERE deleted_at IS NULL ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	return scanRules(rows, ""), nil
}

// DeleteClusterFirewallRule tombstones a cluster-tier rule by id.
func DeleteClusterFirewallRule(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE cluster_firewall_rules SET deleted_at = ?, updated_at = ? WHERE id = ?`, nowRFC3339(), now, id)
}

// ── Host-tier rules ─────────────────────────────────────────────────────────

// InsertHostFirewallRule adds an IPv4 rule to one host's host_overrides
// chain; one that needs a release feature needs InsertHostFirewallRuleWithGrant.
func InsertHostFirewallRule(ctx context.Context, c *Client, r FirewallRule) error {
	return InsertHostFirewallRuleWithGrant(ctx, c, capabilities.FeatureGrant{}, capabilities.FeatureGrant{}, capabilities.FeatureGrant{}, r)
}

// InsertHostFirewallRuleWithGrant adds a rule to one host's host_overrides
// chain. An IPv6 rule is the release feature firewall_ipv6, a logged one
// firewall_log and one matching a tag group firewall_tag_groups: g, gLog and
// gTag must be their grants (FirewallRowFeatures).
func InsertHostFirewallRuleWithGrant(ctx context.Context, c *Client, g, gLog, gTag capabilities.FeatureGrant, r FirewallRule) error {
	if r.HostName == "" {
		return fmt.Errorf("host firewall rule requires a host name")
	}
	r.Proto, r.PortRange, r.Action = rulefield.NormaliseRule(r.Proto, r.PortRange, r.Action)
	if err := rulefield.StoredRule(r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Comment); err != nil {
		return err
	}
	need, err := firewallRowFeatures(r.CIDR, r.Proto, r.Action)
	if err != nil {
		return err
	}
	// One grant per feature the row needs; each writer checks every one
	// itself (release_guard_test.go writerTakesGrant).
	if slices.Contains(need, capabilities.FeatureFirewallIPv6) {
		if err := g.Check(capabilities.FeatureFirewallIPv6); err != nil {
			return noIPv6Grant(err)
		}
	}
	if slices.Contains(need, capabilities.FeatureFirewallLog) {
		if err := gLog.Check(capabilities.FeatureFirewallLog); err != nil {
			return noLogGrant(err)
		}
	}
	if slices.Contains(need, capabilities.FeatureFirewallTagGroups) {
		if err := gTag.Check(capabilities.FeatureFirewallTagGroups); err != nil {
			return noTagGrant(err)
		}
	}
	if err := normRule(&r); err != nil {
		return err
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO host_firewall_rules
		   (id, host_name, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.HostName, r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Priority, r.Comment, r.StackName, nowRFC3339(), now,
	)
}

// ListHostFirewallRules returns the live host-tier rules for one host. An
// empty host returns every host's rules (used by the management UI).
func ListHostFirewallRules(ctx context.Context, c *Client, host string) ([]FirewallRule, error) {
	sql := `SELECT id, host_name, direction, proto, port_range, cidr, action, priority, COALESCE(comment,'') AS comment, stack_name
		FROM host_firewall_rules WHERE deleted_at IS NULL`
	var params []interface{}
	if host != "" {
		sql += " AND host_name = ?"
		params = append(params, host)
	}
	sql += " ORDER BY host_name, priority, id"
	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}
	out := make([]FirewallRule, len(rows))
	for i, r := range rows {
		out[i] = FirewallRule{
			ID:        r.String("id"),
			HostName:  r.String("host_name"),
			Direction: r.String("direction"),
			Proto:     r.String("proto"),
			PortRange: r.String("port_range"),
			CIDR:      r.String("cidr"),
			Action:    r.String("action"),
			Priority:  r.Int("priority"),
			Comment:   r.String("comment"),
			StackName: r.String("stack_name"),
		}
	}
	return out, nil
}

// DeleteHostFirewallRule tombstones a host-tier rule by id.
func DeleteHostFirewallRule(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE host_firewall_rules SET deleted_at = ?, updated_at = ? WHERE id = ?`, nowRFC3339(), now, id)
}

// scanRules maps cluster-rule rows (no host_name column) into FirewallRule.
func scanRules(rows []Row, host string) []FirewallRule {
	out := make([]FirewallRule, len(rows))
	for i, r := range rows {
		out[i] = FirewallRule{
			ID:        r.String("id"),
			HostName:  host,
			Direction: r.String("direction"),
			Proto:     r.String("proto"),
			PortRange: r.String("port_range"),
			CIDR:      r.String("cidr"),
			Action:    r.String("action"),
			Priority:  r.Int("priority"),
			Comment:   r.String("comment"),
			StackName: r.String("stack_name"),
		}
	}
	return out
}

// ── Default-deny policy ──────────────────────────────────────────────────────

// SetFirewallDefault upserts the default-deny policy for a scope ('cluster' or
// a host name). stack is recorded when the policy came from a compose file.
func SetFirewallDefault(ctx context.Context, c *Client, scope string, deny bool, stack string) error {
	now := c.NowTS()
	denyInt := 0
	if deny {
		denyInt = 1
	}
	// Upsert: a scope has at most one live row.
	return c.Execute(ctx,
		`INSERT INTO firewall_defaults (scope, default_deny, stack_name, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(scope) DO UPDATE SET default_deny = excluded.default_deny,
		   stack_name = excluded.stack_name, updated_at = excluded.updated_at, deleted_at = NULL`,
		scope, denyInt, stack, nowRFC3339(), now,
	)
}

// GetFirewallDefault returns the policy for one scope, or nil if unset.
func GetFirewallDefault(ctx context.Context, c *Client, scope string) (*FirewallDefault, error) {
	rows, err := c.Query(ctx,
		`SELECT scope, default_deny, stack_name FROM firewall_defaults
		 WHERE scope = ? AND deleted_at IS NULL`, scope)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &FirewallDefault{
		Scope:       r.String("scope"),
		DefaultDeny: r.Int("default_deny") != 0,
		StackName:   r.String("stack_name"),
	}, nil
}

// ListFirewallDefaults returns every live per-scope default policy (cluster +
// any host overrides), for the management UI / CLI.
func ListFirewallDefaults(ctx context.Context, c *Client) ([]FirewallDefault, error) {
	rows, err := c.Query(ctx,
		`SELECT scope, default_deny, stack_name FROM firewall_defaults
		 WHERE deleted_at IS NULL ORDER BY scope`)
	if err != nil {
		return nil, err
	}
	out := make([]FirewallDefault, len(rows))
	for i, r := range rows {
		out[i] = FirewallDefault{
			Scope:       r.String("scope"),
			DefaultDeny: r.Int("default_deny") != 0,
			StackName:   r.String("stack_name"),
		}
	}
	return out, nil
}

// ResolveDefaultDeny computes the effective default-deny for one host: the
// host-scoped policy if set, else the cluster policy, else false (accept).
func ResolveDefaultDeny(ctx context.Context, c *Client, host string) (bool, error) {
	if host != "" {
		if d, err := GetFirewallDefault(ctx, c, host); err != nil {
			return false, err
		} else if d != nil {
			return d.DefaultDeny, nil
		}
	}
	d, err := GetFirewallDefault(ctx, c, "cluster")
	if err != nil {
		return false, err
	}
	if d != nil {
		return d.DefaultDeny, nil
	}
	return false, nil
}

// DeleteFirewallDefault tombstones a scope's policy (reverts to inherit/accept).
func DeleteFirewallDefault(ctx context.Context, c *Client, scope string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE firewall_defaults SET deleted_at = ?, updated_at = ? WHERE scope = ?`, nowRFC3339(), now, scope)
}

// EnsureClusterDefaultDeny sets the cluster default-deny, owned by stack,
// unless a deny is already in force (whoever owns it keeps it).
func EnsureClusterDefaultDeny(ctx context.Context, c *Client, stack string) error {
	cur, err := GetFirewallDefault(ctx, c, "cluster")
	if err != nil {
		return err
	}
	if cur != nil && cur.DefaultDeny {
		return nil
	}
	return SetFirewallDefault(ctx, c, "cluster", true, stack)
}

// ReassertStackDefaultDeny sets the cluster default-deny, owned by the first
// stack (by name) that asks for it (otherStackWants), when the cluster has no
// live default row: a stack's deploy can miss a handoff from an owner that
// went down while it was in flight, and a removal written on a replica that
// had not yet seen the ask (a teardown's handoff, a redeploy's drop) can
// outrank it. A live row is left as it is: a deny is its owner's, and an
// allow is an operator's decision (`lv firewall default-deny off`).
//
// A stack that asks gets the deny back whatever removed it and whenever: a
// removal never outranks an ask. Its recorded intent outranks its file when
// an Admin's redeploy drops the deny, so its old file does not ask in the
// meantime. A stack with no recorded intent (deployed before
// cluster_policies could be written, or by a previous release) is judged by
// its file alone: its own redeploy dropping the deny can then get it back
// from the old file still in its record, and once the new file is recorded
// the deny is one nothing asks for, kept and reported (fail closed).
//
// No pass removes or withdraws a deny. One that nothing asks for any more
// stays, fail closed, and is reported (UnaskedStackDeny).
func ReassertStackDefaultDeny(ctx context.Context, c *Client, read StackFileWants) error {
	cur, err := GetFirewallDefault(ctx, c, "cluster")
	if err != nil || cur != nil {
		return err // a live row, deny or allow: its owner's decision
	}
	wants, _, err := otherStackWants(ctx, c, "", read)
	if err != nil {
		return err
	}
	for _, w := range wants {
		if w.defaultDeny {
			return SetFirewallDefault(ctx, c, "cluster", true, w.name)
		}
	}
	return nil
}

// UnaskedStackDeny returns the live stack that owns the cluster default-deny
// when nothing asks for it any more: neither that stack (its file, and the
// intent its last deploy with sg.write recorded) nor any other stack, and
// every stack's file can be read. "" otherwise. The deny stays; the caller
// reports it, and an Admin turns it off (`lv firewall default-deny off`) or
// keeps it as an operator's (`lv firewall default-deny on`).
func UnaskedStackDeny(ctx context.Context, c *Client, read StackFileWants) (string, error) {
	cur, err := GetFirewallDefault(ctx, c, "cluster")
	if err != nil || cur == nil || !cur.DefaultDeny || cur.StackName == "" {
		return "", err
	}
	st, err := GetStack(ctx, c, cur.StackName)
	if err != nil || st == nil || st.State == "deleting" {
		return "", err
	}
	wants, unreadable, err := otherStackWants(ctx, c, "", read)
	if err != nil || len(unreadable) > 0 {
		return "", err
	}
	for _, w := range wants {
		if w.defaultDeny {
			return "", nil
		}
	}
	return cur.StackName, nil
}

// ── Stack teardown ───────────────────────────────────────────────────────────

// DeleteStackFirewall tombstones every firewall row a compose stack created:
// its security groups (+ their rules), ip sets, cluster/host tier rules, and
// any default-deny policy it set. Called from `compose down`.
func DeleteStackFirewall(ctx context.Context, c *Client, stack string, read StackFileWants) error {
	if err := DeleteStackFirewallRows(ctx, c, stack); err != nil {
		return err
	}
	return DeleteStackFirewallDefaults(ctx, c, stack, read)
}

// DeleteStackFirewallDefaults tombstones the firewall_defaults rows a stack
// set (its default-deny). A redeploy calls it only once the new config's rows
// are written, and only when the new config drops default-deny, so a
// redeploy that fails part way never leaves the cluster default-allow
// (switch re-review 2, R1).
//
// The cluster default is one row, owned by the stack that set it; another
// stack asking for deny while it is in force leaves it as it is. So when
// another live stack's file asks for default-deny, the row is handed to that
// stack (the first by name) rather than removed, and while any live stack's
// file cannot be read the row is kept: it may ask for deny, and a deny
// removed in error fails the cluster open.
func DeleteStackFirewallDefaults(ctx context.Context, c *Client, stack string, read StackFileWants) error {
	if stack == "" {
		return nil
	}
	cur, err := GetFirewallDefault(ctx, c, "cluster")
	if err != nil {
		return err
	}
	if cur != nil && cur.DefaultDeny && cur.StackName == stack {
		others, unreadable, err := otherStackWants(ctx, c, stack, read)
		if err != nil {
			return err
		}
		var heirs []string
		for _, o := range others {
			if o.defaultDeny {
				heirs = append(heirs, o.name)
			}
		}
		handed, err := handOff(ctx, c, stack, heirs, func(owner string) error {
			return SetFirewallDefault(ctx, c, "cluster", true, owner)
		}, standingDenyAsk)
		if err != nil {
			return err
		}
		if !handed && len(unreadable) > 0 {
			warnOnChange("default-deny/"+stack, strings.Join(unreadable, ","),
				"stack teardown: the cluster default-deny stays, owned by the stack: the compose files of other stacks cannot be read, and one may ask for it",
				"stack", stack, "unreadable", unreadable)
			return nil
		}
	}
	now := c.NowTS()
	wall := nowRFC3339()
	return tombStackRows(ctx, c, stack, `SELECT scope AS pk FROM firewall_defaults WHERE stack_name = ? AND deleted_at IS NULL`,
		func(pk string) error {
			return c.Execute(ctx, `UPDATE firewall_defaults SET deleted_at = ?, updated_at = ? WHERE scope = ? AND deleted_at IS NULL`, wall, now, pk)
		})
}

// tombStackRows runs exec for the primary key of every row sel (one ?, the
// stack) selects locally. Each replicating Execute carries its statement as a
// LITERAL constant in exec, so the ledger/CI guard can resolve it; the local
// SELECT is not replicated, so its SQL may vary.
func tombStackRows(ctx context.Context, c *Client, stack, sel string, exec func(pk string) error) error {
	rows, err := c.Query(ctx, sel, stack)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := exec(row.String("pk")); err != nil {
			return err
		}
	}
	return nil
}

// DeleteStackFirewallRows tombstones a stack's firewall rows but not its
// firewall_defaults row (DeleteStackFirewallDefaults): its security groups
// (+ their rules), ip sets, and cluster/host tier rules.
func DeleteStackFirewallRows(ctx context.Context, c *Client, stack string) error {
	if stack == "" {
		return nil
	}
	// Security groups + their rules.
	sgs, err := ListSecurityGroups(ctx, c, stack)
	if err != nil {
		return err
	}
	for _, sg := range sgs {
		if err := DeleteSGRules(ctx, c, sg.ID); err != nil {
			return err
		}
		if err := DeleteSecurityGroup(ctx, c, sg.ID); err != nil {
			return err
		}
	}
	// Row-scope the tombstones: a single bulk `UPDATE … WHERE stack_name = ?` is not full-PK,
	// so on the replication apply path it can't be LWW-gated per row (a concurrently-newer
	// row on a peer would be wrongly tombstoned). Enumerate the matching rows locally, then
	// emit one full-PK, LWW-gated tombstone per row. Each replicating Execute carries its
	// statement as a LITERAL constant (via forEachStackRow's callback) so the ledger/CI guard
	// can resolve it; the local SELECT is not replicated, so its SQL may vary.
	now := c.NowTS()
	wall := nowRFC3339()
	tomb := func(sel string, exec func(pk string) error) error {
		rows, err := c.Query(ctx, sel, stack)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if err := exec(row.String("pk")); err != nil {
				return err
			}
		}
		return nil
	}
	if err := tomb(`SELECT id AS pk FROM ip_sets WHERE stack_name = ? AND deleted_at IS NULL`,
		func(pk string) error {
			return c.Execute(ctx, `UPDATE ip_sets SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, wall, now, pk)
		}); err != nil {
		return err
	}
	if err := tomb(`SELECT id AS pk FROM cluster_firewall_rules WHERE stack_name = ? AND deleted_at IS NULL`,
		func(pk string) error {
			return c.Execute(ctx, `UPDATE cluster_firewall_rules SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, wall, now, pk)
		}); err != nil {
		return err
	}
	if err := tomb(`SELECT id AS pk FROM host_firewall_rules WHERE stack_name = ? AND deleted_at IS NULL`,
		func(pk string) error {
			return c.Execute(ctx, `UPDATE host_firewall_rules SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, wall, now, pk)
		}); err != nil {
		return err
	}
	return nil
}
