package corrosion

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// SecurityGroup represents a security group.
type SecurityGroup struct {
	ID        string
	Name      string
	StackName string
	// Project owns the group; "" is a global group
	// (docs/design/security-group-projects.md).
	Project   string
	CreatedAt string
	UpdatedAt string
}

// SGRule represents a security group rule.
type SGRule struct {
	ID        string
	SGID      string
	Direction string
	Proto     string
	PortRange string
	CIDR      string
	Action    string
	Priority  int
}

// InsertSecurityGroup creates a new GLOBAL security group, in the previous
// release's statement shape. A project's group is written by
// InsertProjectSecurityGroup.
func InsertSecurityGroup(ctx context.Context, c *Client, sg SecurityGroup) error {
	if sg.Project != "" {
		return errors.New("a project security group is written by InsertProjectSecurityGroup, through the release feature sg_projects")
	}
	now := c.NowTS()
	if sg.CreatedAt == "" {
		sg.CreatedAt = nowRFC3339() // created_at is wall/display, never the HLC key
	}
	return c.Execute(ctx,
		`INSERT INTO security_groups (id, name, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		sg.ID, sg.Name, sg.StackName, sg.CreatedAt, now,
	)
}

// InsertProjectSecurityGroup creates a security group owned by sg.Project
// (docs/design/security-group-projects.md). Its insert names the project
// column, which a previous-release peer cannot decode, so it is the release
// feature sg_projects: g must be that feature's grant.
func InsertProjectSecurityGroup(ctx context.Context, c *Client, g capabilities.FeatureGrant, sg SecurityGroup) error {
	if err := g.Check(capabilities.FeatureSGProjects); err != nil {
		return err
	}
	if sg.Project == "" {
		return errors.New("a project security group needs a project")
	}
	now := c.NowTS()
	if sg.CreatedAt == "" {
		sg.CreatedAt = nowRFC3339() // created_at is wall/display, never the HLC key
	}
	return c.Execute(ctx,
		`INSERT INTO security_groups (id, name, stack_name, project, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sg.ID, sg.Name, sg.StackName, sg.Project, sg.CreatedAt, now,
	)
}

// GetSecurityGroup returns a security group by ID.
func GetSecurityGroup(ctx context.Context, c *Client, id string) (*SecurityGroup, error) {
	rows, err := c.Query(ctx,
		`SELECT id, name, stack_name, project, created_at, updated_at
		 FROM security_groups WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &SecurityGroup{
		ID:        r.String("id"),
		Name:      r.String("name"),
		StackName: r.String("stack_name"),
		Project:   r.String("project"),
		CreatedAt: r.String("created_at"),
		UpdatedAt: r.String("updated_at"),
	}, nil
}

// ListSecurityGroups returns all security groups, optionally filtered by stack.
func ListSecurityGroups(ctx context.Context, c *Client, stackName string) ([]SecurityGroup, error) {
	sql := `SELECT id, name, stack_name, project, created_at, updated_at
		FROM security_groups WHERE deleted_at IS NULL`
	var params []interface{}
	if stackName != "" {
		sql += " AND stack_name = ?"
		params = append(params, stackName)
	}
	// Stable order so the firewall renderer produces byte-identical output for
	// unchanged state (the applier's cache short-circuit relies on this).
	sql += " ORDER BY name, id"

	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}

	sgs := make([]SecurityGroup, len(rows))
	for i, r := range rows {
		sgs[i] = SecurityGroup{
			ID:        r.String("id"),
			Name:      r.String("name"),
			StackName: r.String("stack_name"),
			Project:   r.String("project"),
			CreatedAt: r.String("created_at"),
			UpdatedAt: r.String("updated_at"),
		}
	}
	return sgs, nil
}

// DeleteSecurityGroup tombstones a security group.
func DeleteSecurityGroup(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE security_groups SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		nowRFC3339(), now, id,
	)
}

// InsertSGRule adds an IPv4 rule to a security group; one that needs a release
// feature needs InsertSGRuleWithGrant.
func InsertSGRule(ctx context.Context, c *Client, rule SGRule) error {
	return InsertSGRuleWithGrant(ctx, c, capabilities.FeatureGrant{}, capabilities.FeatureGrant{}, capabilities.FeatureGrant{}, rule)
}

// InsertSGRuleWithGrant adds a rule to a security group. An IPv6 rule renders
// as ip6 on this build, but a peer on an older build refuses its whole plan
// on one, so it is the release feature firewall_ipv6; a logged rule is
// firewall_log and one matching a tag group firewall_tag_groups, for the same
// reason. g, gLog and gTag must be their grants (FirewallRowFeatures). A
// malformed one is never written.
func InsertSGRuleWithGrant(ctx context.Context, c *Client, g, gLog, gTag capabilities.FeatureGrant, rule SGRule) error {
	// proto, port and cidr are written into every host's nft script as text.
	rule.Proto, rule.PortRange, rule.Action = rulefield.NormaliseRule(rule.Proto, rule.PortRange, rule.Action)
	if err := rulefield.StoredRule(rule.Direction, rule.Proto, rule.PortRange, rule.CIDR, rule.Action, ""); err != nil {
		return err
	}
	need, err := firewallRowFeatures(rule.CIDR, rule.Proto, rule.Action)
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
	now := c.NowTS()
	proto := rule.Proto
	if proto == "" {
		proto = "all"
	}
	action := rule.Action
	if action == "" {
		action = "accept"
	}
	priority := rule.Priority
	if priority == 0 {
		priority = 100
	}
	return c.Execute(ctx,
		`INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.SGID, rule.Direction, proto, rule.PortRange, rule.CIDR,
		action, priority, nowRFC3339(), now,
	)
}

// isIPv6CIDR reports whether s is an IPv6 address or CIDR. An empty string
// (any-source) and IPv4 values return false.
func isIPv6CIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.To4() == nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() == nil
	}
	return false // not an IP/CIDR at all — leave other validation to the caller
}

// ListSGRules returns all rules for a security group.
func ListSGRules(ctx context.Context, c *Client, sgID string) ([]SGRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, sg_id, direction, proto, port_range, cidr, action, priority
		 FROM sg_rules WHERE sg_id = ? AND deleted_at IS NULL
		 ORDER BY priority, id`, sgID)
	if err != nil {
		return nil, err
	}

	rules := make([]SGRule, len(rows))
	for i, r := range rows {
		rules[i] = SGRule{
			ID:        r.String("id"),
			SGID:      r.String("sg_id"),
			Direction: r.String("direction"),
			Proto:     r.String("proto"),
			PortRange: r.String("port_range"),
			CIDR:      r.String("cidr"),
			Action:    r.String("action"),
			Priority:  r.Int("priority"),
		}
	}
	return rules, nil
}

// ListAllSGRules returns every live security-group rule, whatever group (or
// legacy name) its sg_id names.
func ListAllSGRules(ctx context.Context, c *Client) ([]SGRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, sg_id, direction, proto, port_range, cidr, action, priority
		 FROM sg_rules WHERE deleted_at IS NULL ORDER BY sg_id, priority, id`)
	if err != nil {
		return nil, err
	}
	rules := make([]SGRule, len(rows))
	for i, r := range rows {
		rules[i] = SGRule{
			ID:        r.String("id"),
			SGID:      r.String("sg_id"),
			Direction: r.String("direction"),
			Proto:     r.String("proto"),
			PortRange: r.String("port_range"),
			CIDR:      r.String("cidr"),
			Action:    r.String("action"),
			Priority:  r.Int("priority"),
		}
	}
	return rules, nil
}

// DeleteSGRules tombstones all rules for a security group.
func DeleteSGRules(ctx context.Context, c *Client, sgID string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE sg_rules SET deleted_at = ?, updated_at = ? WHERE sg_id = ?`,
		nowRFC3339(), now, sgID,
	)
}

// DeleteSGRule tombstones a single rule by its id.
func DeleteSGRule(ctx context.Context, c *Client, ruleID string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE sg_rules SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		nowRFC3339(), now, ruleID,
	)
}

// WorkloadProjects returns the project of every live VM, and of every live
// container on hostName, keyed by name ("" is the default project). The
// firewall reconciler reads it to keep a NIC off another project's security
// group.
func WorkloadProjects(ctx context.Context, c *Client, hostName string) (vms, cts map[string]string, err error) {
	rows, err := c.Query(ctx, `SELECT name, COALESCE(project, '') AS project FROM vms WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, nil, err
	}
	vms = make(map[string]string, len(rows))
	for _, r := range rows {
		vms[r.String("name")] = r.String("project")
	}
	rows, err = c.Query(ctx, `SELECT name, COALESCE(project, '') AS project FROM containers
		WHERE host_name = ? AND deleted_at IS NULL`, hostName)
	if err != nil {
		return nil, nil, err
	}
	cts = make(map[string]string, len(rows))
	for _, r := range rows {
		cts[r.String("name")] = r.String("project")
	}
	return vms, cts, nil
}

// StackOwnsFirewall reports whether stack owns any live firewall row: a
// security group, an ip set, a cluster or host rule, or a firewall default.
// Removing or replacing them is a write to global firewall state.
func StackOwnsFirewall(ctx context.Context, c *Client, stack string) (bool, error) {
	if stack == "" {
		return false, nil
	}
	for _, table := range []string{"security_groups", "ip_sets", "cluster_firewall_rules", "host_firewall_rules", "firewall_defaults"} {
		rows, err := c.Query(ctx, `SELECT 1 FROM `+table+` WHERE stack_name = ? AND deleted_at IS NULL LIMIT 1`, stack)
		if err != nil {
			return false, err
		}
		if len(rows) > 0 {
			return true, nil
		}
	}
	return false, nil
}
