package corrosion

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// SecurityGroup represents a security group.
type SecurityGroup struct {
	ID        string
	Name      string
	StackName string
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

// InsertSecurityGroup creates a new security group.
func InsertSecurityGroup(ctx context.Context, c *Client, sg SecurityGroup) error {
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

// GetSecurityGroup returns a security group by ID.
func GetSecurityGroup(ctx context.Context, c *Client, id string) (*SecurityGroup, error) {
	rows, err := c.Query(ctx,
		`SELECT id, name, stack_name, created_at, updated_at
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
		CreatedAt: r.String("created_at"),
		UpdatedAt: r.String("updated_at"),
	}, nil
}

// ListSecurityGroups returns all security groups, optionally filtered by stack.
func ListSecurityGroups(ctx context.Context, c *Client, stackName string) ([]SecurityGroup, error) {
	sql := `SELECT id, name, stack_name, created_at, updated_at
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

// InsertSGRule adds a rule to a security group.
func InsertSGRule(ctx context.Context, c *Client, rule SGRule) error {
	// F10: the firewall renderer only emits ipv4_addr sets, so an IPv6 CIDR
	// would be silently dropped — the operator would believe IPv6 is filtered
	// when it isn't. Reject it explicitly until ip6 rendering lands.
	if isIPv6CIDR(rule.CIDR) {
		return fmt.Errorf("IPv6 CIDR %q is not supported in security-group rules yet (only IPv4 is enforced); specify an IPv4 CIDR", rule.CIDR)
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

// ListSGRulesFor returns the rules of sg: those stored under its id, plus,
// when legacyByName is true, those an older client stored with the group's NAME
// in sg_id (`lv sg rule-add <name>` used to store the argument verbatim, so such
// a rule never applied). Resolving them here, on read, is the whole repair —
// nothing is rewritten. The caller passes legacyByName only when no other live
// group holds the name: with two holders it is not in the data which group the
// rule meant, so it stays unapplied rather than landing on a guess. Every
// returned rule carries sg.ID in SGID, so callers filtering by group id see it.
func ListSGRulesFor(ctx context.Context, c *Client, sg SecurityGroup, legacyByName bool) ([]SGRule, error) {
	rules, err := ListSGRules(ctx, c, sg.ID)
	if err != nil || !legacyByName || sg.Name == "" || sg.Name == sg.ID {
		return rules, err
	}
	legacy, err := ListSGRules(ctx, c, sg.Name)
	if err != nil {
		return nil, err
	}
	for i := range legacy {
		legacy[i].SGID = sg.ID
	}
	rules = append(rules, legacy...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
	return rules, nil
}

// DeleteLegacyNameRules tombstones the rules an older client stored with sg's
// NAME in sg_id. They go with the group whether or not they were being applied:
// a rule that was unattributable while two groups shared the name must not
// become the survivor's the moment the other is deleted, and one that applied
// must not attach to a later group of the same name. Fail closed.
func DeleteLegacyNameRules(ctx context.Context, c *Client, sg SecurityGroup) error {
	if sg.Name == "" || sg.Name == sg.ID {
		return nil
	}
	return DeleteSGRules(ctx, c, sg.Name)
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
