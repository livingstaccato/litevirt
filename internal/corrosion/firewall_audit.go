package corrosion

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Audit renderings for firewall policy (colonelpanik/litevirt#182).
//
// A firewall audit row records the policy a mutation replaced and the policy it
// left, as `before=<state> after=<state>`. The "before" is the half that
// matters: a removed rule is tombstoned, so once it is gone the audit log is the
// only place that can still say which port the removal opened, and a row that
// records only "rule abc removed" proves a change and destroys the evidence of
// what it was.
//
// The states are:
//
//	{...}    a rule, ip set or group, every field that decides what it matches or does
//	none     a read that SUCCEEDED found no such row
//	unset    a default policy with no row for the scope (the scope inherits)
//	unknown  the read failed, so nothing is claimed about what was there
//
// "none" and "unknown" are kept apart on purpose. A failed read must not be
// recorded as absence: that would turn a lookup error into a signed statement
// that nothing was removed.

// Audit state words shared by every firewall audit row.
const (
	AuditStateNone  = "none"
	AuditStateUnset = "unset"
)

// AuditChange formats the detail of a firewall audit row.
func AuditChange(before, after string) string {
	return "before=" + before + " after=" + after
}

// AuditUnknown is the state recorded when the read that should have produced
// it failed.
func AuditUnknown(err error) string {
	return "unknown(" + err.Error() + ")"
}

// AuditText renders a cluster- or host-tier rule for an audit row.
func (r FirewallRule) AuditText() string {
	var b strings.Builder
	b.WriteByte('{')
	if r.HostName != "" {
		b.WriteString("host=" + r.HostName + " ")
	}
	b.WriteString(ruleCore(r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Priority))
	if r.Comment != "" {
		b.WriteString(" comment=" + strconv.Quote(r.Comment))
	}
	if r.StackName != "" {
		b.WriteString(" stack=" + r.StackName)
	}
	b.WriteByte('}')
	return b.String()
}

// AuditText renders a security-group rule for an audit row.
func (r SGRule) AuditText() string {
	return "{sg=" + r.SGID + " " + ruleCore(r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Priority) + "}"
}

// AuditText renders an ip set for an audit row.
func (s IPSet) AuditText() string {
	out := "{name=" + s.Name + " cidrs=[" + strings.Join(s.CIDRs, ",") + "]"
	if s.StackName != "" {
		out += " stack=" + s.StackName
	}
	return out + "}"
}

// AuditText renders a security group, with the rules that go with it, for an
// audit row.
func (g SecurityGroup) AuditText(rules []SGRule) string {
	out := "{name=" + g.Name
	if g.StackName != "" {
		out += " stack=" + g.StackName
	}
	texts := make([]string, len(rules))
	for i, r := range rules {
		texts[i] = r.AuditText()
	}
	return out + " rules=[" + strings.Join(texts, ",") + "]}"
}

// AuditSGList renders a NIC's security-group binding for an audit row.
func AuditSGList(sgs []string) string {
	return "[" + strings.Join(sgs, ",") + "]"
}

func ruleCore(direction, proto, port, cidr, action string, priority int) string {
	if port == "" {
		port = "any"
	}
	if cidr == "" {
		cidr = "any"
	}
	return fmt.Sprintf("%s %s port=%s cidr=%s %s priority=%d", direction, proto, port, cidr, action, priority)
}

// GetClusterFirewallRule returns one live cluster-tier rule, or nil if there is
// none with that id.
func GetClusterFirewallRule(ctx context.Context, c *Client, id string) (*FirewallRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, direction, proto, port_range, cidr, action, priority, COALESCE(comment,'') AS comment, stack_name
		 FROM cluster_firewall_rules WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &scanRules(rows, "")[0], nil
}

// GetHostFirewallRule returns one live host-tier rule, or nil if there is none
// with that id.
func GetHostFirewallRule(ctx context.Context, c *Client, id string) (*FirewallRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, host_name, direction, proto, port_range, cidr, action, priority, COALESCE(comment,'') AS comment, stack_name
		 FROM host_firewall_rules WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := scanRules(rows, rows[0].String("host_name"))[0]
	return &r, nil
}

// GetIPSet returns one live ip set, or nil if there is none with that id.
func GetIPSet(ctx context.Context, c *Client, id string) (*IPSet, error) {
	rows, err := c.Query(ctx,
		`SELECT id, name, COALESCE(cidrs, '[]') AS cidrs, stack_name
		 FROM ip_sets WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &IPSet{
		ID:        r.String("id"),
		Name:      r.String("name"),
		CIDRs:     decodeSGs(r.String("cidrs")),
		StackName: r.String("stack_name"),
	}, nil
}

// GetSGRule returns one live security-group rule, or nil if there is none with
// that id.
func GetSGRule(ctx context.Context, c *Client, id string) (*SGRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, sg_id, direction, proto, port_range, cidr, action, priority
		 FROM sg_rules WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &SGRule{
		ID:        r.String("id"),
		SGID:      r.String("sg_id"),
		Direction: r.String("direction"),
		Proto:     r.String("proto"),
		PortRange: r.String("port_range"),
		CIDR:      r.String("cidr"),
		Action:    r.String("action"),
		Priority:  r.Int("priority"),
	}, nil
}

// SGRuleAuditState is the audit state of one security-group rule, from the
// result of GetSGRule: the rule, none when a read that succeeded found no such
// rule, or unknown when the read failed. A failed read is never recorded as
// absence.
func SGRuleAuditState(rule *SGRule, err error) string {
	switch {
	case err != nil:
		return AuditUnknown(err)
	case rule == nil:
		return AuditStateNone
	}
	return rule.AuditText()
}

// SecurityGroupAuditState reads one security group, with its rules, and
// renders it as an audit state. The web UI and the gRPC handlers both call it,
// so a group removed either way leaves the same record.
func SecurityGroupAuditState(ctx context.Context, c *Client, id string) string {
	sg, err := GetSecurityGroup(ctx, c, id)
	if err != nil {
		return AuditUnknown(err)
	}
	if sg == nil {
		return AuditStateNone
	}
	rules, err := ListSGRules(ctx, c, id)
	if err != nil {
		return AuditUnknown(err)
	}
	// Rules stored under the group's name go with it on delete (see
	// DeleteLegacyNameRules), so the record of what it allowed includes them.
	if sg.Name != "" && sg.Name != id {
		legacy, lerr := ListSGRules(ctx, c, sg.Name)
		if lerr != nil {
			return AuditUnknown(lerr)
		}
		rules = append(rules, legacy...)
	}
	return sg.AuditText(rules)
}
