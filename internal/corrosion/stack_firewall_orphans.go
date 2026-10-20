package corrosion

import (
	"context"
	"sort"
)

// TornDownStacksOwningFirewall lists the stacks whose record is tombstoned
// while this replica holds a live security group, ip set, or cluster or host
// rule the stack owns, written before the tombstone: a teardown left it, one
// begun on a node it had not reached. A row written after the tombstone is a
// new deploy of the name in progress (a deploy writes its rows before its
// record), and is not counted. A cluster default-deny such a stack owns is
// firewall.default_deny_orphaned's (SweepOrphanStackRows).
func TornDownStacksOwningFirewall(ctx context.Context, c *Client) ([]string, error) {
	rows, err := c.Query(ctx, `SELECT name, updated_at FROM stacks WHERE deleted_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	tomb := make(map[string]string, len(rows))
	for _, r := range rows {
		tomb[r.String("name")] = r.String("updated_at")
	}
	found := map[string]bool{}
	for _, table := range []string{"security_groups", "ip_sets", "cluster_firewall_rules", "host_firewall_rules"} {
		rows, err := c.Query(ctx, `SELECT stack_name, updated_at FROM `+table+
			` WHERE deleted_at IS NULL AND stack_name IS NOT NULL AND stack_name != ''`)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			stack := r.String("stack_name")
			if at, ok := tomb[stack]; ok && lwwOrder(r.String("updated_at"), at) < 0 {
				found[stack] = true
			}
		}
	}
	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}
