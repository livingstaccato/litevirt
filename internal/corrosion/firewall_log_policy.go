package corrosion

// The firewall log policy (docs/firewall.md, "Logging"): whether each guest
// NIC's default verdict is logged, and the per-NIC-side log budget every
// logged line of that NIC side shares. Two cluster_policies keys:
// firewall_log (the cluster's) and firewall_log/<host> (one host's override).
// The value is JSON {"default":"on"|"off","rate":N,"burst":N}; "" is no row,
// since the table has no delete statement. A host row wins over the cluster
// row; with neither, the default verdict is not logged and the budget is the
// default (L-7). Written through clusterPolicyUpsertSQL behind the
// failover_scope_v1 gate, with the firewall_log grant.
//
// The scope is a host name, or "" for the cluster: no host name can collide
// with the cluster's key, a host named "cluster" included.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

const (
	// LogPolicyScopeCluster names the cluster's row in a resolved policy's
	// Scope.
	LogPolicyScopeCluster = "cluster"

	// LogPolicyOn and LogPolicyOff say whether the default verdict is logged.
	LogPolicyOn  = "on"
	LogPolicyOff = "off"

	// LogPolicyDefaultRate (records per second) and LogPolicyDefaultBurst
	// (packets) are the per-NIC-side budget with no policy
	// (firewall.DefaultLogRate, firewall.DefaultLogBurst).
	LogPolicyDefaultRate  = 5
	LogPolicyDefaultBurst = 10

	// LogPolicyMin and LogPolicyMax bound the rate and the burst
	// (firewall.MaxLogRate, firewall.MaxLogBurst): the renderer renders no
	// budget outside them.
	LogPolicyMin = 1
	LogPolicyMax = 10000
)

// FirewallLogPolicy is a log policy. Default "" is no policy (inherit).
type FirewallLogPolicy struct {
	Default string `json:"default"`
	Rate    int    `json:"rate"`
	Burst   int    `json:"burst"`
	// Scope is the scope whose row decided a resolved policy:
	// LogPolicyScopeCluster, a host name, or "" when no row did. Not stored.
	Scope string `json:"-"`
}

// On reports whether the policy logs the default verdict.
func (p FirewallLogPolicy) On() bool { return p.Default == LogPolicyOn }

func logPolicyOff(scope string) FirewallLogPolicy {
	return FirewallLogPolicy{Default: LogPolicyOff, Rate: LogPolicyDefaultRate, Burst: LogPolicyDefaultBurst, Scope: scope}
}

func logBudgetInRange(n int) bool { return n >= LogPolicyMin && n <= LogPolicyMax }

// validate refuses a policy the renderer could not render.
func (p FirewallLogPolicy) validate() error {
	switch p.Default {
	case LogPolicyOn, LogPolicyOff:
		if !logBudgetInRange(p.Rate) || !logBudgetInRange(p.Burst) {
			return fmt.Errorf("log rate %d and burst %d must each be %d-%d", p.Rate, p.Burst, LogPolicyMin, LogPolicyMax)
		}
	case "":
		if p.Rate != 0 || p.Burst != 0 {
			return fmt.Errorf("an inherited log policy carries no rate or burst")
		}
	default:
		return fmt.Errorf("log policy default %q: want %s or %s", p.Default, LogPolicyOn, LogPolicyOff)
	}
	return nil
}

// FirewallLogPolicyKey is the cluster_policies key of host's policy, or of
// the cluster's when host is "".
func FirewallLogPolicyKey(host string) string {
	if host == "" {
		return clusterPolicyFirewallLog
	}
	return clusterPolicyFirewallLog + "/" + host
}

func logPolicyScope(host string) string {
	if host == "" {
		return LogPolicyScopeCluster
	}
	return host
}

// SetFirewallLogPolicy writes host's policy ("" is the cluster's); a policy
// with Default "" writes "", clearing a host's row (the cluster's cannot be
// cleared). It takes the firewall_log grant and refuses with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched. The caller
// owns the operator-facing preconditions (role, a known host).
func SetFirewallLogPolicy(ctx context.Context, c *Client, g capabilities.FeatureGrant, host string, p FirewallLogPolicy, setBy string) error {
	if err := g.Check(capabilities.FeatureFirewallLog); err != nil {
		return err
	}
	if strings.Contains(host, "/") {
		return fmt.Errorf("log policy scope %q: want a host name", host)
	}
	if host == "" && p.Default == "" {
		return fmt.Errorf("the cluster log policy cannot inherit: set it on or off")
	}
	if err := p.validate(); err != nil {
		return err
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	v := ""
	if p.Default != "" {
		b, err := json.Marshal(FirewallLogPolicy{Default: p.Default, Rate: p.Rate, Burst: p.Burst})
		if err != nil {
			return err
		}
		v = string(b)
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, FirewallLogPolicyKey(host), v, setBy, c.NowTS())
}

// LogPolicyRow is one scope's stored log policy row, for status.
type LogPolicyRow struct {
	Policy    FirewallLogPolicy
	SetBy     string
	UpdatedAt string
}

// GetFirewallLogPolicy reads host's own policy ("" is the cluster's) from
// this node's replica. recorded is false for no row or "". A row this build
// cannot read returns off at the default budget, recorded, and
// ErrUnreadableFirewallPolicy naming the key.
func GetFirewallLogPolicy(ctx context.Context, c *Client, host string) (p FirewallLogPolicy, recorded bool, err error) {
	row, recorded, err := GetFirewallLogPolicyRow(ctx, c, host)
	return row.Policy, recorded, err
}

// GetFirewallLogPolicyRow is GetFirewallLogPolicy with who set the row and
// when.
func GetFirewallLogPolicyRow(ctx context.Context, c *Client, host string) (LogPolicyRow, bool, error) {
	key := FirewallLogPolicyKey(host)
	rows, err := c.Query(ctx,
		`SELECT value, COALESCE(set_by, '') AS set_by, COALESCE(updated_at, '') AS updated_at
		 FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, key)
	if err != nil {
		return LogPolicyRow{}, false, err
	}
	if len(rows) == 0 || rows[0].String("value") == "" {
		return LogPolicyRow{}, false, nil
	}
	out := LogPolicyRow{SetBy: rows[0].String("set_by"), UpdatedAt: rows[0].String("updated_at")}
	raw := rows[0].String("value")
	var p FirewallLogPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil || p.Default == "" || p.validate() != nil {
		out.Policy = logPolicyOff(logPolicyScope(host))
		return out, true, fmt.Errorf("%w: %s holds %q", ErrUnreadableFirewallPolicy, key, raw)
	}
	p.Scope = logPolicyScope(host)
	out.Policy = p
	return out, true, nil
}

// ResolveFirewallLogPolicy is host's policy: its own row, else the cluster's,
// else off at the default budget. An unreadable row decides as off at the
// default budget, with ErrUnreadableFirewallPolicy; a host's unreadable row
// does not fall through to the cluster's.
func ResolveFirewallLogPolicy(ctx context.Context, c *Client, host string) (FirewallLogPolicy, error) {
	if host != "" {
		p, recorded, err := GetFirewallLogPolicy(ctx, c, host)
		if recorded || (err != nil && !errors.Is(err, ErrUnreadableFirewallPolicy)) {
			return p, err
		}
	}
	p, recorded, err := GetFirewallLogPolicy(ctx, c, "")
	if recorded || err != nil {
		return p, err
	}
	return logPolicyOff(""), nil
}
