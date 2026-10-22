package corrosion

// SYN-flood protection on guest NICs (docs/firewall.md, "SYN-flood
// protection"): the release feature firewall_synflood
// (capabilities.FeatureFirewallSynflood).
//
// The policy is two cluster_policies keys: firewall_synflood (the cluster's)
// and firewall_synflood/<host> (one host's override). The value is JSON
// {"mode":"on"|"off","rate":N,"burst":N}; "" is no row, since the table has no
// delete statement. A host row wins over the cluster row; with neither,
// protection is off. Written through clusterPolicyUpsertSQL behind the
// failover_scope_v1 gate, with the feature's grant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

const (
	clusterPolicyFirewallSynflood = "firewall_synflood"

	// FirewallSynfloodScopeCluster names the cluster-wide scope in the API.
	// In this package the cluster is host "": a host may be named "cluster".
	FirewallSynfloodScopeCluster = "cluster"

	// SynfloodOn and SynfloodOff are the policy's modes.
	SynfloodOn  = "on"
	SynfloodOff = "off"

	// SynfloodDefaultRate (new SYNs per second per guest NIC and source
	// address) and SynfloodDefaultBurst (packets) are Proxmox's defaults.
	SynfloodDefaultRate  = 200
	SynfloodDefaultBurst = 1000

	// SynfloodMin and SynfloodMax bound the rate and the burst.
	SynfloodMin = 1
	SynfloodMax = 100000
)

// ErrUnreadableFirewallPolicy is returned with a firewall policy row this
// build cannot read: a value that is not JSON, a mode it does not know, or a
// rate or burst out of range. The policy then reads as on at the defaults.
var ErrUnreadableFirewallPolicy = errors.New("unreadable firewall policy")

// FirewallSynflood is a SYN-flood policy. Mode "" is no policy (inherit).
type FirewallSynflood struct {
	Mode  string `json:"mode"`
	Rate  int    `json:"rate"`
	Burst int    `json:"burst"`
	// Not stored: where a read policy came from. Recorded is whether a row
	// decided; Host is the host whose own row did ("" for the cluster's
	// row); SetBy and UpdatedAt are that row's.
	Recorded  bool   `json:"-"`
	Host      string `json:"-"`
	SetBy     string `json:"-"`
	UpdatedAt string `json:"-"`
}

// On reports whether the policy limits SYNs.
func (p FirewallSynflood) On() bool { return p.Mode == SynfloodOn }

func synfloodDefaultOn(host string) FirewallSynflood {
	return FirewallSynflood{Mode: SynfloodOn, Rate: SynfloodDefaultRate, Burst: SynfloodDefaultBurst, Recorded: true, Host: host}
}

func synfloodInRange(n int) bool { return n >= SynfloodMin && n <= SynfloodMax }

// validate refuses a policy the renderer could not render. Off may carry a
// rate and burst (kept for a later on) or none.
func (p FirewallSynflood) validate() error {
	switch p.Mode {
	case SynfloodOn:
		if !synfloodInRange(p.Rate) || !synfloodInRange(p.Burst) {
			return fmt.Errorf("SYN-flood rate %d and burst %d must each be %d-%d", p.Rate, p.Burst, SynfloodMin, SynfloodMax)
		}
	case SynfloodOff:
		if (p.Rate != 0 || p.Burst != 0) && (!synfloodInRange(p.Rate) || !synfloodInRange(p.Burst)) {
			return fmt.Errorf("SYN-flood rate %d and burst %d must each be %d-%d", p.Rate, p.Burst, SynfloodMin, SynfloodMax)
		}
	case "":
		if p.Rate != 0 || p.Burst != 0 {
			return fmt.Errorf("an inherited SYN-flood policy carries no rate or burst")
		}
	default:
		return fmt.Errorf("SYN-flood mode %q: want %s or %s", p.Mode, SynfloodOn, SynfloodOff)
	}
	return nil
}

// FirewallSynfloodKey is the cluster_policies key of host's policy, the
// cluster's for host "". No host name maps to the cluster's key.
func FirewallSynfloodKey(host string) string {
	if host == "" {
		return clusterPolicyFirewallSynflood
	}
	return clusterPolicyFirewallSynflood + "/" + host
}

// SetFirewallSynflood writes host's policy, the cluster's for host ""; a
// policy with Mode "" writes "", clearing it. It takes the firewall_synflood
// grant and refuses with ErrClusterPolicyGateClosed until failover_scope_v1
// has latched. The caller owns the operator-facing preconditions (role, a
// known host).
func SetFirewallSynflood(ctx context.Context, c *Client, g capabilities.FeatureGrant, host string, p FirewallSynflood, setBy string) error {
	if err := g.Check(capabilities.FeatureFirewallSynflood); err != nil {
		return err
	}
	if strings.Contains(host, "/") {
		return fmt.Errorf("SYN-flood host %q: a host name holds no /", host)
	}
	if err := p.validate(); err != nil {
		return err
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	v := ""
	if p.Mode != "" {
		b, err := json.Marshal(FirewallSynflood{Mode: p.Mode, Rate: p.Rate, Burst: p.Burst})
		if err != nil {
			return err
		}
		v = string(b)
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, FirewallSynfloodKey(host), v, setBy, c.NowTS())
}

// GetFirewallSynflood reads host's own policy (the cluster's for host "")
// from this node's replica. recorded is false for no row or "". A row this
// build cannot read returns on at the defaults, recorded, and
// ErrUnreadableFirewallPolicy naming the key.
func GetFirewallSynflood(ctx context.Context, c *Client, host string) (p FirewallSynflood, recorded bool, err error) {
	key := FirewallSynfloodKey(host)
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, key)
	if err != nil {
		return FirewallSynflood{}, false, err
	}
	if len(rows) == 0 || rows[0].String("value") == "" {
		return FirewallSynflood{}, false, nil
	}
	raw := rows[0].String("value")
	if err := json.Unmarshal([]byte(raw), &p); err != nil || p.Mode == "" || p.validate() != nil {
		p = synfloodDefaultOn(host)
		p.SetBy, p.UpdatedAt = rows[0].String("set_by"), rows[0].String("updated_at")
		return p, true, fmt.Errorf("%w: %s holds %q", ErrUnreadableFirewallPolicy, key, raw)
	}
	p.Recorded, p.Host = true, host
	p.SetBy, p.UpdatedAt = rows[0].String("set_by"), rows[0].String("updated_at")
	return p, true, nil
}

// ResolveFirewallSynflood is host's policy: its own row, else the cluster's,
// else off; host "" reads the cluster's alone. An unreadable row decides as
// on at the defaults, with ErrUnreadableFirewallPolicy; a host's unreadable
// row does not fall through to the cluster's.
func ResolveFirewallSynflood(ctx context.Context, c *Client, host string) (FirewallSynflood, error) {
	if host != "" {
		p, recorded, err := GetFirewallSynflood(ctx, c, host)
		if recorded || (err != nil && !errors.Is(err, ErrUnreadableFirewallPolicy)) {
			return p, err
		}
	}
	p, recorded, err := GetFirewallSynflood(ctx, c, "")
	if recorded || err != nil {
		return p, err
	}
	return FirewallSynflood{Mode: SynfloodOff}, nil
}

// seedFirewallSynfloodBeforeWrite runs between the seed's preconditions and
// its write (tests put an operator's row there).
var seedFirewallSynfloodBeforeWrite = func() {}

// SeedFirewallSynflood records SYN-flood protection on at the defaults as the
// cluster's policy, once, from the founder of a cluster this build created
// (DECISION S-1). It takes the firewall_synflood grant, so it runs only once
// release_2026_11_v1 has latched, and writes only while no cluster row is
// recorded (decided in the write's own transaction), the cluster_policies
// gate is open, and this replica has caught up with a peer or has nothing to
// catch up with (SeedFirewallEnforcement's guard: no host but hostName, or no
// gossip member and only hosts still joining). The row is stamped seedTS,
// before any real write, so any operator's write outranks it on every replica. It reports whether it
// wrote.
func SeedFirewallSynflood(ctx context.Context, c *Client, g capabilities.FeatureGrant, hostName string) (bool, error) {
	if err := g.Check(capabilities.FeatureFirewallSynflood); err != nil {
		return false, err
	}
	if !c.MayWriteClusterPolicy() {
		return false, nil
	}
	if caught, _ := c.ReplicaCaughtUp(); !caught {
		alone, err := soleOrOnlyJoiners(ctx, c, hostName)
		if err != nil {
			return false, err
		}
		if !alone {
			return false, nil
		}
	}
	v, err := json.Marshal(FirewallSynflood{Mode: SynfloodOn, Rate: SynfloodDefaultRate, Burst: SynfloodDefaultBurst})
	if err != nil {
		return false, err
	}
	seedFirewallSynfloodBeforeWrite()
	// Insert only if absent, decided inside the write's own transaction: an
	// operator's row that arrives between a separate check and the write
	// must never be overwritten by the 0001 seed stamp, even locally.
	return c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM cluster_policies WHERE key = ?`, FirewallSynfloodKey("")).Scan(&n); err != nil {
			return false, err
		}
		return n == 0, nil
	}, []Statement{{SQL: clusterPolicyUpsertSQL, Params: []interface{}{FirewallSynfloodKey(""), string(v), "litevirt (initial)", seedTS(FirewallEnforce)}}})
}
