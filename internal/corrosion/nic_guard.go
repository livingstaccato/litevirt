package corrosion

// Per-NIC anti-spoofing policy (the "NIC guard", docs/firewall.md).
//
// One record per VM NIC, keyed nic_guard/<vm>/<mac>, in cluster_policies and
// written through its one upsert (clusterPolicyUpsertSQL) — so behind the
// failover_scope_v1 gate, and with no new table and no new statement shape. A
// peer on any build that carries cluster_policies decodes the record and,
// before this feature, ignores it: the NIC is then simply unguarded on that
// peer, which is what every NIC was before.
//
// NO RECORD MEANS UNGUARDED. Every NIC that existed before guards did has no
// record, and must keep working exactly as it did — a guest may be using an
// address litevirt never assigned (a VIP, a VRRP address, a static secondary
// IP). A NIC created or hot-attached by this build gets a record, "on" unless
// the request said otherwise, so guarding is the default for new NICs only.
//
// cluster_policies has no statement that deletes a row, so a record outlives
// its VM. That is harmless: a NIC created under the same VM name and MAC
// writes a fresh record before it is ever rendered.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

const (
	nicGuardKeyPrefix = "nic_guard/"

	// NICGuardOn guards the NIC.
	NICGuardOn = "on"
	// NICGuardOff records an explicit decision not to guard the NIC.
	NICGuardOff = "off"

	// MaxNICGuardAddresses bounds the allowed list of one NIC, so one record
	// cannot bloat every host's ruleset.
	MaxNICGuardAddresses = 64
)

// ErrUnknownNICGuardMode is a mode this build does not implement.
var ErrUnknownNICGuardMode = errors.New("unknown NIC guard mode")

// NICGuardRecord is one NIC's guard policy as replicated.
type NICGuardRecord struct {
	VMName string `json:"-"`
	MAC    string `json:"-"`

	// Mode is NICGuardOn or NICGuardOff.
	Mode string `json:"mode"`
	// Allowed are the extra source addresses or prefixes, beyond the ones
	// litevirt assigned, the guest may send from: a VIP, a VRRP address, a
	// static secondary address, a routed prefix behind the guest.
	Allowed []string `json:"allowed,omitempty"`
	// Known are addresses litevirt assigned to the NIC that its NIC row does
	// not carry (a static IPv6 address from the VM spec).
	Known []string `json:"known,omitempty"`
	// AllowDHCPServer lets the guest answer DHCP (v4 and v6).
	AllowDHCPServer bool `json:"allow_dhcp_server,omitempty"`
	// AllowRouterAdvert lets the guest send router advertisements and
	// redirects.
	AllowRouterAdvert bool `json:"allow_router_advert,omitempty"`

	SetBy     string `json:"-"`
	UpdatedAt string `json:"-"`
}

// Guarded reports whether the record turns the guard on.
func (r NICGuardRecord) Guarded() bool { return r.Mode == NICGuardOn }

// AuditText renders the record for an audit row: every field that decides
// what the guard lets the NIC send.
func (r NICGuardRecord) AuditText() string {
	return fmt.Sprintf("{mode=%s allowed=[%s] dhcp-server=%t router-advert=%t}",
		r.Mode, strings.Join(r.Allowed, ","), r.AllowDHCPServer, r.AllowRouterAdvert)
}

// NICGuardKey is the cluster_policies key of a NIC's record.
func NICGuardKey(vm, mac string) string {
	return nicGuardKeyPrefix + vm + "/" + strings.ToLower(mac)
}

// NormalizeNICGuardAddresses validates an allowed/known list and returns it in
// canonical form (masked prefixes, canonical addresses, sorted, deduplicated).
// An entry that is not an IP address or prefix, carries a zone, or exceeds
// MaxNICGuardAddresses is refused: it would otherwise reach every host's
// renderer, which refuses the whole ruleset on one.
func NormalizeNICGuardAddresses(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		var canon string
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Zone() == "" {
			canon = p.Masked().String()
		} else if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
			canon = a.String()
		} else {
			return nil, fmt.Errorf("%q is not an IP address or prefix", raw)
		}
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	if len(out) > MaxNICGuardAddresses {
		return nil, fmt.Errorf("%d addresses; at most %d per NIC", len(out), MaxNICGuardAddresses)
	}
	sort.Strings(out)
	return out, nil
}

// normalizeNICGuard checks and canonicalises a record before it is written.
func normalizeNICGuard(r *NICGuardRecord) error {
	if r.VMName == "" || strings.Contains(r.VMName, "/") {
		return fmt.Errorf("invalid VM name %q", r.VMName)
	}
	hw, err := net.ParseMAC(r.MAC)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("invalid NIC MAC %q", r.MAC)
	}
	r.MAC = hw.String()
	switch r.Mode {
	case NICGuardOn, NICGuardOff:
	default:
		return fmt.Errorf("%w %q (valid: %s, %s)", ErrUnknownNICGuardMode, r.Mode, NICGuardOn, NICGuardOff)
	}
	if r.Allowed, err = NormalizeNICGuardAddresses(r.Allowed); err != nil {
		return fmt.Errorf("allowed addresses: %w", err)
	}
	if r.Known, err = NormalizeNICGuardAddresses(r.Known); err != nil {
		return fmt.Errorf("known addresses: %w", err)
	}
	return nil
}

// PutNICGuard writes a NIC's guard record. It refuses with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched.
func PutNICGuard(ctx context.Context, c *Client, r NICGuardRecord, setBy string) error {
	if err := normalizeNICGuard(&r); err != nil {
		return err
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, NICGuardKey(r.VMName, r.MAC), string(b), setBy, c.NowTS())
}

// GetNICGuard returns a NIC's record, or nil when it has none (unguarded).
func GetNICGuard(ctx context.Context, c *Client, vm, mac string) (*NICGuardRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		NICGuardKey(vm, mac))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rec, ok := decodeNICGuard(rows[0])
	if !ok {
		return nil, nil
	}
	return &rec, nil
}

// ListNICGuards returns every NIC guard record, keyed by NICGuardKey. A record
// that does not decode, or holds a mode this build does not implement (a later
// release's), is left out: its NIC is unguarded here, as it was before.
func ListNICGuards(ctx context.Context, c *Client) (map[string]NICGuardRecord, error) {
	lo, hi := keyRange(nicGuardKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies
		 WHERE key >= ? AND key < ? AND deleted_at IS NULL ORDER BY key`, lo, hi)
	if err != nil {
		return nil, err
	}
	out := make(map[string]NICGuardRecord, len(rows))
	for _, r := range rows {
		if rec, ok := decodeNICGuard(r); ok {
			out[NICGuardKey(rec.VMName, rec.MAC)] = rec
		}
	}
	return out, nil
}

func decodeNICGuard(r Row) (NICGuardRecord, bool) {
	rest := strings.TrimPrefix(r.String("key"), nicGuardKeyPrefix)
	i := strings.LastIndex(rest, "/")
	if i <= 0 {
		return NICGuardRecord{}, false
	}
	var rec NICGuardRecord
	if json.Unmarshal([]byte(r.String("value")), &rec) != nil {
		return NICGuardRecord{}, false
	}
	if rec.Mode != NICGuardOn && rec.Mode != NICGuardOff {
		return NICGuardRecord{}, false
	}
	rec.VMName, rec.MAC = rest[:i], rest[i+1:]
	rec.SetBy, rec.UpdatedAt = r.String("set_by"), r.String("updated_at")
	return rec, true
}

// NetworkSubnets maps every live network to its declared subnet ("" when it
// declares none). networks.config is json.Marshal of compose.NetworkDef, whose
// field is "Subnet"; encoding/json matches it case-insensitively.
func NetworkSubnets(ctx context.Context, c *Client) (map[string]string, error) {
	rows, err := c.Query(ctx, `SELECT name, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		var def struct{ Subnet string }
		_ = json.Unmarshal([]byte(r.String("config")), &def)
		out[r.String("name")] = def.Subnet
	}
	return out, nil
}
