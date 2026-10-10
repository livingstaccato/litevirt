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

	"github.com/litevirt/litevirt/internal/compose"
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
	// AllowVLANTags lets the guest send 802.1Q / 802.1ad tagged frames (an
	// explicit trunk). Honoured whatever the mode: without it every NIC's
	// tagged frames are dropped, guarded or not.
	AllowVLANTags bool `json:"allow_vlan_tags,omitempty"`

	// The NIC the record was written for, beyond its key: the incarnation of
	// the VM (its spec uuid, minted fresh by every create), the network and
	// the NIC's position. A re-create (rebuild, rolling update) carries a
	// record only onto the same NIC of the incarnation it replaces.
	VMUUID  string `json:"vm_uuid,omitempty"`
	Network string `json:"network,omitempty"`
	Ordinal int    `json:"ordinal,omitempty"`

	// Deleted tombstones the record: the VM (or container) it was written for
	// is gone (DeleteNICGuardsOf). cluster_policies has no delete statement,
	// so a record is retired by rewriting it through the same upsert. Readers
	// skip it, except a re-create, which carries the guard state of the
	// incarnation it replaces (ListNICGuardsWithDeleted).
	Deleted bool `json:"deleted,omitempty"`

	SetBy     string `json:"-"`
	UpdatedAt string `json:"-"`
}

// Guarded reports whether the record turns the guard on.
func (r NICGuardRecord) Guarded() bool { return r.Mode == NICGuardOn }

// AuditText renders the record for an audit row: every field that decides
// what the guard lets the NIC send.
func (r NICGuardRecord) AuditText() string {
	return fmt.Sprintf("{mode=%s allowed=[%s] dhcp-server=%t router-advert=%t vlan-tags=%t}",
		r.Mode, strings.Join(r.Allowed, ","), r.AllowDHCPServer, r.AllowRouterAdvert, r.AllowVLANTags)
}

// NICGuardKey is the cluster_policies key of a VM NIC's record.
func NICGuardKey(vm, mac string) string {
	return nicGuardKeyPrefix + vm + "/" + strings.ToLower(mac)
}

// ContainerGuardOwner is the owner a container NIC's guard record is keyed by
// in place of a VM name: container names are per host, and ':' appears in no
// VM name, so the two can never collide.
func ContainerGuardOwner(host, ct string) string { return "ct:" + host + ":" + ct }

// ParseContainerGuardOwner splits a ContainerGuardOwner; ok is false for a VM
// name.
func ParseContainerGuardOwner(owner string) (host, ct string, ok bool) {
	rest, found := strings.CutPrefix(owner, "ct:")
	if !found {
		return "", "", false
	}
	i := strings.Index(rest, ":")
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
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
	if r.VMName == "" || strings.ContainsAny(r.VMName, "/ ") {
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
	if !ok || rec.Deleted {
		return nil, nil
	}
	return &rec, nil
}

// ListNICGuards returns every NIC guard record, keyed by NICGuardKey. A record
// that does not decode, or holds a mode this build does not implement (a later
// release's), is left out: its NIC is unguarded here, as it was before.
//
// A record tombstoned with its VM (Deleted) is left out too.
func ListNICGuards(ctx context.Context, c *Client) (map[string]NICGuardRecord, error) {
	all, err := ListNICGuardsWithDeleted(ctx, c)
	if err != nil {
		return nil, err
	}
	for k, r := range all {
		if r.Deleted {
			delete(all, k)
		}
	}
	return all, nil
}

// DeleteNICGuardsOf tombstones every guard record of owner (a VM name, or a
// ContainerGuardOwner), keeping what it held for a re-create of it to carry.
// Nothing is written before the cluster_policies gate opens.
func DeleteNICGuardsOf(ctx context.Context, c *Client, owner, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return nil
	}
	all, err := ListNICGuards(ctx, c)
	if err != nil {
		return err
	}
	for _, r := range all {
		if r.VMName != owner {
			continue
		}
		r.Deleted = true
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if err := c.Execute(ctx, clusterPolicyUpsertSQL, NICGuardKey(r.VMName, r.MAC), string(b), setBy, c.NowTS()); err != nil {
			return err
		}
	}
	return nil
}

// ListNICGuardsWithDeleted is ListNICGuards with the tombstoned records.
func ListNICGuardsWithDeleted(ctx context.Context, c *Client) (map[string]NICGuardRecord, error) {
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

// NetworkAssignedAddrs maps every live network to every address assigned on
// it: IPAM leases and the addresses NIC rows (VM and container) record. A
// guard confined to a subnet must still exclude these — they belong to other
// NICs.
func NetworkAssignedAddrs(ctx context.Context, c *Client) (map[string][]string, error) {
	out := map[string][]string{}
	add := func(netName, ip string) {
		if netName == "" || ip == "" {
			return
		}
		if p, err := netip.ParsePrefix(ip); err == nil {
			ip = p.Addr().String()
		} else if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.String()
		} else {
			return
		}
		out[netName] = append(out[netName], ip)
	}
	for _, q := range []string{
		`SELECT network AS n, ip FROM ip_allocations WHERE deleted_at IS NULL`,
		`SELECT network_name AS n, COALESCE(ip,'') AS ip FROM vm_nics WHERE deleted_at IS NULL`,
		`SELECT network_name AS n, COALESCE(ip,'') AS ip FROM vm_interfaces WHERE deleted_at IS NULL`,
		`SELECT network_name AS n, COALESCE(ip,'') AS ip FROM container_interfaces WHERE deleted_at IS NULL`,
	} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			add(r.String("n"), r.String("ip"))
		}
	}
	return out, nil
}

// ── Per-NIC enforcement mode ────────────────────────────────────────────────

const clusterPolicyFirewallEnforcement = "firewall_nic_enforcement"

// Per-NIC enforcement modes. With no row the mode is observe: a cluster that
// upgraded must not start dropping traffic its rules never dropped before.
const (
	FirewallEnforce = "enforce"
	FirewallObserve = "observe"
)

// FirewallEnforcement is the per-NIC enforcement policy row.
type FirewallEnforcement struct {
	Mode      string
	SetBy     string
	UpdatedAt string
	Recorded  bool // false: no row yet (observe)
}

// GetFirewallEnforcement reads the mode; no row (or an unknown value, a later
// release's) is observe.
func GetFirewallEnforcement(ctx context.Context, c *Client) (FirewallEnforcement, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		clusterPolicyFirewallEnforcement)
	if err != nil {
		return FirewallEnforcement{Mode: FirewallObserve}, err
	}
	if len(rows) == 0 {
		return FirewallEnforcement{Mode: FirewallObserve}, nil
	}
	e := FirewallEnforcement{Mode: rows[0].String("value"), SetBy: rows[0].String("set_by"),
		UpdatedAt: rows[0].String("updated_at"), Recorded: true}
	if e.Mode != FirewallEnforce {
		e.Mode = FirewallObserve
	}
	return e, nil
}

// SetFirewallEnforcement writes the mode (behind the cluster_policies gate).
func SetFirewallEnforcement(ctx context.Context, c *Client, mode, setBy string) error {
	if mode != FirewallEnforce && mode != FirewallObserve {
		return fmt.Errorf("firewall enforcement %q: want %s or %s", mode, FirewallEnforce, FirewallObserve)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyFirewallEnforcement, mode, setBy, c.NowTS())
}

// FirewallSeedDecision is the mode a cluster's founding host records for it
// (SeedFirewallEnforcement): enforce when the cluster has nothing yet — no
// workload and no firewall rule of any kind, i.e. one just initialised —
// observe for any other (one that upgraded with workloads or rules in place),
// so nothing its rules never dropped before is dropped until an operator turns
// enforcement on.
func FirewallSeedDecision(ctx context.Context, c *Client) (string, error) {
	rows, err := c.Query(ctx, `SELECT
		(SELECT COUNT(*) FROM vms WHERE deleted_at IS NULL) +
		(SELECT COUNT(*) FROM containers WHERE deleted_at IS NULL) +
		(SELECT COUNT(*) FROM sg_rules WHERE deleted_at IS NULL) +
		(SELECT COUNT(*) FROM cluster_firewall_rules WHERE deleted_at IS NULL) +
		(SELECT COUNT(*) FROM host_firewall_rules WHERE deleted_at IS NULL) +
		(SELECT COUNT(*) FROM firewall_defaults WHERE deleted_at IS NULL AND default_deny != 0) AS n`)
	if err != nil {
		return "", err
	}
	if len(rows) == 1 && rows[0].Int("n") == 0 {
		return FirewallEnforce, nil
	}
	return FirewallObserve, nil
}

// seedTS is the timestamp a seeded mode is written with: before any write a
// clock can stamp, so an operator's `lv firewall enforce` outranks every seed
// on every replica, whenever and wherever either was written. Of two seeds
// observe outranks enforce: failing open, as a cluster did before.
func seedTS(mode string) string {
	if mode == FirewallObserve {
		return "0001-01-01T00:00:00.000000002Z"
	}
	return "0001-01-01T00:00:00.000000001Z"
}

// SeedFirewallEnforcement records mode as the cluster's per-NIC enforcement
// mode, once, from the cluster's founding host. It writes only when no mode is
// recorded, the cluster_policies gate is open, and this replica can be trusted
// to know: it has caught up with a peer since it started, or no host other
// than hostName is known (a cluster of one). A replica that has not caught up
// may simply not have seen the mode yet — a joiner would flip a cluster to
// enforce, a rejoiner back to observe. It returns the mode written, or "".
func SeedFirewallEnforcement(ctx context.Context, c *Client, mode, hostName string) (string, error) {
	if mode != FirewallEnforce && mode != FirewallObserve {
		return "", fmt.Errorf("firewall enforcement %q: want %s or %s", mode, FirewallEnforce, FirewallObserve)
	}
	cur, err := GetFirewallEnforcement(ctx, c)
	if err != nil || cur.Recorded || !c.MayWriteClusterPolicy() {
		return "", err
	}
	if caught, _ := c.ReplicaCaughtUp(); !caught {
		rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM hosts WHERE name != ?`, hostName)
		if err != nil {
			return "", err
		}
		if len(rows) != 1 || rows[0].Int("n") != 0 {
			return "", nil
		}
	}
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyFirewallEnforcement, mode,
		"litevirt (initial)", seedTS(mode)); err != nil {
		return "", err
	}
	return mode, nil
}

// NetworkGuardInfo is what a NIC on a network may not claim as its own, beyond
// another NIC's address.
type NetworkGuardInfo struct {
	Subnet string
	// AllowedVLANs are the VLANs a trunk NIC created on this release may
	// carry on the network (compose.NetworkDef.AllowedVLANs).
	AllowedVLANs []int
	// LitevirtGateway is the subnet's first host where litevirt is the
	// network's router (compose.NetworkDef.LitevirtGateway), else "".
	LitevirtGateway string
	// Reserved are the network's configured gateway and reserved addresses.
	Reserved []string
	// NICGateways are the gateways live VMs' NIC specs on the network route
	// through, each with the VM and its project.
	NICGateways []NICGatewayDecl
}

// NICGatewayDecl is one gateway a VM's NIC routes through.
type NICGatewayDecl struct {
	Addr    string
	VM      string
	Project string
}

// All is every address the network keeps from its NICs, the NIC-declared
// gateways included.
func (g NetworkGuardInfo) All() []string {
	out := append([]string(nil), g.Reserved...)
	if g.LitevirtGateway != "" {
		out = append(out, g.LitevirtGateway)
	}
	for _, d := range g.NICGateways {
		out = append(out, d.Addr)
	}
	return out
}

func canonIP(s string) string {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Zone() == "" {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.String()
	}
	return ""
}

// NetworkGuardInfos returns NetworkGuardInfo for every live network.
// networks.config is json.Marshal of compose.NetworkDef; vms.spec is
// encoding/json of VMSpec.
func NetworkGuardInfos(ctx context.Context, c *Client) (map[string]NetworkGuardInfo, error) {
	rows, err := c.Query(ctx, `SELECT name, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]NetworkGuardInfo, len(rows))
	for _, r := range rows {
		var def compose.NetworkDef
		_ = json.Unmarshal([]byte(r.String("config")), &def)
		info := NetworkGuardInfo{Subnet: def.Subnet, LitevirtGateway: def.LitevirtGateway(), AllowedVLANs: def.AllowedVLANs}
		for _, a := range append([]string{def.Gateway}, def.ReservedAddresses...) {
			if ca := canonIP(a); ca != "" {
				info.Reserved = append(info.Reserved, ca)
			}
		}
		out[r.String("name")] = info
	}
	vms, err := c.Query(ctx, `SELECT name, COALESCE(project, '') AS project, spec FROM vms WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	for _, r := range vms {
		var spec struct {
			Network []struct {
				Name        string `json:"name"`
				Gateway     string `json:"gateway"`
				Ipv6Gateway string `json:"ipv6_gateway"`
			} `json:"network"`
		}
		if json.Unmarshal([]byte(r.String("spec")), &spec) != nil {
			continue
		}
		for _, n := range spec.Network {
			info, ok := out[n.Name]
			if !ok {
				continue
			}
			for _, g := range []string{n.Gateway, n.Ipv6Gateway} {
				if ca := canonIP(g); ca != "" {
					info.NICGateways = append(info.NICGateways, NICGatewayDecl{Addr: ca, VM: r.String("name"), Project: r.String("project")})
				}
			}
			out[n.Name] = info
		}
	}
	return out, nil
}

// AddrOwner is an address or MAC and the workload holding it.
type AddrOwner struct {
	Network string
	Addr    string // canonical IP; "" for a MAC entry
	MAC     string // lower-case; "" for an address entry
	Owner   string // VM name, or ContainerGuardOwner for a container
}

// LiveNICIdentities lists every live NIC's MAC and recorded address, and every
// live IPAM lease, with its owner — what a new NIC's explicit MAC or address
// must not collide with.
func LiveNICIdentities(ctx context.Context, c *Client) ([]AddrOwner, error) {
	var out []AddrOwner
	canon := func(ip string) string {
		if p, err := netip.ParsePrefix(ip); err == nil {
			return p.Addr().String()
		}
		if a, err := netip.ParseAddr(ip); err == nil {
			return a.String()
		}
		return ""
	}
	for _, q := range []string{
		`SELECT network_name AS n, COALESCE(ip,'') AS ip, mac, vm_name AS owner FROM vm_nics WHERE deleted_at IS NULL`,
		`SELECT network_name AS n, COALESCE(ip,'') AS ip, mac, vm_name AS owner FROM vm_interfaces WHERE deleted_at IS NULL`,
		`SELECT network_name AS n, COALESCE(ip,'') AS ip, mac, 'ct:' || host_name || ':' || ct_name AS owner FROM container_interfaces WHERE deleted_at IS NULL`,
		`SELECT network AS n, ip, mac, CASE owner_kind WHEN 'ct' THEN 'ct:' || owner_host || ':' || vm_name ELSE vm_name END AS owner FROM ip_allocations WHERE deleted_at IS NULL`,
	} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			o := r.String("owner")
			if m := strings.ToLower(r.String("mac")); m != "" {
				out = append(out, AddrOwner{Network: r.String("n"), MAC: m, Owner: o})
			}
			if a := canon(r.String("ip")); a != "" {
				out = append(out, AddrOwner{Network: r.String("n"), Addr: a, Owner: o})
			}
		}
	}
	return out, nil
}

// VMSpecOfIncarnation returns the stored spec of name's row when that row is
// the incarnation created at createdAt, live or already tombstoned (a delete
// keeps the spec). found is false when this replica holds another
// incarnation, or none.
func VMSpecOfIncarnation(ctx context.Context, c *Client, name, createdAt string) (spec string, found bool, err error) {
	if createdAt == "" {
		return "", false, nil
	}
	rows, err := c.Query(ctx, `SELECT spec FROM vms WHERE name = ? AND created_at = ?`, name, createdAt)
	if err != nil || len(rows) == 0 {
		return "", false, err
	}
	return rows[0].String("spec"), true, nil
}

// SetClusterPolicy writes one cluster_policies key (behind the gate), through
// the table's one upsert.
func SetClusterPolicy(ctx context.Context, c *Client, key, value, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, key, value, setBy, c.NowTS())
}
