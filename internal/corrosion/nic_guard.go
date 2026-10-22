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
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/hlc"
)

const (
	nicGuardKeyPrefix = "nic_guard/"

	// NICGuardOn guards the NIC.
	NICGuardOn = "on"
	// NICGuardOff records an explicit decision not to guard the NIC.
	NICGuardOff = "off"

	// MaxNICGuardAddresses bounds the allowed list of one NIC, so one record
	// cannot bloat every host's ruleset (compose.MaxGuardAddresses).
	MaxNICGuardAddresses = compose.MaxGuardAddresses
)

// ErrNICStampSkewed refuses a write for a NIC behind a stored write for that
// NIC stamped too far ahead of this host's clock.
var ErrNICStampSkewed = errors.New("a stored write for this NIC is stamped too far ahead of this host's clock")

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

	// Carried marks, in memory only, a record a re-create carries from the
	// incarnation it replaces: the guard a NIC had, which a create must
	// never drop (switch review I2). Not stored.
	Carried bool `json:"-"`
	// Explicit marks, in memory only, a record whose guard settings the
	// request named (spoof_guard and the rest), even with the default's
	// shape: what was asked for is never dropped (switch re-review N3).
	Explicit bool `json:"-"`
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
// renderer, which refuses the whole ruleset on one. It is
// compose.NormalizeGuardAddresses, the one validator the plan shares.
func NormalizeNICGuardAddresses(in []string) ([]string, error) {
	return compose.NormalizeGuardAddresses(in)
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

// PutNICGuard writes a NIC's guard record. The record is the release feature
// nic_guards: g must be its grant (the release token has latched and the use
// is recorded). It refuses with ErrClusterPolicyGateClosed until
// failover_scope_v1 has latched.
func PutNICGuard(ctx context.Context, c *Client, g capabilities.FeatureGrant, r NICGuardRecord, setBy string) error {
	if err := g.Check(capabilities.FeatureNICGuards); err != nil {
		return err
	}
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
	ts, err := nicGuardStamp(ctx, c, r.VMName, r.MAC)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, NICGuardKey(r.VMName, r.MAC), string(b), setBy, ts)
}

// nicGuardStamp is the updated_at a write of owner's NIC mac's guard record
// carries: NowTS, or just past the newest write this replica holds for that
// NIC — its record, live or retired, or its NIC row, live or tombstoned —
// when that one is newer. With RFC3339 keys a peer's clock may run ahead of
// this host's, and a fresh NowTS could then sort below a retire or a row
// tombstone this write follows; every replica holding both would keep the
// older one (a re-attached NIC losing its guard).
func nicGuardStamp(ctx context.Context, c *Client, owner, mac string) (string, error) {
	floor, what := "", ""
	note := func(ts, src string) {
		if ts != "" && (floor == "" || lwwOrder(ts, floor) > 0) {
			floor, what = ts, src
		}
	}
	rows, err := c.Query(ctx, `SELECT set_by, updated_at FROM cluster_policies WHERE key = ?`, NICGuardKey(owner, strings.ToLower(mac)))
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		note(r.String("updated_at"), "guard record (set by "+r.String("set_by")+")")
	}
	if !strings.HasPrefix(owner, "ct:") {
		for _, table := range []string{"vm_nics", "vm_interfaces"} {
			nics, err := GetVMNICsRaw(ctx, c, table, owner)
			if err != nil {
				return "", err
			}
			for _, n := range nics {
				if strings.EqualFold(n.MAC, mac) {
					note(n.UpdatedAt, table+" row")
				}
			}
		}
	}
	return c.nicStampAfter(owner, mac, floor, what)
}

// nicStampAfter is stampAfter for a write of owner's NIC mac whose newest
// stored write is floor (what names it), after this host's clock has observed
// floor. A floor stamped beyond the skew limit is refused as what it is, with
// the remedy (ErrNICStampSkewed).
func (c *Client) nicStampAfter(owner, mac, floor, what string) (string, error) {
	if floor != "" && tsFutureSkewed(floor, c.now()) {
		return "", nicStampSkewed(owner, mac, floor, what)
	}
	// This host's clock moves past the stored write, as the replicator's does
	// for a write it applies (ObserveStamp): this stamp, and every later one
	// this host takes — a detach right after a re-attach — orders after it.
	ObserveStamp(c, floor)
	return c.stampAfter(floor, c.now())
}

// nicStampSkewed is ErrNICStampSkewed for owner's NIC mac behind its stored
// write what, stamped floor.
func nicStampSkewed(owner, mac, floor, what string) error {
	limit := time.Duration(hlc.MaxSkewMS) * time.Millisecond
	host := "the stamp does not name the host that wrote it"
	if p, ok := hlc.Parse(floor); ok && hlc.IsHLC(floor) {
		host = "written by " + p.NodeID
	}
	retry := ""
	if inst, ok := tsInstant(floor); ok {
		retry = " (" + inst.Add(-limit).UTC().Format(time.RFC3339) + ")"
	}
	return fmt.Errorf("%w: NIC %s of %s: its %s is stamped %s, more than %s ahead of this host's clock (%s); "+
		"check NTP on the host that wrote it — this write can be retried once this host's clock passes the stamp less %s%s",
		ErrNICStampSkewed, strings.ToLower(mac), owner, what, floor, limit, host, limit, retry)
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
		ts, err := nicGuardStamp(ctx, c, r.VMName, r.MAC)
		if err != nil {
			return err
		}
		if err := c.Execute(ctx, clusterPolicyUpsertSQL, NICGuardKey(r.VMName, r.MAC), string(b), setBy, ts); err != nil {
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
// than hostName is known (a cluster of one), or none but hosts still joining
// while it has no gossip member (ClusterOfOneBut: a founder's own half-added
// second host, which has written nothing). A replica that has not caught up
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
		alone, err := soleOrOnlyJoiners(ctx, c, hostName)
		if err != nil {
			return "", err
		}
		if !alone {
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
	// Type is the network's type (compose.GuardUnenforcedOn).
	Type string
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
	// IsolatedBridge is the host bridge of an `isolated` network
	// (compose.IsolatedBridgeName), else "".
	IsolatedBridge string
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
	rows, err := c.Query(ctx, `SELECT name, COALESCE(type, '') AS type, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]NetworkGuardInfo, len(rows))
	for _, r := range rows {
		var def compose.NetworkDef
		_ = json.Unmarshal([]byte(r.String("config")), &def)
		typ := r.String("type")
		if typ == "" {
			typ = def.Type
		}
		info := NetworkGuardInfo{Subnet: def.Subnet, LitevirtGateway: def.LitevirtGateway(), AllowedVLANs: def.AllowedVLANs, Type: typ}
		if typ == "isolated" {
			info.IsolatedBridge = compose.IsolatedBridgeName(r.String("name"))
		}
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

// GuardedMACsOf is the MACs (lower-case, sorted) of owner's NICs whose guard
// is on — only records of the incarnation that exists now: one an earlier VM
// of the same name left, or one tombstoned with its VM, guards nothing
// (re-review m1, round 3).
//
// It reads owner's own records and nothing else (re-review m1, round 5): a
// record of another workload that cannot be read is no reason to refuse
// this one, so an unguarded VM's start goes ahead as on main. An error says
// owner may have a guard: its own records could not be read, or it has a
// record on and its VM row, which says which incarnation runs, could not be.
//
// A record whose NIC row was tombstoned no earlier than the record was
// written is left out: its NIC was removed (a detach, or a rolled-back
// attach, by a build that left the record live), and no host renders a NIC
// whose row is tombstoned, so the record could never be in force. A record
// with no row at all, or newer than its row's tombstone (a re-attach whose
// row has not landed here), is still demanded.
func GuardedMACsOf(ctx context.Context, c *Client, owner string) ([]string, error) {
	return GuardedMACsOfIncarnation(ctx, c, owner, "")
}

// GuardedMACsOfIncarnation is GuardedMACsOf for a VM that a create on this
// host is bringing up as the incarnation creating (its spec uuid): that
// create's incarnation is the one that runs, whatever VM row of the name this
// replica holds (none yet, or the one it replaces). A record another
// incarnation of the name left live — a create that failed on an earlier
// build — guards nothing the firewall renders for this one, so it is not
// demanded. creating "" is GuardedMACsOf.
func GuardedMACsOfIncarnation(ctx context.Context, c *Client, owner, creating string) ([]string, error) {
	lo, hi := keyRange(nicGuardKeyPrefix + owner + "/")
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies
		 WHERE key >= ? AND key < ? AND deleted_at IS NULL ORDER BY key`, lo, hi)
	if err != nil {
		return nil, err
	}
	var own []NICGuardRecord
	for _, r := range rows {
		if rec, ok := decodeNICGuard(r); ok && rec.VMName == owner && (rec.Deleted || rec.Guarded()) {
			own = append(own, rec)
		}
	}
	if len(own) == 0 {
		return nil, nil
	}
	uuid, inFlight := "", false
	vm, err := GetVM(ctx, c, owner)
	if err != nil {
		return nil, fmt.Errorf("read the VM row of %s, which has a NIC guard record: %w", owner, err)
	}
	if vm != nil {
		var sp struct {
			UUID string `json:"uuid"`
		}
		_ = json.Unmarshal([]byte(vm.Spec), &sp)
		uuid = sp.UUID
		inFlight = vm.ActiveOperationID != ""
	}
	if creating != "" {
		uuid = creating
	}
	live, removed, err := nicRowStatesOf(ctx, c, owner)
	if err != nil {
		return nil, fmt.Errorf("read the NIC rows of %s, which has a NIC guard record: %w", owner, err)
	}
	var out []string
	for _, r := range own {
		mac := strings.ToLower(r.MAC)
		if r.Deleted {
			row, ok := live[mac]
			if !ok {
				continue
			}
			typ, err := NetworkType(ctx, c, row.NetworkName)
			if err != nil {
				return nil, fmt.Errorf("read network %s of %s, which has a NIC guard record: %w", row.NetworkName, owner, err)
			}
			if _, ok := RetiredGuardOver(r, uuid, typ, row.NetworkName); ok {
				out = append(out, mac)
			}
			continue
		}
		if r.VMUUID != "" && uuid != "" && r.VMUUID != uuid {
			continue
		}
		if ts, gone := removed[mac]; gone && !inFlight && lwwOrder(ts, r.UpdatedAt) >= 0 {
			// The NIC was removed after its record was written (a detach,
			// or an attach rolled back), by a build that left the record
			// live. No host renders a NIC whose row is tombstoned, so the
			// record could never be in force: it is not demanded. Not
			// while an operation holds the VM: a detach that tombstoned
			// the row and then failed may leave the NIC in its domain.
			continue
		}
		out = append(out, mac)
	}
	sort.Strings(out)
	return out, nil
}

// nicRowStatesOf maps each lower-case MAC of vm by the MergedVMNICs overlay's
// winning row: live, or tombstoned (to that tombstone's updated_at). A MAC
// with no row at all is in neither.
func nicRowStatesOf(ctx context.Context, c *Client, vm string) (live map[string]NICRecord, removed map[string]string, err error) {
	nics, err := GetVMNICsRaw(ctx, c, "vm_nics", vm)
	if err != nil {
		return nil, nil, err
	}
	ifaces, err := GetVMNICsRaw(ctx, c, "vm_interfaces", vm)
	if err != nil {
		return nil, nil, err
	}
	live, removed = map[string]NICRecord{}, map[string]string{}
	for k, w := range nicRowWinners(ifaces, nics) {
		if w.DeletedAt != "" {
			removed[k.mac] = w.UpdatedAt
		} else {
			live[k.mac] = w
		}
	}
	return live, removed, nil
}

// TrunkVLANsRecordedKey is the cluster_policies key under which the upgrade
// recording of trunk VLANs keeps what it has recorded: a JSON object of
// network name → the VLANs it recorded for that network's trunks that predate
// guards (re-review R2-I1, R3-I1). Its presence says the recording has run at
// least once.
const TrunkVLANsRecordedKey = "firewall_trunk_vlans_recorded"

// TrunkVLANsRecorded reads what the upgrade recording has recorded. ok is
// false until its first pass. A value that does not parse (an earlier build of
// this release wrote "done") counts as a pass that recorded nothing.
func TrunkVLANsRecorded(ctx context.Context, c *Client) (map[string][]int, bool, error) {
	raw, have, err := clusterPolicyValue(ctx, c, TrunkVLANsRecordedKey)
	if err != nil || !have {
		return nil, false, err
	}
	return DecodeVLANMap(raw), true, nil
}

// SetClusterPolicy writes one cluster_policies key (behind the gate), through
// the table's one upsert. It refuses a firewall-tags or tag-group key
// (ErrReservedClusterPolicyKey): those rows have their own writers, which
// check the sg.write authority and the grammar (firewall_tags.go,
// firewall_tag_group.go).
func SetClusterPolicy(ctx context.Context, c *Client, key, value, setBy string) error {
	if err := refuseReservedPolicyKey(key); err != nil {
		return err
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, key, value, setBy, c.NowTS())
}

// LiveNICSecurity is each NIC of vmName, in ordinal order, with the
// security-group binding its row holds and the guard record the firewall
// enforces for it: only a record of the incarnation vmUUID names (an earlier
// VM of the same name and MAC left one that guards nothing), and none for a
// NIC that has no record (unguarded). A compose deploy compares the file with
// this, not with the create-time values in the stored spec.
func LiveNICSecurity(ctx context.Context, c *Client, vmName, vmUUID string) ([]compose.LiveNIC, error) {
	nics, err := MergedVMNICs(ctx, c, vmName)
	if err != nil {
		return nil, err
	}
	out := make([]compose.LiveNIC, 0, len(nics))
	for _, n := range nics {
		ln := compose.LiveNIC{Network: n.NetworkName, MAC: n.MAC, Ordinal: n.Ordinal,
			SecurityGroups: decodeSGs(n.SecurityGroups)}
		rec, err := GetNICGuard(ctx, c, vmName, n.MAC)
		if err != nil {
			return nil, fmt.Errorf("read the guard of NIC %s: %w", n.MAC, err)
		}
		if rec != nil && (rec.VMUUID == "" || vmUUID == "" || rec.VMUUID == vmUUID) {
			ln.Guard = &compose.LiveGuard{Mode: rec.Mode, Allowed: rec.Allowed,
				AllowDHCPServer: rec.AllowDHCPServer, AllowRouterAdvert: rec.AllowRouterAdvert, AllowVLANTags: rec.AllowVLANTags}
		}
		if rec == nil {
			retired, err := GetRetiredNICGuard(ctx, c, vmName, n.MAC)
			if err != nil {
				return nil, fmt.Errorf("read the guard of NIC %s: %w", n.MAC, err)
			}
			if retired != nil {
				typ, err := NetworkType(ctx, c, n.NetworkName)
				if err != nil {
					return nil, fmt.Errorf("read network %s: %w", n.NetworkName, err)
				}
				if g, ok := RetiredGuardOver(*retired, vmUUID, typ, n.NetworkName); ok {
					ln.Guard = &compose.LiveGuard{Mode: g.Mode, FailClosed: RetiredGuardNote(vmName, n.MAC)}
				}
			}
		}
		out = append(out, ln)
	}
	return out, nil
}

// RetireNICGuard tombstones the guard record of owner's NIC mac, keeping what
// it held as DeleteNICGuardsOf does (not meant for a re-create to carry: the
// NIC is not part of the incarnation it replaces). A NIC that has no live record is left as
// it is. It refuses with ErrClusterPolicyGateClosed when there is a record and
// this host cannot write cluster_policies.
func RetireNICGuard(ctx context.Context, c *Client, owner, mac, setBy string) error {
	r, err := GetNICGuard(ctx, c, owner, strings.ToLower(mac))
	if err != nil || r == nil {
		return err
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	r.Deleted = true
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	ts, err := nicGuardStamp(ctx, c, r.VMName, r.MAC)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, NICGuardKey(r.VMName, r.MAC), string(b), setBy, ts)
}

// RetireNICGuardsOfIncarnation retires the live guard records of owner's
// NICs macs that the incarnation uuid wrote, and nothing else: a record of
// that MAC another incarnation wrote since is left as it is. It is how a
// create that failed takes back the records it wrote before it failed. A
// MAC with no live record of that incarnation is skipped. It returns the
// first error and goes on with the other MACs.
func RetireNICGuardsOfIncarnation(ctx context.Context, c *Client, owner, uuid string, macs []string, setBy string) error {
	if uuid == "" {
		return nil
	}
	var first error
	for _, mac := range macs {
		r, err := GetNICGuard(ctx, c, owner, strings.ToLower(mac))
		if err == nil && (r == nil || r.Deleted || r.VMUUID != uuid) {
			continue
		}
		if err == nil {
			err = RetireNICGuard(ctx, c, owner, mac, setBy)
		}
		if err != nil && first == nil {
			first = fmt.Errorf("retire the guard record of NIC %s of %s: %w", strings.ToLower(mac), owner, err)
		}
	}
	return first
}

// RetiredGuardOver is what a retired record of the VM incarnation vmUUID
// enforces on a NIC of that MAC whose row is live: the default guard (on, no
// relaxation). A record is retired only once its NIC's row is gone, so a live
// row over a retired record means the two writes reached this replica out of
// order (a retire whose host's clock ran ahead of a later re-attach, or a row
// that arrived after its record was judged orphaned): the NIC is guarded
// rather than left unguarded. ok is false for a live record, and for one of
// another or an unknown incarnation.
//
// A NIC on a network that cannot enforce a guard (netType and network, as
// compose.GuardUnenforcedOn judges them: direct, SR-IOV) gets nothing: no
// guard could be put in force there.
func RetiredGuardOver(r NICGuardRecord, vmUUID, netType, network string) (NICGuardRecord, bool) {
	if !r.Deleted || r.VMUUID == "" || r.VMUUID != vmUUID || compose.GuardUnenforcedOn(netType, network) != "" {
		return NICGuardRecord{}, false
	}
	return NICGuardRecord{VMName: r.VMName, MAC: r.MAC, Mode: NICGuardOn, VMUUID: r.VMUUID,
		Network: r.Network, Ordinal: r.Ordinal, SetBy: r.SetBy, UpdatedAt: r.UpdatedAt}, true
}

// RetiredGuardNote says why a NIC runs under the default guard of
// RetiredGuardOver, and how an operator replaces it.
func RetiredGuardNote(vm, mac string) string {
	return "fail-closed default guard: the NIC's guard record of this VM is retired while its NIC row is live " +
		"(their writes arrived out of order); `lv firewall nic-guard set " + vm + " --mac " + strings.ToLower(mac) +
		"` records its guard"
}

// NetworkType is the type of the live network name ("" when it has none, or
// there is no such network).
func NetworkType(ctx context.Context, c *Client, name string) (string, error) {
	rows, err := c.Query(ctx, `SELECT COALESCE(type, '') AS type, config FROM networks WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	if t := rows[0].String("type"); t != "" {
		return t, nil
	}
	var def compose.NetworkDef
	_ = json.Unmarshal([]byte(rows[0].String("config")), &def)
	return def.Type, nil
}

// GetRetiredNICGuard returns a NIC's retired record, or nil when it has a
// live one or none.
func GetRetiredNICGuard(ctx context.Context, c *Client, vm, mac string) (*NICGuardRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		NICGuardKey(vm, mac))
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	rec, ok := decodeNICGuard(rows[0])
	if !ok || !rec.Deleted {
		return nil, nil
	}
	return &rec, nil
}
