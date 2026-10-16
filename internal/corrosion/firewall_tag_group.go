package corrosion

// Firewall tag groups (docs/design: firewall extras spec §4): a named selector
// over workloads' firewall tags. Each group is one cluster_policies row
// firewall_tag_group/<name>, written only by SetFirewallTagGroup through the
// table's one upsert, so no new statement shape. The row is data of the
// firewall_tag_groups release feature, so its writer takes that feature's
// grant.
//
// ListTagGroupMembers resolves every group to its member workloads and their
// addresses. Membership is decided ONLY by a workload's firewall identity
// (fw_id: VMSpec.firewall_id, containers.create_spec fw_id) and the firewall
// tags row keyed by it (firewall_tags/vm|ct/<fw_id>); no name, host or MAC is
// matched to decide WHO is a member. A member's addresses are ONLY the live
// ip_allocations leases litevirt's allocators wrote for it: owned by the
// member, and matching a live NIC of the member on the lease's network by
// MAC. A NIC row's ip (SetVMIP, guest discovery, a static address), a
// litevirt.ip label and a guard's Known and Allowed never count.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

const (
	// FirewallTagGroupKeyPrefix starts a group's cluster_policies key.
	FirewallTagGroupKeyPrefix = "firewall_tag_group/"
	// FirewallTagsKeyPrefix starts a workload's firewall-tags key:
	// firewall_tags/vm/<fw_id> or firewall_tags/ct/<fw_id>.
	FirewallTagsKeyPrefix = "firewall_tags/"

	// TagMemberVM and TagMemberCT are a member's kind, and the kind segment
	// of its firewall-tags key.
	TagMemberVM = "vm"
	TagMemberCT = "ct"
)

var (
	firewallTagWordRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	firewallIDRE      = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ValidFirewallTagGroupName reports whether name is a group name:
// [a-z][a-z0-9_]{0,30}. It becomes the nft set name lv_tg_<name>, and a rule
// references it as tag:<name> (rulefield.TagGroupName, the one grammar).
func ValidFirewallTagGroupName(name string) bool { return rulefield.TagGroupName(name) }

// ValidFirewallTagWord reports whether s is a firewall tag key or value:
// [a-z0-9][a-z0-9_.-]{0,62}.
func ValidFirewallTagWord(s string) bool { return firewallTagWordRE.MatchString(s) }

// ValidFirewallID reports whether id is a firewall identity as the server
// mints it: 32 lower-case hex characters.
func ValidFirewallID(id string) bool { return firewallIDRE.MatchString(id) }

// FirewallTagGroupDef is a group's stored definition.
type FirewallTagGroupDef struct {
	// Match is ANDed: each key must be among the workload's tags, with an
	// equal value, or with any value when the match value is "".
	Match map[string]string `json:"match"`
	// Networks limits the group BINDING to these networks; empty, every
	// network. It does not limit the address set.
	Networks []string `json:"networks"`
	// SecurityGroups are bound to every NIC of every member the binding
	// covers.
	SecurityGroups []string `json:"security_groups"`
}

// FirewallTagGroup is one group row as this replica holds it.
type FirewallTagGroup struct {
	Name      string
	Def       FirewallTagGroupDef
	SetBy     string
	UpdatedAt string
	// Unreadable: the row is malformed JSON, has a field of the wrong type,
	// or names a selector outside the grammar (no match, or a key or value
	// outside it), or its key's name is outside the group-name grammar. It
	// has no members and binds nothing; Def is empty.
	Unreadable bool
}

// Matches reports whether tags satisfy the group's selector. An unreadable
// group, or one with no match, matches nothing.
func (g FirewallTagGroup) Matches(tags map[string]string) bool {
	if g.Unreadable || len(g.Def.Match) == 0 {
		return false
	}
	for k, want := range g.Def.Match {
		have, ok := tags[k]
		if !ok || (want != "" && have != want) {
			return false
		}
	}
	return true
}

// BindsNetwork reports whether the group's binding covers network.
func (g FirewallTagGroup) BindsNetwork(network string) bool {
	if g.Unreadable {
		return false
	}
	return len(g.Def.Networks) == 0 || slices.Contains(g.Def.Networks, network)
}

// normaliseTagGroupDef checks def against the grammar and returns it with its
// lists de-duplicated and sorted.
func normaliseTagGroupDef(def FirewallTagGroupDef) (FirewallTagGroupDef, error) {
	if len(def.Match) == 0 {
		return def, errors.New("a tag group needs at least one match")
	}
	match := make(map[string]string, len(def.Match))
	for k, v := range def.Match {
		if !ValidFirewallTagWord(k) {
			return def, fmt.Errorf("match key %q: want [a-z0-9][a-z0-9_.-]{0,62}", k)
		}
		if v != "" && !ValidFirewallTagWord(v) {
			return def, fmt.Errorf("match value %q of %q: want [a-z0-9][a-z0-9_.-]{0,62}, or none for \"has the key\"", v, k)
		}
		match[k] = v
	}
	list := func(what string, in []string) ([]string, error) {
		var out []string
		for _, s := range in {
			if strings.TrimSpace(s) == "" || s != strings.TrimSpace(s) {
				return nil, fmt.Errorf("%s %q: empty or padded", what, s)
			}
			out = append(out, s)
		}
		slices.Sort(out)
		return slices.Compact(out), nil
	}
	nets, err := list("network", def.Networks)
	if err != nil {
		return def, err
	}
	sgs, err := list("security group", def.SecurityGroups)
	if err != nil {
		return def, err
	}
	return FirewallTagGroupDef{Match: match, Networks: nets, SecurityGroups: sgs}, nil
}

// SetFirewallTagGroup writes group name's definition; a nil def removes the
// group (the row's value becomes ""). It takes the firewall_tag_groups grant,
// refuses a name or definition outside the grammar, and refuses with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched. The caller
// (the gRPC handler) owns authorisation, audit, and the references a removal
// must not strand.
func SetFirewallTagGroup(ctx context.Context, c *Client, g capabilities.FeatureGrant, name string, def *FirewallTagGroupDef, setBy string) error {
	if err := g.Check(capabilities.FeatureFirewallTagGroups); err != nil {
		return err
	}
	if !ValidFirewallTagGroupName(name) {
		return fmt.Errorf("tag group name %q: want [a-z][a-z0-9_]{0,30}", name)
	}
	value := ""
	if def != nil {
		norm, err := normaliseTagGroupDef(*def)
		if err != nil {
			return fmt.Errorf("tag group %s: %w", name, err)
		}
		if norm.Networks == nil {
			norm.Networks = []string{}
		}
		if norm.SecurityGroups == nil {
			norm.SecurityGroups = []string{}
		}
		b, err := json.Marshal(norm)
		if err != nil {
			return err
		}
		value = string(b)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, FirewallTagGroupKeyPrefix+name, value, setBy, c.NowTS())
}

// storedTagGroupDef decodes a group row: a JSON null match value is a wrong
// type (encoding/json would store it as "", "has the key"), not a value.
type storedTagGroupDef struct {
	Match          map[string]*string `json:"match"`
	Networks       []string           `json:"networks"`
	SecurityGroups []string           `json:"security_groups"`
}

// nonNullStrings converts a decoded map, refusing a JSON null value.
func nonNullStrings(in map[string]*string) (map[string]string, bool) {
	if in == nil {
		return nil, true
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if v == nil {
			return nil, false
		}
		out[k] = *v
	}
	return out, true
}

// decodeTagGroup reads one group row. Decoding is lenient: an unknown field
// is ignored, so a later release that adds one does not make the row
// unreadable here.
func decodeTagGroup(name, value, setBy, updatedAt string) FirewallTagGroup {
	g := FirewallTagGroup{Name: name, SetBy: setBy, UpdatedAt: updatedAt}
	var stored storedTagGroupDef
	if !ValidFirewallTagGroupName(name) || json.Unmarshal([]byte(value), &stored) != nil {
		g.Unreadable = true
		return g
	}
	match, ok := nonNullStrings(stored.Match)
	if !ok {
		g.Unreadable = true
		return g
	}
	def := FirewallTagGroupDef{Match: match, Networks: stored.Networks, SecurityGroups: stored.SecurityGroups}
	norm, err := normaliseTagGroupDef(def)
	if err != nil {
		g.Unreadable = true
		return g
	}
	g.Def = norm
	return g
}

// ListFirewallTagGroups returns every group this replica holds, sorted by
// name, unreadable ones included. A removed group (value "") is not listed.
func ListFirewallTagGroups(ctx context.Context, c *Client) ([]FirewallTagGroup, error) {
	lo, hi := keyRange(FirewallTagGroupKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies
		 WHERE key >= ? AND key < ? AND deleted_at IS NULL ORDER BY key`, lo, hi)
	if err != nil {
		return nil, err
	}
	var out []FirewallTagGroup
	for _, r := range rows {
		name := strings.TrimPrefix(r.String("key"), FirewallTagGroupKeyPrefix)
		value := r.String("value")
		if value == "" {
			continue
		}
		out = append(out, decodeTagGroup(name, value, r.String("set_by"), r.String("updated_at")))
	}
	return out, nil
}

// GetFirewallTagGroup returns group name; ok is false when it does not exist
// or was removed.
func GetFirewallTagGroup(ctx context.Context, c *Client, name string) (FirewallTagGroup, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		FirewallTagGroupKeyPrefix+name)
	if err != nil || len(rows) == 0 || rows[0].String("value") == "" {
		return FirewallTagGroup{}, false, err
	}
	return decodeTagGroup(name, rows[0].String("value"), rows[0].String("set_by"), rows[0].String("updated_at")), true, nil
}

// TagGroupAddr is one member address: a host address inside its network's
// subnet.
type TagGroupAddr struct {
	Network string
	Addr    netip.Addr
}

// TagGroupMember is one workload a group matches.
type TagGroupMember struct {
	Kind string // TagMemberVM or TagMemberCT
	Name string
	Host string // the container's host; "" for a VM
	FWID string
	// Addrs are the member's qualifying leases, sorted. Empty: no allocated
	// address, so it contributes nothing to the set.
	Addrs []TagGroupAddr
	// Bound are the networks of the member's live NICs the group's binding
	// covers, sorted.
	Bound []string
}

// TagGroupView is one group and its members, sorted by kind, host, name.
type TagGroupView struct {
	Group   FirewallTagGroup
	Members []TagGroupMember
	// Kept: the row cannot be read here, and Group.Def is the definition
	// the caller kept from an earlier read (ListTagGroupMembersKeeping).
	Kept bool
}

// TagWorkload names a live workload the membership read could not admit.
type TagWorkload struct {
	Kind, Name, Host, FWID string
	// On is the host the workload runs on: a VM's host_name, a container's
	// host.
	On string
	// Networks are the networks of its live NICs, sorted.
	Networks []string
}

// TagGroupMembership is one read of every group's members.
type TagGroupMembership struct {
	// Groups is every group, sorted by name; an unreadable one has no
	// members.
	Groups []TagGroupView
	// Skipped counts the members' lease addresses left out because they do
	// not parse as an address or do not lie inside their network's subnet.
	Skipped int
	// TagsUnreadable are live workloads whose firewall-tags row cannot be
	// read. They are members of nothing.
	TagsUnreadable []TagWorkload
	// SharedFWID are live workloads of one kind that carry the same fw_id,
	// every holder listed, except the source and target of an open move of
	// that workload (movingSources): the target is then the identity's one
	// holder and the source is left out. Neither holder is a member of any group: that
	// fails closed for a rule ACCEPTING a tag group's addresses, and OPEN for
	// a drop or reject rule on one and for the group bindings' security
	// groups. The renderer must hold every NIC of each listed workload at
	// drop and raise a critical condition.
	SharedFWID []TagWorkload
	// IdentityLost are live workloads with no firewall identity whose name a
	// non-empty, readable tags row of their kind still names while no live
	// workload holds that row's identity (FWID is the row's): their
	// membership was most likely lost on the way here, by a relocation that
	// landed without its identity (D2b review M-7) or a restore into a freed
	// name. For display only; nothing matches on the name for membership.
	IdentityLost []TagWorkload
	// Tagged are the live workloads with a unique identity (or an open
	// move's target) and non-empty, readable tags: every workload a group
	// could match.
	Tagged []TagWorkload
}

type tagWorkloadKey struct{ kind, host, name string }

type tagWorkload struct {
	tagWorkloadKey
	fwID string
	on   string // the host it runs on
	nics []tagNIC
	// move is a container row's part in a move (containerMove): its state,
	// state_detail and relocate_token.
	move containerMove
}

type tagNIC struct{ network, mac string }

type tagsRow struct {
	tags       map[string]string
	unreadable bool
	name       string // the workload's name when the tags were set: display only
}

// ListTagGroupMembers resolves every group on this replica to its members.
// It reads nothing beyond the groups when no group exists.
func ListTagGroupMembers(ctx context.Context, c *Client) (*TagGroupMembership, error) {
	return ListTagGroupMembersKeeping(ctx, c, nil)
}

// ListTagGroupMembersKeeping is ListTagGroupMembers where a group whose row
// cannot be read is evaluated from kept[name], a definition the caller kept
// from an earlier read, when there is one (the view is then Kept).
func ListTagGroupMembersKeeping(ctx context.Context, c *Client, kept map[string]FirewallTagGroupDef) (*TagGroupMembership, error) {
	groups, err := ListFirewallTagGroups(ctx, c)
	if err != nil {
		return nil, err
	}
	keptGroup := map[string]bool{}
	for i, g := range groups {
		if def, ok := kept[g.Name]; ok && g.Unreadable {
			if norm, err := normaliseTagGroupDef(def); err == nil {
				groups[i].Def, groups[i].Unreadable = norm, false
				keptGroup[g.Name] = true
			}
		}
	}
	out := &TagGroupMembership{}
	if len(groups) == 0 {
		return out, nil
	}
	tags, err := readFirewallTagsRows(ctx, c)
	if err != nil {
		return nil, err
	}
	workloads, err := readTagWorkloads(ctx, c)
	if err != nil {
		return nil, err
	}
	leases, err := c.Query(ctx,
		`SELECT network, ip, mac, vm_name, owner_kind, owner_host FROM ip_allocations WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	subnets, err := NetworkSubnets(ctx, c)
	if err != nil {
		return nil, err
	}

	// One identity, one live holder per kind; a shared one admits neither.
	// The one exception is an open move's own pair (movingSources): its
	// source is left out, and its target is the identity's one holder.
	holders := map[string]int{}
	for _, w := range workloads {
		if w.fwID != "" {
			holders[w.kind+"/"+w.fwID]++
		}
	}
	moving, err := movingSources(ctx, c, workloads, holders)
	if err != nil {
		return nil, err
	}
	for _, w := range moving {
		holders[w.kind+"/"+w.fwID]--
	}

	// The candidates: live workloads with a unique identity and readable,
	// non-empty tags.
	type candidate struct {
		w    *tagWorkload
		tags map[string]string
	}
	byKey := map[tagWorkloadKey]*candidate{}
	var cands []*candidate
	for _, w := range workloads {
		if w.fwID == "" || slices.Contains(moving, w) {
			continue
		}
		if holders[w.kind+"/"+w.fwID] > 1 {
			out.SharedFWID = append(out.SharedFWID, w.public())
			continue
		}
		row, ok := tags[w.kind+"/"+w.fwID]
		if !ok {
			continue
		}
		if row.unreadable {
			out.TagsUnreadable = append(out.TagsUnreadable, w.public())
			continue
		}
		if len(row.tags) == 0 {
			continue
		}
		cd := &candidate{w: w, tags: row.tags}
		byKey[w.tagWorkloadKey] = cd
		cands = append(cands, cd)
		out.Tagged = append(out.Tagged, w.public())
	}

	// Each candidate's addresses: its own leases on a live NIC of its own.
	addrs := map[tagWorkloadKey][]TagGroupAddr{}
	for _, r := range leases {
		// Owned by the member: kind, host ("" for a VM) and name, exactly.
		key := tagWorkloadKey{kind: r.String("owner_kind"), host: r.String("owner_host"), name: r.String("vm_name")}
		cd, ok := byKey[key]
		if !ok {
			continue
		}
		network := r.String("network")
		mac := strings.ToLower(r.String("mac"))
		if mac == "" || !slices.Contains(cd.w.nics, tagNIC{network: network, mac: mac}) {
			continue
		}
		a, ok := leaseElement(r.String("ip"), subnets[network])
		if !ok {
			out.Skipped++
			continue
		}
		addrs[key] = append(addrs[key], TagGroupAddr{Network: network, Addr: a})
	}

	for _, g := range groups {
		v := TagGroupView{Group: g, Kept: keptGroup[g.Name]}
		for _, cd := range cands {
			if !g.Matches(cd.tags) {
				continue
			}
			m := TagGroupMember{Kind: cd.w.kind, Name: cd.w.name, Host: cd.w.host, FWID: cd.w.fwID}
			m.Addrs = slices.Clone(addrs[cd.w.tagWorkloadKey])
			sort.Slice(m.Addrs, func(i, j int) bool {
				if m.Addrs[i].Network != m.Addrs[j].Network {
					return m.Addrs[i].Network < m.Addrs[j].Network
				}
				return m.Addrs[i].Addr.Less(m.Addrs[j].Addr)
			})
			m.Addrs = slices.Compact(m.Addrs)
			for _, n := range cd.w.networks() {
				if g.BindsNetwork(n) {
					m.Bound = append(m.Bound, n)
				}
			}
			v.Members = append(v.Members, m)
		}
		out.Groups = append(out.Groups, v)
	}
	out.IdentityLost = identityLost(workloads, tags)
	return out, nil
}

// identityLost lists each live workload with no identity whose name a
// non-empty, readable tags row of its kind names while no live workload holds
// that row's identity (TagGroupMembership.IdentityLost), FWID the row's.
func identityLost(workloads []*tagWorkload, tags map[string]tagsRow) []TagWorkload {
	held := map[string]bool{}
	for _, w := range workloads {
		if w.fwID != "" {
			held[w.kind+"/"+w.fwID] = true
		}
	}
	orphans := map[string][]string{} // kind/name -> the identities its rows name
	for key, row := range tags {
		if held[key] || row.unreadable || len(row.tags) == 0 || row.name == "" {
			continue
		}
		kind, id, _ := strings.Cut(key, "/")
		orphans[kind+"/"+row.name] = append(orphans[kind+"/"+row.name], id)
	}
	var out []TagWorkload
	for _, w := range workloads {
		if w.fwID != "" {
			continue
		}
		ids := orphans[w.kind+"/"+w.name]
		slices.Sort(ids)
		for _, id := range ids {
			lost := w.public()
			lost.FWID = id
			out = append(out, lost)
		}
	}
	return out
}

// leaseElement parses a lease's address and checks it lies inside subnet. A
// lease keyed with its mask (written before normalisation) is its host
// address. Only an address of the subnet's family, with no zone, inside a
// parseable subnet qualifies; an IPv4-mapped IPv6 address never does.
func leaseElement(ip, subnet string) (netip.Addr, bool) {
	pfx, err := netip.ParsePrefix(subnet)
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		p, perr := netip.ParsePrefix(ip)
		if perr != nil {
			return netip.Addr{}, false
		}
		a = p.Addr()
	}
	// Contains refuses another family and a zoned address.
	if a.Is4In6() || !pfx.Masked().Contains(a) {
		return netip.Addr{}, false
	}
	return a, true
}

func (w *tagWorkload) networks() []string {
	var out []string
	for _, n := range w.nics {
		out = append(out, n.network)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (w *tagWorkload) public() TagWorkload {
	return TagWorkload{Kind: w.kind, Name: w.name, Host: w.host, FWID: w.fwID, On: w.on, Networks: w.networks()}
}

// readFirewallTagsRows reads every firewall-tags row, keyed "<kind>/<fw_id>".
// A row whose key names no kind, or no well-formed identity, is ignored, as
// ListFirewallTagsRows ignores it; a removed row ("") has no tags.
func readFirewallTagsRows(ctx context.Context, c *Client) (map[string]tagsRow, error) {
	lo, hi := keyRange(FirewallTagsKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key >= ? AND key < ? AND deleted_at IS NULL`, lo, hi)
	if err != nil {
		return nil, err
	}
	out := make(map[string]tagsRow, len(rows))
	for _, r := range rows {
		kind, id, ok := strings.Cut(strings.TrimPrefix(r.String("key"), FirewallTagsKeyPrefix), "/")
		if !ok || (kind != TagMemberVM && kind != TagMemberCT) || !ValidFirewallID(id) {
			continue
		}
		// One decoder for every reader (decodeFirewallTags): name and host
		// are for display only and never matched.
		rec := decodeFirewallTags(kind, id, r.String("value"), "", "")
		out[kind+"/"+id] = tagsRow{tags: rec.Tags, unreadable: rec.Unreadable, name: rec.Name}
	}
	return out, nil
}

// readTagWorkloads reads every live VM and container, in any state, with its
// firewall identity ("" when it has none, or one that is not well formed)
// and its live NICs.
func readTagWorkloads(ctx context.Context, c *Client) ([]*tagWorkload, error) {
	vms, err := c.Query(ctx, `SELECT name, COALESCE(host_name, '') AS host_name, spec FROM vms WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	cts, err := c.Query(ctx, `SELECT host_name, name, COALESCE(create_spec, '') AS create_spec,
		COALESCE(state, '') AS state, COALESCE(state_detail, '') AS state_detail,
		COALESCE(relocate_token, '') AS relocate_token FROM containers WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	nics, err := c.Query(ctx, `
		SELECT 'vm' AS kind, '' AS host, vm_name AS name, network_name AS network, mac FROM vm_nics WHERE deleted_at IS NULL
		UNION ALL
		SELECT 'vm', '', vm_name, network_name, mac FROM vm_interfaces WHERE deleted_at IS NULL
		UNION ALL
		SELECT 'ct', host_name, ct_name, network_name, mac FROM container_interfaces WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	byKey := map[tagWorkloadKey]*tagWorkload{}
	var out []*tagWorkload
	// The identity is read by firewallIDOf, as the mint and the writers read
	// it, so every reader sees the same holders.
	add := func(key tagWorkloadKey, fwID string) *tagWorkload {
		w := &tagWorkload{tagWorkloadKey: key, fwID: fwID}
		byKey[key] = w
		out = append(out, w)
		return w
	}
	for _, r := range vms {
		w := add(tagWorkloadKey{kind: TagMemberVM, name: r.String("name")}, firewallIDOf(TagMemberVM, r.String("spec")))
		w.on = r.String("host_name")
	}
	for _, r := range cts {
		w := add(tagWorkloadKey{kind: TagMemberCT, host: r.String("host_name"), name: r.String("name")}, firewallIDOf(TagMemberCT, r.String("create_spec")))
		w.on = w.host
		w.move = containerMove{host: w.host, name: w.name, state: r.String("state"),
			detail: r.String("state_detail"), token: r.String("relocate_token")}
	}
	for _, r := range nics {
		w, ok := byKey[tagWorkloadKey{kind: r.String("kind"), host: r.String("host"), name: r.String("name")}]
		mac := strings.ToLower(r.String("mac"))
		if !ok || mac == "" {
			continue
		}
		nic := tagNIC{network: r.String("network"), mac: mac}
		if !slices.Contains(w.nics, nic) {
			w.nics = append(w.nics, nic)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.kind != b.kind {
			return a.kind > b.kind // VMs first
		}
		if a.host != b.host {
			return a.host < b.host
		}
		return a.name < b.name
	})
	return out, nil
}

// jsonExactString returns the string member key of the JSON object doc,
// matched exactly: encoding/json's struct decoding also takes a key that
// differs only in case ("Firewall_ID"), which no writer produces.
func jsonExactString(doc, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(doc), &m) != nil {
		return ""
	}
	var s string
	if raw, ok := m[key]; !ok || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// tagCIDRTrimSet is every rune unicode.IsSpace holds, so the use probe's
// LTRIM, whose character set SQLite reads as UTF-8, removes what
// strings.TrimSpace removes ahead of the loader's tagRef (D5a re-review m-c).
var tagCIDRTrimSet = func() string {
	var b strings.Builder
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}()

// FirewallTagGroupsDataPresent reports whether this replica holds any data of
// the release feature firewall_tag_groups (spec DECISION 0-A): a group row or
// a firewall-tags row with a value, or a live rule whose cidr starts with the
// tag-group prefix in any case after the white space strings.TrimSpace
// removes, Unicode included (the loader's tagRef reads it so; tagCIDRTrimSet),
// as an entry daemon on an older build
// stores one verbatim. The release use sweep records the feature's use when it
// finds one (DECISION 0-F).
func FirewallTagGroupsDataPresent(ctx context.Context, c *Client) (bool, error) {
	for _, prefix := range []string{FirewallTagGroupKeyPrefix, FirewallTagsKeyPrefix} {
		lo, hi := keyRange(prefix)
		rows, err := c.Query(ctx,
			`SELECT 1 FROM cluster_policies
			 WHERE key >= ? AND key < ? AND deleted_at IS NULL AND value != '' LIMIT 1`, lo, hi)
		if err != nil {
			return false, err
		}
		if len(rows) > 0 {
			return true, nil
		}
	}
	for _, table := range []string{"cluster_firewall_rules", "host_firewall_rules", "sg_rules"} {
		rows, err := c.Query(ctx,
			`SELECT 1 FROM `+table+`
			 WHERE deleted_at IS NULL AND LTRIM(COALESCE(cidr, ''), ?) LIKE 'tag:%' LIMIT 1`, tagCIDRTrimSet)
		if err != nil {
			return false, err
		}
		if len(rows) > 0 {
			return true, nil
		}
	}
	return false, nil
}
