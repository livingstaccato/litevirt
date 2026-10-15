package corrosion

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func tagGroupGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups)
}

// tgID is a well-formed firewall identity: 32 lower-case hex characters.
func tgID(n int) string { return fmt.Sprintf("%032x", n) }

type tagGroupFixture struct {
	t   *testing.T
	ctx context.Context
	c   *Client
}

func newTagGroupFixture(t *testing.T) *tagGroupFixture {
	c := testClient(t)
	openClusterPolicyGate(c)
	f := &tagGroupFixture{t: t, ctx: context.Background(), c: c}
	f.network("prod", "10.0.0.0/24")
	f.network("dev", "10.1.0.0/24")
	return f
}

func (f *tagGroupFixture) network(name, subnet string) {
	mustExec(f.t, f.c, `INSERT INTO networks (name, type, config, created_at, updated_at) VALUES (?, 'bridge', ?, 't', 't')`,
		name, fmt.Sprintf(`{"Subnet":%q}`, subnet))
}

// vm inserts a live VM in state whose spec carries fwID (none when "") and
// the static address and litevirt.ip label that must never count.
func (f *tagGroupFixture) vm(name, fwID, state string) {
	spec := fmt.Sprintf(`{"name":%q,"labels":{"litevirt.ip":"10.0.0.77"},"network":[{"name":"prod","ip":"10.0.0.55"}]`, name)
	if fwID != "" {
		spec += fmt.Sprintf(`,"firewall_id":%q`, fwID)
	}
	spec += "}"
	mustExec(f.t, f.c, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, 'node-0', ?, ?, 't', 't')`,
		name, spec, state)
}

func (f *tagGroupFixture) vmNIC(table, vm, network, mac, ip string) {
	switch table {
	case "vm_nics":
		mustExec(f.t, f.c, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES (?, ?, ?, ?, 0, ?, 't')`,
			vm, network+"-"+mac, network, mac, ip)
	default:
		mustExec(f.t, f.c, `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, updated_at) VALUES (?, ?, 0, ?, ?, 't')`,
			vm, network, mac, ip)
	}
}

func (f *tagGroupFixture) ct(host, name, fwID, state string) {
	cs := `{"template":"debian"}`
	if fwID != "" {
		cs = fmt.Sprintf(`{"template":"debian","fw_id":%q}`, fwID)
	}
	mustExec(f.t, f.c, `INSERT INTO containers (host_name, name, state, create_spec, created_at, updated_at) VALUES (?, ?, ?, ?, 't', 't')`,
		host, name, state, cs)
}

func (f *tagGroupFixture) ctNIC(host, ct, network, mac, ip string) {
	mustExec(f.t, f.c, `INSERT INTO container_interfaces (host_name, ct_name, network_name, ordinal, mac, ip, updated_at) VALUES (?, ?, ?, 0, ?, ?, 't')`,
		host, ct, network, mac, ip)
}

func (f *tagGroupFixture) lease(network, ip, mac, kind, host, owner string) {
	mustExec(f.t, f.c, `INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 't', 't')`,
		network, ip, mac, owner, kind, host)
}

func (f *tagGroupFixture) policy(key, value string) {
	if err := f.c.Execute(f.ctx, clusterPolicyUpsertSQL, key, value, "test", f.c.NowTS()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *tagGroupFixture) tags(kind, fwID, value string) {
	f.policy("firewall_tags/"+kind+"/"+fwID, value)
}

func (f *tagGroupFixture) group(name string, def FirewallTagGroupDef) {
	f.t.Helper()
	if err := SetFirewallTagGroup(f.ctx, f.c, tagGroupGrant(f.t), name, &def, "alice"); err != nil {
		f.t.Fatal(err)
	}
}

func (f *tagGroupFixture) members() *TagGroupMembership {
	f.t.Helper()
	m, err := ListTagGroupMembers(f.ctx, f.c)
	if err != nil {
		f.t.Fatal(err)
	}
	return m
}

// view returns group's view; it fails the test when the group is absent.
func (m *TagGroupMembership) viewFor(t *testing.T, group string) TagGroupView {
	t.Helper()
	for _, v := range m.Groups {
		if v.Group.Name == group {
			return v
		}
	}
	t.Fatalf("group %q absent from %+v", group, m.Groups)
	return TagGroupView{}
}

// memberNames is "vm:<name>" / "ct:<host>:<name>" for each member, sorted.
func (v TagGroupView) memberNames() []string {
	var out []string
	for _, m := range v.Members {
		if m.Kind == TagMemberCT {
			out = append(out, "ct:"+m.Host+":"+m.Name)
		} else {
			out = append(out, "vm:"+m.Name)
		}
	}
	slices.Sort(out)
	return out
}

// addrs is every address of every member, "<network>=<addr>", sorted.
func (v TagGroupView) addrs() []string {
	var out []string
	for _, m := range v.Members {
		for _, a := range m.Addrs {
			out = append(out, a.Network+"="+a.Addr.String())
		}
	}
	slices.Sort(out)
	return out
}

func TestFirewallTagGroup_RoundTripAndEmptyRemoves(t *testing.T) {
	f := newTagGroupFixture(t)
	def := FirewallTagGroupDef{
		Match:          map[string]string{"role": "web", "env": ""},
		Networks:       []string{"prod", "dev", "prod"},
		SecurityGroups: []string{"web-in"},
	}
	f.group("web", def)
	g, ok, err := GetFirewallTagGroup(f.ctx, f.c, "web")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	want := FirewallTagGroupDef{
		Match:          map[string]string{"role": "web", "env": ""},
		Networks:       []string{"dev", "prod"},
		SecurityGroups: []string{"web-in"},
	}
	if g.Name != "web" || g.Unreadable || !reflect.DeepEqual(g.Def, want) || g.SetBy != "alice" || g.UpdatedAt == "" {
		t.Fatalf("round trip: %+v, want def %+v set by alice", g, want)
	}
	all, err := ListFirewallTagGroups(f.ctx, f.c)
	if err != nil || len(all) != 1 || all[0].Name != "web" {
		t.Fatalf("list: %+v err=%v", all, err)
	}

	if err := SetFirewallTagGroup(f.ctx, f.c, tagGroupGrant(t), "web", nil, "bob"); err != nil {
		t.Fatal(err)
	}
	raw, have, err := clusterPolicyValue(f.ctx, f.c, "firewall_tag_group/web")
	if err != nil || !have || raw != "" {
		t.Fatalf("removal stores %q (have=%v err=%v), want the empty value", raw, have, err)
	}
	if _, ok, err := GetFirewallTagGroup(f.ctx, f.c, "web"); ok || err != nil {
		t.Fatalf("removed group still read: ok=%v err=%v", ok, err)
	}
	if all, err := ListFirewallTagGroups(f.ctx, f.c); err != nil || len(all) != 0 {
		t.Fatalf("removed group still listed: %+v err=%v", all, err)
	}
}

func TestFirewallTagGroup_WriterRefuses(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	good := &FirewallTagGroupDef{Match: map[string]string{"role": "web"}}
	if err := SetFirewallTagGroup(ctx, c, tagGroupGrant(t), "web", good, "alice"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("gate closed: %v, want ErrClusterPolicyGateClosed", err)
	}
	openClusterPolicyGate(c)
	for name, g := range map[string]capabilities.FeatureGrant{
		"no grant":          {},
		"another feature's": capabilities.GrantForTest(t, capabilities.FeatureFirewallLog),
	} {
		if err := SetFirewallTagGroup(ctx, c, g, "web", good, "alice"); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s: %v, want ErrNoFeatureGrant", name, err)
		}
		if err := SetFirewallTagGroup(ctx, c, g, "web", nil, "alice"); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s removal: %v, want ErrNoFeatureGrant", name, err)
		}
	}
	for name, tc := range map[string]struct {
		group string
		def   *FirewallTagGroupDef
	}{
		"empty name":          {"", good},
		"upper-case name":     {"Web", good},
		"name with a dash":    {"web-1", good},
		"name starts digit":   {"1web", good},
		"name too long":       {"a234567890123456789012345678901x", good},
		"nft injection":       {"web;flush", good},
		"removal, bad name":   {"web}", nil},
		"no match":            {"web", &FirewallTagGroupDef{}},
		"bad match key":       {"web", &FirewallTagGroupDef{Match: map[string]string{"Role": "web"}}},
		"bad match value":     {"web", &FirewallTagGroupDef{Match: map[string]string{"role": "we b"}}},
		"empty network":       {"web", &FirewallTagGroupDef{Match: map[string]string{"role": "web"}, Networks: []string{""}}},
		"empty sg":            {"web", &FirewallTagGroupDef{Match: map[string]string{"role": "web"}, SecurityGroups: []string{""}}},
		"key starts with _":   {"web", &FirewallTagGroupDef{Match: map[string]string{"_role": "web"}}},
		"value starts with -": {"web", &FirewallTagGroupDef{Match: map[string]string{"role": "-web"}}},
	} {
		if err := SetFirewallTagGroup(ctx, c, tagGroupGrant(t), tc.group, tc.def, "alice"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if all, err := ListFirewallTagGroups(ctx, c); err != nil || len(all) != 0 {
		t.Fatalf("a refused write left rows: %+v err=%v", all, err)
	}
	// The longest name the grammar takes is accepted.
	if err := SetFirewallTagGroup(ctx, c, tagGroupGrant(t), "a234567890123456789012345678901", good, "alice"); err != nil {
		t.Fatalf("31-character name: %v", err)
	}
}

// Decoding is lenient (m-6): an unknown field is ignored; only malformed JSON
// or a field of the wrong type makes a row unreadable. A selector that could
// match nothing it was written for (no match, or one outside the grammar) is
// unreadable too, so it neither admits nor silently drops.
func TestFirewallTagGroup_GarbageReadsUnreadable(t *testing.T) {
	f := newTagGroupFixture(t)
	f.vm("web-1", tgID(1), "running")
	f.vmNIC("vm_interfaces", "web-1", "prod", "52:54:00:00:00:01", "")
	f.lease("prod", "10.0.0.5", "52:54:00:00:00:01", "vm", "", "web-1")
	f.tags("vm", tgID(1), `{"tags":{"role":"web"},"name":"web-1"}`)

	for value, wantUnreadable := range map[string]bool{
		`{"match":`:            true,
		`not json`:             true,
		`{"match":{"role":1}}`: true,
		`{"match":"role=web"}`: true,
		`{"match":{"role":"web"},"networks":"prod"}`:   true,
		`{"match":{"role":"web"},"security_groups":7}`: true,
		`{"match":{}}`:             true,
		`{}`:                       true,
		`null`:                     true,
		`{"match":{"Role":"web"}}`: true,
		`{"match":{"role":"web"},"future_field":{"x":[1,2]}}`: false,
		`{"match":{"role":"web"}}`:                            false,
	} {
		f.policy("firewall_tag_group/web", value)
		g, ok, err := GetFirewallTagGroup(f.ctx, f.c, "web")
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", value, ok, err)
		}
		if g.Unreadable != wantUnreadable {
			t.Errorf("%s: unreadable=%v, want %v", value, g.Unreadable, wantUnreadable)
		}
		v := f.members().viewFor(t, "web")
		if v.Group.Unreadable != wantUnreadable {
			t.Errorf("%s: member view unreadable=%v, want %v", value, v.Group.Unreadable, wantUnreadable)
		}
		if wantUnreadable && len(v.Members) != 0 {
			t.Errorf("%s: an unreadable group has members %v", value, v.memberNames())
		}
		if !wantUnreadable && !slices.Equal(v.addrs(), []string{"prod=10.0.0.5"}) {
			t.Errorf("%s: addrs %v, want the lease", value, v.addrs())
		}
	}

	// A key whose name is outside the grammar is unreadable, never a set name.
	f.policy("firewall_tag_group/web;x", `{"match":{"role":"web"}}`)
	g, ok, err := GetFirewallTagGroup(f.ctx, f.c, "web;x")
	if err != nil || !ok || !g.Unreadable {
		t.Fatalf("bad key name: %+v ok=%v err=%v, want unreadable", g, ok, err)
	}
}

// Members are every live VM and container whose firewall tags match, in any
// state (DECISION T-5); a deleted workload is not one.
func TestTagGroupMembers_VMsAndContainersInEveryState(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	n := 0
	for _, state := range []string{"running", "stopped", "creating", "error", "paused", "migrating", "unknown"} {
		n++
		name := "vm-" + state
		mac := fmt.Sprintf("52:54:00:00:01:%02x", n)
		ip := fmt.Sprintf("10.0.0.%d", 10+n)
		f.vm(name, tgID(n), state)
		f.vmNIC("vm_nics", name, "prod", mac, "")
		f.lease("prod", ip, mac, "vm", "", name)
		f.tags("vm", tgID(n), `{"tags":{"role":"web"}}`)
	}
	for _, state := range []string{"running", "stopped", "frozen", "error"} {
		n++
		name := "ct-" + state
		mac := fmt.Sprintf("00:16:3e:00:01:%02x", n)
		ip := fmt.Sprintf("10.0.0.%d", 10+n)
		f.ct("node-1", name, tgID(n), state)
		f.ctNIC("node-1", name, "prod", mac, "")
		f.lease("prod", ip, mac, "ct", "node-1", name)
		f.tags("ct", tgID(n), `{"tags":{"role":"web"}}`)
	}
	// Deleted: tagged, leased, but tombstoned.
	n++
	f.vm("vm-deleted", tgID(n), "stopped")
	f.vmNIC("vm_nics", "vm-deleted", "prod", "52:54:00:00:02:01", "")
	f.lease("prod", "10.0.0.200", "52:54:00:00:02:01", "vm", "", "vm-deleted")
	f.tags("vm", tgID(n), `{"tags":{"role":"web"}}`)
	mustExec(t, f.c, `UPDATE vms SET deleted_at = 't' WHERE name = 'vm-deleted'`)
	n++
	f.ct("node-1", "ct-deleted", tgID(n), "stopped")
	f.ctNIC("node-1", "ct-deleted", "prod", "00:16:3e:00:02:01", "")
	f.lease("prod", "10.0.0.201", "00:16:3e:00:02:01", "ct", "node-1", "ct-deleted")
	f.tags("ct", tgID(n), `{"tags":{"role":"web"}}`)
	mustExec(t, f.c, `UPDATE containers SET deleted_at = 't' WHERE name = 'ct-deleted'`)
	// Untagged and differently tagged workloads are not members.
	n++
	f.vm("vm-db", tgID(n), "running")
	f.vmNIC("vm_nics", "vm-db", "prod", "52:54:00:00:03:01", "")
	f.lease("prod", "10.0.0.202", "52:54:00:00:03:01", "vm", "", "vm-db")
	f.tags("vm", tgID(n), `{"tags":{"role":"db"}}`)
	n++
	f.vm("vm-untagged", tgID(n), "running")
	f.vmNIC("vm_nics", "vm-untagged", "prod", "52:54:00:00:03:02", "")
	f.lease("prod", "10.0.0.203", "52:54:00:00:03:02", "vm", "", "vm-untagged")
	f.tags("vm", tgID(n), "")

	v := f.members().viewFor(t, "web")
	want := []string{
		"ct:node-1:ct-error", "ct:node-1:ct-frozen", "ct:node-1:ct-running", "ct:node-1:ct-stopped",
		"vm:vm-creating", "vm:vm-error", "vm:vm-migrating", "vm:vm-paused", "vm:vm-running", "vm:vm-stopped", "vm:vm-unknown",
	}
	if got := v.memberNames(); !slices.Equal(got, want) {
		t.Fatalf("members %v, want %v", got, want)
	}
	var wantAddrs []string
	for i := 1; i <= 11; i++ {
		wantAddrs = append(wantAddrs, fmt.Sprintf("prod=10.0.0.%d", 10+i))
	}
	slices.Sort(wantAddrs)
	if got := v.addrs(); !slices.Equal(got, wantAddrs) {
		t.Fatalf("addrs %v, want %v", got, wantAddrs)
	}
	for _, m := range v.Members {
		if m.Kind == TagMemberCT && (m.Host != "node-1" || m.FWID == "") {
			t.Errorf("container member %+v: want host node-1 and its fw_id", m)
		}
		if m.Kind == TagMemberVM && (m.Host != "" || m.FWID == "") {
			t.Errorf("VM member %+v: want no host and its fw_id", m)
		}
	}
}

// C-2: only live allocator leases count, matched to a live NIC of the member
// on the lease's network by MAC, and owned by that member. Nothing the guest,
// vm.update or a guard record can write counts.
func TestTagGroupMembers_OnlyAllocatorLeasesMatchedByMACAndOwner(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	const mac = "52:54:00:aa:00:01"
	f.vm("web-1", tgID(1), "running")
	f.tags("vm", tgID(1), `{"tags":{"role":"web"},"name":"web-1"}`)
	f.vmNIC("vm_interfaces", "web-1", "prod", mac, "")
	f.vmNIC("vm_nics", "web-1", "dev", "52:54:00:aa:00:02", "10.1.0.98") // NIC row ip: never counts
	f.lease("prod", "10.0.0.5", "52:54:00:AA:00:01", "vm", "", "web-1")  // the one lease (MAC case differs)

	// SetVMIP and guest discovery both write the NIC row's ip.
	if err := UpdateVMInterfaceIP(f.ctx, f.c, "web-1", "prod", "10.0.0.99"); err != nil {
		t.Fatal(err)
	}
	// A guard's Known and Allowed.
	f.policy(nicGuardKeyPrefix+"web-1/"+mac, `{"mode":"on","allowed":["10.0.0.66"],"known":["10.0.0.65"]}`)

	// Leases that must not count.
	f.lease("prod", "10.0.0.20", "52:54:00:aa:00:09", "vm", "", "web-1") // MAC of no NIC of web-1
	f.lease("dev", "10.1.0.21", mac, "vm", "", "web-1")                  // web-1's prod MAC, on dev
	f.lease("prod", "10.0.0.22", mac, "vm", "", "web-2")                 // web-1's MAC, another owner
	f.lease("prod", "10.0.0.23", mac, "ct", "", "web-1")                 // a container named web-1
	f.lease("prod", "10.0.0.24", mac, "vm", "node-0", "web-1")           // a VM lease never has a host
	f.lease("prod", "10.0.0.25", mac, "VM", "", "web-1")                 // kind is exact
	f.lease("prod", "10.0.0.26", "", "vm", "", "web-1")                  // no MAC
	f.lease("prod", "10.0.0.27", mac, "vm", "", "web-1")                 // released below
	mustExec(t, f.c, `UPDATE ip_allocations SET deleted_at = 't' WHERE ip = '10.0.0.27'`)
	f.vmNIC("vm_nics", "web-1", "prod", "52:54:00:aa:00:03", "") // NIC removed below
	f.lease("prod", "10.0.0.28", "52:54:00:aa:00:03", "vm", "", "web-1")
	mustExec(t, f.c, `UPDATE vm_nics SET deleted_at = 't' WHERE mac = '52:54:00:aa:00:03'`)

	// A container: its lease must name its host.
	f.ct("node-1", "cache-1", tgID(2), "running")
	f.tags("ct", tgID(2), `{"tags":{"role":"web"},"name":"cache-1","host":"node-1"}`)
	f.ctNIC("node-1", "cache-1", "prod", "00:16:3e:00:00:01", "10.0.0.97") // NIC row ip: never counts
	f.lease("prod", "10.0.0.30", "00:16:3e:00:00:01", "ct", "node-1", "cache-1")
	f.lease("prod", "10.0.0.31", "00:16:3e:00:00:01", "ct", "node-2", "cache-1") // another host's cache-1
	f.lease("prod", "10.0.0.32", "00:16:3e:00:00:01", "vm", "", "cache-1")       // a VM named cache-1
	// A same-name container on another host with the member's MAC is not a member.
	f.ct("node-2", "cache-1", "", "running")
	f.ctNIC("node-2", "cache-1", "prod", "00:16:3e:00:00:01", "")

	v := f.members().viewFor(t, "web")
	if got, want := v.addrs(), []string{"prod=10.0.0.30", "prod=10.0.0.5"}; !slices.Equal(got, want) {
		t.Fatalf("addrs %v, want %v", got, want)
	}
	if got, want := v.memberNames(), []string{"ct:node-1:cache-1", "vm:web-1"}; !slices.Equal(got, want) {
		t.Fatalf("members %v, want %v", got, want)
	}
}

// An element outside the network's subnet, or one that does not parse, is
// skipped and counted; a legacy lease keyed with its mask is its host address.
func TestTagGroupMembers_SkipsUnparsedAndOutsideSubnet(t *testing.T) {
	f := newTagGroupFixture(t)
	f.network("nosubnet", "")
	f.network("badsubnet", "10.2.0.0/33")
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	f.vm("web-1", tgID(1), "running")
	f.tags("vm", tgID(1), `{"tags":{"role":"web"}}`)
	const mac = "52:54:00:bb:00:01"
	for _, n := range []string{"prod", "nosubnet", "badsubnet", "gone"} {
		f.vmNIC("vm_nics", "web-1", n, mac, "")
	}
	for _, ip := range []string{
		"10.0.0.5",        // counts
		"10.0.0.6/24",     // legacy masked key: counts as 10.0.0.6
		"10.9.9.9",        // outside the subnet
		"garbage",         // does not parse
		"10.0.0.7 ",       // does not parse
		"::ffff:10.0.0.8", // not an IPv4 address
		"fd00::1",         // another family
		"",                // empty
		"10.0.0.9/33",     // bad mask
	} {
		f.lease("prod", ip, mac, "vm", "", "web-1")
	}
	f.lease("nosubnet", "10.0.0.10", mac, "vm", "", "web-1")
	f.lease("badsubnet", "10.2.0.1", mac, "vm", "", "web-1")
	f.lease("gone", "10.0.0.11", mac, "vm", "", "web-1") // no network row

	m := f.members()
	v := m.viewFor(t, "web")
	if got, want := v.addrs(), []string{"prod=10.0.0.5", "prod=10.0.0.6"}; !slices.Equal(got, want) {
		t.Fatalf("addrs %v, want %v", got, want)
	}
	if m.Skipped != 10 {
		t.Fatalf("skipped %d, want 10", m.Skipped)
	}
	for _, a := range v.Members[0].Addrs {
		if !a.Addr.Is4() || a.Addr.Zone() != "" || !netip.MustParsePrefix("10.0.0.0/24").Contains(a.Addr) {
			t.Fatalf("element %v", a)
		}
	}
}

// --network limits the group binding to the networks named; with none, every
// network. The address set is cluster-wide whatever it says (§4.2).
func TestTagGroupMembers_NetworkFilter(t *testing.T) {
	f := newTagGroupFixture(t)
	f.network("lab", "10.3.0.0/24")
	f.group("webprod", FirewallTagGroupDef{Match: map[string]string{"role": "web"}, Networks: []string{"prod", "lab"}, SecurityGroups: []string{"web-in"}})
	f.group("weball", FirewallTagGroupDef{Match: map[string]string{"role": "web"}, SecurityGroups: []string{"web-in"}})
	f.vm("web-1", tgID(1), "running")
	f.tags("vm", tgID(1), `{"tags":{"role":"web"}}`)
	f.vmNIC("vm_nics", "web-1", "prod", "52:54:00:cc:00:01", "")
	f.vmNIC("vm_interfaces", "web-1", "dev", "52:54:00:cc:00:02", "")
	f.lease("prod", "10.0.0.5", "52:54:00:cc:00:01", "vm", "", "web-1")
	f.lease("dev", "10.1.0.5", "52:54:00:cc:00:02", "vm", "", "web-1")

	m := f.members()
	for group, wantBound := range map[string][]string{
		"webprod": {"prod"},
		"weball":  {"dev", "prod"},
	} {
		v := m.viewFor(t, group)
		if len(v.Members) != 1 {
			t.Fatalf("%s: members %v", group, v.memberNames())
		}
		if got := v.Members[0].Bound; !slices.Equal(got, wantBound) {
			t.Errorf("%s: bound %v, want %v", group, got, wantBound)
		}
		if got, want := v.addrs(), []string{"dev=10.1.0.5", "prod=10.0.0.5"}; !slices.Equal(got, want) {
			t.Errorf("%s: addrs %v, want %v", group, got, want)
		}
	}
	g := m.viewFor(t, "webprod").Group
	if !g.BindsNetwork("prod") || g.BindsNetwork("dev") || !m.viewFor(t, "weball").Group.BindsNetwork("dev") {
		t.Fatal("BindsNetwork")
	}
}

// Membership is decided ONLY by the firewall identity: no name is matched, a
// row keyed by another kind or another id grants nothing, an id two live
// workloads carry admits neither, and an unreadable tags row admits nothing
// and is reported.
func TestTagGroupMembers_IdentityOnly(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web", "env": ""}})
	add := func(name, fwID string, n int) {
		mac := fmt.Sprintf("52:54:00:dd:00:%02x", n)
		f.vm(name, fwID, "running")
		f.vmNIC("vm_nics", name, "prod", mac, "")
		f.lease("prod", fmt.Sprintf("10.0.0.%d", n), mac, "vm", "", name)
	}
	add("ok", tgID(1), 1)
	f.tags("vm", tgID(1), `{"tags":{"role":"web","env":"prod"},"name":"ok"}`)
	add("noid", "", 2) // a row naming it, under no id it carries
	f.tags("vm", tgID(2), `{"tags":{"role":"web","env":"x"},"name":"noid"}`)
	add("badid", "NOT-HEX", 3)
	f.tags("vm", "NOT-HEX", `{"tags":{"role":"web","env":"x"}}`)
	add("upperid", "ABCDEF0123456789ABCDEF0123456789", 4)
	f.tags("vm", "ABCDEF0123456789ABCDEF0123456789", `{"tags":{"role":"web","env":"x"}}`)
	add("ctrow", tgID(5), 5) // its id's row is a container's
	f.tags("ct", tgID(5), `{"tags":{"role":"web","env":"x"}}`)
	add("dup-a", tgID(6), 6)
	add("dup-b", tgID(6), 7)
	f.tags("vm", tgID(6), `{"tags":{"role":"web","env":"x"}}`)
	add("garbled", tgID(8), 8)
	f.tags("vm", tgID(8), `{"tags":{"role":"web",`)
	add("wrongtype", tgID(9), 9)
	f.tags("vm", tgID(9), `{"tags":["role=web"]}`)
	add("nokey", tgID(10), 10) // lacks env
	f.tags("vm", tgID(10), `{"tags":{"role":"web"}}`)
	add("future", tgID(11), 11) // an unknown field is ignored
	f.tags("vm", tgID(11), `{"tags":{"role":"web","env":"y"},"later":1}`)
	add("removed", tgID(12), 12)
	f.tags("vm", tgID(12), "")
	add("notags", tgID(13), 13)
	add("casekey", "", 14) // its id under a key differing only in case
	mustExec(t, f.c, `UPDATE vms SET spec = ? WHERE name = 'casekey'`, fmt.Sprintf(`{"name":"casekey","Firewall_ID":%q}`, tgID(14)))
	f.tags("vm", tgID(14), `{"tags":{"role":"web","env":"x"}}`)

	m := f.members()
	v := m.viewFor(t, "web")
	if got, want := v.memberNames(), []string{"vm:future", "vm:ok"}; !slices.Equal(got, want) {
		t.Fatalf("members %v, want %v", got, want)
	}
	var unreadable, shared []string
	for _, w := range m.TagsUnreadable {
		unreadable = append(unreadable, w.Name)
	}
	for _, w := range m.SharedFWID {
		shared = append(shared, w.Name)
	}
	slices.Sort(unreadable)
	slices.Sort(shared)
	if want := []string{"garbled", "wrongtype"}; !slices.Equal(unreadable, want) {
		t.Errorf("tags unreadable %v, want %v", unreadable, want)
	}
	if want := []string{"dup-a", "dup-b"}; !slices.Equal(shared, want) {
		t.Errorf("shared fw_id %v, want %v", shared, want)
	}
	for _, w := range m.TagsUnreadable {
		if !slices.Equal(w.Networks, []string{"prod"}) {
			t.Errorf("%s: networks %v, want its NIC networks", w.Name, w.Networks)
		}
	}
}

// A member with no qualifying lease is still a member, with no address.
func TestTagGroupMembers_MemberWithoutLease(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	f.vm("web-1", tgID(1), "stopped")
	f.vmNIC("vm_nics", "web-1", "prod", "52:54:00:ee:00:01", "10.0.0.5")
	f.tags("vm", tgID(1), `{"tags":{"role":"web"}}`)
	v := f.members().viewFor(t, "web")
	if len(v.Members) != 1 || len(v.Members[0].Addrs) != 0 || !slices.Equal(v.Members[0].Bound, []string{"prod"}) {
		t.Fatalf("members %+v, want web-1 with no address, bound on prod", v.Members)
	}
}

// No member query runs when no group exists: with the lease table gone, a
// query would fail.
func TestTagGroupMembers_NoQueryWithoutGroup(t *testing.T) {
	f := newTagGroupFixture(t)
	mustExec(t, f.c, `DROP TABLE ip_allocations`)
	m, err := ListTagGroupMembers(f.ctx, f.c)
	if err != nil || len(m.Groups) != 0 {
		t.Fatalf("no group: %+v err=%v, want nothing and no query", m, err)
	}
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	if _, err := ListTagGroupMembers(f.ctx, f.c); err == nil {
		t.Fatal("with a group the member query must run (and fail here)")
	}
}

// The group rows are firewall_tag_groups data: their writer is listed under
// the feature, so a minted group records the use (release_guard_test checks a
// listed writer takes and Checks the grant).
func TestSetFirewallTagGroup_ListedAsFeatureWriter(t *testing.T) {
	info, ok := capabilities.LookupFeature(capabilities.FeatureFirewallTagGroups)
	if !ok || !slices.Contains(info.Writers, "internal/corrosion.SetFirewallTagGroup") {
		t.Fatalf("firewall_tag_groups writers %v: SetFirewallTagGroup is not listed", info.Writers)
	}
}
