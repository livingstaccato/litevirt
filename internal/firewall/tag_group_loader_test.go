package firewall

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// tgLab is a replica holding tag groups, firewall tags and the workloads they
// select, written as replicated rows.
type tgLab struct {
	t   *testing.T
	ctx context.Context
	db  *corrosion.Client
	now time.Time
	run map[string]map[string]string // VM -> MAC -> tap, for RunningTaps
}

func newTGLab(t *testing.T) *tgLab {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	l := &tgLab{t: t, ctx: ctx, db: db, now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), run: map[string]map[string]string{}}
	l.network("prod", "10.0.0.0/24")
	l.network("dev", "10.1.0.0/24")
	l.network("prod6", "fd00:1::/64")
	return l
}

func tgFWID(n int) string { return fmt.Sprintf("%032x", n) }

func (l *tgLab) network(name, subnet string) {
	rawRow(l.t, l.db, `INSERT INTO networks (name, type, config, created_at, updated_at) VALUES (?, 'bridge', ?, 't', 't')`,
		name, fmt.Sprintf(`{"Subnet":%q}`, subnet))
}

// vm is a running VM on host with identity fwID ("" none).
func (l *tgLab) vm(name, host, fwID string) {
	spec := fmt.Sprintf(`{"name":%q`, name)
	if fwID != "" {
		spec += fmt.Sprintf(`,"firewall_id":%q`, fwID)
	}
	rawRow(l.t, l.db, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, ?, ?, 'running', 't', 't')`,
		name, host, spec+"}")
}

// nic gives VM vm a NIC on network, running on tap, bound to sgs, holding
// the lease ip ("" none).
func (l *tgLab) nic(vm, network, mac, tap, ip string, sgs ...string) {
	groups := "[]"
	if len(sgs) > 0 {
		groups = `["` + strings.Join(sgs, `","`) + `"]`
	}
	rawRow(l.t, l.db, `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, tap_device, security_groups, updated_at)
		VALUES (?, ?, 0, ?, ?, ?, ?, 't')`, vm, network, mac, ip, tap, groups)
	if l.run[vm] == nil {
		l.run[vm] = map[string]string{}
	}
	l.run[vm][mac] = tap
	if ip != "" {
		l.lease(network, ip, mac, "vm", "", vm)
	}
}

func (l *tgLab) lease(network, ip, mac, kind, host, owner string) {
	rawRow(l.t, l.db, `INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 't', 't')`, network, ip, mac, owner, kind, host)
}

// ct is a container on host with identity fwID ("" none): running, or
// relocating when detail is a relocation marker; token is its relocate_token.
func (l *tgLab) ct(host, name, fwID, detail, token string) {
	state := "running"
	if strings.HasPrefix(detail, corrosion.ContainerRelocateRestorePrefix) {
		state = "relocating"
	}
	cs := `{"template":"debian"}`
	if fwID != "" {
		cs = fmt.Sprintf(`{"template":"debian","fw_id":%q}`, fwID)
	}
	rawRow(l.t, l.db, `INSERT INTO containers (host_name, name, state, state_detail, relocate_token, create_spec, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 't', 't')`, host, name, state, detail, token, cs)
}

func (l *tgLab) ctNIC(host, ct, network, mac, veth, ip string, sgs ...string) {
	groups := "[]"
	if len(sgs) > 0 {
		groups = `["` + strings.Join(sgs, `","`) + `"]`
	}
	rawRow(l.t, l.db, `INSERT INTO container_interfaces (host_name, ct_name, network_name, ordinal, mac, ip, veth_device, security_groups, updated_at)
		VALUES (?, ?, ?, 0, ?, ?, ?, ?, 't')`, host, ct, network, mac, ip, veth, groups)
	if ip != "" {
		l.lease(network, ip, mac, "ct", host, ct)
	}
}

func (l *tgLab) policy(key, value string) {
	rawRow(l.t, l.db, `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'test', 't')`, key, value)
}

func (l *tgLab) group(name, def string) { l.policy(corrosion.FirewallTagGroupKeyPrefix+name, def) }

func (l *tgLab) tags(kind, fwID, value string) {
	l.policy(corrosion.FirewallTagsKeyPrefix+kind+"/"+fwID, value)
}

func (l *tgLab) sg(id, name string, rules ...[4]string) {
	rawRow(l.t, l.db, `INSERT INTO security_groups (id, name, created_at, updated_at) VALUES (?, ?, 't', 't')`, id, name)
	for i, r := range rules {
		rawRow(l.t, l.db, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, created_at, updated_at)
			VALUES (?, ?, 'ingress', ?, ?, ?, ?, 't', 't')`, fmt.Sprintf("%s-r%d", id, i), id, r[0], r[1], r[2], r[3])
	}
}

func (l *tgLab) clusterRule(id, proto, port, cidr, action string) {
	rawRow(l.t, l.db, `INSERT INTO cluster_firewall_rules
		(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES (?, 'ingress', ?, ?, ?, ?, 100, '', '', 't', 't')`, id, proto, port, cidr, action)
}

// loader is host's production loader on this replica, its clock l.now.
func (l *tgLab) loader(host string, members *map[string]int) PlanLoader {
	opts := LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) { return l.run, nil },
		Now:         func() time.Time { return l.now },
	}
	if members != nil {
		opts.OnTagGroupMembers = func(m map[string]int) { *members = m }
	}
	return CorrosionPlanLoader(l.db, host, Plan{}, opts)
}

func (l *tgLab) load(p PlanLoader) (Plan, string) {
	l.t.Helper()
	plan, err := p(l.ctx)
	if err != nil {
		l.t.Fatalf("loader: %v", err)
	}
	script, err := Render(plan)
	if err != nil {
		l.t.Fatalf("Render: %v", err)
	}
	return plan, script
}

func planNIC(t *testing.T, p Plan, dev string) NICBinding {
	t.Helper()
	for _, n := range p.NICs {
		if n.NICDev == dev {
			return n
		}
	}
	t.Fatalf("no NIC %s in the plan", dev)
	return NICBinding{}
}

// heldAtDrop reports whether a NIC binding is a hold: no group rendered,
// every new frame dropped both ways.
func heldAtDrop(n NICBinding) bool {
	if len(n.SecurityGroups) != 0 || len(n.ExtraRules) != 2 {
		return false
	}
	for _, r := range n.ExtraRules {
		if r.Action != Drop || r.CIDR != "" || (r.Proto != "all" && r.Proto != "") {
			return false
		}
	}
	return true
}

func setElems(p Plan, name string) []string {
	var out []string
	for _, s := range p.IPSets {
		if s.Name == name {
			out = append(out, s.CIDRs...)
		}
	}
	slices.Sort(out)
	return out
}

func hasSet(p Plan, name string) bool {
	for _, s := range p.IPSets {
		if s.Name == name {
			return true
		}
	}
	return false
}

const webGroup = `{"match":{"role":"web"},"networks":[],"security_groups":[]}`

// Each group becomes the set lv_tg_<name> holding its members' leased
// addresses, v4 and v6 (the v6 ones in the _v6 companion), and a rule's
// tag:<name> is rewritten to @lv_tg_<name> before validate: the rule renders,
// in every tier, and is not reported invalid.
//
// Mutations: no rewrite (the rows are judged as IPv6 literals and left out)
// — red; drop the v6 members — red; declare no set — red (Render refuses).
func TestTagGroupLoader_SetsAndRewrite(t *testing.T) {
	l := newTGLab(t)
	l.group("web", webGroup)
	l.vm("web-1", "host-a", tgFWID(1))
	l.nic("web-1", "prod", "52:54:00:00:00:01", "tap1", "10.0.0.5")
	l.lease("prod6", "fd00:1::5", "52:54:00:00:00:06", "vm", "", "web-1")
	rawRow(t, l.db, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('web-1', 'n6', 'prod6', '52:54:00:00:00:06', 1, '', 't')`)
	l.tags("vm", tgFWID(1), `{"tags":{"role":"web"}}`)
	l.ct("host-b", "web-c", tgFWID(2), "", "")
	l.ctNIC("host-b", "web-c", "prod", "00:16:3e:00:00:02", "veth2", "10.0.0.7")
	l.tags("ct", tgFWID(2), `{"tags":{"role":"web"}}`)
	l.vm("db", "host-a", "")
	l.nic("db", "prod", "52:54:00:00:00:09", "tap9", "10.0.0.9", "db")
	l.sg("sg-db", "db", [4]string{"tcp", "5432", "tag:web", "accept"}, [4]string{"tcp", "22", "tag:web", "drop"})
	l.clusterRule("c1", "tcp", "443", "tag:web", "accept")

	var members map[string]int
	plan, script := l.load(l.loader("host-a", &members))
	if got, want := setElems(plan, "lv_tg_web"), []string{"10.0.0.5", "10.0.0.7", "fd00:1::5"}; !slices.Equal(got, want) {
		t.Errorf("lv_tg_web = %v, want %v", got, want)
	}
	if len(plan.InvalidRows) != 0 {
		t.Errorf("a tag: rule was judged as written: %+v", plan.InvalidRows)
	}
	mustContainAll(t, script,
		"set lv_tg_web {", "set lv_tg_web_v6 {", "elements = { 10.0.0.5, 10.0.0.7 }", "elements = { fd00:1::5 }",
		"tcp dport 443 ip saddr @lv_tg_web accept", "tcp dport 443 ip6 saddr @lv_tg_web_v6 accept",
		"oifname tap9 tcp dport 5432 ip saddr @lv_tg_web accept", "oifname tap9 tcp dport 22 ip6 saddr @lv_tg_web_v6 counter",
	)
	if strings.Contains(script, "tag:") {
		t.Errorf("the script holds a tag: cidr:\n%s", script)
	}
	if members["web"] != 2 {
		t.Errorf("members metric %v, want web=2", members)
	}
	if plan.TagGroups.Members["web"] != 2 {
		t.Errorf("report members %v, want web=2", plan.TagGroups.Members)
	}
}

// A rule naming a group this replica does not hold: an accept renders against
// an empty set (it matches nothing), a drop or reject without its address
// match (it denies everything else it names). The condition names each rule
// once that has lasted emptySetGrace. A group row that cannot be read is
// handled the same, and named at once.
//
// Mutations: render a drop on a missing group against the empty set — red;
// let a negated reference take the empty set for a whole one — red.
func TestTagGroupLoader_MissingAndUnreadableGroups(t *testing.T) {
	l := newTGLab(t)
	l.group("bad", `{"match":`)
	l.clusterRule("c-acc", "tcp", "80", "tag:gone", "accept")
	l.clusterRule("c-drop", "tcp", "22", "tag:gone", "drop")
	l.clusterRule("c-rej", "udp", "53", "tag:bad", "reject")
	l.clusterRule("c-bad-acc", "tcp", "81", "tag:bad", "accept")
	// "Not in" the empty set a missing group's accept is rendered against
	// would be every address: such a reference is never rendered.
	l.clusterRule("c-neg", "tcp", "82", "!= @lv_tg_gone", "accept")
	load := l.loader("host-a", nil)

	plan, script := l.load(load)
	mustContainAll(t, script,
		"set lv_tg_gone {", "tcp dport 80 ip saddr @lv_tg_gone accept",
		"tcp dport 22 drop", "udp dport 53 reject", "tcp dport 81 ip saddr @lv_tg_bad accept")
	for _, bad := range []string{"saddr @lv_tg_gone drop", "saddr @lv_tg_bad reject"} {
		if strings.Contains(script, bad) {
			t.Errorf("a deny on a missing group matched its (empty) set: %q", bad)
		}
	}
	if setElems(plan, "lv_tg_gone") != nil || setElems(plan, "lv_tg_bad") != nil {
		t.Error("a missing or unreadable group's set has elements")
	}
	if strings.Contains(script, "dport 82") {
		t.Errorf("a negated reference to a missing group's empty set was rendered:\n%s", script)
	}
	if len(plan.InvalidRows) != 1 || plan.InvalidRows[0].ID != "c-neg" {
		t.Errorf("invalid rows %+v, want only c-neg", plan.InvalidRows)
	}
	rep := plan.TagGroups
	if len(rep.Missing) != 0 {
		t.Errorf("missing reported before the grace: %+v", rep.Missing)
	}
	if got := refIDs(rep.Unreadable); !slices.Equal(got, []string{"bad:", "bad:c-bad-acc", "bad:c-rej"}) {
		t.Errorf("unreadable %v (%+v)", got, rep.Unreadable)
	}

	l.now = l.now.Add(emptySetGrace)
	plan, _ = l.load(load)
	if got := refIDs(plan.TagGroups.Missing); !slices.Equal(got, []string{"gone:c-acc", "gone:c-drop"}) {
		t.Errorf("missing %v after the grace (%+v)", got, plan.TagGroups.Missing)
	}
	for _, r := range plan.TagGroups.Missing {
		want := TagHandlingNoAddress
		if r.ID == "c-acc" {
			want = TagHandlingEmptySet
		}
		if r.Handling != want || r.Table != "cluster_firewall_rules" {
			t.Errorf("%s: %+v, want handling %q", r.ID, r, want)
		}
	}
}

// refIDs is "<group>:<rule id>" of each reference, sorted.
func refIDs(refs []TagGroupRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.Group+":"+r.ID)
	}
	slices.Sort(out)
	return out
}

// A group whose name is another group's IPv6 companion (x and x_v6) would
// declare one set twice, and nft would refuse the whole ruleset. It is
// unreadable here: no members, its accepts left out, its denies without the
// address.
//
// Its bindings, which need no set, are rendered.
//
// Mutations: no shadow rule — Render refuses the plan (set declared twice):
// red; drop the shadowed group's bindings — red.
func TestTagGroupLoader_AGroupNamedLikeAnotherGroupsV6Companion(t *testing.T) {
	l := newTGLab(t)
	l.sg("sg-v6", "v6-in")
	l.group("web", webGroup)
	l.group("web_v6", `{"match":{"role":"web"},"networks":[],"security_groups":["v6-in"]}`)
	l.vm("web-1", "host-a", tgFWID(1))
	l.nic("web-1", "prod", "52:54:00:00:00:01", "tap1", "10.0.0.5")
	l.lease("prod6", "fd00:1::5", "52:54:00:00:00:06", "vm", "", "web-1")
	rawRow(t, l.db, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('web-1', 'n6', 'prod6', '52:54:00:00:00:06', 1, '', 't')`)
	l.tags("vm", tgFWID(1), `{"tags":{"role":"web"}}`)
	l.clusterRule("c1", "tcp", "80", "tag:web_v6", "accept")
	l.clusterRule("c2", "tcp", "22", "tag:web_v6", "drop")

	plan, script := l.load(l.loader("host-a", nil))
	if strings.Contains(script, "dport 80") {
		t.Errorf("an accept on the shadowed group was rendered:\n%s", script)
	}
	mustContainAll(t, script, "set lv_tg_web_v6 {", "elements = { fd00:1::5 }", "tcp dport 22 drop")
	if got := refIDs(plan.TagGroups.Unreadable); !slices.Equal(got, []string{"web_v6:", "web_v6:c1", "web_v6:c2"}) {
		t.Errorf("unreadable %v", got)
	}
	// Its bindings still apply (controller ruling 2026-10-16).
	if got := planNIC(t, plan, "tap1").SecurityGroups; !slices.Equal(got, []string{"v6-in"}) {
		t.Errorf("tap1 = %v: the shadowed group's binding was dropped", got)
	}
	// And its member count is its real one (D4 re-review m-B).
	if got := plan.TagGroups.Members["web_v6"]; got != 1 {
		t.Errorf("web_v6 members = %d, want 1", got)
	}
}

// A NIC's bound groups are its own plus those of every group it is a member
// of whose binding covers the NIC's network, de-duplicated, merged BEFORE the
// ambiguity check: a bound name two live groups hold holds the NIC at drop.
//
// Mutations: bind before the ambiguity check (group groups appended after
// bind) — red; ignore the binding's networks — red.
func TestTagGroupLoader_BindingsMergeBeforeTheAmbiguityCheck(t *testing.T) {
	l := newTGLab(t)
	l.sg("sg-base", "base")
	l.sg("sg-web", "web-in")
	l.sg("sg-d1", "dup")
	l.sg("sg-d2", "dup")
	l.group("web", `{"match":{"role":"web"},"networks":["prod"],"security_groups":["web-in"]}`)
	l.group("amb", `{"match":{"tier":"x"},"networks":[],"security_groups":["dup"]}`)
	l.vm("w1", "host-a", tgFWID(1))
	l.nic("w1", "prod", "52:54:00:00:00:01", "tap1", "10.0.0.5", "base", "web-in")
	rawRow(t, l.db, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('w1', 'n2', 'dev', '52:54:00:00:00:02', 1, '', 't')`)
	l.run["w1"]["52:54:00:00:00:02"] = "tap2"
	l.tags("vm", tgFWID(1), `{"tags":{"role":"web"}}`)
	l.vm("w2", "host-a", tgFWID(2))
	l.nic("w2", "prod", "52:54:00:00:00:03", "tap3", "10.0.0.6", "base")
	l.tags("vm", tgFWID(2), `{"tags":{"role":"web","tier":"x"}}`)
	l.ct("host-a", "c1", tgFWID(3), "", "")
	l.ctNIC("host-a", "c1", "prod", "00:16:3e:00:00:01", "veth1", "10.0.0.8")
	l.tags("ct", tgFWID(3), `{"tags":{"role":"web"}}`)

	plan, _ := l.load(l.loader("host-a", nil))
	if got := planNIC(t, plan, "tap1").SecurityGroups; !slices.Equal(got, []string{"base", "web-in"}) {
		t.Errorf("tap1 (own + bound, once) = %v", got)
	}
	if got := planNIC(t, plan, "tap2"); len(got.SecurityGroups) != 0 || heldAtDrop(got) {
		t.Errorf("tap2 is on dev, which the binding does not cover: %+v", got)
	}
	if got := planNIC(t, plan, "veth1").SecurityGroups; !slices.Equal(got, []string{"web-in"}) {
		t.Errorf("a container member's veth = %v, want [web-in]", got)
	}
	if n := planNIC(t, plan, "tap3"); !heldAtDrop(n) {
		t.Errorf("a NIC bound through a group to an ambiguous name is not held: %+v", n)
	}
}

// An unreadable tags row holds only that workload's NICs, and only on the
// networks a group with security groups binds (spec §4.6, T-7 scoped by m-6);
// every other NIC renders as before. A drop rule on a tag group widens the
// hold to every network of the workload: its address may be one the drop
// should match, on any network. The report names the workload.
//
// Mutations: hold every NIC of the workload — red; hold nothing — red;
// ignore the deny reference — red.
func TestTagGroupLoader_UnreadableTagsHoldOnlyThatWorkloadOnCoveredNetworks(t *testing.T) {
	l := newTGLab(t)
	l.sg("sg-web", "web-in")
	l.group("web", `{"match":{"role":"web"},"networks":["prod"],"security_groups":["web-in"]}`)
	l.vm("u", "host-a", tgFWID(1))
	l.nic("u", "prod", "52:54:00:00:00:01", "tap1", "10.0.0.5")
	rawRow(t, l.db, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('u', 'n2', 'dev', '52:54:00:00:00:02', 1, '', 't')`)
	l.run["u"]["52:54:00:00:00:02"] = "tap2"
	l.tags("vm", tgFWID(1), `{"tags":{"role":null}}`)
	l.vm("ok", "host-a", tgFWID(2))
	l.nic("ok", "prod", "52:54:00:00:00:03", "tap3", "10.0.0.6")
	l.tags("vm", tgFWID(2), `{"tags":{"role":"web"}}`)
	load := l.loader("host-a", nil)

	plan, _ := l.load(load)
	if !heldAtDrop(planNIC(t, plan, "tap1")) {
		t.Error("the unreadable workload's NIC on a covered network is not held")
	}
	if heldAtDrop(planNIC(t, plan, "tap2")) {
		t.Error("its NIC on a network no binding covers is held")
	}
	if n := planNIC(t, plan, "tap3"); heldAtDrop(n) || !slices.Equal(n.SecurityGroups, []string{"web-in"}) {
		t.Errorf("another workload is affected: %+v", n)
	}
	if got := plan.TagGroups.TagsUnreadable; len(got) != 1 || got[0].Name != "u" || !slices.Equal(got[0].NICs, []string{"tap1"}) {
		t.Errorf("report %+v, want u with tap1 held", got)
	}

	l.clusterRule("c1", "tcp", "22", "tag:web", "drop")
	plan, _ = l.load(load)
	if !heldAtDrop(planNIC(t, plan, "tap2")) {
		t.Error("with a drop on a tag group, the unreadable workload's NIC on another network is not held")
	}
}

// A workload whose firewall identity another live workload of its kind holds
// too has EVERY NIC held at drop, and the report names every holder (D1
// review I-2). An open move's own pair, recognised from its records, is not
// held and not reported, on either host (D2b concern 5).
//
// Mutations: no hold for a shared identity — red; hold the move pair — red.
func TestTagGroupLoader_SharedIdentityHoldsEveryNICButAMovePair(t *testing.T) {
	l := newTGLab(t)
	l.sg("sg-web", "web-in")
	l.group("web", `{"match":{"role":"web"},"networks":["prod"],"security_groups":["web-in"]}`)
	l.vm("a", "host-a", tgFWID(1))
	l.nic("a", "prod", "52:54:00:00:00:01", "tap1", "10.0.0.5", "web-in")
	rawRow(t, l.db, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('a', 'n2', 'dev', '52:54:00:00:00:02', 1, '', 't')`)
	l.run["a"]["52:54:00:00:00:02"] = "tap2"
	l.vm("b", "host-b", tgFWID(1))
	l.tags("vm", tgFWID(1), `{"tags":{"role":"web"}}`)
	// A relocation's pair: the source marked onto host-b under tok, which the
	// target carries.
	l.ct("host-a", "mv", tgFWID(2), corrosion.RelocateRestoreDetail("host-b", "tok"), "")
	l.ctNIC("host-a", "mv", "prod", "00:16:3e:00:00:01", "vethsrc", "")
	l.ct("host-b", "mv", tgFWID(2), "", "tok")
	l.ctNIC("host-b", "mv", "prod", "00:16:3e:00:00:01", "vethdst", "10.0.0.9")
	l.tags("ct", tgFWID(2), `{"tags":{"role":"web"}}`)

	plan, _ := l.load(l.loader("host-a", nil))
	for _, dev := range []string{"tap1", "tap2"} {
		if !heldAtDrop(planNIC(t, plan, dev)) {
			t.Errorf("%s of a shared identity is not held", dev)
		}
	}
	if n := planNIC(t, plan, "tap1"); len(n.ExtraRules) == 0 || !strings.Contains(n.ExtraRules[0].Comment, "firewall identity shared") {
		t.Errorf("the hold does not say why: %+v", n.ExtraRules)
	}
	if n := planNIC(t, plan, "vethsrc"); heldAtDrop(n) {
		t.Errorf("a relocation's source is held: %+v", n)
	}
	got := plan.TagGroups.SharedIdentity
	if len(got) != 1 || got[0].Name != "a" || !slices.Equal(got[0].Holders, []string{"VM a", "VM b"}) ||
		!slices.Equal(got[0].NICs, []string{"tap1", "tap2"}) {
		t.Errorf("report %+v, want a, its holders and both NICs", got)
	}

	plan, _ = l.load(l.loader("host-b", nil))
	if n := planNIC(t, plan, "vethdst"); heldAtDrop(n) || !slices.Equal(n.SecurityGroups, []string{"web-in"}) {
		t.Errorf("a relocation's target is not the member: %+v", n)
	}
	if got := plan.TagGroups.SharedIdentity; len(got) != 1 || got[0].Name != "b" || len(got[0].NICs) != 0 {
		t.Errorf("host-b reports %+v, want b (which runs there, with no NIC) and not the move pair", got)
	}
	if got := setElems(plan, "lv_tg_web"); !slices.Equal(got, []string{"10.0.0.9"}) {
		t.Errorf("lv_tg_web = %v, want the target's lease only", got)
	}
}

// A workload on this host with no identity whose name a non-empty tags row
// still names, while no live workload holds that row's identity, is reported
// (a relocation that landed without its identity: D2b review M-7). Only on
// the host it runs on; nothing is held for it.
//
// Mutation: report it on every host — red.
func TestTagGroupLoader_ReportsAnIdentityLostOnItsHost(t *testing.T) {
	l := newTGLab(t)
	l.group("web", webGroup)
	l.ct("host-b", "web", "", "", "")
	l.ctNIC("host-b", "web", "prod", "00:16:3e:00:00:01", "veth1", "10.0.0.9")
	l.tags("ct", tgFWID(7), `{"tags":{"role":"web"},"name":"web","host":"host-a"}`)

	plan, _ := l.load(l.loader("host-b", nil))
	got := plan.TagGroups.IdentityLost
	if len(got) != 1 || got[0].Name != "web" || got[0].Host != "host-b" || got[0].FWID != tgFWID(7) {
		t.Fatalf("identity lost %+v", got)
	}
	if heldAtDrop(planNIC(t, plan, "veth1")) {
		t.Error("a workload whose identity was lost is held")
	}
	plan, _ = l.load(l.loader("host-a", nil))
	if got := plan.TagGroups.IdentityLost; len(got) != 0 {
		t.Errorf("host-a reports another host's workload: %+v", got)
	}
}

// A user ip set named with the tag-group prefix would be merged into a
// group's set (widening who matches its rules) or declared twice: it is left
// out and reported.
//
// Mutation: keep it — the group's set holds the user's element: red.
func TestTagGroupLoader_AUserSetWithTheTagGroupPrefixIsLeftOut(t *testing.T) {
	l := newTGLab(t)
	l.group("web", webGroup)
	rawRow(t, l.db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at) VALUES ('s1', 'lv_tg_web', '["192.0.2.1"]', '', 't', 't')`)
	l.clusterRule("c1", "tcp", "80", "tag:web", "accept")

	plan, _ := l.load(l.loader("host-a", nil))
	if got := setElems(plan, "lv_tg_web"); len(got) != 0 {
		t.Errorf("lv_tg_web = %v: a user set was merged into the group's", got)
	}
	if !hasSet(plan, "lv_tg_web") {
		t.Error("the group's set is not declared")
	}
	found := false
	for _, r := range plan.InvalidRows {
		found = found || (r.Table == "ip_sets" && r.ID == "s1" && r.Handling == HandlingSetLeftOut)
	}
	if !found {
		t.Errorf("the user set is not reported: %+v", plan.InvalidRows)
	}
}

// A deny this host keeps as it last rendered it (its row turned unreadable)
// still names the group's set; once the group is gone too, it loses its
// address like any deny on a missing group, rather than match the empty set.
//
// Mutation: no check on the kept rendering — the drop matches the empty
// set: red.
func TestTagGroupLoader_AKeptDenyLosesItsAddressWithItsGroup(t *testing.T) {
	l := newTGLab(t)
	l.group("web", webGroup)
	l.clusterRule("c1", "tcp", "22", "tag:web", "drop")
	load := l.loader("host-a", nil)
	if _, script := l.load(load); !strings.Contains(script, "tcp dport 22 ip saddr @lv_tg_web drop") {
		t.Fatalf("premise: the drop renders against the group:\n%s", script)
	}
	rawRow(t, l.db, `UPDATE cluster_firewall_rules SET proto = 'tcp;' WHERE id = 'c1'`)
	rawRow(t, l.db, `UPDATE cluster_policies SET value = '' WHERE key = ?`, corrosion.FirewallTagGroupKeyPrefix+"web")
	plan, script := l.load(load)
	if strings.Contains(script, "@lv_tg_web drop") || !strings.Contains(script, "tcp dport 22 drop") {
		t.Errorf("the kept drop on a removed group:\n%s", script)
	}
	if len(plan.InvalidRows) != 1 || plan.InvalidRows[0].Handling != HandlingKeptLast {
		t.Errorf("premise: the row is kept as last rendered: %+v", plan.InvalidRows)
	}
}

// A group whose row turns unreadable is rendered from the last definition
// this loader read (controller ruling 2026-10-16): its set, its bindings and
// its rules stay, and the report says "kept as last read".
//
// Mutation: forget the last readable definition — the binding and the set
// go: red.
func TestTagGroupLoader_AnUnreadableGroupKeepsItsLastReadableDefinition(t *testing.T) {
	l := newTGLab(t)
	l.sg("sg-web", "web-in")
	l.group("web", `{"match":{"role":"web"},"networks":["prod"],"security_groups":["web-in"]}`)
	l.vm("u", "host-a", tgFWID(1))
	l.nic("u", "prod", "52:54:00:00:00:01", "tap1", "10.0.0.5")
	l.tags("vm", tgFWID(1), `{"tags":{"role":"web"}}`)
	l.clusterRule("c1", "tcp", "22", "tag:web", "drop")
	load := l.loader("host-a", nil)
	l.load(load)

	rawRow(t, l.db, `UPDATE cluster_policies SET value = '{"match":' WHERE key = ?`, corrosion.FirewallTagGroupKeyPrefix+"web")
	plan, script := l.load(load)
	if got := planNIC(t, plan, "tap1").SecurityGroups; !slices.Equal(got, []string{"web-in"}) {
		t.Errorf("tap1 = %v: the unreadable group's binding was dropped", got)
	}
	if got := setElems(plan, "lv_tg_web"); !slices.Equal(got, []string{"10.0.0.5"}) {
		t.Errorf("lv_tg_web = %v", got)
	}
	mustContainAll(t, script, "tcp dport 22 ip saddr @lv_tg_web drop")
	if got := plan.TagGroups.Unreadable; len(got) != 1 || got[0].Group != "web" || got[0].Handling != TagHandlingKeptLastRead {
		t.Errorf("report %+v, want web kept as last read", got)
	}
}

// A group that cannot be read and was never read by this loader (a fresh
// daemon) holds at drop, on every network, every NIC of every workload here
// with non-empty tags — neither its selector nor its networks are known —
// until it reads again. Untagged workloads are untouched.
//
// Mutation: no hold — red.
func TestTagGroupLoader_AnUnreadableGroupNeverReadHoldsEveryTaggedWorkload(t *testing.T) {
	l := newTGLab(t)
	l.group("web", `{"match":`)
	l.vm("t1", "host-a", tgFWID(1))
	l.nic("t1", "prod", "52:54:00:00:00:01", "tap1", "10.0.0.5")
	rawRow(t, l.db, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('t1', 'n2', 'dev', '52:54:00:00:00:02', 1, '', 't')`)
	l.run["t1"]["52:54:00:00:00:02"] = "tap2"
	l.tags("vm", tgFWID(1), `{"tags":{"env":"x"}}`)
	l.vm("n1", "host-a", "")
	l.nic("n1", "prod", "52:54:00:00:00:03", "tap3", "10.0.0.6")
	load := l.loader("host-a", nil)

	plan, _ := l.load(load)
	for _, dev := range []string{"tap1", "tap2"} {
		if !heldAtDrop(planNIC(t, plan, dev)) {
			t.Errorf("%s of a tagged workload is not held", dev)
		}
	}
	if heldAtDrop(planNIC(t, plan, "tap3")) {
		t.Error("an untagged workload is held")
	}
	rep := plan.TagGroups
	if len(rep.Unreadable) != 1 || rep.Unreadable[0].Handling != TagHandlingHeldTagged ||
		len(rep.UnreadableHolds) != 1 || !slices.Equal(rep.UnreadableHolds[0].NICs, []string{"tap1", "tap2"}) {
		t.Errorf("report %+v", rep)
	}

	rawRow(t, l.db, `UPDATE cluster_policies SET value = ? WHERE key = ?`, webGroup, corrosion.FirewallTagGroupKeyPrefix+"web")
	plan, _ = l.load(load)
	if heldAtDrop(planNIC(t, plan, "tap1")) {
		t.Error("still held once the group reads again")
	}
}

// A deny on a tag group that lives in ANOTHER host's host tier still widens
// the unreadable-tags hold here: that host's chains match this workload's
// address too (D4 review I-2). So does a direct, positive @lv_tg_<g> deny
// (I-3).
//
// Mutations: read only this host's host rules — red; no denyRef from a
// direct reference — red.
func TestTagGroupLoader_AnyHostsDenyOrADirectReferenceWidensTheHold(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"another host's host rule", `INSERT INTO host_firewall_rules (id, host_name, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
			VALUES ('h1', 'host-b', 'ingress', 'tcp', '22', 'tag:web', 'drop', 100, '', '', 't', 't')`},
		{"a direct set reference", `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
			VALUES ('c1', 'ingress', 'tcp', '22', '@lv_tg_web', 'drop', 100, '', '', 't', 't')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newTGLab(t)
			l.group("web", webGroup)
			l.vm("u", "host-a", tgFWID(1))
			rawRow(t, l.db, `INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('u', 'n2', 'dev', '52:54:00:00:00:02', 0, '', 't')`)
			l.run["u"] = map[string]string{"52:54:00:00:00:02": "tap2"}
			l.tags("vm", tgFWID(1), `{"tags":{"role":null}}`)
			rawRow(t, l.db, tc.sql)
			plan, _ := l.load(l.loader("host-a", nil))
			if !heldAtDrop(planNIC(t, plan, "tap2")) {
				t.Error("the unreadable workload's NIC is not held")
			}
		})
	}
}

// A negated accept against a group's set (!= @lv_tg_<g>) would admit every
// workload whose membership cannot be proven: it is left out and reported
// (D4 review I-3).
//
// Mutation: render it — red.
func TestTagGroupLoader_ANegatedAcceptOnAGroupsSetIsLeftOut(t *testing.T) {
	l := newTGLab(t)
	l.group("web", webGroup)
	l.clusterRule("c1", "tcp", "80", "!= @lv_tg_web", "accept")
	l.clusterRule("c2", "tcp", "81", "!= @lv_tg_web", "drop")
	plan, script := l.load(l.loader("host-a", nil))
	if strings.Contains(script, "dport 80") {
		t.Errorf("the negated accept was rendered:\n%s", script)
	}
	if !strings.Contains(script, "tcp dport 81 ip saddr != @lv_tg_web drop") {
		t.Errorf("a negated drop was not kept:\n%s", script)
	}
	if len(plan.InvalidRows) != 1 || plan.InvalidRows[0].ID != "c1" {
		t.Errorf("invalid rows %+v, want c1", plan.InvalidRows)
	}
}

// A negated deny on a group's set this pass does not render — missing, or
// unreadable and never read here — means "deny everyone not in an unknown
// group": it renders without its address, denying everyone, as a tag: deny
// does (D4 re-review I-A). Left out, it would deny no one.
//
// Mutation: no such branch (the row is left out) — red.
func TestTagGroupLoader_ANegatedDenyOnAGroupNotRenderedDeniesEveryone(t *testing.T) {
	for _, tc := range []struct{ name, group string }{{"missing", ""}, {"never read", `{"match":`}} {
		t.Run(tc.name, func(t *testing.T) {
			l := newTGLab(t)
			if tc.group != "" {
				l.group("g", tc.group)
			}
			l.clusterRule("c1", "tcp", "22", "!= @lv_tg_g", "drop")
			load := l.loader("host-a", nil)
			plan, script := l.load(load)
			if !strings.Contains(script, "tcp dport 22 drop") || strings.Contains(script, "lv_tg_g ") || strings.Contains(script, "@lv_tg_g") {
				t.Errorf("the negated drop on a group not rendered:\n%s", script)
			}
			if len(plan.InvalidRows) != 0 {
				t.Errorf("reported as invalid rows: %+v", plan.InvalidRows)
			}
			l.now = l.now.Add(emptySetGrace)
			plan, _ = l.load(load)
			refs := append(plan.TagGroups.Missing, plan.TagGroups.Unreadable...)
			found := false
			for _, r := range refs {
				found = found || (r.ID == "c1" && r.Group == "g" && r.Handling == TagHandlingNoAddress)
			}
			if !found {
				t.Errorf("not reported: %+v", refs)
			}
		})
	}
}
