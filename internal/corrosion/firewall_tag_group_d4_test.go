package corrosion

import (
	"fmt"
	"slices"
	"testing"
)

// Every workload the members read reports names the host it runs on (On): a
// VM's host_name, a container's host. The renderer raises its conditions only
// on that host.
//
// Mutation: leave On unset for VMs — red.
func TestTagGroupMembers_ReportsTheHostAWorkloadRunsOn(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	f.vm("vm-a", tgID(1), "running")
	f.vm("vm-b", tgID(1), "running")
	f.ct("node-2", "ct-u", tgID(2), "running")
	f.tags("ct", tgID(2), `{"tags":`)

	m := f.members()
	var got []string
	for _, w := range append(m.SharedFWID, m.TagsUnreadable...) {
		got = append(got, w.Kind+":"+w.Name+"@"+w.On)
	}
	slices.Sort(got)
	if want := []string{"ct:ct-u@node-2", "vm:vm-a@node-0", "vm:vm-b@node-0"}; !slices.Equal(got, want) {
		t.Fatalf("reported %v, want %v", got, want)
	}
}

// A live workload with no firewall identity, whose name a non-empty tags row
// of its kind still names while no live workload holds that row's identity, is
// reported (IdentityLost): its tag-group membership was most likely lost on
// the way here (a relocation that landed without its identity, D2b review
// M-7; a restore into a freed name). Display only: nothing is matched on the
// name for membership.
//
// A container is matched only on the host the row was recorded on, or on
// another host when a relocation record binds it there (its relocate_token
// names a proof into its host, or the source's relocate-restore marker
// names its host and token): container names are unique per host only. A
// container with no create spec (an earlier build's) cannot have held an
// identity, so it never lost one (Track D final fix re-review I-A).
//
// Mutations: report a row a live workload still holds — red; report a
// workload that has an identity — red; match a row of the other kind — red;
// match a container on another host with no relocation record — red; report
// a container with no create spec — red; ignore the proof or the marker —
// red.
func TestTagGroupMembers_IdentityLostNamesAnOrphanRowOfTheName(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	// Migrated node-1 -> node-2 with no identity: its relocate_token names
	// a proof into node-2; its old row names it (written on node-1).
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, relocate_token, create_spec, created_at, updated_at) VALUES ('node-2', 'web', 'running', 'tok-web', '{"template":"debian"}', 't', 't')`)
	f.ctNIC("node-2", "web", "prod", "00:16:3e:00:00:01", "")
	f.tags("ct", tgID(1), `{"tags":{"role":"web"},"name":"web","host":"node-1"}`)
	mustExec(t, f.c, `INSERT INTO runtime_action_proofs (id, action, target_kind, target_name, dest_host, coordinator, relocation_token, status, created_at, updated_at)
		VALUES ('p1', ?, 'container', 'web', 'node-2', 'node-1', 'tok-web', ?, 't', 't')`, ActionRelocate, ProofCompleted)
	// Relocated by failover node-5 -> node-6: the source's marker, on its
	// tombstone, names node-6 and the target's token.
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, state_detail, create_spec, created_at, updated_at, deleted_at) VALUES ('node-5', 'fo', 'relocating', ?, '{}', 't', 't', 't')`,
		RelocateRestoreDetail("node-6", "tok-fo"))
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, relocate_token, create_spec, created_at, updated_at) VALUES ('node-6', 'fo', 'running', 'tok-fo', '{"template":"debian"}', 't', 't')`)
	f.tags("ct", tgID(9), `{"tags":{"role":"web"},"name":"fo","host":"node-5"}`)
	// An unrelated container of the name on another host, with no
	// relocation record (and one whose token binds nothing): not reported.
	f.ct("node-7", "api", "", "running")
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, relocate_token, create_spec, created_at, updated_at) VALUES ('node-8', 'api', 'running', 'tok-other', '{"template":"debian"}', 't', 't')`)
	f.tags("ct", tgID(10), `{"tags":{"role":"web"},"name":"api","host":"node-1"}`)
	// On the row's own host: reported. With no create spec there: not.
	f.ct("node-1", "same", "", "running")
	f.tags("ct", tgID(11), `{"tags":{"role":"web"},"name":"same","host":"node-1"}`)
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, create_spec, created_at, updated_at) VALUES ('node-1', 'legacy', 'running', '', 't', 't')`)
	f.tags("ct", tgID(12), `{"tags":{"role":"web"},"name":"legacy","host":"node-1"}`)
	// A VM restored into a freed name.
	f.vm("app", "", "running")
	f.tags("vm", tgID(2), `{"tags":{"role":"web"},"name":"app"}`)
	// The row's identity is still held by a live container of the name on
	// another host: not lost, an unrelated container of the same name.
	f.ct("node-3", "db", tgID(3), "running")
	f.ct("node-4", "db", "", "running")
	f.tags("ct", tgID(3), `{"tags":{"role":"db"},"name":"db","host":"node-3"}`)
	// Has an identity of its own: not reported.
	f.vm("own", tgID(4), "running")
	f.tags("vm", tgID(5), `{"tags":{"role":"web"},"name":"own"}`)
	// A row of the other kind names it.
	f.vm("cross", "", "running")
	f.tags("ct", tgID(6), `{"tags":{"role":"web"},"name":"cross","host":"node-1"}`)
	// A removed row and an unreadable one name nothing.
	f.vm("gone", "", "running")
	f.tags("vm", tgID(7), "")
	f.tags("vm", tgID(8), `{"tags":{"role":null},"name":"gone"}`)

	m := f.members()
	var got []string
	for _, w := range m.IdentityLost {
		got = append(got, fmt.Sprintf("%s:%s:%s@%s:%s:%v", w.Kind, w.Host, w.Name, w.On, w.FWID, w.Networks))
	}
	want := []string{
		"vm::app@node-0:" + tgID(2) + ":[]",
		"ct:node-1:same@node-1:" + tgID(11) + ":[]",
		"ct:node-2:web@node-2:" + tgID(1) + ":[prod]",
		"ct:node-6:fo@node-6:" + tgID(9) + ":[]",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("identity lost %v, want %v", got, want)
	}
	if v := m.viewFor(t, "web"); len(v.Members) != 0 {
		t.Errorf("a name matched a tags row into membership: %v", v.memberNames())
	}
}

// A group that cannot be read here is evaluated from the definition the
// caller kept from an earlier read (the loader's last readable one), and
// marked Kept; without one it stays unreadable. Tagged lists every live
// workload with a unique identity and non-empty readable tags, which the
// loader holds when a group has no definition at all.
//
// Mutations: ignore the kept definition — red; leave Tagged empty — red.
func TestTagGroupMembers_KeptDefinitionAndTagged(t *testing.T) {
	f := newTagGroupFixture(t)
	f.policy("firewall_tag_group/web", `{"match":`)
	f.policy("firewall_tag_group/bad", `{"match":`)
	f.vm("vm-a", tgID(1), "running")
	f.tags("vm", tgID(1), `{"tags":{"role":"web"}}`)
	f.ct("node-1", "ct-b", tgID(2), "running")
	f.tags("ct", tgID(2), `{"tags":{"env":"x"}}`)
	f.vm("vm-none", tgID(3), "running")
	f.tags("vm", tgID(3), "")

	m, err := ListTagGroupMembersKeeping(f.ctx, f.c, map[string]FirewallTagGroupDef{"web": {Match: map[string]string{"role": "web"}}})
	if err != nil {
		t.Fatal(err)
	}
	web := m.viewFor(t, "web")
	if !web.Kept || web.Group.Unreadable || !slices.Equal(web.memberNames(), []string{"vm:vm-a"}) {
		t.Errorf("web = kept %v unreadable %v members %v, want kept with vm-a", web.Kept, web.Group.Unreadable, web.memberNames())
	}
	if bad := m.viewFor(t, "bad"); bad.Kept || !bad.Group.Unreadable || len(bad.Members) != 0 {
		t.Errorf("bad = %+v, want unreadable with no members", bad)
	}
	var tagged []string
	for _, w := range m.Tagged {
		tagged = append(tagged, w.Kind+":"+w.Name+"@"+w.On)
	}
	if want := []string{"vm:vm-a@node-0", "ct:ct-b@node-1"}; !slices.Equal(tagged, want) {
		t.Errorf("tagged %v, want %v", tagged, want)
	}
}
