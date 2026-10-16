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
// Mutations: report a row a live workload still holds — red; report a
// workload that has an identity — red; match a row of the other kind — red.
func TestTagGroupMembers_IdentityLostNamesAnOrphanRowOfTheName(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	// Relocated to node-2 with no identity; its old row names it (written
	// on node-1).
	f.ct("node-2", "web", "", "running")
	f.ctNIC("node-2", "web", "prod", "00:16:3e:00:00:01", "")
	f.tags("ct", tgID(1), `{"tags":{"role":"web"},"name":"web","host":"node-1"}`)
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
		"ct:node-2:web@node-2:" + tgID(1) + ":[prod]",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("identity lost %v, want %v", got, want)
	}
	if v := m.viewFor(t, "web"); len(v.Members) != 0 {
		t.Errorf("a name matched a tags row into membership: %v", v.memberNames())
	}
}
