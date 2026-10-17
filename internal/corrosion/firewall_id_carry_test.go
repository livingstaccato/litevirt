package corrosion

import (
	"context"
	"maps"
	"testing"
)

// The carry tokens' corrosion side (spec §4.3, D2b): what a re-create's delete
// snapshot records, the token made from it, and what a restore into a freed
// name says the deleted incarnation left behind.

// TestSnapshotForDelete_RecordsTheFirewallID: the snapshot a rebuild's delete
// takes holds the identity of the row it tombstoned, read as the members
// query reads it, so the re-create carries exactly that.
//
// Mutation: leave FirewallID out of SnapshotForDelete — red.
func TestSnapshotForDelete_RecordsTheFirewallID(t *testing.T) {
	id := tgID(7)
	for _, tc := range []struct {
		spec, want string
	}{
		{`{"name":"web","firewall_id":"` + id + `"}`, id},
		{`{"name":"web"}`, ""},
		{`{"name":"web","firewall_id":"not-an-id"}`, ""},
		{`{"name":"web","Firewall_ID":"` + id + `"}`, ""},
	} {
		if got := SnapshotForDelete(VMRecord{Name: "web", CreatedAt: "c", Spec: tc.spec}).FirewallID; got != tc.want {
			t.Errorf("snapshot of %s: firewall id %q, want %q", tc.spec, got, tc.want)
		}
	}
}

// TestCarryFirewallIDOf: a well-formed id of the right kind carries; anything
// else is the zero token, and a token of one kind carries nothing for the
// other.
func TestCarryFirewallIDOf(t *testing.T) {
	id := tgID(9)
	if got := CarryFirewallIDOf(TagMemberVM, id).idFor(TagMemberVM); got != id {
		t.Fatalf("vm token carries %q, want %q", got, id)
	}
	if got := CarryFirewallIDOf(TagMemberVM, id).idFor(TagMemberCT); got != "" {
		t.Fatalf("a vm token carries %q for a container", got)
	}
	for _, bad := range []string{"", "x", id + "0", "ABCDEF0123456789ABCDEF0123456789"} {
		if tok := CarryFirewallIDOf(TagMemberVM, bad); tok != (FirewallIDCarry{}) {
			t.Errorf("CarryFirewallIDOf(%q) = %+v, want the zero token", bad, tok)
		}
	}
	// What the token carries is what the insert keeps.
	c := testClient(t)
	ctx := context.Background()
	if err := InsertVM(ctx, c, VMRecord{Name: "web", HostName: "h1", State: "stopped",
		Spec: `{"name":"web"}`, FirewallCarry: CarryFirewallIDOf(TagMemberVM, id)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	assertIdentity(t, "insert carrying CarryFirewallIDOf", TagMemberVM, storedVMSpec(t, c, "web"), id)
}

// TestDeletedFirewallTags: a restore into a freed name says what the deleted
// incarnation's identity is still tagged with. Nothing is said when the
// tombstone held no identity, when a live row holds it (the workload moved
// on), when the tags row is removed or unreadable, or for a container of
// another project.
//
// Mutation: skip the live-holder check — the moved case is red.
func TestDeletedFirewallTags(t *testing.T) {
	f := newTagGroupFixture(t)
	ctx := context.Background()
	want := map[string]string{"role": "web", "env": "prod"}

	// A deleted VM whose tags row is still non-empty.
	f.vm("web", tgID(1), "stopped")
	f.tags(TagMemberVM, tgID(1), `{"tags":{"role":"web","env":"prod"},"name":"web"}`)
	mustExec(t, f.c, `UPDATE vms SET deleted_at = '2026-10-15T00:00:00Z' WHERE name = 'web'`)
	id, host, tags, err := DeletedFirewallTags(ctx, f.c, TagMemberVM, "", "web")
	if err != nil || id != tgID(1) || host != "node-0" || !maps.Equal(tags, want) {
		t.Fatalf("deleted vm: (%q, %q, %v, %v), want (%q, node-0, %v)", id, host, tags, err, tgID(1), want)
	}

	// A deleted container, read within its project.
	f.ct("h2", "cache", tgID(2), "stopped")
	f.tags(TagMemberCT, tgID(2), `{"tags":{"role":"web","env":"prod"}}`)
	mustExec(t, f.c, `UPDATE containers SET deleted_at = '2026-10-15T00:00:00Z' WHERE name = 'cache'`)
	id, host, tags, err = DeletedFirewallTags(ctx, f.c, TagMemberCT, "_default", "cache")
	if err != nil || id != tgID(2) || host != "h2" || !maps.Equal(tags, want) {
		t.Fatalf("deleted container: (%q, %q, %v, %v)", id, host, tags, err)
	}
	if id, _, _, _ = DeletedFirewallTags(ctx, f.c, TagMemberCT, "other", "cache"); id != "" {
		t.Fatalf("another project's container named cache reads identity %q", id)
	}

	nothing := func(what, kind, name string) {
		t.Helper()
		id, _, tags, err := DeletedFirewallTags(ctx, f.c, kind, "", name)
		if err != nil || id != "" || tags != nil {
			t.Fatalf("%s: (%q, %v, %v), want nothing", what, id, tags, err)
		}
	}
	// A tombstone with no identity.
	f.vm("plain", "", "stopped")
	mustExec(t, f.c, `UPDATE vms SET deleted_at = 't' WHERE name = 'plain'`)
	nothing("no identity", TagMemberVM, "plain")
	// A moved container: its old row is a tombstone, its live row on another
	// host holds the same identity.
	f.ct("h1", "moved", tgID(3), "stopped")
	f.tags(TagMemberCT, tgID(3), `{"tags":{"role":"web"}}`)
	mustExec(t, f.c, `UPDATE containers SET deleted_at = 't' WHERE host_name = 'h1' AND name = 'moved'`)
	f.ct("h3", "moved", tgID(3), "running")
	nothing("moved", TagMemberCT, "moved")
	// A removed tags row, and an unreadable one.
	f.vm("removed", tgID(4), "stopped")
	f.tags(TagMemberVM, tgID(4), "")
	mustExec(t, f.c, `UPDATE vms SET deleted_at = 't' WHERE name = 'removed'`)
	nothing("removed tags row", TagMemberVM, "removed")
	f.vm("garbled", tgID(5), "stopped")
	f.tags(TagMemberVM, tgID(5), `{"tags":`)
	mustExec(t, f.c, `UPDATE vms SET deleted_at = 't' WHERE name = 'garbled'`)
	nothing("unreadable tags row", TagMemberVM, "garbled")
	// A live VM is not a deleted incarnation.
	f.vm("live", tgID(6), "running")
	f.tags(TagMemberVM, tgID(6), `{"tags":{"role":"web"}}`)
	nothing("live", TagMemberVM, "live")
}
