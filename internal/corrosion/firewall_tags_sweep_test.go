package corrosion

import (
	"slices"
	"testing"
	"time"
)

// The orphan sweep's selection (spec §4.3, m-4). A tags row is an orphan
// when no live workload of its kind carries its fw_id AND either the newest
// tombstone carrying it is older than the grace, or no row carries it at all
// and the tags row itself is older than the grace. A removed row ("") is
// never listed.
//
// Mutations: sweep without the grace; drop the no-row case; read only the
// oldest tombstone — red.
func TestFirewallTagsOrphans(t *testing.T) {
	f := newTagGroupFixture(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	old := now.Add(-25 * time.Hour).Format(time.RFC3339Nano)
	recent := now.Add(-time.Hour).Format(time.RFC3339Nano)
	tags := `{"tags":{"role":"web"}}`
	row := func(kind, id, value, updated string) {
		mustExec(t, f.c, `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'x', ?)`,
			FirewallTagsKeyPrefix+kind+"/"+id, value, updated)
	}
	tombVM := func(name, id, deleted string) {
		mustExec(t, f.c, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at, deleted_at) VALUES (?, 'node-0', ?, 'stopped', 't', 't', ?)`,
			name, `{"firewall_id":"`+id+`"}`, deleted)
	}
	tombCT := func(host, name, id, deleted string) {
		mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, create_spec, created_at, updated_at, deleted_at) VALUES (?, ?, 'stopped', ?, 't', 't', ?)`,
			host, name, `{"fw_id":"`+id+`"}`, deleted)
	}

	// live: a live VM holds it (old row, old tombstone elsewhere): kept.
	f.vm("live", tgID(1), "running")
	tombVM("live-old", tgID(1), old)
	row(TagMemberVM, tgID(1), tags, old)
	// tomb-old: only an old tombstone: cleared.
	tombVM("gone", tgID(2), old)
	row(TagMemberVM, tgID(2), tags, recent)
	// tomb-recent: a recent tombstone (a move or re-create in flight): kept,
	// even beside an old one.
	tombCT("node-1", "moving", tgID(3), old)
	tombCT("node-2", "moving", tgID(3), recent)
	row(TagMemberCT, tgID(3), tags, old)
	// none-old: no row at all, tags row past the grace: cleared.
	row(TagMemberCT, tgID(4), tags, old)
	// none-recent: no row, tags row inside the grace: kept.
	row(TagMemberVM, tgID(5), tags, recent)
	// removed: already "": not listed.
	row(TagMemberVM, tgID(6), "", old)
	// kind matters: a container holding a VM row's id does not keep it.
	f.ct("node-1", "ct", tgID(7), "running")
	row(TagMemberVM, tgID(7), tags, old)
	// unreadable, no holder, old: cleared too.
	row(TagMemberVM, tgID(8), `{"tags":`, old)

	got, err := FirewallTagsOrphans(f.ctx, f.c, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range got {
		ids = append(ids, r.Kind+"/"+r.FWID)
	}
	slices.Sort(ids)
	want := []string{"ct/" + tgID(4), "vm/" + tgID(2), "vm/" + tgID(7), "vm/" + tgID(8)}
	if !slices.Equal(ids, want) {
		t.Fatalf("orphans = %v, want %v", ids, want)
	}
}
