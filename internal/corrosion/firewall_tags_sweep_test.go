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

// The sweep never clears, at any age, a tags row whose display name matches
// a live workload of the row's kind that has no identity (its membership was
// lost, and the row is the evidence the loader holds it on: Track D final
// review I-1), nor one whose name matches a workload of its kind with a
// relocation or move still in flight (m-4). A name on a workload of the other
// kind, or on one that has an identity of its own, spares nothing.
//
// Mutations: drop the no-identity spare — red; drop the in-flight spare —
// red; match the name across kinds — red.
func TestFirewallTagsOrphans_SparesALostIdentityAndAMoveInFlight(t *testing.T) {
	f := newTagGroupFixture(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	ancient := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano)
	row := func(kind, id, name string) {
		host := ""
		if kind == TagMemberCT {
			host = "node-1"
		}
		mustExec(t, f.c, `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'x', ?)`,
			FirewallTagsKeyPrefix+kind+"/"+id, `{"tags":{"role":"web"},"name":"`+name+`","host":"`+host+`"}`, ancient)
	}
	proof := func(id, kind, name, status, deleted string) {
		mustExec(t, f.c, `INSERT INTO runtime_action_proofs (id, action, target_kind, target_name, dest_host, coordinator,
			relocation_token, status, created_at, updated_at, deleted_at) VALUES (?, ?, ?, ?, 'node-2', 'node-1', 'tok-'||?, ?, 't', 't', NULLIF(?, ''))`,
			id, ActionRelocate, kind, name, id, status, deleted)
	}

	// lost-vm: a live VM of the name with no identity: kept.
	f.vm("lost-vm", "", "running")
	row(TagMemberVM, tgID(1), "lost-vm")
	// lost-ct: a live container of the name with no identity, on the host
	// the row was recorded on: kept.
	f.ct("node-1", "lost-ct", "", "stopped")
	row(TagMemberCT, tgID(2), "lost-ct")
	// other-kind: only a VM of the name has no identity; the row is a
	// container's: cleared.
	f.vm("other-kind", "", "running")
	row(TagMemberCT, tgID(3), "other-kind")
	// has-own: the VM of the name has an identity of its own: cleared.
	f.vm("has-own", tgID(4), "running")
	row(TagMemberVM, tgID(5), "has-own")
	// relocating: the container of the name is marked relocating (and holds
	// an identity of its own): kept.
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, state_detail, create_spec, created_at, updated_at) VALUES ('node-1', 'relocating', 'relocating', ?, ?, 't', 't')`,
		RelocateRestoreDetail("node-2", "tok"), `{"fw_id":"`+tgID(6)+`"}`)
	row(TagMemberCT, tgID(7), "relocating")
	// proof-open: no live row of the name, an open relocation proof names
	// it: kept.
	proof("p1", "container", "proof-open", ProofInProgress, "")
	row(TagMemberCT, tgID(8), "proof-open")
	// proof-done: the proofs naming it completed, failed or were reaped:
	// cleared.
	proof("p2", "container", "proof-done", ProofCompleted, "")
	proof("p3", "container", "proof-done", ProofFailed, "")
	proof("p4", "container", "proof-done", ProofPrepared, ancient)
	row(TagMemberCT, tgID(9), "proof-done")
	// proof-vm: an open proof for a VM of the name keeps a VM row only.
	proof("p5", "vm", "proof-vm", ProofPrepared, "")
	row(TagMemberVM, tgID(10), "proof-vm")
	row(TagMemberCT, tgID(11), "proof-vm")

	got, err := FirewallTagsOrphans(f.ctx, f.c, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range got {
		ids = append(ids, r.Kind+"/"+r.FWID)
	}
	slices.Sort(ids)
	want := []string{"ct/" + tgID(11), "ct/" + tgID(3), "ct/" + tgID(9), "vm/" + tgID(5)}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("orphans = %v, want %v", ids, want)
	}
}

// The no-identity spare matches a container as the loader's hold does
// (Track D final fix re-review I-A): on the row's own host, or on another
// host only with a relocation record binding it there, and never a container
// with no create spec. An unrelated container of the name elsewhere, or a
// legacy one, leaves the row to the grace.
//
// Mutations: spare by name across hosts — red; spare a container with no
// create spec — red; ignore the relocation proof — red.
func TestFirewallTagsOrphans_SparesOnlyAContainerThatCouldHaveLostTheIdentity(t *testing.T) {
	f := newTagGroupFixture(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	old := now.Add(-25 * time.Hour).Format(time.RFC3339Nano)
	row := func(id, name string) {
		mustExec(t, f.c, `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'x', ?)`,
			FirewallTagsKeyPrefix+TagMemberCT+"/"+id, `{"tags":{"role":"web"},"name":"`+name+`","host":"host-a"}`, old)
	}
	// unrelated: an untagged web on host-b, no relocation record: swept.
	f.ct("host-b", "web", "", "running")
	row(tgID(1), "web")
	// legacy: a container on the row's host with no create spec: swept.
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, create_spec, created_at, updated_at) VALUES ('host-a', 'legacy', 'running', '', 't', 't')`)
	row(tgID(2), "legacy")
	// moved: migrated host-a -> host-b without its identity, its token bound
	// by a proof into host-b: kept.
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, relocate_token, create_spec, created_at, updated_at) VALUES ('host-b', 'moved', 'running', 'tok-m', '{"template":"debian"}', 't', 't')`)
	mustExec(t, f.c, `INSERT INTO runtime_action_proofs (id, action, target_kind, target_name, dest_host, coordinator, relocation_token, status, created_at, updated_at)
		VALUES ('pm', ?, 'container', 'moved', 'host-b', 'host-a', 'tok-m', ?, 't', 't')`, ActionRelocate, ProofCompleted)
	row(tgID(3), "moved")

	got, err := FirewallTagsOrphans(f.ctx, f.c, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range got {
		ids = append(ids, r.FWID)
	}
	slices.Sort(ids)
	if want := []string{tgID(1), tgID(2)}; !slices.Equal(ids, want) {
		t.Fatalf("orphans = %v, want %v", ids, want)
	}
}
