package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// HLC stamps in increasing order, for readable fixtures.
const (
	tsOld    = "1790000000000-0000-n"
	tsMid    = "1790000005000-0000-n"
	tsNew    = "1790000009000-0000-n"
	tsFuture = "9790000000000-0000-n"
)

// seedSnap writes a snapshots row on c only (never replicated).
func seedSnap(t *testing.T, c *Client, id, vm, name, updatedAt string, deleted bool, parent string) {
	t.Helper()
	var del, par interface{}
	if deleted {
		del = "2026-10-12T00:00:00Z"
	}
	if parent != "" {
		par = parent
	}
	if _, err := c.DB().Exec(`INSERT INTO snapshots (id, vm_name, host_name, name, state, parent_id, created_at, updated_at, deleted_at)
		VALUES (?, ?, 'here', ?, 'ok', ?, '2026-01-01T00:00:00Z', ?, ?)`, id, vm, name, par, updatedAt, del); err != nil {
		t.Fatal(err)
	}
}

type snapState struct {
	id      string
	deleted bool
}

// snapsUnder lists every row (live or not) holding (vm, name) on c.
func snapsUnder(t *testing.T, c *Client, vm, name string) []snapState {
	t.Helper()
	rows, err := c.DB().Query(`SELECT id, COALESCE(deleted_at, '') FROM snapshots WHERE vm_name = ? AND name = ?`, vm, name)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []snapState
	for rows.Next() {
		var id, del string
		if err := rows.Scan(&id, &del); err != nil {
			t.Fatal(err)
		}
		out = append(out, snapState{id: id, deleted: del != ""})
	}
	return out
}

func snapEntryAt(t *testing.T, seq int64, id, vm, name, updatedAt string) *pb.MutationEntry {
	t.Helper()
	stmts := []Statement{{SQL: insertSnapshotSQL, Params: []interface{}{
		id, vm, "peer", name, "ok", 1, "disk", "", 0, "2026-10-12T00:00:00Z", updatedAt,
	}}}
	b, err := json.Marshal(stmts)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.MutationEntry{Seq: seq, Hlc: fmt.Sprintf("17900000%05d-0000-peer", seq), Origin: "peer", Stmts: string(b)}
}

func decideColl(t *testing.T, c *Client, in identityIncoming) (identityCollision, string) {
	t.Helper()
	tx, err := c.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	in.table = "snapshots"
	if in.now.IsZero() {
		in.now = time.Now()
	}
	d, local, err := decideIdentityCollision(tx, in)
	if err != nil {
		t.Fatal(err)
	}
	return d, local
}

// The decision table in identity.go, row by row, and each exclusion on its
// own.
func TestDecideIdentityCollision_Table(t *testing.T) {
	nat := []interface{}{"vm", "s1"}
	cases := []struct {
		name         string
		localTS      string
		localDeleted bool
		localID      string
		in           identityIncoming
		want         identityCollision
	}{
		{"older tombstone yields to a newer live row", tsOld, true, "L", identityIncoming{id: "I", ts: tsNew}, collisionYieldLocal},
		{"newer tombstone stays: older live row skipped (no resurrection)", tsNew, true, "L", identityIncoming{id: "I", ts: tsOld}, collisionSkipIncoming},
		{"equal-time tombstone stays: a delete wins a tie with a live row", tsMid, true, "L", identityIncoming{id: "I", ts: tsMid}, collisionSkipIncoming},
		{"tombstone vs newer tombstone: incoming wins", tsOld, true, "L", identityIncoming{id: "I", ts: tsNew, deleted: true}, collisionYieldLocal},
		{"tombstone vs older tombstone: local stays", tsNew, true, "L", identityIncoming{id: "I", ts: tsOld, deleted: true}, collisionSkipIncoming},
		{"tombstone tie: smaller incoming id wins", tsMid, true, "m", identityIncoming{id: "a", ts: tsMid, deleted: true}, collisionYieldLocal},
		{"tombstone tie: larger incoming id loses", tsMid, true, "a", identityIncoming{id: "m", ts: tsMid, deleted: true}, collisionSkipIncoming},
		{"live row vs older tombstone: stale, skipped", tsNew, false, "L", identityIncoming{id: "I", ts: tsOld, deleted: true}, collisionSkipIncoming},
		{"live row vs newer tombstone: no decision", tsOld, false, "L", identityIncoming{id: "I", ts: tsNew, deleted: true}, collisionNone},
		{"two live rows: canonical_identity's, no decision", tsOld, false, "L", identityIncoming{id: "I", ts: tsNew}, collisionNone},
		{"same id: ordinary LWW, no decision", tsOld, true, "I", identityIncoming{id: "I", ts: tsNew}, collisionNone},
		{"future-skewed incoming with the guard on: no yield", tsOld, true, "L", identityIncoming{id: "I", ts: tsFuture, skewGuard: true}, collisionNone},
		{"future-skewed incoming with the guard off: yields", tsOld, true, "L", identityIncoming{id: "I", ts: tsFuture}, collisionYieldLocal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := parkTestClient(t)
			seedSnap(t, c, tc.localID, "vm", "s1", tc.localTS, tc.localDeleted, "")
			tc.in.natVals = nat
			if got, _ := decideColl(t, c, tc.in); got != tc.want {
				t.Fatalf("decision = %d, want %d", got, tc.want)
			}
		})
	}
}

// A tombstone a child row references does not yield.
func TestDecideIdentityCollision_ChildReferenceKeepsTheTombstone(t *testing.T) {
	c := parkTestClient(t)
	seedSnap(t, c, "L", "vm", "s1", tsOld, true, "")
	in := identityIncoming{natVals: []interface{}{"vm", "s1"}, id: "I", ts: tsNew}
	if got, _ := decideColl(t, c, in); got != collisionYieldLocal {
		t.Fatalf("control: decision = %d, want a yield", got)
	}
	seedSnap(t, c, "child", "vm", "s2", tsOld, false, "L")
	if got, _ := decideColl(t, c, in); got != collisionNone {
		t.Fatalf("a referenced tombstone yielded: decision = %d", got)
	}
}

// An incoming id already bound to another name does not take this one.
func TestDecideIdentityCollision_IDBoundToAnotherNameKeepsTheTombstone(t *testing.T) {
	c := parkTestClient(t)
	seedSnap(t, c, "L", "vm", "s1", tsOld, true, "")
	in := identityIncoming{natVals: []interface{}{"vm", "s1"}, id: "I", ts: tsNew}
	if got, _ := decideColl(t, c, in); got != collisionYieldLocal {
		t.Fatalf("control: decision = %d, want a yield", got)
	}
	seedSnap(t, c, "I", "vm", "other", tsOld, false, "")
	if got, _ := decideColl(t, c, in); got != collisionNone {
		t.Fatalf("an id bound to another name took this one: decision = %d", got)
	}
}

// WAL: a newer tombstone of the name is not displaced by an older live row,
// and the stale row is not held either (it is superseded, not refused).
func TestApplyRemoteMutations_NewerTombstoneStays(t *testing.T) {
	for _, ts := range []string{tsOld, tsMid} { // older, and the exact tie
		c := parkTestClient(t)
		r := NewReplicator(c, "", RelayConfig{})
		seedSnap(t, c, "L", "vm", "s1", tsMid, true, "")
		if _, err := r.ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{snapEntryAt(t, 1, "I", "vm", "s1", ts)}); err != nil {
			t.Fatalf("ts %s: %v", ts, err)
		}
		if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "L" || !got[0].deleted {
			t.Fatalf("ts %s: rows = %+v, want the tombstone L alone", ts, got)
		}
		if p := r.ParkedEntries(); len(p) != 0 {
			t.Fatalf("ts %s: a superseded row was held: %+v", ts, p)
		}
	}
}

// WAL: a tombstone that may not yield (child reference, id bound elsewhere)
// stays, and the refused insert is held rather than applied over it.
func TestApplyRemoteMutations_ExcludedYieldKeepsTheTombstone(t *testing.T) {
	for _, setup := range []struct {
		name string
		seed func(c *Client)
	}{
		{"child reference", func(c *Client) { seedSnap(t, c, "child", "vm", "s2", tsOld, false, "L") }},
		{"id bound to another name", func(c *Client) { seedSnap(t, c, "I", "vm", "other", tsOld, false, "") }},
	} {
		c := parkTestClient(t)
		r := NewReplicator(c, "", RelayConfig{})
		seedSnap(t, c, "L", "vm", "s1", tsOld, true, "")
		setup.seed(c)
		if _, err := r.ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{snapEntryAt(t, 1, "I", "vm", "s1", tsNew)}); err != nil {
			t.Fatalf("%s: %v", setup.name, err)
		}
		if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "L" || !got[0].deleted {
			t.Fatalf("%s: rows = %+v, want the tombstone L kept", setup.name, got)
		}
		if p := r.ParkedEntries(); len(p) != 1 {
			t.Fatalf("%s: held = %+v, want the refused insert held", setup.name, p)
		}
	}
}

func aeMerge(t *testing.T, c *Client, rows ...[]interface{}) {
	t.Helper()
	if err := c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{Name: "snapshots", Columns: snapshotDumpCols, Rows: rows}}}); err != nil {
		t.Fatal(err)
	}
}

func aeRow(id, name, ts string, deleted bool) []interface{} {
	r := snapshotDumpRow(id, "vm", "peer", name, ts)
	if deleted {
		r[12] = "2026-10-12T00:00:00Z"
	}
	return r
}

// Anti-entropy: a newer tombstone stays against an older live row.
func TestAntiEntropy_NewerTombstoneStays(t *testing.T) {
	c := parkTestClient(t)
	seedSnap(t, c, "L", "vm", "s1", tsNew, true, "")
	aeMerge(t, c, aeRow("I", "s1", tsOld, false))
	if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "L" || !got[0].deleted {
		t.Fatalf("rows = %+v, want the tombstone L alone", got)
	}
}

// Anti-entropy: an older tombstone offered against a newer live row is
// skipped — decided, not refused, so it raises no held signal.
func TestAntiEntropy_StaleIncomingTombstoneIsSkippedNotRefused(t *testing.T) {
	c := parkTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	seedSnap(t, c, "L", "vm", "s1", tsNew, false, "")
	aeMerge(t, c, aeRow("I", "s1", tsOld, true))
	if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "L" || got[0].deleted {
		t.Fatalf("rows = %+v, want the live row L alone", got)
	}
	if p := r.ParkedEntries(); len(p) != 0 {
		t.Fatalf("a stale tombstone raised the held signal: %+v", p)
	}
}

// Anti-entropy: two tombstones of one name at the same instant converge on
// the smaller id, whichever side holds which.
func TestAntiEntropy_EqualTimeTombstonesConvergeOnTheSmallerID(t *testing.T) {
	for _, pair := range [][2]string{{"a", "m"}, {"m", "a"}} {
		c := parkTestClient(t)
		seedSnap(t, c, pair[0], "vm", "s1", tsMid, true, "")
		aeMerge(t, c, aeRow(pair[1], "s1", tsMid, true))
		if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "a" || !got[0].deleted {
			t.Fatalf("local %s, incoming %s: rows = %+v, want the tombstone a", pair[0], pair[1], got)
		}
	}
}

// Anti-entropy: a yield is undone when the incoming row does not land, so
// the name is never left empty.
func TestAntiEntropy_YieldIsUndoneWhenTheIncomingRowIsRefused(t *testing.T) {
	c := parkTestClient(t)
	seedSnap(t, c, "L", "vm", "s1", tsOld, true, "")
	bad := aeRow("I", "s1", tsNew, false)
	bad[4] = nil // state NOT NULL: the incoming row cannot land
	aeMerge(t, c, bad)
	if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "L" || !got[0].deleted {
		t.Fatalf("rows = %+v, want the tombstone L put back", got)
	}
}

// Anti-entropy: a refused identity-table row raises the held signal, from
// state, and it clears once the row applies.
func TestAntiEntropy_RefusalRaisesAndClearsTheHeldSignal(t *testing.T) {
	c := parkTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	seedSnap(t, c, "L", "vm", "s1", tsOld, false, "")
	aeMerge(t, c, aeRow("I", "s1", tsNew, false)) // two live rows: refused
	p := r.ParkedEntries()
	if len(p) != 1 || p[0].Source != "ae" || p[0].RowID != "I" || p[0].Origin != "peer" || p[0].Table != "snapshots" {
		t.Fatalf("held = %+v, want the refused row I from peer", p)
	}
	if _, err := c.DB().Exec(`DELETE FROM snapshots WHERE id = 'L'`); err != nil {
		t.Fatal(err)
	}
	aeMerge(t, c, aeRow("I", "s1", tsNew, false))
	if p := r.ParkedEntries(); len(p) != 0 {
		t.Fatalf("held after the row applied = %+v", p)
	}
}

// Only the allowlist is holdable, and the allowlist is exactly the
// replicated tables with a secondary UNIQUE: a new one fails here until it is
// judged and added (or the test says why not).
func TestParkableTables_AreTheIdentityTables(t *testing.T) {
	c := parkTestClient(t)
	var withUnique []string
	for _, table := range tableNames {
		rows, err := c.DB().Query(`SELECT "unique", origin FROM pragma_index_list(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for rows.Next() {
			var unique int
			var origin string
			if err := rows.Scan(&unique, &origin); err != nil {
				t.Fatal(err)
			}
			if unique == 1 && origin != "pk" {
				found = true
			}
		}
		rows.Close()
		if found {
			withUnique = append(withUnique, table)
		}
	}
	var allow []string
	for table := range parkableTables {
		allow = append(allow, table)
		if !hasIdentityKey(table) {
			t.Errorf("parkable table %s is not a natural-key identity table", table)
		}
	}
	sort.Strings(withUnique)
	sort.Strings(allow)
	if fmt.Sprint(withUnique) != fmt.Sprint(allow) {
		t.Fatalf("replicated tables with a secondary UNIQUE = %v, holdable tables = %v: a new UNIQUE does not make "+
			"a table holdable by itself — judge it and add it to parkableTables with its reasons, or record here why not", withUnique, allow)
	}
}

// A constraint refusal on a table not on the list back-pressures as before.
func TestApplyRemoteMutations_NonAllowlistedRefusalBackpressures(t *testing.T) {
	c := parkTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	stmts, _ := json.Marshal([]Statement{{
		SQL:    `INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		Params: []interface{}{"img", nil, "", "", 1, "2020-01-01T00:00:00Z", tsNew}, // format NOT NULL
	}})
	seq, err := r.ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{{Seq: 1, Hlc: tsNew, Origin: "peer", Stmts: string(stmts)}})
	if err == nil || seq != 0 {
		t.Fatalf("a NOT NULL refusal on images = (%d, %v), want back-pressure", seq, err)
	}
	if p := r.ParkedEntries(); len(p) != 0 {
		t.Fatalf("a non-allowlisted refusal was held: %+v", p)
	}
}

// A batch with held entries is applied once: every statement runs once, and
// a held entry's retries are not counted as new refusals.
func TestApplyRemoteMutations_BatchAppliesOnceAndRetriesAreNotCounted(t *testing.T) {
	c := parkTestClient(t)
	m := &fakeSyncMetrics{}
	c.SetSyncMetrics(m)
	r := NewReplicator(c, "", RelayConfig{})
	seedSnap(t, c, "L1", "vm", "a", tsOld, false, "")
	seedSnap(t, c, "L2", "vm", "b", tsOld, false, "")
	// No retry right after this push, so the count below is the batch alone.
	r.park.lastRetry = time.Now()
	var applied int
	releaseUseApplyHook = func(Statement) { applied++ }
	t.Cleanup(func() { releaseUseApplyHook = nil })

	batch := []*pb.MutationEntry{
		snapEntryAt(t, 1, "G1", "vm", "g1", tsNew),
		snapEntryAt(t, 2, "H1", "vm", "a", tsNew), // held
		snapEntryAt(t, 3, "H2", "vm", "b", tsNew), // held
		snapEntryAt(t, 4, "G2", "vm", "g2", tsNew),
	}
	if _, err := r.ApplyRemoteMutations(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if applied != 4 {
		t.Fatalf("statements applied %d times for a batch of 4: the batch re-ran", applied)
	}
	countConstraint := func() int {
		m.mu.Lock()
		defer m.mu.Unlock()
		n := 0
		for _, r := range m.mergeRejected {
			if r == "snapshots/wal/unique" {
				n++
			}
		}
		return n
	}
	if got := countConstraint(); got != 2 {
		t.Fatalf("unique refusals counted %d, want 2", got)
	}
	r.RetryParked(context.Background())
	if got := countConstraint(); got != 2 {
		t.Fatalf("a retry counted as a new refusal: %d", got)
	}
}

// The create uses the existing row's id over a caller's, and the caller's only
// when no row holds the name.
func TestInsertSnapshot_CallerIDOnlyForAFreeName(t *testing.T) {
	c := parkTestClient(t)
	ctx := context.Background()
	if err := InsertSnapshot(ctx, c, SnapshotRecord{ID: "mine", VMName: "vm", HostName: "h", Name: "s1", State: "ok"}); err != nil {
		t.Fatal(err)
	}
	if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "mine" {
		t.Fatalf("free name: rows = %+v, want the caller's id", got)
	}
	if err := DeleteSnapshot(ctx, c, "vm", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := InsertSnapshot(ctx, c, SnapshotRecord{ID: "other", VMName: "vm", HostName: "h", Name: "s1", State: "ok"}); err != nil {
		t.Fatal(err)
	}
	if got := snapsUnder(t, c, "vm", "s1"); len(got) != 1 || got[0].id != "mine" || got[0].deleted {
		t.Fatalf("re-create over a tombstone: rows = %+v, want mine, live", got)
	}
}
