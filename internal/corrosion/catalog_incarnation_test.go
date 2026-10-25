package corrosion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// Catalog birth incarnations (catalog_incarnation.go): every birth of an image
// or a pool records a fresh lifetime, every other write keeps it, and no write
// of one lifetime reaches another, on any replica, in any order.

func catalogGrant(t *testing.T) *capabilities.FeatureGrant {
	g := capabilities.GrantForTest(t, capabilities.FeatureCatalogIncarnation)
	return &g
}

// recordImg records name as an operator's op (revive) or a copy does: from
// the row it reads as the op begins, at clocks reserved then.
func recordImg(t *testing.T, c *Client, name, sum string, revive bool, g *capabilities.FeatureGrant) error {
	t.Helper()
	ctx := context.Background()
	start, err := ImageDeletedAt(ctx, c, name)
	if err != nil {
		return err
	}
	res, err := RecordImageWithGrant(ctx, c, ImageRecord{Name: name, Format: "qcow2", Checksum: sum, SizeBytes: 1},
		revive, start, ReserveImageClocks(c), g)
	if err == nil && res.Outcome != ImageRecordWritten {
		return fmt.Errorf("record %s: %s", name, res.Outcome)
	}
	return err
}

func mustImageBirth(t *testing.T, c *Client, name string) ImageBirth {
	t.Helper()
	b, err := ImageBirthOf(context.Background(), c, name)
	if err != nil {
		t.Fatalf("ImageBirthOf %s: %v", name, err)
	}
	if !ValidCatalogIncarnation(b.Incarnation) {
		t.Fatalf("image %s incarnation %q is not a born one", name, b.Incarnation)
	}
	return b
}

func rawIncarnation(t *testing.T, c *Client, table, where string, args ...any) string {
	t.Helper()
	var inc string
	if err := c.DB().QueryRow(`SELECT incarnation FROM `+table+` WHERE `+where, args...).Scan(&inc); err != nil {
		t.Fatalf("read %s incarnation: %v", table, err)
	}
	return inc
}

// Mutations: a birth form that omits the fresh incarnation (red at "first
// birth"); a continuation that mints one (red at "copy kept"); a rebirth that
// reuses the old one (red at "rebirth").
func TestCatalogIncarnation_ImageBirthContinuationAndRebirth(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	g := catalogGrant(t)

	if err := recordImg(t, c, "ubuntu", "aa", true, nil); !errors.Is(err, ErrCatalogBirthNeeded) {
		t.Fatalf("an operator's first record without the grant: %v, want ErrCatalogBirthNeeded", err)
	}
	if err := recordImg(t, c, "ubuntu", "aa", true, g); err != nil {
		t.Fatal(err)
	}
	first := mustImageBirth(t, c, "ubuntu")
	if !strings.Contains(first.Incarnation, "~f") {
		t.Fatalf("first birth: incarnation %q, want a first-birth (f) one", first.Incarnation)
	}
	// A copy and a re-import over the live image keep its lifetime and need
	// no grant.
	if err := recordImg(t, c, "ubuntu", "bb", false, nil); err != nil {
		t.Fatalf("copy over a born image: %v", err)
	}
	if err := recordImg(t, c, "ubuntu", "cc", true, nil); err != nil {
		t.Fatalf("re-import over a born image: %v", err)
	}
	kept := mustImageBirth(t, c, "ubuntu")
	if kept.Incarnation != first.Incarnation || kept.Checksum != "cc" {
		t.Fatalf("copy kept: %+v, want incarnation %s and the new content", kept, first.Incarnation)
	}
	if err := DeleteImage(ctx, c, "ubuntu"); err != nil {
		t.Fatal(err)
	}
	if _, err := ImageBirthOf(ctx, c, "ubuntu"); !errors.Is(err, ErrCatalogNoBirth) {
		t.Fatalf("deleted image: %v, want ErrCatalogNoBirth", err)
	}
	if got := rawIncarnation(t, c, "images", "name = ?", "ubuntu"); got != first.Incarnation {
		t.Fatalf("the tombstone holds %q, want the dead lifetime %s", got, first.Incarnation)
	}
	if err := recordImg(t, c, "ubuntu", "dd", false, nil); err == nil {
		// A copy never revives (the guard reports the delete).
		if _, err := ImageBirthOf(ctx, c, "ubuntu"); err == nil {
			t.Fatal("a copy revived a deleted image")
		}
	}
	if err := recordImg(t, c, "ubuntu", "ee", true, nil); !errors.Is(err, ErrCatalogBirthNeeded) {
		t.Fatalf("re-create without the grant: %v, want ErrCatalogBirthNeeded", err)
	}
	if err := recordImg(t, c, "ubuntu", "ee", true, g); err != nil {
		t.Fatal(err)
	}
	re := mustImageBirth(t, c, "ubuntu")
	if re.Incarnation == first.Incarnation || !strings.Contains(re.Incarnation, "~r") || CompareCatalogIncarnations(re.Incarnation, first.Incarnation) <= 0 {
		t.Fatalf("rebirth: incarnation %q after %q, want a later rebirth (r) one", re.Incarnation, first.Incarnation)
	}
}

// A row written before the latch is no lifetime, and nothing makes it one
// implicitly; a node not latched refuses to give birth over a born lifetime.
//
// Mutation: let the unlatched record write its previous-release pair over the
// born tombstone — red at "unlatched rebirth".
func TestCatalogIncarnation_LegacyRowsAndUnlatchedRebirth(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if _, err := RecordImage(ctx, c, ImageRecord{Name: "old", Format: "qcow2", Checksum: "aa"}, true, "", ReserveImageClocks(c)); err != nil {
		t.Fatal(err)
	}
	if _, err := ImageBirthOf(ctx, c, "old"); !errors.Is(err, ErrCatalogNoBirth) {
		t.Fatalf("a pre-latch row: %v, want ErrCatalogNoBirth", err)
	}
	if err := recordImg(t, c, "old", "bb", true, catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	if got := rawIncarnation(t, c, "images", "name = ?", "old"); got != "" {
		t.Fatalf("a write to a live pre-latch row gave it incarnation %q: no implicit adoption", got)
	}

	if err := recordImg(t, c, "born", "aa", true, catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	if err := DeleteImage(ctx, c, "born"); err != nil {
		t.Fatal(err)
	}
	d, _ := ImageDeletedAt(ctx, c, "born")
	_, err := RecordImage(ctx, c, ImageRecord{Name: "born", Format: "qcow2", Checksum: "zz"}, true, d, ReserveImageClocks(c))
	if !errors.Is(err, ErrCatalogBirthNeedsLatch) {
		t.Fatalf("unlatched rebirth over a born tombstone: %v, want ErrCatalogBirthNeedsLatch", err)
	}
	if d2, _ := ImageDeletedAt(ctx, c, "born"); d2 == "" {
		t.Fatal("unlatched rebirth revived the born image")
	}
}

func seedCatalogHost(t *testing.T, c *Client, name string, incarnation int64) {
	t.Helper()
	if err := InsertHost(context.Background(), c, HostRecord{Name: name, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = ? WHERE name = ?`, incarnation, name); err != nil {
		t.Fatal(err)
	}
}

func catalogPool(host, name string, total int64) StoragePoolRecord {
	return StoragePoolRecord{HostName: host, Name: name, Driver: "dir", Target: "/srv/" + name, State: "active", TotalBytes: total}
}

// Mutations: a refresh (UpdateStoragePool) giving birth over a tombstone —
// red at "no revival"; a birth that records no host incarnation — red at "host
// lifetime"; the consumer not comparing it — red at "stale host".
func TestCatalogIncarnation_PoolLifetimes(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedCatalogHost(t, c, "host-a", 0)
	g := catalogGrant(t)

	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 1), nil); !errors.Is(err, ErrCatalogBirthNeeded) {
		t.Fatalf("pool create without the grant: %v, want ErrCatalogBirthNeeded", err)
	}
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 1), g); err != nil {
		t.Fatal(err)
	}
	born, err := StoragePoolBirthOf(ctx, c, "host-a", "p")
	if err != nil || !strings.Contains(born.Incarnation, "~f") || born.HostIncarnation != 0 {
		t.Fatalf("first pool birth: %+v %v", born, err)
	}
	// Capacity refreshes keep the lifetime, on a latched node and not.
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 2), nil); err != nil {
		t.Fatal(err)
	}
	if err := UpsertStoragePool(ctx, c, catalogPool("host-a", "p", 3)); err != nil {
		t.Fatal(err)
	}
	if b, err := StoragePoolBirthOf(ctx, c, "host-a", "p"); err != nil || b.Incarnation != born.Incarnation {
		t.Fatalf("capacity refresh changed the lifetime: %+v %v", b, err)
	}
	if got, _, _ := GetStoragePool(ctx, c, "host-a", "p"); got.TotalBytes != 3 {
		t.Fatalf("capacity refresh not written: %+v", got)
	}

	if err := MarkStoragePoolDeleted(ctx, c, "host-a", "p"); err != nil {
		t.Fatal(err)
	}
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 4), nil); !errors.Is(err, ErrCatalogBirthNeeded) {
		t.Fatalf("a refresh of a deleted pool: %v, want ErrCatalogBirthNeeded (no revival)", err)
	}
	if err := UpsertStoragePool(ctx, c, catalogPool("host-a", "p", 4)); !errors.Is(err, ErrCatalogBirthNeedsLatch) {
		t.Fatalf("an unlatched refresh of a born, deleted pool: %v, want ErrCatalogBirthNeedsLatch", err)
	}
	if err := UpdateStoragePool(ctx, c, catalogPool("host-a", "p", 4)); err != nil {
		t.Fatalf("a capacity refresh of a deleted pool: %v", err)
	}
	if _, ok, _ := GetStoragePool(ctx, c, "host-a", "p"); ok {
		t.Fatal("no revival: a write to a deleted pool brought it back")
	}
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 5), g); err != nil {
		t.Fatal(err)
	}
	re, err := StoragePoolBirthOf(ctx, c, "host-a", "p")
	if err != nil || CompareCatalogIncarnations(re.Incarnation, born.Incarnation) <= 0 || !strings.Contains(re.Incarnation, "~r") {
		t.Fatalf("pool rebirth: %+v %v after %s", re, err, born.Incarnation)
	}

	// The host is removed and re-admitted (incarnation 1): the pool row it
	// left is of its earlier lifetime.
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1 WHERE name = 'host-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := StoragePoolBirthOf(ctx, c, "host-a", "p"); !errors.Is(err, ErrCatalogHostLifetime) {
		t.Fatalf("stale host: %v, want ErrCatalogHostLifetime", err)
	}
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 6), nil); !errors.Is(err, ErrCatalogBirthNeeded) {
		t.Fatalf("the re-admitted host's write: %v, want a birth (ErrCatalogBirthNeeded)", err)
	}
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 6), g); err != nil {
		t.Fatal(err)
	}
	host, err := StoragePoolBirthOf(ctx, c, "host-a", "p")
	if err != nil || host.HostIncarnation != 1 || CompareCatalogIncarnations(host.Incarnation, re.Incarnation) <= 0 {
		t.Fatalf("host lifetime: %+v %v, want a rebirth under host incarnation 1", host, err)
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET deleted_at = '2026-01-01T00:00:00Z' WHERE name = 'host-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := StoragePoolBirthOf(ctx, c, "host-a", "p"); !errors.Is(err, ErrCatalogHostLifetime) {
		t.Fatalf("a removed host's pool: %v, want ErrCatalogHostLifetime", err)
	}
}

// loggedEntries returns c's mutation_log entries after seq, as a peer would
// receive them.
func catalogLogged(t *testing.T, c *Client, after int64) ([]*pb.MutationEntry, int64) {
	t.Helper()
	rows, err := c.DB().Query(`SELECT seq, hlc, origin, stmts FROM mutation_log WHERE seq > ? ORDER BY seq`, after)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []*pb.MutationEntry
	last := after
	for rows.Next() {
		e := &pb.MutationEntry{}
		if err := rows.Scan(&e.Seq, &e.Hlc, &e.Origin, &e.Stmts); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
		last = e.Seq
	}
	return out, last
}

func catalogShip(t *testing.T, r *Replicator, es ...*pb.MutationEntry) {
	t.Helper()
	if _, err := r.ApplyRemoteMutationsFrom(context.Background(), es, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// redeliver is e's statements again under a fresh entry clock, as a replay
// through another relay would carry them.
func catalogRedeliver(e *pb.MutationEntry, n int) *pb.MutationEntry {
	return &pb.MutationEntry{Seq: e.Seq + 1000, Hlc: fmt.Sprintf("2999000000%03d-0000-relay", n), Origin: "relay", Stmts: e.Stmts}
}

type catalogImgRow struct{ inc, sum, deleted string }

func catalogImageRow(t *testing.T, c *Client, name string) catalogImgRow {
	t.Helper()
	var r catalogImgRow
	if err := c.DB().QueryRow(`SELECT incarnation, COALESCE(checksum, ''), COALESCE(deleted_at, '') FROM images WHERE name = ?`, name).
		Scan(&r.inc, &r.sum, &r.deleted); err != nil {
		t.Fatal(err)
	}
	return r
}

// The WAL rules. Mutations, one at a time in catalogLifetimeDecision: the
// birth judged by its clock (red at "stale clock"); a lesser birth applied
// (red at "older birth"); legacy writes applied to a born row (red at
// "legacy"); the same lifetime's delete judged by its clock (red at
// "tombstone final"); a re-delivered birth reviving its own tombstone (red at
// "re-delivered").
func TestCatalogIncarnation_ReceiverOrdersLifetimes(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)
	r := NewReplicator(b, "", RelayConfig{})
	g := catalogGrant(t)

	if err := recordImg(t, a, "img", "v1", true, g); err != nil {
		t.Fatal(err)
	}
	birth1, seq := catalogLogged(t, a, 0)
	if err := recordImg(t, a, "img", "v1-copy", false, nil); err != nil {
		t.Fatal(err)
	}
	cont1, seq := catalogLogged(t, a, seq)
	if err := DeleteImage(ctx, a, "img"); err != nil {
		t.Fatal(err)
	}
	del1, seq := catalogLogged(t, a, seq)
	if err := recordImg(t, a, "img", "v2", true, g); err != nil {
		t.Fatal(err)
	}
	birth2, _ := catalogLogged(t, a, seq)

	// b holds the first lifetime, and writes to it itself AFTER a's rebirth
	// was stamped: its row's clock is newer than the birth that ends it.
	catalogShip(t, r, birth1...)
	if err := recordImg(t, b, "img", "b-local", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DB().Exec(`UPDATE images SET updated_at = '2999999999998-0000-b' WHERE name = 'img'`); err != nil {
		t.Fatal(err)
	}
	catalogShip(t, r, birth2...)
	got := catalogImageRow(t, b, "img")
	if got.inc != rawIncarnation(t, a, "images", "name = 'img'") || got.sum != "v2" || got.deleted != "" {
		t.Fatalf("stale clock: b holds %+v after the rebirth, want the second lifetime live with v2", got)
	}
	// The first lifetime's late writes change nothing of the second.
	catalogShip(t, r, cont1...)
	catalogShip(t, r, del1...)
	catalogShip(t, r, catalogRedeliver(birth1[0], 1))
	if now := catalogImageRow(t, b, "img"); now != got {
		t.Fatalf("older birth / late writes: b holds %+v, want %+v", now, got)
	}
	// A previous-release write, however new its clock, never reaches a born row.
	legacy := Statement{SQL: imageInsertSQL, Params: []interface{}{"img", "raw", "", "legacy", 9, nowRFC3339(), "2999999999999-0000-old"}}
	revive := Statement{SQL: imageDeletedAtSQL, Params: []interface{}{nil, "2999999999999-0001-old", "img"}}
	catalogShip(t, r, replayEntry(t, "old", "2999999999999-0000-old", legacy, revive)...)
	if now := catalogImageRow(t, b, "img"); now != got {
		t.Fatalf("legacy: b holds %+v after a previous-release write, want %+v", now, got)
	}

	// The tombstone is final within its lifetime: b writes the live row at a
	// clock newer than a's delete, and the delete still ends it.
	if err := recordImg(t, b, "img", "b-later", false, nil); err != nil {
		t.Fatal(err)
	}
	seqBefore := catalogLastSeq(t, a)
	if err := DeleteImage(ctx, a, "img"); err != nil {
		t.Fatal(err)
	}
	del2, _ := catalogLogged(t, a, seqBefore)
	// Re-stamp b's live row far in the future, as a skewed clock would.
	if _, err := b.DB().Exec(`UPDATE images SET updated_at = '2999999999999-0005-b' WHERE name = 'img'`); err != nil {
		t.Fatal(err)
	}
	catalogShip(t, r, del2...)
	if now := catalogImageRow(t, b, "img"); now.deleted == "" {
		t.Fatalf("tombstone final: b's newer live write outlived its lifetime's delete: %+v", now)
	}
	// The tombstone's clock is the oldest there is (a deleter's clock far
	// behind): only the lifetime keeps the birth off it.
	if _, err := b.DB().Exec(`UPDATE images SET updated_at = '2000-01-01T00:00:00.000000000Z' WHERE name = 'img'`); err != nil {
		t.Fatal(err)
	}
	catalogShip(t, r, catalogRedeliver(birth2[0], 2))
	if now := catalogImageRow(t, b, "img"); now.deleted == "" {
		t.Fatalf("re-delivered: the second lifetime's birth revived its own tombstone: %+v", now)
	}
}

func catalogLastSeq(t *testing.T, c *Client) int64 {
	t.Helper()
	var n int64
	if err := c.DB().QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM mutation_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The pool's WAL rules, and its host lifetime: a late mutate of an earlier
// lifetime, and a previous-release upsert, change nothing of a reborn pool.
//
// Mutation: drop the incarnation predicate from storagePoolMutateSQL — red at
// "late mutate".
func TestCatalogIncarnation_ReceiverPoolLifetimes(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)
	seedCatalogHost(t, a, "host-a", 0)
	seedCatalogHost(t, b, "host-a", 0)
	r := NewReplicator(b, "", RelayConfig{})
	g := catalogGrant(t)

	if err := UpsertStoragePoolWithGrant(ctx, a, catalogPool("host-a", "p", 1), g); err != nil {
		t.Fatal(err)
	}
	birth1, seq := catalogLogged(t, a, 0)
	if err := UpsertStoragePoolWithGrant(ctx, a, catalogPool("host-a", "p", 2), nil); err != nil {
		t.Fatal(err)
	}
	mut1, seq := catalogLogged(t, a, seq)
	if err := MarkStoragePoolDeleted(ctx, a, "host-a", "p"); err != nil {
		t.Fatal(err)
	}
	_, seq = catalogLogged(t, a, seq)
	if err := UpsertStoragePoolWithGrant(ctx, a, catalogPool("host-a", "p", 7), g); err != nil {
		t.Fatal(err)
	}
	birth2, _ := catalogLogged(t, a, seq)
	want, err := StoragePoolBirthOf(ctx, a, "host-a", "p")
	if err != nil {
		t.Fatal(err)
	}

	catalogShip(t, r, birth1...)
	catalogShip(t, r, birth2...)
	// b's row of the second lifetime is stamped before the first lifetime's
	// mutate (a clock far behind): only the lifetime keeps it off.
	if _, err := b.DB().Exec(`UPDATE storage_pools SET updated_at = '2000-01-01T00:00:00.000000000Z' WHERE name = 'p'`); err != nil {
		t.Fatal(err)
	}
	catalogShip(t, r, mut1...)
	got, err := StoragePoolBirthOf(ctx, b, "host-a", "p")
	if err != nil || got.Incarnation != want.Incarnation {
		t.Fatalf("late mutate: b holds %+v %v, want %s", got, err, want.Incarnation)
	}
	if p, _, _ := GetStoragePool(ctx, b, "host-a", "p"); p.TotalBytes != 7 {
		t.Fatalf("late mutate: the first lifetime's capacity reached the second: %+v", p)
	}
	legacy := Statement{SQL: storagePoolLegacySQL, Params: []interface{}{"host-a", "p", "dir", "", "/elsewhere", "{}", "", 99, 0, "active", "2999999999999-0000-old"}}
	catalogShip(t, r, replayEntry(t, "old", "2999999999999-0000-old", legacy)...)
	if p, _, _ := GetStoragePool(ctx, b, "host-a", "p"); p.Target == "/elsewhere" {
		t.Fatalf("legacy: a previous-release upsert reached a born pool: %+v", p)
	}
}

// Anti-entropy applies the same order. Mutation: return mergeAuthorityNormal
// from catalogDumpDecision — red at "ae".
func TestCatalogIncarnation_AntiEntropyOrdersLifetimes(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)
	g := catalogGrant(t)
	if err := recordImg(t, a, "img", "v1", true, g); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeStateBytesLWW(catalogDump(t, a, "images")); err != nil {
		t.Fatal(err)
	}
	first := catalogImageRow(t, b, "img")
	if err := DeleteImage(ctx, a, "img"); err != nil {
		t.Fatal(err)
	}
	if err := recordImg(t, a, "img", "v2", true, g); err != nil {
		t.Fatal(err)
	}
	// b's first-lifetime row is stamped far ahead of a's rebirth.
	if _, err := b.DB().Exec(`UPDATE images SET updated_at = '2999999999999-0000-b', checksum = 'stale' WHERE name = 'img'`); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeStateBytesLWW(catalogDump(t, a, "images")); err != nil {
		t.Fatal(err)
	}
	second := catalogImageRow(t, a, "img")
	if got := catalogImageRow(t, b, "img"); got != second || got.inc == first.inc {
		t.Fatalf("ae: b holds %+v after the merge, want the second lifetime %+v", got, second)
	}
	// And the other way: a keeps its later lifetime over b's earlier, newer row.
	stale := newTestDB(t)
	if err := stale.MergeStateBytesLWW(catalogDump(t, a, "images")); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.DB().Exec(`UPDATE images SET incarnation = ?, updated_at = '2999999999999-0001-s' WHERE name = 'img'`, first.inc); err != nil {
		t.Fatal(err)
	}
	if err := a.MergeStateBytesLWW(catalogDump(t, stale, "images")); err != nil {
		t.Fatal(err)
	}
	if got := catalogImageRow(t, a, "img"); got != second {
		t.Fatalf("ae: a holds %+v after merging an earlier lifetime's newer row, want %+v", got, second)
	}
	// A tombstone is final within its lifetime.
	if err := DeleteImage(ctx, a, "img"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DB().Exec(`UPDATE images SET updated_at = '2999999999999-0009-b' WHERE name = 'img'`); err != nil {
		t.Fatal(err)
	}
	if err := a.MergeStateBytesLWW(catalogDump(t, b, "images")); err != nil {
		t.Fatal(err)
	}
	if got := catalogImageRow(t, a, "img"); got.deleted == "" {
		t.Fatalf("ae: a's tombstone was revived by a newer live row of its own lifetime: %+v", got)
	}
	if err := b.MergeStateBytesLWW(catalogDump(t, a, "images")); err != nil {
		t.Fatal(err)
	}
	if got := catalogImageRow(t, b, "img"); got.deleted == "" {
		t.Fatalf("ae: b's newer live row of a deleted lifetime outlived the delete: %+v", got)
	}
}

func catalogDump(t *testing.T, c *Client, tables ...string) []byte {
	t.Helper()
	b, err := c.DumpTablesBytes(tables)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A node whose rows were all born before the latch leaves the new columns out
// of its dump, so a previous-release node keeps taking its rows. Mutation:
// drop images from unsetIncarnationColumns — red.
func TestCatalogIncarnation_DumpOmitsUnsetColumns(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedCatalogHost(t, c, "host-a", 0)
	if _, err := RecordImage(ctx, c, ImageRecord{Name: "old", Format: "qcow2"}, true, "", ReserveImageClocks(c)); err != nil {
		t.Fatal(err)
	}
	if err := UpsertStoragePool(ctx, c, catalogPool("host-a", "old", 1)); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"images", "storage_pools"} {
		st, ok := c.dumpTable(table)
		if !ok {
			t.Fatalf("dump %s", table)
		}
		for _, col := range []string{"incarnation", "host_incarnation"} {
			if indexOf(st.Columns, col) >= 0 {
				t.Errorf("%s's dump carries %s while every row's is unset: %v", table, col, st.Columns)
			}
		}
	}
	if err := recordImg(t, c, "new", "aa", true, catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.dumpTable("images"); indexOf(st.Columns, "incarnation") < 0 {
		t.Errorf("images' dump omits incarnation with a born row: %v", st.Columns)
	}
}
