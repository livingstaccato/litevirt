package corrosion

import (
	"context"
	"testing"
	"time"
)

// Review of bef946be5: the interleavings that crossed a lifetime.

// F1 (the reviewer's interleaving): a capacity refresh lists the pool, lv
// pool rm and lv pool create (another target) run, and the refresh then
// writes. It must write nothing into the new pool. A refresh of the current
// lifetime writes capacity and state only, never configuration.
//
// Mutations: UpdateStoragePool not scoped to the record's incarnation — red
// at "stale refresh"; writing configuration from the record — red at
// "config".
func TestCatalogReview_StaleRefreshNeverReachesANewLifetime(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedCatalogHost(t, c, "host-a", 0)
	g := catalogGrant(t)
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 1), g); err != nil {
		t.Fatal(err)
	}
	stale, ok, err := GetStoragePool(ctx, c, "host-a", "p") // the refresh's listing
	if err != nil || !ok {
		t.Fatalf("listing: %v %v", ok, err)
	}
	if err := MarkStoragePoolDeleted(ctx, c, "host-a", "p"); err != nil {
		t.Fatal(err)
	}
	fresh := catalogPool("host-a", "p", 2)
	fresh.Target = "/srv/new"
	if err := UpsertStoragePoolWithGrant(ctx, c, fresh, g); err != nil {
		t.Fatal(err)
	}
	born, err := StoragePoolBirthOf(ctx, c, "host-a", "p")
	if err != nil {
		t.Fatal(err)
	}
	stale.TotalBytes, stale.State = 99, "error"
	if err := UpdateStoragePool(ctx, c, stale); err != nil {
		t.Fatalf("stale refresh: %v", err)
	}
	got, _, _ := GetStoragePool(ctx, c, "host-a", "p")
	if got.Target != "/srv/new" || got.TotalBytes == 99 || got.State == "error" {
		t.Fatalf("stale refresh: the earlier lifetime's refresh reached the new pool: %+v", got)
	}
	if b, err := StoragePoolBirthOf(ctx, c, "host-a", "p"); err != nil || b.Incarnation != born.Incarnation {
		t.Fatalf("stale refresh changed the lifetime: %+v %v", b, err)
	}

	cur, _, _ := GetStoragePool(ctx, c, "host-a", "p")
	cur.TotalBytes, cur.Target, cur.Driver = 7, "/elsewhere", "nfs"
	if err := UpdateStoragePool(ctx, c, cur); err != nil {
		t.Fatal(err)
	}
	got, _, _ = GetStoragePool(ctx, c, "host-a", "p")
	if got.TotalBytes != 7 {
		t.Fatalf("a refresh of the current lifetime wrote no capacity: %+v", got)
	}
	if got.Target != "/srv/new" || got.Driver != "dir" {
		t.Fatalf("config: a refresh wrote configuration: %+v", got)
	}
}

// futureStamp is now plus d in the RFC3339 form NowTS writes.
func futureStamp(d time.Duration) string {
	return time.Now().Add(d).UTC().Format(nowTSLayout)
}

// recordUntilWritten records an operator's op as grpcapi does: a superseded
// record is taken again at fresh clocks (ObserveStamp is the record's own).
func recordUntilWritten(t *testing.T, c *Client, name, sum string) {
	t.Helper()
	ctx := context.Background()
	g := catalogGrant(t)
	for i := 0; i < 4; i++ {
		d, inc, err := ImageLifetimeAt(ctx, c, name)
		if err != nil {
			t.Fatal(err)
		}
		clk := ReserveImageClocks(c)
		clk.Lifetime = inc
		res, err := RecordImageWithGrant(ctx, c, ImageRecord{Name: name, Format: "qcow2", Checksum: sum, SizeBytes: 1}, true, d, clk, g)
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome == ImageRecordWritten {
			return
		}
		if res.Outcome != ImageRecordSuperseded {
			t.Fatalf("record %s: %s", name, res.Outcome)
		}
		ObserveStamp(c, res.UpdatedAt)
	}
	t.Fatalf("record %s never written", name)
}

// F2: an image born on a node whose clock runs 2s ahead reaches this node by
// anti-entropy; lv image rm and import here must give a lifetime that sorts
// AFTER it, so neither the WAL nor anti-entropy brings the earlier one back.
//
// Mutation: catalogRowFloor returning updated_at only (the birth clock not
// observed) — red at "rebirth sorts".
func TestCatalogReview_RebirthSortsAfterASkewedLifetime(t *testing.T) {
	ctx := context.Background()
	ahead, b := newTestDB(t), newTestDB(t)
	if err := recordImg(t, ahead, "img", "v1", true, catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	// The birth as the skewed node stamped it: its clock 2s ahead.
	future := futureStamp(2 * time.Second)
	old := future + "~f0123456789abcdef0123456789abcdef"
	if _, err := ahead.DB().Exec(`UPDATE images SET incarnation = ?, updated_at = ? WHERE name = 'img'`, old, future); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeStateBytesLWW(catalogDump(t, ahead, "images")); err != nil {
		t.Fatal(err)
	}
	// A later write from a node whose clock did not observe that birth left
	// the row stamped before its own lifetime's birth clock.
	if _, err := b.DB().Exec(`UPDATE images SET updated_at = ? WHERE name = 'img'`, futureStamp(0)); err != nil {
		t.Fatal(err)
	}
	seq := catalogLastSeq(t, b)
	if err := DeleteImage(ctx, b, "img"); err != nil {
		t.Fatal(err)
	}
	var tomb string
	if err := b.DB().QueryRow(`SELECT updated_at FROM images WHERE name = 'img'`).Scan(&tomb); err != nil || lwwOrder(tomb, future) <= 0 {
		t.Fatalf("delete stamp: the tombstone %s is not stamped after its lifetime's birth %s (%v)", tomb, future, err)
	}
	recordUntilWritten(t, b, "img", "v2")
	reborn := catalogImageRow(t, b, "img")
	if CompareCatalogIncarnations(reborn.inc, old) <= 0 || reborn.deleted != "" {
		t.Fatalf("rebirth sorts: the re-import's lifetime %q does not sort after the one it ends %q", reborn.inc, old)
	}

	// The WAL: a replica holding the earlier lifetime takes the rm and the
	// re-import, and ends on the new lifetime, live.
	wal := newTestDB(t)
	if err := wal.MergeStateBytesLWW(catalogDump(t, ahead, "images")); err != nil {
		t.Fatal(err)
	}
	entries, _ := catalogLogged(t, b, seq)
	catalogShip(t, NewReplicator(wal, "", RelayConfig{}), entries...)
	if got := catalogImageRow(t, wal, "img"); got.inc != reborn.inc || got.deleted != "" || got.sum != "v2" {
		t.Fatalf("wal: the replica holds %+v, want the re-import %+v", got, reborn)
	}
	// Anti-entropy, both ways.
	ae := newTestDB(t)
	if err := ae.MergeStateBytesLWW(catalogDump(t, ahead, "images")); err != nil {
		t.Fatal(err)
	}
	if err := ae.MergeStateBytesLWW(catalogDump(t, b, "images")); err != nil {
		t.Fatal(err)
	}
	if got := catalogImageRow(t, ae, "img"); got != reborn {
		t.Fatalf("ae: the replica holds %+v, want the re-import %+v", got, reborn)
	}
	if err := b.MergeStateBytesLWW(catalogDump(t, ahead, "images")); err != nil {
		t.Fatal(err)
	}
	if got := catalogImageRow(t, b, "img"); got != reborn {
		t.Fatalf("ae: the earlier lifetime came back: %+v, want %+v", got, reborn)
	}
}

// F2, pools: the same for a pool's rebirth.
func TestCatalogReview_PoolRebirthSortsAfterASkewedLifetime(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedCatalogHost(t, c, "host-a", 0)
	g := catalogGrant(t)
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 1), g); err != nil {
		t.Fatal(err)
	}
	future := futureStamp(2 * time.Second)
	old := future + "~f0123456789abcdef0123456789abcdef"
	if _, err := c.DB().Exec(`UPDATE storage_pools SET incarnation = ?, updated_at = ? WHERE name = 'p'`, old, futureStamp(0)); err != nil {
		t.Fatal(err)
	}
	if err := MarkStoragePoolDeleted(ctx, c, "host-a", "p"); err != nil {
		t.Fatal(err)
	}
	var tomb string
	if err := c.DB().QueryRow(`SELECT updated_at FROM storage_pools WHERE name = 'p'`).Scan(&tomb); err != nil || lwwOrder(tomb, future) <= 0 {
		t.Fatalf("delete stamp: the tombstone %s is not stamped after its lifetime's birth %s (%v)", tomb, future, err)
	}
	// And a tombstone a lagging node stamped before that birth.
	if _, err := c.DB().Exec(`UPDATE storage_pools SET updated_at = ? WHERE name = 'p'`, futureStamp(0)); err != nil {
		t.Fatal(err)
	}
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 2), g); err != nil {
		t.Fatal(err)
	}
	b, err := StoragePoolBirthOf(ctx, c, "host-a", "p")
	if err != nil || CompareCatalogIncarnations(b.Incarnation, old) <= 0 {
		t.Fatalf("rebirth sorts: pool %+v %v, want a lifetime after %s", b, err, old)
	}
}

// F3: a pool born under an earlier lifetime of its host (removed and
// re-admitted since) is not offered to anything, and a refresh read before
// the re-admission writes nothing to it.
//
// Mutation: storagePoolUsable without the host-incarnation clause — red at
// "listed".
func TestCatalogReview_AStaleHostPoolIsNotUsable(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedCatalogHost(t, c, "host-a", 0)
	if _, err := c.DB().Exec(`UPDATE hosts SET state = 'active' WHERE name = 'host-a'`); err != nil {
		t.Fatal(err)
	}
	if err := UpsertStoragePoolWithGrant(ctx, c, catalogPool("host-a", "p", 1), catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	before, _, _ := GetStoragePool(ctx, c, "host-a", "p")
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1 WHERE name = 'host-a'`); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := GetStoragePool(ctx, c, "host-a", "p"); ok {
		t.Fatal("listed: GetStoragePool returns a pool of the host's earlier lifetime")
	}
	for name, list := range map[string]func() ([]StoragePoolRecord, error){
		"all":     func() ([]StoragePoolRecord, error) { return ListAllStoragePools(ctx, c) },
		"host":    func() ([]StoragePoolRecord, error) { return ListStoragePoolsForHost(ctx, c, "host-a") },
		"by name": func() ([]StoragePoolRecord, error) { return ListStoragePoolsNamed(ctx, c, "p") },
	} {
		if ps, err := list(); err != nil || len(ps) != 0 {
			t.Errorf("listed: %s lists %+v %v", name, ps, err)
		}
	}
	if hs, err := HostsWithPool(ctx, c, "p", ""); err != nil || len(hs) != 0 {
		t.Errorf("listed: HostsWithPool offers %v %v", hs, err)
	}
	before.TotalBytes = 42
	if err := UpdateStoragePool(ctx, c, before); err != nil {
		t.Fatal(err)
	}
	var total int64
	if err := c.DB().QueryRow(`SELECT total_bytes FROM storage_pools WHERE name = 'p'`).Scan(&total); err != nil || total == 42 {
		t.Fatalf("a refresh wrote to a pool of the host's earlier lifetime: total %d %v", total, err)
	}
	if err := NoteStaleHostPools(ctx, c, "host-a"); err != nil {
		t.Fatal(err)
	}
}

// F4: a copy begun under one lifetime, which records after a rebirth stamped
// before it began (a delete and an import on another node, not yet here when
// the copy began), never writes its content into the new lifetime.
//
// Mutation: drop the clk.Lifetime check in RecordImageLifetime — red.
func TestCatalogReview_ALateCopyStaysInItsLifetime(t *testing.T) {
	ctx := context.Background()
	a, c := newTestDB(t), newTestDB(t)
	if err := recordImg(t, a, "img", "v1", true, catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	born, seq := catalogLogged(t, a, 0)
	catalogShip(t, NewReplicator(c, "", RelayConfig{}), born...)
	if err := DeleteImage(ctx, a, "img"); err != nil {
		t.Fatal(err)
	}
	if err := recordImg(t, a, "img", "v2", true, catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	rebirth, _ := catalogLogged(t, a, seq)
	// The copy begins on c, under the first lifetime, after a's rebirth was
	// stamped.
	_, startInc, err := ImageLifetimeAt(ctx, c, "img")
	if err != nil {
		t.Fatal(err)
	}
	clk := ReserveImageClocks(c)
	clk.Lifetime = startInc
	catalogShip(t, NewReplicator(c, "", RelayConfig{}), rebirth...)
	res, err := RecordImageWithGrant(ctx, c, ImageRecord{Name: "img", Format: "qcow2", Checksum: "v1-copy", SizeBytes: 1}, false, "", clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := catalogImageRow(t, c, "img"); got.sum != "v2" {
		t.Fatalf("the late copy (%s) wrote the first lifetime's content into the second: %+v", res.Outcome, got)
	}
	if res.Outcome != ImageRecordSuperseded || res.Checksum != "v2" {
		t.Fatalf("the late copy reported %+v, want superseded by the second lifetime's v2", res)
	}
}

// F2, the floor alone: a tombstone a lagging node stamped BEFORE the birth
// of the lifetime it ends (the birth came from a node whose clock ran ahead),
// arriving on a node whose clock observed neither. The rebirth here must
// still sort after that lifetime.
//
// Mutations: catalogRowFloor ignoring the birth clock — red at "image"; the
// pool birth stamped after updated_at only — red at "pool".
func TestCatalogReview_RebirthOverALaggingTombstone(t *testing.T) {
	ctx := context.Background()
	future := futureStamp(2 * time.Second)
	old := future + "~f0123456789abcdef0123456789abcdef"

	c := newTestDB(t)
	if _, err := c.DB().Exec(`INSERT INTO images (name, format, checksum, size_bytes, created_at, updated_at, deleted_at, incarnation)
		VALUES ('img', 'qcow2', 'v1', 1, ?, ?, ?, ?)`, nowRFC3339(), futureStamp(0), nowRFC3339Nano(), old); err != nil {
		t.Fatal(err)
	}
	recordUntilWritten(t, c, "img", "v2")
	if got := catalogImageRow(t, c, "img"); CompareCatalogIncarnations(got.inc, old) <= 0 {
		t.Fatalf("image: the rebirth %q sorts below the lifetime it ends %q", got.inc, old)
	}

	p := newTestDB(t)
	seedCatalogHost(t, p, "host-a", 0)
	if _, err := p.DB().Exec(`INSERT INTO storage_pools (host_name, name, driver, target, state, updated_at, deleted_at, incarnation, host_incarnation)
		VALUES ('host-a', 'p', 'dir', '/srv/p', 'active', ?, ?, ?, 0)`, futureStamp(0), nowRFC3339(), old); err != nil {
		t.Fatal(err)
	}
	if err := UpsertStoragePoolWithGrant(ctx, p, catalogPool("host-a", "p", 2), catalogGrant(t)); err != nil {
		t.Fatal(err)
	}
	if b, err := StoragePoolBirthOf(ctx, p, "host-a", "p"); err != nil || CompareCatalogIncarnations(b.Incarnation, old) <= 0 {
		t.Fatalf("pool: the rebirth %+v %v sorts below the lifetime it ends %q", b, err, old)
	}
}
