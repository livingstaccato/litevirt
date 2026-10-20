package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedSourceBackedMove is seedMovedVM for a live move, not pivoted, of an
// overlay on base:root: the persistent config names the source, the record
// keeps the source's backing record, and the disk row is left where rowOn
// says, with no backing record (the commit cleared it for the flattened copy).
func seedSourceBackedMove(t *testing.T, db *corrosion.Client, dir, rowOn string) (src, dst string, dom MoveDomain) {
	t.Helper()
	ctx := context.Background()
	fake, src, dst := seedMovedVM(t, db, dir, "src", true, false)
	ms, err := UnresolvedMovesOf(dir, "mv")
	if err != nil || len(ms) != 1 {
		t.Fatalf("record: %+v %v", ms, err)
	}
	ms[0].SrcBackingDisk = "base:root"
	if err := RecordUnresolvedMove(dir, ms[0]); err != nil {
		t.Fatal(err)
	}
	if rowOn == "dst" {
		if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-a", dst, "local", "warm"); err != nil {
			t.Fatal(err)
		}
	}
	return src, dst, fakeMoveDomain(fake)
}

// failBackingOn makes every write of the disk row on path with its backing
// record base:root fail, until the returned func drops it.
func failBackingOn(t *testing.T, db *corrosion.Client, path string) (drop func()) {
	t.Helper()
	ctx := context.Background()
	if err := db.Execute(ctx, `CREATE TRIGGER fail_backing_restore BEFORE INSERT ON vm_disks
		WHEN NEW.backing_disk = 'base:root' AND NEW.path = '`+path+`'
		BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := db.Execute(ctx, `DROP TRIGGER fail_backing_restore`); err != nil {
			t.Fatal(err)
		}
	}
}

func backedRow(t *testing.T, db *corrosion.Client) corrosion.DiskRecord {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), db, "mv")
	if err != nil || len(disks) != 1 {
		t.Fatalf("disk rows: %+v %v", disks, err)
	}
	return disks[0]
}

// I1: the source's backing record is restored with its placement, or the
// record of the move stays. A restore that fails once, then a retry, never
// ends with the record gone and the source's base unreferenced.
//
// Mutation "placement written without the backing record" (pointRow's
// guarded write leaves BackingDisk/BackingImage as read): red.
func TestResolveUnresolvedMoves_RetryAfterAFailedBackingRestoreKeepsTheBase(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	src, _, dom := seedSourceBackedMove(t, db, dir, "dst")
	drop := failBackingOn(t, db, src)

	err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", dom)
	if err == nil {
		t.Fatal("the source's backing record could not be written, but the move was settled")
	}
	if row := backedRow(t, db); row.Path == src && row.BackingDisk != "base:root" {
		t.Errorf("row = %+v: the source without its backing record", row)
	}
	if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 1 {
		t.Errorf("record dropped after a failed restore: %+v", left)
	}

	drop()
	if err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", dom); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if row := backedRow(t, db); row.Path != src || row.BackingDisk != "base:root" {
		t.Fatalf("after the retry the row = %+v, want %s backed on base:root", row, src)
	}
	if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 0 {
		t.Fatalf("record kept after its resolution: %+v", left)
	}
}

// A row already on the source without its backing record (a daemon that died
// between the two writes of an older build) is repaired before the record is
// cleared; while the repair fails, the record stays.
//
// Mutation "a row on the source is taken as settled" (pointRow returns early
// whatever its backing record): red.
func TestResolveUnresolvedMoves_SourceRowWithoutItsBackingIsRepairedFirst(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	src, _, dom := seedSourceBackedMove(t, db, dir, "src")
	drop := failBackingOn(t, db, src)

	if err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", dom); err == nil {
		t.Fatal("the backing record could not be repaired, but the move was settled")
	}
	if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 1 {
		t.Fatalf("record dropped with the source's base unreferenced: %+v", left)
	}

	drop()
	if err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", dom); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if row := backedRow(t, db); row.Path != src || row.BackingDisk != "base:root" {
		t.Fatalf("row = %+v, want %s backed on base:root", row, src)
	}
	if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 0 {
		t.Fatalf("record kept after its resolution: %+v", left)
	}
}
