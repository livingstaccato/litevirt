package health

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// holdOnly is a kept-disk hold (grpcapi.Server.KeptHolds) holding exactly
// path: the base of a kept linked clone, whose clone has no disk row.
func holdOnly(path string) func(context.Context, string) (bool, string) {
	return func(_ context.Context, p string) (bool, string) {
		if filepath.Clean(p) == filepath.Clean(path) {
			return true, "the disk /x/svc-root.qcow2 the deleted VM svc was kept with backs on it"
		}
		return false, ""
	}
}

// Re-review P5: a failover's set-aside of the real disk it left on its old
// host renamed it to .superseded- after checking disk rows only. A kept
// linked clone has none, so its base was renamed, which breaks the kept
// overlay (it names the base by its path), and the hourly purge then
// removed it once the VM was gone. A file a kept disk holds stays where it
// is; the entry is looked at again next pass.
//
// Mutation: drop the keptHold check from setAsideStrandedFile: red.
func TestTendStrandedDisks_LeavesAFileAKeptDiskHolds(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC))
	r.SetKeptHold(holdOnly(path))

	r.tendStrandedDisks(ctx)

	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, []byte("the real disk")) {
		t.Fatalf("the file a kept disk holds was moved from %s (err %v)", path, err)
	}
	if aside, _ := filepath.Glob(path + ".superseded-*"); len(aside) > 0 {
		t.Fatalf("it was set aside to %v", aside)
	}
	if _, ev, ok := strandedRow(t, db, "web", "node-a"); !ok || len(ev.Disks) != 1 || ev.Disks[0].Copy != "" {
		t.Fatalf("the entry should stay, with no copy: %+v", ev)
	}
}

// The other set-aside, of a file found at a disk's path when a transfer
// moves the VM onto this host, does not rename a held file either: it fails
// the start (retried), naming why, and the file stays.
//
// Mutation: drop the keptHold check from setAsideSupersededDisk: red.
func TestSetAsideSupersededDisk_LeavesAFileAKeptDiskHolds(t *testing.T) {
	_, _, r, _, path := strandedFixture(t)
	r.SetKeptHold(holdOnly(path))
	d := corrosion.DiskRecord{VMName: "web", DiskName: "root", HostName: "node-a", Path: path, StorageType: "local"}
	aside, err := r.setAsideSupersededDisk(context.Background(), "web", "proof-1", d)
	if err == nil || aside != "" || !strings.Contains(err.Error(), "svc-root.qcow2") {
		t.Fatalf("setAsideSupersededDisk = %q, %v; want a refusal naming the kept disk", aside, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, []byte("the real disk")) {
		t.Fatalf("the held file was moved (err %v)", err)
	}
}

// The hourly purge, and a bare --purge, never remove a set-aside copy a
// kept disk backs on, whatever its age and whether its VM still exists.
//
// Mutation: drop the keptHold filter from PurgeSupersededDisks: red (the
// control proves the copy is otherwise purgeable).
func TestPurgeSupersededDisks_KeepsACopyAKeptDiskHolds(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	disks := filepath.Join(dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	copyAt := supersededName(filepath.Join(disks, "gone-root.qcow2"), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err := os.WriteFile(copyAt, []byte("a base a kept overlay was rebased onto"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	if gone, err := PurgeSupersededDisks(ctx, db, dataDir, 7*24*time.Hour, now, holdOnly(copyAt)); err != nil || len(gone) != 0 {
		t.Fatalf("purge with the copy held = %+v, %v; want nothing removed", gone, err)
	}
	if !exists(copyAt) {
		t.Fatal("the purge removed a copy a kept disk backs on")
	}
	if gone, err := PurgeSupersededDisks(ctx, db, dataDir, 7*24*time.Hour, now, holdOnly("/elsewhere")); err != nil || len(gone) != 1 {
		t.Fatalf("control: purge with nothing held = %+v, %v; want the old copy removed", gone, err)
	}
}
