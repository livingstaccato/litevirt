package pbsstore

import (
	"context"
	"strings"
	"testing"
)

// ManifestsFor reads only the named container's manifests and stops when the
// caller's context ends.
func TestManifestsFor_ScopedAndCancellable(t *testing.T) {
	dir := t.TempDir()
	repo, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"web", "db"} {
		if _, err := PushDisk(context.Background(), repo, strings.NewReader("x-"+n), PushOptions{
			VMName: n, DiskName: "rootfs", Timestamp: "2026-10-08T10:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}
	ms, err := repo.ManifestsFor(context.Background(), "web", "rootfs")
	if err != nil || len(ms) != 1 || ms[0].VMName != "web" {
		t.Fatalf("ManifestsFor(web) = %+v, %v", ms, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repo.ManifestsFor(ctx, "web", "rootfs"); err == nil {
		t.Fatal("a cancelled walk returned no error")
	}
}
