package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

var badPoolNames = []string{"x/../../../etc", "..", "a/b", "evil\x00name", "-opt", strings.Repeat("a", 300)}

// (re-review rr3 3) A pool name joined into a path is validated first:
// localPoolDir names no directory for a name that is not a valid pool name,
// so a replicated row named with "/", "..", a NUL, a leading "-" or past the
// length cap never reaches outside <data_dir>/pools.
//
// Mutation: drop the validation from localPoolDir — red.
func TestLocalPoolDir_RefusesInvalidNames(t *testing.T) {
	data := t.TempDir()
	if got := localPoolDir(data, "vmpool"); got != filepath.Join(data, "pools", "vmpool") {
		t.Fatalf("localPoolDir(vmpool) = %q", got)
	}
	for _, n := range badPoolNames {
		if got := localPoolDir(data, n); got != "" {
			t.Errorf("localPoolDir(%q) = %q, want none", n, got)
		}
	}
}

// (re-review rr4 1) A row whose name is not a valid pool name — forged: no
// create makes one — can be deleted, so pool_row_untrusted stops naming it,
// and its delete touches nothing on the host: no teardown, no libvirt pool
// destroy, no directory removal at the place its name or target points. This
// holds whatever trust store the server has (none here).
//
// Mutation: drop the name check from the untrusted-row branch — with no
// trust store the row takes the host-side path and the libvirt pool destroy
// runs for it, red.
func TestDeleteStoragePool_AnInvalidNamedRowIsDeletedTouchingNothing(t *testing.T) {
	s := newPoolTestServer(t)
	fake := libvirtfake.New()
	destroyed := 0
	fake.FailPoolDestroy = func(string) error { destroyed++; return nil }
	s.virt = fake
	ctx := context.Background()
	victim := filepath.Join(filepath.Dir(s.dataDir), "victim")
	if err := os.MkdirAll(filepath.Join(victim, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	name := "x/../../../victim"
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "local", Target: filepath.Join(s.dataDir, "pools", name), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: name, Force: true}); err != nil {
		t.Fatalf("delete of a forged invalid-named row: %v", err)
	}
	if _, ok, _ := corrosion.GetStoragePool(ctx, s.db, s.hostName, name); ok {
		t.Fatal("the row is still there")
	}
	if destroyed != 0 {
		t.Fatal("the delete acted on the host for an invalid-named row")
	}
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Fatalf("the place the name points at was touched: %v", err)
	}
}

// (re-review rr3 3) The image-archive deny list (poolDiskDirs) names no
// directory for a row whose name is not a valid pool name.
//
// Mutation: drop the validation from localPoolDir — the escaped directory is
// listed, red.
func TestPoolDiskDirs_SkipInvalidNames(t *testing.T) {
	s := trustServer(t)
	for _, n := range badPoolNames {
		for _, d := range s.poolDiskDirs(corrosion.StoragePoolRecord{Name: n, Driver: "local"}) {
			if d != "" && !strings.HasPrefix(d, s.dataDir+string(filepath.Separator)) {
				t.Errorf("poolDiskDirs(%q) lists %q, outside the data directory", n, d)
			}
			if d != "" && d != filepath.Join(s.dataDir, "disks") {
				t.Errorf("poolDiskDirs(%q) lists %q", n, d)
			}
		}
	}
}
