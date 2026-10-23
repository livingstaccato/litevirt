package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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

// (re-review rr3 3) DeleteStoragePool takes only a valid pool name: a forged
// row named to traverse out of pools/ (its target that path) is not deleted
// by name, and nothing on the host is touched.
//
// Mutation: drop the name validation in DeleteStoragePool (and in
// localPoolDir) — the forged row is deleted and the directory removed, red.
func TestDeleteStoragePool_RefusesAnInvalidName(t *testing.T) {
	s := trustServer(t)
	ctx := context.Background()
	victim := filepath.Join(filepath.Dir(s.dataDir), "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "x/../../../victim"
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "local", Target: filepath.Join(s.dataDir, "pools", name), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: name, Force: true})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("delete of a traversal name: %v, want InvalidArgument", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the directory a traversal name points at was removed: %v", err)
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
