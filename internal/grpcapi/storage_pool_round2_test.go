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

// N1: re-creating a non-local row as local must not land on the shared
// <data_dir>/disks. Every zfs, ceph, iscsi and target-less nfs row has an
// empty Target, which used to read as "a legacy shared local pool".
func TestPoolRound2_RecreatingAnotherDriverAsLocalGetsItsOwnDirectory(t *testing.T) {
	for _, driver := range []string{"zfs", "nfs", "lvm-thin"} {
		t.Run(driver, func(t *testing.T) {
			s := newPoolTestServer(t)
			pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
			if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
				HostName: s.hostName, Name: "fast", Driver: driver, Source: "tank/acme", Project: "acme", State: "active",
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{Name: "fast", Driver: "local", Project: "acme"}); err != nil {
				t.Fatalf("re-create as local: %v", err)
			}
			rec, _, _ := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "fast")
			if want := filepath.Join(s.dataDir, "pools", "fast"); rec.Target != want {
				t.Fatalf("target = %q, want %q (not the shared disks dir)", rec.Target, want)
			}
		})
	}
}

// N2 (a pool on <data_dir>/disks, and two pools on one directory) is now
// served with per-file confinement: storage_pool_restore_test.go.

// N3: a pool's own directory goes with it, never with files in it, and is
// never handed to the next pool of that name with someone else's files.
func TestPoolRound2_OwnDirectoryLifecycle(t *testing.T) {
	s := newPoolTestServer(t)
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "scratch", Driver: "local"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.dataDir, "pools", "scratch")
	left := filepath.Join(dir, "a-images.iso")
	if err := os.WriteFile(left, []byte("A's"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "scratch"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "a-images.iso") {
		t.Fatalf("deleting a pool that holds files: got %v, want FailedPrecondition naming the file", err)
	}
	if _, ok, _ := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "scratch"); !ok {
		t.Fatalf("the refused delete removed the row")
	}
	if err := os.Remove(left); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "scratch"}); err != nil {
		t.Fatalf("deleting an empty pool: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the empty pool directory was left behind: %v", err)
	}

	// A directory left with files (by an older build, or by hand) is not
	// inherited by a new pool of that name.
	stale := filepath.Join(s.dataDir, "pools", "again")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "old.iso"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if _, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{Name: "again", Driver: "local", Project: "acme"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("creating a pool over a non-empty leftover directory: got %v, want FailedPrecondition", err)
	}
}

// N5: VM import into a pool goes through the same write check.
func TestPoolRound2_ImportIntoARefusedPoolIsRefused(t *testing.T) {
	s := newPoolTestServer(t)
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "legacy", Driver: "dir", Target: s.dataDir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.importPoolDir(context.Background(), "legacy"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("import into a refused pool: got %v, want FailedPrecondition", err)
	}
}
