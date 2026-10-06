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

// N2: a pool on the shared <data_dir>/disks — every target-less local pool
// created before pools got their own directories — is refused outright, to
// admins too: nothing records whose a file there is (another project's disk, a
// failover's set-aside copy, a restore, a deleted VM's kept disk).
func TestPoolRound2_SharedDisksDirectoryIsRefused(t *testing.T) {
	s := newPoolTestServer(t)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	setAside := filepath.Join(disks, "bvm-root.qcow2.superseded-20261006T000000Z")
	if err := os.WriteFile(setAside, []byte("B's copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "shared", Driver: "local", Project: "acme", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	for name, ctx := range map[string]context.Context{"operator": pat, "admin": adminCtx()} {
		if _, err := s.ListStoragePoolContents(ctx, &pb.ListStoragePoolContentsRequest{PoolName: "shared"}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s listing: got %v, want FailedPrecondition", name, err)
		}
		if _, err := s.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: filepath.Base(setAside)}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s delete: got %v, want FailedPrecondition", name, err)
		}
		if err := uploadAs(ctx, s, "shared", "new.iso", "x"); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s upload: got %v, want FailedPrecondition", name, err)
		}
		if _, err := s.resolveVolume(ctx, "", "shared"); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s disk on the shared pool: got %v, want FailedPrecondition", name, err)
		}
	}
	if _, err := os.Stat(setAside); err != nil {
		t.Errorf("the set-aside copy was deleted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disks, "new.iso")); err == nil {
		t.Errorf("an upload landed in <data_dir>/disks")
	}
}

// N2: two pool rows on one directory: neither is used, and a second pool is
// never created on a directory another pool already has.
func TestPoolRound2_TwoPoolsOnOneDirectoryAreRefused(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "a", Driver: "dir", Target: dir, Project: "acme"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "b", Driver: "dir", Target: dir, Project: "bravo"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a second pool on the same directory: got %v, want FailedPrecondition", err)
	}
	// A pair that already exists (created before this check) is refused.
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "b", Driver: "dir", Target: dir, Project: "bravo", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bravo.iso"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if _, err := s.ListStoragePoolContents(pat, &pb.ListStoragePoolContentsRequest{PoolName: "a"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("listing acme's pool on bravo's directory: got %v, want FailedPrecondition", err)
	}
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "a", Filename: "bravo.iso"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("deleting bravo's file through acme's pool: got %v, want FailedPrecondition", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bravo.iso")); err != nil {
		t.Errorf("bravo's file was deleted: %v", err)
	}
}

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
