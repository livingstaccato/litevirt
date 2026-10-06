package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Item 3: two directory pools on one directory — the same one, a symlink
// alias, one inside the other — are both created and both used; what each
// lists is confined per file (storage_pool_restore_test.go).
func TestPoolRound3_AliasedOrNestedDirectoriesAreShared(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "a")
	if err := os.MkdirAll(filepath.Join(base, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(base, alias); err != nil {
		t.Fatal(err)
	}
	for name, second := range map[string]string{
		"symlink alias": alias,
		"nested inside": filepath.Join(base, "sub"),
		"containing":    parent,
	} {
		t.Run(name, func(t *testing.T) {
			s := newPoolTestServer(t)
			if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "a", Driver: "dir", Target: base}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "b", Driver: "dir", Target: second}); err != nil {
				t.Fatalf("second pool on %s: %v", name, err)
			}
			for _, p := range []string{"a", "b"} {
				if _, err := s.resolveVolume(adminCtx(), "", p); err != nil {
					t.Errorf("use of %s: %v", p, err)
				}
				rec, _, _ := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, p)
				if !s.poolDirShared(adminCtx(), rec) {
					t.Errorf("%s is not seen as a shared directory", p)
				}
			}
		})
	}
}

// I1: the roots of the pool areas are not pools: a pool there contains every
// project's pool directory (pools/) or every NFS mount (mounts/).
func TestPoolRound3_PoolAreaRootsAreRefused(t *testing.T) {
	s := newPoolTestServer(t)
	for _, area := range []string{"pools", "mounts"} {
		dir := filepath.Join(s.dataDir, area)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "root-" + area, Driver: "dir", Target: dir}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("a pool on <data_dir>/%s: got %v, want InvalidArgument", area, err)
		}
	}
}

// I1: one NFS export mounted at two places is one directory.
func TestPoolRound3_OneNFSExportAtTwoTargetsIsShared(t *testing.T) {
	s := newPoolTestServer(t)
	t1, t2 := t.TempDir(), t.TempDir()
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "n1", Driver: "nfs", Source: "nas:/x", Target: t1, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "n2", Driver: "nfs", Source: "nas:/x/", Target: t2})
	wantSharedRefusal(t, "a second pool on the same export", err)
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "n2", Driver: "nfs", Source: "nas:/x", Target: t2, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveVolume(adminCtx(), "", "n1"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("use of an export another pool also mounts: got %v, want FailedPrecondition", err)
	}
}

// I2: a zfs dataset or an LVM volume group / thin pool is host storage; naming
// one needs storage.hostpath, like any network or path-backed pool.
func TestPoolRound3_ZfsAndLvmThinNeedRootAuthority(t *testing.T) {
	reqs := map[string]*pb.CreateStoragePoolRequest{
		"zfs":      {Driver: "zfs", Source: "rpool/ROOT"},
		"lvm-thin": {Driver: "lvm-thin", Source: "vg0", Options: map[string]string{"thinpool": "pool0"}},
	}
	callers := map[string]func(t *testing.T, s *Server) (context.Context, string){
		"legacy operator": func(*testing.T, *Server) (context.Context, string) { return userCtx("op", "operator"), "" },
		"project operator": func(t *testing.T, s *Server) (context.Context, string) {
			return hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme")), "acme"
		},
	}
	for cname, mk := range callers {
		for rname, req := range reqs {
			t.Run(cname+"/"+rname, func(t *testing.T) {
				s := newPoolTestServer(t)
				ctx, project := mk(t, s)
				r := proto.Clone(req).(*pb.CreateStoragePoolRequest)
				r.Name, r.Project = "p", project
				if _, err := s.CreateStoragePool(ctx, r); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("got %v, want PermissionDenied", err)
				}
			})
		}
	}
}

// m-b: a refusal tells a caller how many files an earlier pool left, not their
// names; nor does it name another pool, which may be another project's.
func TestPoolRound3_RefusalsDoNotLeakNames(t *testing.T) {
	s := newPoolTestServer(t)
	stale := filepath.Join(s.dataDir, "pools", "again")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "secret-merger-plan.iso"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	_, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{Name: "again", Driver: "local", Project: "acme"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	if strings.Contains(err.Error(), "secret-merger-plan") {
		t.Errorf("the refusal names another pool's file: %v", err)
	}
	if !strings.Contains(err.Error(), "1 file") {
		t.Errorf("the refusal does not say how many files: %v", err)
	}

	dir := t.TempDir()
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: s.hostName, Name: "mine", Driver: "dir", Target: dir, Project: "acme", State: "active"},
		{HostName: s.hostName, Name: "bravo-secret", Driver: "dir", Target: dir, Project: "bravo", State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(adminCtx(), s.db, p); err != nil {
			t.Fatal(err)
		}
	}
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	if err := uploadAs(bob, s, "bravo-secret", "bravo-plan.iso", "b"); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListStoragePoolContents(pat, &pb.ListStoragePoolContentsRequest{PoolName: "mine"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Contents) != 0 {
		t.Errorf("acme's listing of a shared directory shows files it does not own: %v", resp.Contents)
	}
	_, err = s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "mine", Filename: "bravo-plan.iso"})
	if status.Code(err) != codes.NotFound || strings.Contains(err.Error(), "bravo-secret") {
		t.Errorf("deleting another project's file: got %v, want NotFound naming no other pool", err)
	}
}

// m-f: the migration helpers' artifact roots and the scratch sweep use the
// same check as every other use: a weakly mounted pool is no root; a shared
// directory, which VM disks use, is one.
func TestPoolRound3_ArtifactRootsUseTheSameCheck(t *testing.T) {
	s := newPoolTestServer(t)
	shared := t.TempDir()
	weak := t.TempDir()
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: s.hostName, Name: "x", Driver: "dir", Target: shared, State: "active"},
		{HostName: s.hostName, Name: "y", Driver: "dir", Target: shared, State: "active"},
		{HostName: s.hostName, Name: "nas", Driver: "nfs", Source: "nas:/w", Target: weak, State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(adminCtx(), s.db, p); err != nil {
			t.Fatal(err)
		}
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"x":   {Driver: "dir", Target: shared},
		"y":   {Driver: "dir", Target: shared},
		"nas": {Driver: "nfs", Source: "nas:/w", Target: weak},
	})
	defer storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 1 0:1 / %s rw,relatime - nfs4 nas:/w rw\n", weak)), nil
	})()
	if !s.withinDiskArtifactRoot(filepath.Join(shared, "vm-root.qcow2")) {
		t.Errorf("a shared directory (usable for VM disks) is not a disk-artifact root")
	}
	if s.withinDiskArtifactRoot(filepath.Join(weak, "vm-root.qcow2")) {
		t.Errorf("a weakly mounted NFS pool is a disk-artifact root")
	}
}

// replicaNames (promote's and the failover coordinator's listing) does
// not list a refused pool's directory.
func TestPoolRound3_ContentNamesOfARefusedPoolAreNotListed(t *testing.T) {
	s := newPoolTestServer(t)
	if err := os.WriteFile(filepath.Join(s.dataDir, "state.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "legacy", Driver: "dir", Target: s.dataDir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dataDir, "vm-root-20260101-000000.qcow2"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if names := s.replicaNames(context.Background(), "legacy", "", replicaKey{VM: "vm", Disk: "root"}, "", false); len(names) != 0 {
		t.Fatalf("a refused pool's directory was listed: %v", names)
	}
}
