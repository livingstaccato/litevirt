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

// I1: "every pool has its own directory" is judged on resolved, canonical
// directories — a symlink alias, a directory inside another pool's or one
// containing it is not a directory of its own — at create and at use.
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
			if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "b", Driver: "dir", Target: second}); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("create: got %v, want FailedPrecondition", err)
			}
			// The same pair, already stored, is refused at use.
			if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
				HostName: s.hostName, Name: "b", Driver: "dir", Target: second, State: "active",
			}); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{"a", "b"} {
				if _, err := s.resolveVolume(adminCtx(), "", p); status.Code(err) != codes.FailedPrecondition {
					t.Errorf("use of %s: got %v, want FailedPrecondition", p, err)
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
	if status.Code(err) != codes.FailedPrecondition || strings.Contains(err.Error(), "prepare") {
		t.Fatalf("a second pool on the same export: got %v, want a FailedPrecondition before any mount", err)
	}
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
	_, err = s.ListStoragePoolContents(pat, &pb.ListStoragePoolContentsRequest{PoolName: "mine"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	if strings.Contains(err.Error(), "bravo-secret") {
		t.Errorf("the refusal names another project's pool: %v", err)
	}
}

// m-f: the migration helpers' artifact roots and the scratch sweep use the
// same check as every other use: a shared or weakly mounted pool is no root.
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
	if s.withinDiskArtifactRoot(filepath.Join(shared, "vm-root.qcow2")) {
		t.Errorf("a shared directory is a disk-artifact root")
	}
	if s.withinDiskArtifactRoot(filepath.Join(weak, "vm-root.qcow2")) {
		t.Errorf("a weakly mounted NFS pool is a disk-artifact root")
	}
}

// The replica listing (promote's and the failover coordinator's) does not
// read a refused pool's directory.
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
	if _, err := s.replicaPoolDir(context.Background(), "legacy"); err == nil {
		t.Fatal("a refused pool resolved for the replica paths")
	}
	if recs := s.replicaRecordsOn(context.Background(), "legacy", "", "", "vm"); len(recs) != 0 {
		t.Fatalf("a refused pool's replicas were listed: %v", recs)
	}
}
