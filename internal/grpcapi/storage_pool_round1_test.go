package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// I1: a network-backed pool's server decides what the daemon finds on it —
// files, symlinks it then follows as root, block devices — so attaching one is
// a host-level act even with no local target.
func TestPoolHostPath_NetworkPoolsNeedRootAuthority(t *testing.T) {
	reqs := map[string]*pb.CreateStoragePoolRequest{
		"nfs":   {Driver: "nfs", Source: "nas:/x"},
		"ceph":  {Driver: "ceph", Source: "rbd"},
		"iscsi": {Driver: "iscsi", Source: "iqn.2024-01.com.example:s", Options: map[string]string{"portal": "10.0.0.5"}},
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
				if _, ok, _ := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "p"); ok {
					t.Fatalf("the refused pool was persisted")
				}
			})
		}
	}
}

// I1: the copy fallback writes a move's destination itself; a symlink at that
// name must not redirect it.
func TestCopyFileWithProgress_DoesNotFollowASymlinkAtTheDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	if err := os.WriteFile(src, []byte("disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "vm-root.qcow2")
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}
	_ = copyFileWithProgress(context.Background(), src, dst, func(*pb.MoveVolumeProgress) error { return nil })
	if got, _ := os.ReadFile(victim); string(got) != "keep" {
		t.Fatalf("written through the symlink: %q", got)
	}
}

// I2: a source shaped like an option is refused before any tool sees it, to
// admins too.
func TestPoolHostPath_OptionShapedSourcesAreRefused(t *testing.T) {
	s := newPoolTestServer(t)
	for name, req := range map[string]*pb.CreateStoragePoolRequest{
		"nfs":          {Driver: "nfs", Source: "-oexec:/x"},
		"nfs comma":    {Driver: "nfs", Source: "nas:/x,suid"},
		"ceph":         {Driver: "ceph", Source: "-c/tmp/evil.conf"},
		"zfs":          {Driver: "zfs", Source: "-o"},
		"lvm":          {Driver: "lvm-thin", Source: "-v", Options: map[string]string{"thinpool": "tp"}},
		"iscsi":        {Driver: "iscsi", Source: "-x"},
		"iscsi portal": {Driver: "iscsi", Source: "iqn.2024-01.com.example:s", Options: map[string]string{"portal": "-p"}},
		"btrfs":        {Driver: "btrfs", Source: "-x"},
	} {
		t.Run(name, func(t *testing.T) {
			r := proto.Clone(req).(*pb.CreateStoragePoolRequest)
			r.Name = "p"
			if _, err := s.CreateStoragePool(adminCtx(), r); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("got %v, want InvalidArgument", err)
			}
		})
	}
}

// I3: a pool created before the checks, aimed at a refused directory, takes no
// disk (CreateVM resolves storage through resolveVolume), no replica increment,
// and is no root for the migration helpers' create/remove.
func TestPoolHostPath_PreexistingRefusedPoolTakesNoWrites(t *testing.T) {
	s := newPoolTestServer(t)
	legacy := corrosion.StoragePoolRecord{HostName: s.hostName, Name: "legacy", Driver: "dir", Target: s.dataDir, State: "active"}
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, legacy); err != nil {
		t.Fatal(err)
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"legacy": {Driver: "dir", Target: s.dataDir}})

	if _, err := s.resolveVolume(adminCtx(), "", "legacy"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a disk on the legacy pool: got %v, want FailedPrecondition", err)
	}
	if s.withinDiskArtifactRoot(filepath.Join(s.dataDir, "state.db")) {
		t.Errorf("the legacy pool made <data_dir>/state.db a disk-artifact root")
	}
	rec := newReplicaRecord("", "x", "root", "x/legacy", "20260101-000000", "raw")
	err := s.applyIncrementLocal(context.Background(), "legacy", rec, "", 4, bytes.NewReader([]byte("data")), [][2]int64{{0, 4}})
	if err == nil {
		t.Errorf("a replica increment into the legacy pool was applied")
	}
	if _, serr := os.Lstat(filepath.Join(s.dataDir, replicaAreaDir)); serr == nil {
		t.Errorf("a replica increment landed in the data dir")
	}
}

// I4: a target-less local pool is not a window onto every local VM disk on the
// host. A new one gets its own directory; in a legacy one that shares
// <data_dir>/disks, files live disks use are neither listed nor deletable.
func TestPoolContents_ProjectCannotReachAnotherProjectsDisks(t *testing.T) {
	s := newPoolTestServer(t)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(disks, "bvm-root.qcow2")
	if err := os.WriteFile(theirs, []byte("tenant B"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{
		VMName: "bvm", DiskName: "root", HostName: s.hostName, Path: theirs, StorageType: "local",
	}); err != nil {
		t.Fatal(err)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))

	t.Run("new pool", func(t *testing.T) {
		if _, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{Name: "mine", Driver: "local", Project: "acme"}); err != nil {
			t.Fatalf("create: %v", err)
		}
		resp, err := s.ListStoragePoolContents(pat, &pb.ListStoragePoolContentsRequest{PoolName: "mine"})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, c := range resp.Contents {
			if c.Name == "bvm-root.qcow2" {
				t.Errorf("another project's disk is listed in a new pool")
			}
		}
		_, _ = s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "mine", Filename: "bvm-root.qcow2"})
		if _, err := os.Stat(theirs); err != nil {
			t.Fatalf("another project's disk was deleted through a new pool: %v", err)
		}
	})

	// A legacy pool on the shared <data_dir>/disks: storage_pool_restore_test.go.
}

// The new per-pool directory is recorded as the pool's target.
func TestPoolContents_NewTargetlessLocalPoolGetsItsOwnDirectory(t *testing.T) {
	s := newPoolTestServer(t)
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "mine", Driver: "local"}); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "mine")
	if err != nil || !ok {
		t.Fatalf("pool: ok=%v err=%v", ok, err)
	}
	if want := filepath.Join(s.dataDir, "pools", "mine"); rec.Target != want {
		t.Fatalf("target = %q, want %q", rec.Target, want)
	}
	if fi, err := os.Stat(rec.Target); err != nil || !fi.IsDir() {
		t.Fatalf("pool directory not created: %v", err)
	}
}

// Minor: more directories refused to everyone.
func TestPoolHostPath_MoreProtectedDirectories(t *testing.T) {
	s := newPoolTestServer(t)
	for _, target := range []string{"/home/someone/vms", "/var/lib/libvirt/images", "/var/lib/litevirt-gitops/repo", "/var/lib/litevirt/state.db"} {
		t.Run(target, func(t *testing.T) {
			if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "p", Driver: "local", Target: target}); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("got %v, want InvalidArgument", err)
			}
		})
	}
}

// Minor: a custom absolute repo or restore path is the same host-path
// authority as a pool target — a cluster-root binding, not a legacy role a
// project-scoped admin also carries.
func TestHostPathAuthority_RepoAndRestorePathsUseTheRBACVerb(t *testing.T) {
	s := testServer(t)
	mallory := poolTenantCtx(t, s) // legacy role admin, Admin only on /projects/acme
	if _, err := s.resolveBackupRepoPath(mallory, "/srv/backups"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("project admin, absolute repo_path: got %v, want PermissionDenied", err)
	}
	if _, err := s.resolveRestoreTarget(mallory, "/srv/restore.qcow2", t.TempDir()); status.Code(err) != codes.PermissionDenied {
		t.Errorf("project admin, absolute target_path: got %v, want PermissionDenied", err)
	}
	if _, err := s.resolveBackupRepoPath(adminCtx(), "/srv/backups"); err != nil {
		t.Errorf("cluster admin, absolute repo_path: %v", err)
	}
}
