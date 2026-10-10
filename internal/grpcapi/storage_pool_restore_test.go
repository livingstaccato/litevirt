package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func listNames(t *testing.T, s *Server, ctx context.Context, pool string) []string {
	t.Helper()
	resp, err := s.ListStoragePoolContents(ctx, &pb.ListStoragePoolContentsRequest{PoolName: pool})
	if err != nil {
		t.Fatalf("list %s: %v", pool, err)
	}
	var out []string
	for _, c := range resp.Contents {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

func writePoolFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func insertProjectVM(t *testing.T, s *Server, name, project, disk, path, pool string) {
	t.Helper()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, Project: project, HostName: s.hostName, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: name, DiskName: disk, HostName: s.hostName, Path: path, StorageType: "local", StorageVolume: pool,
	}); err != nil {
		t.Fatal(err)
	}
}

func insertReplicationSchedule(t *testing.T, s *Server, vm, pool string) {
	t.Helper()
	if err := corrosion.UpsertBackupSchedule(adminCtx(), s.db, corrosion.BackupScheduleRecord{
		VMName: vm, Scope: "vm", Repo: pool, Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: pool, TargetHost: s.hostName, KeepReplicas: 2,
	}); err != nil {
		t.Fatal(err)
	}
}

// Item 3: a pool on <data_dir>/disks — an older cluster's default, or any
// target-less local pool created before pools got their own directories —
// keeps working. VM disks go there as before; its content operations show and
// touch only the caller's project's files by record: its VMs' disks, their
// replicas, and what was uploaded into the pool. A file with no owner record
// is an admin's to delete; an unowned plain ISO/image is library content
// everyone who reads the pool sees, and anything else unowned (a failover's
// set-aside copy) only an admin sees.
func TestPoolRestore_DisksPoolIsConfinedPerFile(t *testing.T) {
	s := newPoolTestServer(t)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "shared", Driver: "local", Project: "acme"})
	in := func(n string) string { return filepath.Join(disks, n) }

	insertProjectVM(t, s, "avm", "acme", "root", in("avm-root.qcow2"), "shared")
	insertProjectVM(t, s, "bvm", "bravo", "root", in("bvm-root.qcow2"), "shared")
	insertReplicationSchedule(t, s, "avm", "shared")
	insertReplicationSchedule(t, s, "bvm", "shared")
	for _, n := range []string{
		"avm-root.qcow2", "bvm-root.qcow2",
		"avm-root-20261006T000000Z.qcow2", "bvm-root-20261006T000000Z.qcow2",
		"bvm-root.qcow2.superseded-20261006T000000Z", "stray.iso",
	} {
		writePoolFile(t, in(n), n)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))

	// VM disks on the pool work as before.
	if _, err := s.resolveVolume(pat, "", "shared"); err != nil {
		t.Fatalf("a disk on the pool: %v", err)
	}
	if err := uploadAs(pat, s, "shared", "inst.iso", "iso"); err != nil {
		t.Fatalf("acme uploads into the pool: %v", err)
	}

	// A replica is owned only by an exact record (none yet on this branch),
	// never by its name: avm's replica is an unowned disk image, an admin's.
	want := []string{"avm-root.qcow2", "inst.iso", "stray.iso"}
	if got := listNames(t, s, pat, "shared"); !slices.Equal(got, want) {
		t.Fatalf("acme's listing = %v, want %v", got, want)
	}
	if got := listNames(t, s, adminCtx(), "shared"); !slices.Contains(got, "bvm-root.qcow2.superseded-20261006T000000Z") || !slices.Contains(got, "stray.iso") {
		t.Errorf("the admin's listing lacks the unowned files: %v", got)
	}

	// Another project's files and unowned non-image files are absent to acme:
	// never deleted, and reported as not there. Unowned library content is
	// seen but deleted only by an admin.
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: "stray.iso"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("acme deleting unowned stray.iso: got %v, want PermissionDenied", err)
	}
	for _, n := range []string{"bvm-root.qcow2.superseded-20261006T000000Z", "bvm-root-20261006T000000Z.qcow2", "avm-root-20261006T000000Z.qcow2"} {
		if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: n}); status.Code(err) != codes.NotFound {
			t.Errorf("acme deleting %s: got %v, want NotFound", n, err)
		}
		if _, err := os.Stat(in(n)); err != nil {
			t.Errorf("%s was deleted: %v", n, err)
		}
	}
	// A live disk is never content to delete, even its own project's.
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: "avm-root.qcow2"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("deleting a live disk: got %v, want FailedPrecondition", err)
	}
	// Its own upload is acme's to delete.
	for _, n := range []string{"inst.iso"} {
		if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: n}); err != nil {
			t.Errorf("acme deleting its own %s: %v", n, err)
		}
	}

	// An upload record names the file it was made for, not the name: a file
	// put at that name afterwards is nobody's — library content acme sees but
	// may not delete.
	if err := uploadAs(pat, s, "shared", "again.iso", "iso"); err != nil {
		t.Fatal(err)
	}
	// Uploads into <data_dir>/disks live in disks/uploads.
	again := filepath.Join(disks, "uploads", "again.iso")
	if err := os.Remove(again); err != nil {
		t.Fatal(err)
	}
	writePoolFile(t, again, "someone else's")
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: "again.iso"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("acme deleting a file recreated at its uploaded name: got %v, want PermissionDenied", err)
	}
}

// Item 3: two pools on one directory are both created and both used, each
// project seeing and changing only its own files there.
func TestPoolRestore_TwoPoolsOnOneDirectory(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	for _, r := range []*pb.CreateStoragePoolRequest{
		{Name: "a", Driver: "dir", Target: dir, Project: "acme"},
		{Name: "b", Driver: "dir", Target: dir, Project: "bravo"},
	} {
		if _, err := s.CreateStoragePool(adminCtx(), r); err != nil {
			t.Fatalf("create %s: %v", r.Name, err)
		}
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	if err := uploadAs(pat, s, "a", "a.iso", "acme"); err != nil {
		t.Fatal(err)
	}
	if err := uploadAs(bob, s, "b", "b.iso", "bravo"); err != nil {
		t.Fatal(err)
	}
	if got := listNames(t, s, pat, "a"); !slices.Equal(got, []string{"a.iso"}) {
		t.Errorf("acme's listing = %v, want [a.iso]", got)
	}
	if got := listNames(t, s, bob, "b"); !slices.Equal(got, []string{"b.iso"}) {
		t.Errorf("bravo's listing = %v, want [b.iso]", got)
	}
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "a", Filename: "b.iso"}); status.Code(err) != codes.NotFound {
		t.Errorf("acme deleting bravo's upload through its pool: got %v, want NotFound", err)
	}
	if err := uploadAs(pat, s, "a", "b.iso", "overwrite"); status.Code(err) != codes.AlreadyExists {
		t.Errorf("acme uploading over bravo's file: got %v, want AlreadyExists", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "b.iso")); string(b) != "bravo" {
		t.Errorf("bravo's file was changed: %q", b)
	}
	for _, p := range []string{"a", "b"} {
		if _, err := s.resolveVolume(adminCtx(), "", p); err != nil {
			t.Errorf("use of %s: %v", p, err)
		}
	}
	if got := listNames(t, s, adminCtx(), "a"); !slices.Equal(got, []string{"a.iso", "b.iso"}) {
		t.Errorf("the admin's listing = %v", got)
	}
}

// A pool whose directory is its own is not confined: a file an admin put
// there by hand is listed to the pool's operators, as before.
func TestPoolRestore_OwnDirectoryIsNotConfined(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "a", Driver: "dir", Target: dir, Project: "acme"}); err != nil {
		t.Fatal(err)
	}
	writePoolFile(t, filepath.Join(dir, "by-hand.iso"), "x")
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if got := listNames(t, s, pat, "a"); !slices.Equal(got, []string{"by-hand.iso"}) {
		t.Errorf("listing = %v, want [by-hand.iso]", got)
	}
}
