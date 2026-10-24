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

// dirPoolRow records a dir pool of this host at target, in its row and in
// memory, as `lv pool create` leaves it.
func dirPoolRow(t *testing.T, s *Server, name, target string) {
	t.Helper()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "dir", Target: target, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.addStoragePoolRef(name, StoragePoolRef{Driver: "dir", Target: target})
}

// While kept-disks.json cannot be read, the scan reads every pool directory
// of this host, not only those usable for writes: a disk kept in a pool
// that is refused now (here one whose directory is inside the daemon's own
// state, which an earlier build let a pool name) is still a kept
// overlay whose missing base a create can become.
//
// Mutation: list only the usable pool roots in keptScanDirs
// (s.filePoolRoots() for the refs): red (the create goes ahead and writes
// the base).
func TestCreateVM_KeptScanReadsAPoolRefusedForUse(t *testing.T) {
	s, _ := provableCreateServer(t)
	dir := filepath.Join(s.dataDir, "vmstate", "ssd")
	dirPoolRow(t, s, "ssd", dir)
	if s.poolUsableForWrite(context.Background(), "ssd", StoragePoolRef{Driver: "dir", Target: dir}) {
		t.Fatal("the pool is usable for writes: this proves nothing")
	}
	base := s.images.DiskPath("web", "root")
	ov := filepath.Join(dir, "db-snap1.qcow2.kept-20261023")
	overlayOn(t, ov, base)
	named := unreadableKeptRegistry(t, s)
	req := disklessCreateRequest("web")
	req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
	_, err := s.CreateVM(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), ov) || !strings.Contains(err.Error(), named) {
		t.Fatalf("create web = %v; want FailedPrecondition naming %s and %s", err, ov, named)
	}
	if exists(base) {
		t.Fatal("a refused create wrote the base the overlay in the refused pool names")
	}
}

// A pool directory of this host that cannot be listed refuses, fail-closed
// and naming it, every create that writes a local disk while kept-disks.json
// cannot be read: a kept overlay in it would go unseen.
//
// Mutation: skip a directory whose listing fails in keptCollisionScan (as
// for one that does not exist): red (the create goes ahead).
func TestCreateVM_KeptScanRefusesWhenAPoolDirectoryCannotBeListed(t *testing.T) {
	s, _ := provableCreateServer(t)
	target := filepath.Join(t.TempDir(), "ssd")
	if err := os.WriteFile(target, []byte("not a directory"), 0o600); err != nil { // listing it fails, as root or not
		t.Fatal(err)
	}
	dirPoolRow(t, s, "ssd", target)
	named := unreadableKeptRegistry(t, s)
	req := disklessCreateRequest("web")
	req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
	_, err := s.CreateVM(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), target) || !strings.Contains(err.Error(), named) {
		t.Fatalf("create web = %v; want FailedPrecondition naming %s and %s", err, target, named)
	}
	if exists(s.images.DiskPath("web", "root")) {
		t.Fatal("a refused create wrote its disk")
	}
}

// While kept-disks.json cannot be read, the scan compares the files on this
// host with what the create really writes (keptWrites): a disk on a pool is
// written where the pool's driver puts it, and each side is compared with
// its directory resolved through symlinks, so an overlay in a pool that
// names its missing base by another spelling of the pool's directory still
// refuses the create that would write it. A pool create no file names goes
// ahead.
//
// Mutations: compare the scan's files with the disk-directory shape alone
// (createDiskPathOf, not the keptWrites files): "dir pool" and "pool
// symlinked to disks/" red; compare without resolving the scanned side
// (writesResolved(p, p)): "pool symlinked to disks/" red; take every scanned
// file as a collision: "nothing names it" red.
func TestCreateVM_KeptScanComparesThePathsAPoolCreateWrites(t *testing.T) {
	t.Run("dir pool", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "ssd")
		writePathsDirPool(t, s, "ssd", dir)
		base := filepath.Join(dir, "web-root.qcow2")
		ov := filepath.Join(dir, "db-snap1.qcow2.kept-20261023")
		overlayOn(t, ov, base)
		named := unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		wantMissingBaseRefusal(t, "create on a dir pool", err, ov, base)
		if !strings.Contains(err.Error(), named) {
			t.Fatalf("create web = %v; want it naming %s", err, named)
		}
	})
	t.Run("pool symlinked to disks/", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		alias := symlinkToDisks(t, s)
		writePathsDirPool(t, s, "alias", alias)
		// The overlay names its base through another symlink to disks/ (an
		// older pool's): neither the pool's spelling nor the resolved one.
		other := symlinkToDisks(t, s)
		base := filepath.Join(other, "web-root.qcow2")
		ov := filepath.Join(alias, "db-snap1.qcow2.kept-20261023")
		overlayOn(t, ov, base)
		named := unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "alias"))
		wantMissingBaseRefusal(t, "create on a pool symlinked to the disk directory", err, filepath.Base(ov), base)
		if !strings.Contains(err.Error(), named) {
			t.Fatalf("create web = %v; want it naming %s", err, named)
		}
	})
	t.Run("nothing names it", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "ssd")
		writePathsDirPool(t, s, "ssd", dir)
		overlayOn(t, filepath.Join(dir, "db-snap1.qcow2.kept-20261023"), filepath.Join(dir, "db-root.qcow2"))
		unreadableKeptRegistry(t, s)
		if _, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd")); err != nil {
			t.Fatalf("create on a pool no file on this host names, while kept-disks.json cannot be read: %v", err)
		}
		if !exists(filepath.Join(dir, "web-root.qcow2")) {
			t.Fatal("the create did not write its disk in the pool: this proves nothing")
		}
	})
}
