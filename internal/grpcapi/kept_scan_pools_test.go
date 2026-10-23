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
