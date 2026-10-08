package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// realSnapChain gives vm a real disk chain for snapshot snap: a qcow2 base,
// the fake domain on it, and the overlay a libvirt external snapshot would
// cut over to (<stem>.<snap>). It returns the base and the overlay.
func realSnapChain(t *testing.T, fake *libvirtfake.Fake, vm, snap string) (string, string) {
	t.Helper()
	needQemuImg(t)
	dir := t.TempDir()
	base := filepath.Join(dir, vm+"-root.qcow2")
	overlay := filepath.Join(dir, vm+"-root."+snap)
	runQemuImg(t, "create", "-q", "-f", "qcow2", base, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, overlay)
	fake.SetDiskSource(vm, "vda", base)
	return base, overlay
}

// seedSnapVM inserts a running (or stopped) VM with one disk (a real qcow2
// chain) + one disk snapshot in both corrosion and the fake libvirt backend.
// It returns the disk's base.
func seedSnapVM(t *testing.T, ctx context.Context, s *Server, fake *libvirtfake.Fake, name, state string) string {
	t.Helper()
	s.dataDir = t.TempDir()
	base, _ := realSnapChain(t, fake, name, "s1")
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: name, HostName: "host-a", State: state},
		nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "host-a", Path: base, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		ID: name + "-s1", VMName: name, HostName: "host-a", Name: "s1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	if _, err := fake.CreateSnapshot(name, "s1"); err != nil {
		t.Fatalf("fake CreateSnapshot: %v", err)
	}
	return base
}

// Deleting the last snapshot of a RUNNING VM flattens the disk (block-commit),
// so the chain collapses and the VM stays migratable — not a metadata-only delete.
func TestDeleteSnapshot_RunningLastSnapshotFlattens(t *testing.T) {
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	seedSnapVM(t, ctx, s, fake, "flat-vm", "running")

	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "flat-vm", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}

	flattened, plain := false, false
	for _, e := range fake.EventLog() {
		if e.Domain != "flat-vm" {
			continue
		}
		if e.Op == "snapshot-flatten" {
			flattened = true
		}
		if e.Op == "snapshot-delete" {
			plain = true
		}
	}
	if !flattened {
		t.Error("expected a flatten (block-commit) when deleting the last snapshot of a running VM")
	}
	if plain {
		t.Error("did not expect a metadata-only delete for the running last-snapshot case")
	}
}

// Deleting the last snapshot of a STOPPED VM merges offline (qemu-img commit
// into the base, the definition repointed): the chain does not grow by a
// layer per cycle (review I-1).
func TestDeleteSnapshot_StoppedLastSnapshotMergesOffline(t *testing.T) {
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	base := seedSnapVM(t, ctx, s, fake, "stopped-vm", "stopped")

	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "stopped-vm", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if n := len(fake.FlattenBases); n != 1 || fake.FlattenBases[0]["vda"] != base {
		t.Fatalf("flatten bases = %v, want one merge of vda into %s", fake.FlattenBases, base)
	}
}

// While another snapshot remains, its frozen layers must not change: the
// delete is metadata-only.
func TestDeleteSnapshot_NotLastIsMetadataOnly(t *testing.T) {
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	seedSnapVM(t, ctx, s, fake, "two", "running")
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		ID: "two-s2", VMName: "two", HostName: "host-a", Name: "s2", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "two", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if hasOp(fake.EventLog(), "snapshot-flatten", "two") {
		t.Fatal("a snapshot was merged while another remains")
	}
}
