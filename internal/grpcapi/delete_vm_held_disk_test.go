package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// corruptKeptRegistry makes s's kept-disks.json unreadable, which holds every
// disk file on the host (keptHolds), and returns its path.
func corruptKeptRegistry(t *testing.T, s *Server) string {
	t.Helper()
	p := filepath.Join(s.dataDir, diskKeptFile)
	if err := os.WriteFile(p, []byte("[{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Lab 2: `lv rm --force` of a running VM while kept-disks.json could not be
// read failed with "its file is still there after its removal" — no removal
// had been tried, the hold had left the file, and the reason (the record
// cannot be read; repair it) was only in the log. The delete still fails and
// keeps the record and the file, and its error now says the disk is held and
// why.
//
// Mutation: deleteDiskAtRecordedLocation answers a hold with nil again — the
// error says "still there after its removal" and not the record: red.
func TestDeleteVM_AHeldDiskSaysWhyNotThatItsRemovalLeftIt(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, fake := deleteDiskServer(t, disk)
	registry := corruptKeptRegistry(t, s)

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a", Force: true})
	if err == nil {
		t.Fatal("the delete reported success with a held disk left")
	}
	if !strings.Contains(err.Error(), "held and not removed") || !strings.Contains(err.Error(), registry) ||
		!strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("the failure %q does not say the disk is held by the unreadable %s", err, registry)
	}
	if strings.Contains(err.Error(), "still there after its removal") {
		t.Errorf("the failure %q claims a removal that was never tried", err)
	}
	if !exists(disk) {
		t.Fatal("a held disk was removed")
	}
	if fake.DomainExists("a") {
		t.Error("the domain is still defined: the failure is not the one after the teardown")
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil {
		t.Fatal("the failed delete dropped the record of a disk it left")
	}
}

// A disk whose driver reported it removed and whose file is there afterwards
// (here a stand-in btrfs whose subvolume delete succeeds and writes the file
// back) is still reported as such.
//
// Mutation: drop the post-removal check in freeRecordedVMDisks — the delete
// succeeds with the file there: red.
func TestDeleteVM_AFileStillThereAfterItsRemovalIsNamedSo(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\ncase \"$1 $2\" in\n" +
		"\"subvolume delete\") : > \"$4/a-root.qcow2\"; exit 0;;\n" +
		"\"subvolume show\") [ -d \"$4\" ] && exit 0; exit 1;;\nesac\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	root := t.TempDir()
	subvol := filepath.Join(root, "a-root")
	if err := os.MkdirAll(subvol, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(subvol, "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := deleteDiskServerWith(t, true, corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: disk, SizeBytes: 1 << 20,
		StorageType: "btrfs", StorageVolume: "bt", DeleteWithVM: true})
	s.addStoragePoolRef("bt", StoragePoolRef{Driver: "btrfs", Source: root})

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
	if err == nil {
		t.Fatal("the delete reported success with the disk's file there after its removal")
	}
	if !strings.Contains(err.Error(), "its file is still there after its removal") {
		t.Errorf("the failure %q does not say the file is still there", err)
	}
	if strings.Contains(err.Error(), "held") {
		t.Errorf("the failure %q calls a removed disk held", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil {
		t.Fatal("the failed delete dropped the record")
	}
}

// The other removals through deleteDiskAtRecordedLocation — a delete's
// record pass and a cutover cleanup — leave a held disk and go on, as before
// the hold became an error: neither fails on it.
//
// Mutation: drop the isDiskHeld check in either caller — it fails: red.
func TestDiskVolumeCleanups_LeaveAHeldDiskWithoutFailing(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := deleteDiskServer(t, disk)
	corruptKeptRegistry(t, s)
	disks, err := corrosion.GetVMDisks(context.Background(), s.db, "a")
	if err != nil || len(disks) != 1 {
		t.Fatalf("disks of a: %v %v", disks, err)
	}
	if _, err := s.deleteRecordedVMDiskVolumeRecordsKept(adminCtx(), "a", disks); err != nil {
		t.Errorf("the record pass failed on a held disk: %v", err)
	}
	// A cutover cleanup's disks are no live VM's.
	orphan := filepath.Join(t.TempDir(), "gone-root.qcow2")
	if err := qcow2.Create(orphan, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	captured := []corrosion.DiskRecord{{VMName: "gone", DiskName: "root", HostName: s.hostName, Path: orphan, StorageType: "local", DeleteWithVM: true}}
	if err := s.deleteCapturedVMDiskVolumes(adminCtx(), captured); err != nil {
		t.Errorf("the cutover cleanup failed on a held disk: %v", err)
	}
	for _, p := range []string{disk, orphan} {
		if !exists(p) {
			t.Fatalf("a held disk %s was removed", filepath.Base(p))
		}
	}
}
