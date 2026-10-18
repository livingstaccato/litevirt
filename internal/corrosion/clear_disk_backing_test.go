package corrosion

import (
	"context"
	"testing"
)

// m5: ClearDiskBacking re-writes the whole row from a read taken before its
// transaction. A column changed in between — a resize's size_bytes here — is
// never reverted: the write is withheld, and the row keeps the change.
func TestClearDiskBacking_NeverRevertsAColumnChangedSinceTheRead(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	row := DiskRecord{VMName: "cv", DiskName: "root", HostName: "h1", Path: "/d/cv-root.qcow2",
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda", BackingDisk: "/d/tpl-root.qcow2", DeleteWithVM: true}
	if err := InsertVM(ctx, c, VMRecord{Name: "cv", HostName: "h1", State: "stopped"}, nil, []DiskRecord{row}); err != nil {
		t.Fatal(err)
	}
	resized := row
	resized.SizeBytes = 2 << 30
	clearDiskBackingAfterRead = func() {
		if err := InsertDisk(ctx, c, resized); err != nil {
			t.Error(err)
		}
	}
	defer func() { clearDiskBackingAfterRead = nil }()
	if err := ClearDiskBacking(ctx, c, "cv", "root", row.Path); err != nil {
		t.Fatal(err)
	}
	disks, _ := GetVMDisks(ctx, c, "cv")
	if len(disks) != 1 || disks[0].SizeBytes != resized.SizeBytes {
		t.Fatalf("size_bytes = %d, want the resize's %d kept: a stale whole-row write reverted it", disks[0].SizeBytes, resized.SizeBytes)
	}
}

// ... and an unchanged row is cleared.
func TestClearDiskBacking_ClearsAnUnchangedRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	row := DiskRecord{VMName: "cv", DiskName: "root", HostName: "h1", Path: "/d/cv-root.qcow2",
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda", BackingDisk: "/d/tpl-root.qcow2", BackingImage: "ubuntu"}
	if err := InsertVM(ctx, c, VMRecord{Name: "cv", HostName: "h1", State: "stopped"}, nil, []DiskRecord{row}); err != nil {
		t.Fatal(err)
	}
	if err := ClearDiskBacking(ctx, c, "cv", "root", row.Path); err != nil {
		t.Fatal(err)
	}
	disks, _ := GetVMDisks(ctx, c, "cv")
	if disks[0].BackingDisk != "" || disks[0].BackingImage != "" {
		t.Errorf("backing %q/%q left on an unchanged row", disks[0].BackingDisk, disks[0].BackingImage)
	}
}

// UpdateDiskPlacementIfStill writes only over the row it was given: a row
// changed since (here a path another writer set) is left as it is.
func TestUpdateDiskPlacementIfStill_OnlyOverTheRowRead(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	row := DiskRecord{VMName: "cv", DiskName: "root", HostName: "h1", Path: "/a/root", SizeBytes: 1, StorageType: "local", StorageVolume: "hot", TargetDev: "vda", DeleteWithVM: true}
	if err := InsertVM(ctx, c, VMRecord{Name: "cv", HostName: "h1", State: "stopped"}, nil, []DiskRecord{row}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateDiskPlacement(ctx, c, "cv", "root", "h1", "/c/root", "local", "hot"); err != nil {
		t.Fatal(err)
	}
	if ok, err := UpdateDiskPlacementIfStill(ctx, c, row, "h1", "/b/root", "nfs", "warm"); err != nil || ok {
		t.Fatalf("applied=%v err=%v over a changed row", ok, err)
	}
	disks, _ := GetVMDisks(ctx, c, "cv")
	if disks[0].Path != "/c/root" {
		t.Fatalf("path = %s", disks[0].Path)
	}
	cur := disks[0]
	if ok, err := UpdateDiskPlacementIfStill(ctx, c, cur, "h2", "/b/root", "nfs", "warm"); err != nil || !ok {
		t.Fatalf("applied=%v err=%v over the row read", ok, err)
	}
	disks, _ = GetVMDisks(ctx, c, "cv")
	if d := disks[0]; d.Path != "/b/root" || d.HostName != "h2" || d.StorageType != "nfs" || d.StorageVolume != "warm" || d.SizeBytes != 1 {
		t.Fatalf("row = %+v", d)
	}
}
