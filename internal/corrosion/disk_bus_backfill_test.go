package corrosion

import (
	"context"
	"testing"
)

func seedBusLessDisk(t *testing.T, c *Client, host string) DiskRecord {
	t.Helper()
	ctx := context.Background()
	if err := InsertVM(ctx, c, VMRecord{Name: "bfvm", HostName: host, State: "running"}, nil, []DiskRecord{{
		VMName: "bfvm", DiskName: "root", HostName: host, Path: "/d/bfvm-root.qcow2",
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	disks, err := GetVMDisks(ctx, c, "bfvm")
	if err != nil || len(disks) != 1 {
		t.Fatalf("GetVMDisks: %v %+v", err, disks)
	}
	if disks[0].Bus != "" {
		t.Fatalf("setup: want a bus-less row, have %q", disks[0].Bus)
	}
	return disks[0]
}

// TestBackfillDiskBus_FillsOnlyAnUnmovedRowOfItsOwn: the startup backfill's
// disk write fills the bus of a row that is still exactly as read and still
// the backfilling host's, and of no other row. A row that moved between the
// read and the write keeps its move.
//
// Mutation: make the guard return true unconditionally — "moved" goes red: the
// write lands the read row, host and all, over the move.
func TestBackfillDiskBus_FillsOnlyAnUnmovedRowOfItsOwn(t *testing.T) {
	ctx := context.Background()

	t.Run("unchanged", func(t *testing.T) {
		c := newTestDB(t)
		read := seedBusLessDisk(t, c, "h1")
		applied, err := BackfillDiskBus(ctx, c, read, "virtio", "h1")
		if err != nil || !applied {
			t.Fatalf("BackfillDiskBus on an unchanged row: applied=%v err=%v", applied, err)
		}
		got, _ := GetVMDisks(ctx, c, "bfvm")
		if got[0].Bus != "virtio" || got[0].HostName != "h1" || got[0].Path != read.Path {
			t.Fatalf("want the bus filled and nothing else changed, have %+v", got[0])
		}
	})

	t.Run("moved", func(t *testing.T) {
		c := newTestDB(t)
		read := seedBusLessDisk(t, c, "h1")
		// Failover moves the disk row after the backfill read it.
		if err := UpdateDiskHostAndPath(ctx, c, "bfvm", "root", "h2", read.Path); err != nil {
			t.Fatal(err)
		}
		applied, err := BackfillDiskBus(ctx, c, read, "virtio", "h1")
		if err != nil {
			t.Fatal(err)
		}
		got, _ := GetVMDisks(ctx, c, "bfvm")
		if applied || got[0].HostName != "h2" || got[0].Bus != "" {
			t.Fatalf("the backfill wrote over a row that moved since it read it: applied=%v row=%+v", applied, got[0])
		}
	})

	t.Run("not-ours", func(t *testing.T) {
		c := newTestDB(t)
		read := seedBusLessDisk(t, c, "h2")
		applied, err := BackfillDiskBus(ctx, c, read, "virtio", "h1")
		if err != nil {
			t.Fatal(err)
		}
		got, _ := GetVMDisks(ctx, c, "bfvm")
		if applied || got[0].HostName != "h2" || got[0].Bus != "" {
			t.Fatalf("the backfill wrote another host's disk row: applied=%v row=%+v", applied, got[0])
		}
	})
}
