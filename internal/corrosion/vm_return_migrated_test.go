package corrosion

import (
	"context"
	"testing"
)

const returnUUID = "6f1c2a4e-1b2c-4d3e-8f90-0a1b2c3d4e5f"

// returnRig is VM "fw" committed to host-b by a live firmware move from
// host-a, with two shared disks whose rows the commit moved to host-b.
func returnRig(t *testing.T) (*Client, VMRecord, []DiskRecord) {
	t.Helper()
	ctx := context.Background()
	c := newTestDB(t)
	disks := []DiskRecord{
		{VMName: "fw", DiskName: "root", HostName: "host-a", Path: "/nfs/fw-root", StorageType: "nfs"},
		{VMName: "fw", DiskName: "data", HostName: "host-a", Path: "/nfs/fw-data", StorageType: "nfs"},
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "fw", HostName: "host-a", State: "migrating",
		Spec: `{"name":"fw","secure_boot":true,"tpm":true,"uuid":"` + returnUUID + `"}`}, nil, disks); err != nil {
		t.Fatal(err)
	}
	before, err := GetVMDisks(ctx, c, "fw")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := CommitMigrationOwnership(ctx, c, "fw", "host-a", "host-b", "running", before); err != nil || !ok {
		t.Fatalf("commit: ok=%v err=%v", ok, err)
	}
	vm, err := GetVM(ctx, c, "fw")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", vm, err)
	}
	after, err := GetVMDisks(ctx, c, "fw")
	if err != nil {
		t.Fatal(err)
	}
	return c, *vm, after
}

// T-33: the D-5 --accept-source return writer moves the VM row AND every disk
// row the commit moved back to the source, stopped.
//
// Mutation: drop the disk statements (move the VM row only) — red.
func TestReturnMigratedVM_MovesVMAndDisks(t *testing.T) {
	ctx := context.Background()
	c, vm, disks := returnRig(t)
	for _, d := range disks {
		if d.HostName != "host-b" {
			t.Fatalf("the rig's commit left disk %s on %s", d.DiskName, d.HostName)
		}
	}
	ok, err := ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, vm.CreatedAt, "stopped", disks)
	if err != nil || !ok {
		t.Fatalf("ReturnMigratedVM: ok=%v err=%v", ok, err)
	}
	got, _ := GetVM(ctx, c, "fw")
	if got == nil || got.HostName != "host-a" || got.State != "stopped" {
		t.Fatalf("row after the return: %+v", got)
	}
	back, _ := GetVMDisks(ctx, c, "fw")
	if len(back) != 2 {
		t.Fatalf("disk rows after the return: %+v", back)
	}
	for _, d := range back {
		if d.HostName != "host-a" {
			t.Errorf("disk %s on %s after the return, want host-a", d.DiskName, d.HostName)
		}
	}
	// Once returned, the same call is not the commit it undoes.
	if ok, err := ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, vm.CreatedAt, "stopped", back); err != nil || ok {
		t.Errorf("second return: ok=%v err=%v, want declined", ok, err)
	}
}

// The return is refused for another incarnation (uuid or created_at), a row
// that does not name the target, disks changed since the commit, and any
// state but stopped. Nothing is written.
//
// Mutation: drop the incarnation check, or the disk checks — red.
func TestReturnMigratedVM_RefusesWrongIncarnation(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(c *Client, vm VMRecord, disks []DiskRecord) (bool, error){
		"other_uuid": func(c *Client, vm VMRecord, disks []DiskRecord) (bool, error) {
			return ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", "00000000-0000-4000-8000-000000000000", vm.CreatedAt, "stopped", disks)
		},
		"other_created_at": func(c *Client, vm VMRecord, disks []DiskRecord) (bool, error) {
			return ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, "2001-01-01T00:00:00Z", "stopped", disks)
		},
		"row_not_on_target": func(c *Client, vm VMRecord, disks []DiskRecord) (bool, error) {
			return ReturnMigratedVM(ctx, c, "fw", "host-c", "host-a", returnUUID, vm.CreatedAt, "stopped", disks)
		},
		"disk_moved_since": func(c *Client, vm VMRecord, disks []DiskRecord) (bool, error) {
			if err := UpdateDiskStorage(ctx, c, "fw", "data", "ceph", "pool/x"); err != nil {
				t.Fatal(err)
			}
			return ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, vm.CreatedAt, "stopped", disks)
		},
		"disk_added_since": func(c *Client, vm VMRecord, disks []DiskRecord) (bool, error) {
			if err := InsertDisk(ctx, c, DiskRecord{VMName: "fw", DiskName: "extra", HostName: "host-b", Path: "/nfs/fw-extra", StorageType: "nfs"}); err != nil {
				t.Fatal(err)
			}
			return ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, vm.CreatedAt, "stopped", disks)
		},
		"running": func(c *Client, vm VMRecord, disks []DiskRecord) (bool, error) {
			return ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, vm.CreatedAt, "running", disks)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			c, vm, disks := returnRig(t)
			if ok, _ := run(c, vm, disks); ok {
				t.Fatal("returned, want declined")
			}
			got, _ := GetVM(ctx, c, "fw")
			if got == nil || got.HostName != "host-b" || got.State != "running" {
				t.Errorf("row after a declined return: %+v, want running on host-b", got)
			}
			for _, d := range mustDisks(t, c) {
				if d.HostName != "host-b" {
					t.Errorf("disk %s moved to %s by a declined return", d.DiskName, d.HostName)
				}
			}
		})
	}
}

func mustDisks(t *testing.T, c *Client) []DiskRecord {
	t.Helper()
	d, err := GetVMDisks(context.Background(), c, "fw")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// D2 merge with cand31, review N-1: every expected disk row must be the
// returned VM's. The guard reads rows by vmName, and the update is keyed on
// each row's own VMName; a row of another VM is refused up front and nothing
// is written.
//
// Mutation: drop the up-front check — the mismatched row's update is
// written, red.
func TestReturnMigratedVM_RefusesAnotherVMsDiskRow(t *testing.T) {
	ctx := context.Background()
	c, vm, disks := returnRig(t)
	bad := append([]DiskRecord(nil), disks...)
	bad[0].VMName = "other"
	ok, err := ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, vm.CreatedAt, "stopped", bad)
	if ok || err == nil {
		t.Fatalf("ok=%v err=%v, want refused with an error", ok, err)
	}
	got, _ := GetVM(ctx, c, "fw")
	if got == nil || got.HostName != "host-b" {
		t.Errorf("row after the refusal: %+v, want on host-b", got)
	}
	for _, d := range mustDisks(t, c) {
		if d.HostName != "host-b" {
			t.Errorf("disk %s moved to %s by a refused return", d.DiskName, d.HostName)
		}
	}
}
