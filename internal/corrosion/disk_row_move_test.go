package corrosion

import (
	"context"
	"encoding/json"
	"testing"
)

// diskRowMovers is every write that moves a VM's disk rows to another host
// with the VM: the failover reschedule (proof-linked and legacy), a
// migration's ownership commit, the stopped re-key (claimed and not), and an
// owner transfer with its disks.
func diskRowMovers(t *testing.T) map[string]func(c *Client) error {
	ctx := context.Background()
	stop := func(c *Client) error {
		_, err := c.DB().Exec(`UPDATE vms SET state = 'stopped', state_detail = 'stopped by operator' WHERE name = 'db'`)
		return err
	}
	return map[string]func(c *Client) error{
		"reschedule proof": func(c *Client) error {
			return WriteVMRescheduleProof(ctx, c, ActionProof{ID: "p", Action: ActionReschedule, TargetKind: "vm", TargetName: "db",
				DestHost: "dest", Coordinator: "dest", OwnerEpoch: "0"}, "db", "dest")
		},
		"legacy reschedule": func(c *Client) error { return RescheduleVMHost(ctx, c, "db", "dest", "pending") },
		"migration commit": func(c *Client) error {
			disks, err := GetVMDisks(ctx, c, "db")
			if err != nil {
				return err
			}
			if _, err := c.DB().Exec(`UPDATE vms SET state = 'migrating' WHERE name = 'db'`); err != nil {
				return err
			}
			ok, err := CommitMigrationOwnership(ctx, c, "db", "src", "dest", "running", disks)
			if err == nil && !ok {
				t.Fatal("the migration commit declined")
			}
			return err
		},
		"stopped re-key": func(c *Client) error {
			if err := stop(c); err != nil {
				return err
			}
			return RekeyStoppedVM(ctx, c, "db", "src", "dest", "stopped", 0)
		},
		"stopped re-key, claimed": func(c *Client) error {
			if err := stop(c); err != nil {
				return err
			}
			return RekeyStoppedVMClaimed(ctx, c, "db", "src", "dest", "stopped", 0)
		},
		"owner transfer with disks": func(c *Client) error { return TransferVMOwnerWithDisks(ctx, c, "db", "dest", "running", 0) },
	}
}

func diskRowMoveFixture(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	c := testClient(t)
	for _, h := range []HostRecord{
		{Name: "src", Address: "10.0.0.1", State: "fenced"},
		{Name: "dest", Address: "10.0.0.2", State: "active"},
	} {
		if err := InsertHost(ctx, c, h); err != nil {
			t.Fatal(err)
		}
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "db", HostName: "src", State: "running", Spec: `{}`}, nil, []DiskRecord{{
		VMName: "db", DiskName: "root", HostName: "src", Path: "/s/root", SizeBytes: 1 << 30,
		StorageType: "nfs", StorageVolume: "pool", TargetDev: "vda", Bus: "virtio",
	}}); err != nil {
		t.Fatal(err)
	}
	return c
}

// I7-2: every mover publishes the disk row it moves whole — InsertDisk's
// shape, carrying the path, pool and driver it read — never host_name alone.
// A replica applies a row last-writer-wins whole, so after a host-only move
// its path was whatever it held when the move arrived.
//
// Mutation: emit the host-only UPDATE from diskRowMove — red on every mover.
func TestDiskRowMove_PublishesTheWholeRowItRead(t *testing.T) {
	ctx := context.Background()
	wholeRow := mustStatementFingerprint(diskRowSQL)
	for name, move := range diskRowMovers(t) {
		t.Run(name, func(t *testing.T) {
			c := diskRowMoveFixture(t)
			var before int64
			if err := c.DB().QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM mutation_log`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := move(c); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			rows, err := c.Query(ctx, `SELECT stmts FROM mutation_log WHERE seq > ? ORDER BY seq`, before)
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, r := range rows {
				var stmts []Statement
				if err := json.Unmarshal([]byte(r.String("stmts")), &stmts); err != nil {
					t.Fatal(err)
				}
				for _, s := range stmts {
					sh, _, err := parseResolved(s.SQL)
					if err != nil {
						t.Fatal(err)
					}
					if sh.Table != "vm_disks" {
						continue
					}
					found++
					if fp := stmtFingerprint(sh); fp != wholeRow {
						t.Fatalf("%s published a vm_disks statement of shape %s, want the whole row (diskRowSQL):\n%s", name, fp, s.SQL)
					}
					if cols, vals, ok := insertRowFromShape(sh, s); ok {
						got := map[string]interface{}{}
						for i, col := range cols {
							got[col] = vals[i]
						}
						for col, want := range map[string]interface{}{"host_name": "dest", "path": "/s/root",
							"storage_volume": "pool", "storage_type": "nfs", "bus": "virtio"} {
							if coerceString(got[col]) != want {
								t.Errorf("%s: %s = %v, want %v", name, col, got[col], want)
							}
						}
					} else {
						t.Fatalf("%s: cannot read the published row", name)
					}
				}
			}
			if found != 1 {
				t.Fatalf("%s published %d vm_disks statements, want 1", name, found)
			}
		})
	}
}

// A whole-row move never reverts a column written between its read of the row
// and its transaction: it reads again and moves the row as it now is.
//
// Mutation: drop disksStill from a mover's guard — that mover's resize is
// reverted to the size it read.
func TestDiskRowMove_RereadsARowWrittenSinceItsRead(t *testing.T) {
	ctx := context.Background()
	for name, move := range diskRowMovers(t) {
		t.Run(name, func(t *testing.T) {
			c := diskRowMoveFixture(t)
			resized := 0
			diskMoveAfterRead = func() {
				if resized++; resized == 1 {
					if err := UpdateDiskSize(ctx, c, "db", "root", 2<<30); err != nil {
						t.Error(err)
					}
				}
			}
			t.Cleanup(func() { diskMoveAfterRead = nil })
			if err := move(c); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if resized != 2 {
				t.Errorf("%s read the disk rows %d times, want 2 (the second after the resize)", name, resized)
			}
			disks, err := GetVMDisks(ctx, c, "db")
			if err != nil || len(disks) != 1 {
				t.Fatalf("disks = %+v %v", disks, err)
			}
			if d := disks[0]; d.HostName != "dest" || d.SizeBytes != 2<<30 || d.Path != "/s/root" {
				t.Errorf("%s: row = %+v, want it on dest at the new size", name, d)
			}
		})
	}
}
