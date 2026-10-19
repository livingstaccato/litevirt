package corrosion

import (
	"context"
	"encoding/json"
	"strings"
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

// I7-2: every mover publishes the disk row's placement — host, path, driver
// and pool, as it read them (vmDiskPlacementSQL, UpdateDiskPlacement's shape) —
// never host_name alone. A replica applies a row last-writer-wins, so after a
// host-only move its path was whatever it held when the move arrived. The
// placement only: the move's read may be stale in the row's other columns.
//
// Mutation: emit the host-only UPDATE from diskPlacementMove — red on every
// mover. Emit the whole row (diskRowSQL) — red on every mover.
func TestDiskPlacementMove_PublishesThePlacementItRead(t *testing.T) {
	ctx := context.Background()
	placement := mustStatementFingerprint(vmDiskPlacementSQL)
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
					if fp := stmtFingerprint(sh); fp != placement {
						t.Fatalf("%s published a vm_disks statement of shape %s, want the placement (vmDiskPlacementSQL):\n%s", name, fp, s.SQL)
					}
					want := []interface{}{"dest", "/s/root", "nfs", "pool", nil, "db", "root"}
					if len(s.Params) != len(want) {
						t.Fatalf("%s: params %v", name, s.Params)
					}
					for i, w := range want {
						if w != nil && coerceString(s.Params[i]) != w {
							t.Errorf("%s: param %d = %v, want %v", name, i, s.Params[i], w)
						}
					}
				}
			}
			if found != 1 {
				t.Fatalf("%s published %d vm_disks statements, want 1", name, found)
			}
		})
	}
}

// A move never reverts a placement written between its read of the row and its
// transaction: it reads again and moves the row as it now is. (The migration
// commit refuses a pool changed since cutover outright; its reread is
// TestCommitMigrationOwnership_RereadsAHostWrittenSinceItsRead.)
//
// Mutation: drop disksStill from a mover's guard — that mover's pool change is
// reverted to the pool it read.
func TestDiskPlacementMove_RereadsAPlacementWrittenSinceItsRead(t *testing.T) {
	ctx := context.Background()
	for name, move := range diskRowMovers(t) {
		if name == "migration commit" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			c := diskRowMoveFixture(t)
			reads := 0
			diskMoveAfterRead = func() {
				if reads++; reads == 1 {
					if _, err := c.DB().Exec(`UPDATE vm_disks SET storage_volume = 'pool2' WHERE disk_name = 'root'`); err != nil {
						t.Error(err)
					}
				}
			}
			t.Cleanup(func() { diskMoveAfterRead = nil })
			if err := move(c); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if reads != 2 {
				t.Errorf("%s read the disk rows %d times, want 2 (the second after the change)", name, reads)
			}
			disks, err := GetVMDisks(ctx, c, "db")
			if err != nil || len(disks) != 1 {
				t.Fatalf("disks = %+v %v", disks, err)
			}
			if d := disks[0]; d.HostName != "dest" || d.StorageVolume != "pool2" || d.Path != "/s/root" {
				t.Errorf("%s: row = %+v, want it on dest in the new pool", name, d)
			}
		})
	}
}

// A column a move does not publish never makes it read again.
//
// Mutation: compare every column in disksStill — a resize is "a change", and
// the mover reads twice.
func TestDiskPlacementMove_IgnoresAColumnItDoesNotWrite(t *testing.T) {
	ctx := context.Background()
	for name, move := range diskRowMovers(t) {
		t.Run(name, func(t *testing.T) {
			c := diskRowMoveFixture(t)
			reads := 0
			diskMoveAfterRead = func() {
				if reads++; reads == 1 {
					if err := UpdateDiskSize(ctx, c, "db", "root", 2<<30); err != nil {
						t.Error(err)
					}
				}
			}
			t.Cleanup(func() { diskMoveAfterRead = nil })
			if err := move(c); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if reads != 1 {
				t.Errorf("%s read the disk rows %d times, want 1", name, reads)
			}
			disks, _ := GetVMDisks(ctx, c, "db")
			if len(disks) != 1 || disks[0].HostName != "dest" || disks[0].SizeBytes != 2<<30 {
				t.Errorf("%s: row = %+v, want it on dest at the new size", name, disks)
			}
		})
	}
}

// A migration commit that rereads a host change made since its read commits
// on the reread row.
func TestCommitMigrationOwnership_RereadsAHostWrittenSinceItsRead(t *testing.T) {
	ctx := context.Background()
	c := diskRowMoveFixture(t)
	expected, err := GetVMDisks(ctx, c, "db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(`UPDATE vms SET state = 'migrating' WHERE name = 'db'`); err != nil {
		t.Fatal(err)
	}
	reads := 0
	diskMoveAfterRead = func() {
		if reads++; reads == 1 {
			if _, err := c.DB().Exec(`UPDATE vm_disks SET host_name = 'dest' WHERE disk_name = 'root'`); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { diskMoveAfterRead = nil })
	ok, err := CommitMigrationOwnership(ctx, c, "db", "src", "dest", "running", expected)
	if err != nil || !ok {
		t.Fatalf("commit = %v %v, want committed", ok, err)
	}
	if reads != 2 {
		t.Errorf("read the disk rows %d times, want 2", reads)
	}
}

// m-5: a migration commit that keeps losing to writes between its read and its
// transaction declines, so the caller's RepointMigratedVM moves the VM row to
// where the guest runs. An error would leave the row `migrating` on the source
// after the caller's retries, which nothing heals.
//
// Mutation: return the exhausted retry's error — red.
func TestCommitMigrationOwnership_DeclinesWhenItKeepsLosingToWrites(t *testing.T) {
	ctx := context.Background()
	c := diskRowMoveFixture(t)
	expected, err := GetVMDisks(ctx, c, "db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(`UPDATE vms SET state = 'migrating' WHERE name = 'db'`); err != nil {
		t.Fatal(err)
	}
	// Every read is followed by a write that flips the row between the hosts
	// the commit accepts, so the row is never the one it read.
	reads := 0
	diskMoveAfterRead = func() {
		reads++
		if _, err := c.DB().Exec(`UPDATE vm_disks SET host_name = CASE host_name WHEN 'src' THEN 'dest' ELSE 'src' END WHERE disk_name = 'root'`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { diskMoveAfterRead = nil })
	ok, err := CommitMigrationOwnership(ctx, c, "db", "src", "dest", "running", expected)
	if err != nil || ok {
		t.Fatalf("commit = %v %v, want a decline (false, nil)", ok, err)
	}
	if reads < 2 {
		t.Errorf("read the disk rows %d times, want it to have retried", reads)
	}
	moved, err := RepointMigratedVM(ctx, c, "db", "src", "dest", "running")
	if err != nil || !moved {
		t.Fatalf("the caller's fallback RepointMigratedVM = %v %v, want the VM row moved", moved, err)
	}
	if vm, _ := GetVM(ctx, c, "db"); vm == nil || vm.HostName != "dest" || vm.State != "running" {
		t.Fatalf("vm = %+v, want running on dest", vm)
	}
}

// m-1: the host-only move's historical entry may be removed only once the
// newest release that emits it is unsupported, not the oldest.
//
// Mutation: register it with add() (v1.3.0's horizon) — red.
func TestHistoricalLedger_HostOnlyDiskMoveHorizonIsItsNewestEmitter(t *testing.T) {
	fp := mustStatementFingerprint(`UPDATE vm_disks SET host_name = ?, updated_at = ?
		WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`)
	e, ok := historicalLedger[fp]
	if !ok {
		t.Fatalf("%s is not in the historical ledger", fp)
	}
	if !strings.Contains(e.RemovalHorizon, "v1.9.0") {
		t.Fatalf("RemovalHorizon = %q, want it to name v1.9.0, the newest release that emits it", e.RemovalHorizon)
	}
	for _, hs := range HistoricalShapes() {
		if hs.Family == "vm_disk_host_move_v130" && !strings.Contains(hs.LastEmitter, "v1.9.0") {
			t.Fatalf("LastEmitter = %q, want v1.9.0", hs.LastEmitter)
		}
	}
}
