package corrosion

import (
	"context"
	"testing"
	"time"
)

// Review I1: every move of a VM — a failover reschedule (proof-linked and
// legacy), a migration's ownership commit, the stopped re-key (claimed and
// not), and an owner transfer with its disks (repair-owner, owner-assert, a
// cold firmware migration) — leaves a shared disk's row naming a THIRD host
// that is not proven off; it re-points every other row, a shared row whose
// host is proven off, and a row naming the host the VM leaves.
//
// Mutation "SharedRowKeepsOwner never keeps" — red on every move's
// "unproven" row.
func TestMoves_KeepASharedRowWhoseThirdHostIsNotProvenOff(t *testing.T) {
	ctx := context.Background()
	moves := map[string]func(c *Client) error{
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
			if _, err := c.DB().Exec(`UPDATE vms SET state = 'stopped', state_detail = 'stopped by operator' WHERE name = 'db'`); err != nil {
				return err
			}
			return RekeyStoppedVM(ctx, c, "db", "src", "dest", "stopped", 0)
		},
		"stopped re-key, claimed": func(c *Client) error {
			if _, err := c.DB().Exec(`UPDATE vms SET state = 'stopped', state_detail = 'stopped by operator' WHERE name = 'db'`); err != nil {
				return err
			}
			return RekeyStoppedVMClaimed(ctx, c, "db", "src", "dest", "stopped", 0)
		},
		"owner transfer with disks": func(c *Client) error { return TransferVMOwnerWithDisks(ctx, c, "db", "dest", "running", 0) },
	}
	for name, move := range moves {
		t.Run(name, func(t *testing.T) {
			c := testClient(t)
			for _, h := range []HostRecord{
				{Name: "src", Address: "10.0.0.1", State: "fenced"},
				{Name: "dest", Address: "10.0.0.2", State: "active"},
				{Name: "unproven", Address: "10.0.0.3", State: "fenced"},
				{Name: "proven", Address: "10.0.0.4", State: "fenced"},
			} {
				if err := InsertHost(ctx, c, h); err != nil {
					t.Fatal(err)
				}
			}
			ts := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
			for _, f := range [][2]string{{"unproven", "ssh"}, {"proven", "ipmi"}, {"src", "ipmi"}} {
				if err := c.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
					VALUES (?, ?, ?, 'fenced', ?, '')`, f[0], f[0], f[1], ts); err != nil {
					t.Fatal(err)
				}
			}
			disks := []DiskRecord{
				{VMName: "db", DiskName: "root", HostName: "src", Path: "/s/root", StorageType: "nfs"},
				{VMName: "db", DiskName: "kept", HostName: "unproven", Path: "/s/kept", StorageType: "nfs"},
				{VMName: "db", DiskName: "freed", HostName: "proven", Path: "/s/freed", StorageType: "nfs"},
			}
			// A host-local row naming a third host moves as before (a stopped
			// re-key carries only VMs whose disks are all shared).
			withLocal := name != "stopped re-key" && name != "stopped re-key, claimed"
			if withLocal {
				disks = append(disks, DiskRecord{VMName: "db", DiskName: "local", HostName: "unproven", Path: "/s/local", StorageType: "local"})
			}
			if err := InsertVM(ctx, c, VMRecord{Name: "db", HostName: "src", State: "running", Spec: `{}`}, nil, disks); err != nil {
				t.Fatal(err)
			}
			if err := move(c); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			disks, err := GetVMDisks(ctx, c, "db")
			if err != nil {
				t.Fatal(err)
			}
			if len(disks) != 3 && !withLocal || len(disks) != 4 && withLocal {
				t.Fatalf("disks = %+v", disks)
			}
			want := map[string]string{"root": "dest", "kept": "unproven", "freed": "dest", "local": "dest"}
			for _, d := range disks {
				if d.HostName != want[d.DiskName] {
					t.Errorf("%s: disk %s row names %q, want %q", name, d.DiskName, d.HostName, want[d.DiskName])
				}
			}
		})
	}
}
