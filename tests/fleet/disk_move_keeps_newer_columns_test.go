// A failover's move of a VM's disk rows carries the placement the coordinator
// read, and nothing else: applying the move itself does not overwrite a newer
// change a replica holds to one of the rows' other columns, nor its detach.
//
// It guards against the round-0 design of this branch, a move that published
// the whole row it read: from a coordinator whose replica lacked the old
// owner's last writes, that put a backing the owner had cleared back on every
// replica, and brought back as live a disk the owner had detached — on the
// destination, which then booted it. The test passes on the base too: the
// host-only move wrote neither column.
//
// What it asserts holds only until anti-entropy runs. One pass copies the
// coordinator's newer live row over the destination's detach, and settles the
// differing backing by content, which can bring back the cleared one. That is
// pre-existing (I-2 in .superpowers/sdd/plan-residuals-2026-10-05/
// rsdisk-r1-rereview.md) and left to its follow-up.
//
// Multi-node by construction: the owner's last write reaches the destination
// and not the coordinator, which only per-replica delivery can arrange.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_DiskMoveKeepsTheOwnersNewerWrites.
//
//  1. VM dm runs on a with a root disk (an overlay on a base) and a data disk;
//     every replica has it.
//  2. a writes, and only c receives: the root's backing cleared (a flattening
//     move's ClearDiskBacking), or the data disk detached.
//  3. a dies; b reschedules dm to c from its own replica, which still has the
//     backing and the data disk.
//  4. c receives the reschedule: its root row names c with no backing, and its
//     data row stays detached (before any anti-entropy pass; see above).
//
// Mutation: publish the whole row read (diskRowSQL) from the move — c gets
// the backing back, and the detached disk back as live.
func TestFleet_DiskMoveKeepsTheOwnersNewerWrites(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(ctx context.Context, n *Node) error
		check func(t *testing.T, disks []corrosion.DiskRecord)
	}{
		{
			name: "backing cleared",
			write: func(ctx context.Context, n *Node) error {
				return corrosion.ClearDiskBacking(ctx, n.DB, "dm", "root", "/shared/dm-root.qcow2")
			},
			check: func(t *testing.T, disks []corrosion.DiskRecord) {
				for _, d := range disks {
					if d.DiskName == "root" && (d.BackingDisk != "" || d.BackingImage != "") {
						t.Fatalf("root row on the destination = %+v, want the backing the owner cleared to stay cleared", d)
					}
				}
			},
		},
		{
			name: "data disk detached",
			write: func(ctx context.Context, n *Node) error {
				return corrosion.SoftDeleteDisk(ctx, n.DB, "dm", "data")
			},
			check: func(t *testing.T, disks []corrosion.DiskRecord) {
				for _, d := range disks {
					if d.DiskName == "data" {
						t.Fatalf("the detached data disk is live on the destination again: %+v", d)
					}
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3})
			a, b, cn := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
				Name: "dm", HostName: a.Name, State: "running", CPUActual: 1, MemActual: 256,
				Spec: `{"name":"dm","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
			}, nil, []corrosion.DiskRecord{
				{VMName: "dm", DiskName: "root", HostName: a.Name, Path: "/shared/dm-root.qcow2", SizeBytes: 1 << 30,
					StorageType: "nfs", TargetDev: "vda", BackingDisk: "/shared/base.qcow2", BackingImage: "base"},
				{VMName: "dm", DiskName: "data", HostName: a.Name, Path: "/shared/dm-data.qcow2", SizeBytes: 1 << 30,
					StorageType: "nfs", TargetDev: "vdb"},
			}); err != nil {
				t.Fatal(err)
			}
			pumpMutations(t, c, a, b)
			pumpMutations(t, c, a, cn)

			// 2. a's last write reaches only c.
			if err := tc.write(ctx, a); err != nil {
				t.Fatal(err)
			}
			pumpMutations(t, c, a, cn)
			time.Sleep(5 * time.Millisecond)

			// 3. b reschedules dm to c from what it holds.
			if err := corrosion.RescheduleVMHost(ctx, b.DB, "dm", cn.Name, "pending"); err != nil {
				t.Fatalf("reschedule dm to %s: %v", cn.Name, err)
			}

			// 4. c keeps a's newer write.
			pumpMutations(t, c, b, cn)
			disks, err := corrosion.GetVMDisks(ctx, cn.DB, "dm")
			if err != nil {
				t.Fatal(err)
			}
			root := false
			for _, d := range disks {
				if d.DiskName == "root" {
					root = true
					if d.HostName != cn.Name || d.Path != "/shared/dm-root.qcow2" {
						t.Fatalf("root row on %s = %+v, want it moved to %s on its path", cn.Name, d, cn.Name)
					}
				}
			}
			if !root {
				t.Fatalf("no root row on %s: %+v", cn.Name, disks)
			}
			tc.check(t, disks)
		})
	}
}
