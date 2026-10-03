// A VM's disk rows follow it through failover, and a migration of a VM whose
// disk rows were left behind still commits.
//
// Observed on the kvm003-f3 lab (main-b3368d7c): failover moved pp3 off the
// failed node-3 by re-keying its vms row only, so its vm_disks rows went on
// naming node-3. A later `lv migrate` of pp3 to a third host cut over, and then
// CommitMigrationOwnership refused, because it accepts a disk row only on the
// source or the target. The guest ran on the target, the vms row stayed on the
// source in `migrating`, vm_dual_run was raised, and owner-assert skips
// `migrating` rows, so nothing healed it until `lv doctor repair-owner`.
//
// Multi-node by construction: the failover is decided by one node's
// coordinator, the migration is served by the destination and commits a row
// every node reads.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
)

const diskRowsVM = "pp3"

func insertVMWithDisk(t *testing.T, n *Node, name, host, diskHost string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
		CPUActual: 1, MemActual: 512,
	}, nil, []corrosion.DiskRecord{{
		VMName: name, DiskName: "root", HostName: diskHost, Path: "/var/lib/litevirt/disks/" + name + "-root.qcow2",
		SizeBytes: 1 << 30, StorageType: "nfs", StorageVolume: "shared",
	}}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

func diskHosts(t *testing.T, n *Node, vm string) []string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), n.DB, vm)
	if err != nil {
		t.Fatalf("%s: disks of %s: %v", n.Name, vm, err)
	}
	var out []string
	for _, d := range disks {
		out = append(out, d.HostName)
	}
	return out
}

// migrateToThird runs the lab's second step: pp3 runs on owner, and is
// migrated to another live host. It returns that host.
func migrateToThird(t *testing.T, c *Cluster, owner *Node, skip ...*Node) *Node {
	t.Helper()
	ctx := context.Background()
	var target *Node
	for _, n := range c.Nodes {
		excluded := n == owner
		for _, s := range skip {
			excluded = excluded || n == s
		}
		if !excluded {
			target = n
			break
		}
	}
	if err := migrateAt(t, c, owner, diskRowsVM, target.Name); err != nil {
		t.Fatalf("migrate %s %s → %s: %v", diskRowsVM, owner.Name, target.Name, err)
	}
	vm, err := corrosion.GetVM(ctx, owner.DB, diskRowsVM)
	if err != nil || vm == nil {
		t.Fatalf("read %s: %+v %v", diskRowsVM, vm, err)
	}
	if vm.HostName != target.Name || vm.State != "running" {
		t.Fatalf("after the migration %s's row names %s in state %q; want %s, running — the guest "+
			"runs there", diskRowsVM, vm.HostName, vm.State, target.Name)
	}
	for _, h := range diskHosts(t, owner, diskRowsVM) {
		if h != target.Name {
			t.Fatalf("after the migration a disk row of %s names %s, want %s", diskRowsVM, h, target.Name)
		}
	}
	return target
}

// TestFleet_Failover_DiskRowsFollowTheVM: victim fails and the coordinator
// reschedules pp3, through the proof-linked write split_brain_gate_v1 uses
// (the lab's path) and through the write before it. Its disk row names the
// destination as soon as the vms row does, and a later migration to a third
// host commits.
//
// Mutation: drop the disk statements from WriteVMRescheduleProof — the gated
// arm's disk row still names victim after the failover; from RescheduleVMHost
// — the legacy arm's does.
func TestFleet_Failover_DiskRowsFollowTheVM(t *testing.T) {
	for _, gated := range []bool{true, false} {
		t.Run(map[bool]string{true: "proof-gated", false: "legacy"}[gated], func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 4, SharedCRDT: true})
			a, victim := c.Nodes[0], c.Nodes[3]
			insertVMWithDisk(t, a, diskRowsVM, victim.Name, victim.Name)
			now := time.Now().UTC()
			for _, n := range c.Nodes[:3] {
				PublishHealth(t, n, victim.Name, 5, now)
			}

			coord := failover.NewCoordinator(a.Name, a.DB)
			coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
				return fence.Result{Method: "fleet-test", Success: true}
			})
			if gated {
				coord.Gate = quorateGate{}
			}
			coord.RunOnce(ctx)

			vm, err := corrosion.GetVM(ctx, a.DB, diskRowsVM)
			if err != nil || vm == nil || vm.HostName == victim.Name {
				t.Fatalf("failover did not reschedule %s: %+v %v", diskRowsVM, vm, err)
			}
			if gated && vm.PendingActionID == "" {
				t.Fatalf("the gated arm did not take the proof-linked write: %+v", vm)
			}
			dest := c.Node(vm.HostName)
			for _, h := range diskHosts(t, a, diskRowsVM) {
				if h != dest.Name {
					t.Fatalf("after failover %s's row names %s and its disk row names %s: the disk rows must "+
						"move with the VM", diskRowsVM, dest.Name, h)
				}
			}

			// The destination starts it, as its reconciler does.
			dest.Virt.SetState(diskRowsVM, "running")
			if err := corrosion.UpdateVMState(ctx, a.DB, diskRowsVM, "running", ""); err != nil {
				t.Fatal(err)
			}
			migrateToThird(t, c, dest, victim)
		})
	}
}

// TestFleet_Migrate_CommitsOverADiskRowLeftOnTheFailedHost is the lab's state
// as an older build left it: pp3 runs on owner, its disk row still names the
// host it was recovered from. The migration commits, and moves the disk row
// with the VM.
//
// Mutation: restore the guard's source-or-target-only host check in
// CommitMigrationOwnership — the migration cuts over and returns an error, and
// the row is left `migrating`... unless RepointMigratedVM moves it; the
// assertion on the disk rows fails either way.
func TestFleet_Migrate_CommitsOverADiskRowLeftOnTheFailedHost(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	owner, gone := c.Nodes[0], c.Nodes[2]
	insertVMWithDisk(t, owner, diskRowsVM, owner.Name, gone.Name)
	owner.Virt.SetState(diskRowsVM, "running")
	migrateToThird(t, c, owner, gone)
}
