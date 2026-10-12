package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// partialOnB is db promoted by an operator on b from a replica of its root,
// while its owner a is fenced by SSH only: the shared (NFS) data1 is left
// unattached, its row still naming a. The promoted root's pool stands in for
// a shared one (the fleet cannot mount NFS), so db can move on without
// copying. It returns data1's path.
func partialOnB(t *testing.T, c *Cluster, a, b *Node) string {
	t.Helper()
	ctx := context.Background()
	dr := filepath.Join(c.tmpRoot, "shared-dr")
	nfs := filepath.Join(c.tmpRoot, "nfs")
	for _, d := range []string{dr, nfs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertStoragePool(ctx, b.DB, corrosion.StoragePoolRecord{
		HostName: b.Name, Name: "dr", Driver: "local", Target: dr, State: "active"}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(c.tmpRoot, a.Name, "db-root.qcow2")
	data1 := filepath.Join(nfs, "db-data1.qcow2")
	for _, p := range []string{root, data1} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "db", Cpu: 1, MemoryMib: 256, Onboot: true, OnHostFailure: "restart-any"})
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "db", HostName: a.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "db", DiskName: "root", HostName: a.Name, Path: root, SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda", Bus: "virtio"},
		{VMName: "db", DiskName: "data1", HostName: a.Name, Path: data1, SizeBytes: 1 << 20, StorageType: "nfs", StorageVolume: "nfs", TargetDev: "vdb", Bus: "virtio"},
	}); err != nil {
		t.Fatal(err)
	}
	a.Virt.SetState("db", libvirtfake.StateRunning)
	sched := corrosion.BackupScheduleRecord{VMName: "db", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: b.Name, KeepReplicas: 1}
	if err := corrosion.UpsertBackupSchedule(ctx, a.DB, sched); err != nil {
		t.Fatal(err)
	}
	if err := a.Server.RunReplication(ctx, sched, time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatalf("replicate db: %v", err)
	}
	// a is fenced by a fence that proves nothing.
	if err := corrosion.RecordFenceWithState(ctx, a.DB, corrosion.FenceLogRecord{ID: "ssh-" + a.Name, HostName: a.Name,
		Method: "ssh", Result: "fenced", Detail: "poweroff sent"}, "fenced"); err != nil {
		t.Fatal(err)
	}
	st, err := c.SelfClient(b).PromoteReplica(ctx, &pb.PromoteReplicaRequest{VmName: "db", TargetHost: b.Name, TargetPool: "dr",
		Force: true, NoLocalize: true})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil {
		t.Fatalf("operator promotion of db on %s: %v", b.Name, err)
	}
	if xml := b.Virt.DefinedXML("db"); xml == "" || strings.Contains(xml, data1) {
		t.Fatalf("want db promoted on %s without data1:\n%s", b.Name, xml)
	}
	// The promoted root on a pool every host reaches.
	if err := b.DB.Execute(ctx, `UPDATE vm_disks SET storage_type = 'nfs' WHERE vm_name = 'db' AND disk_name = 'root'`); err != nil {
		t.Fatal(err)
	}
	return data1
}

// data1Row is data1's row on n.
func data1Row(t *testing.T, n *Node) corrosion.DiskRecord {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), n.DB, "db")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range disks {
		if d.DiskName == "data1" {
			return d
		}
	}
	t.Fatal("db has no data1 row")
	return corrosion.DiskRecord{}
}

// Review I1: a shared disk a partial promotion left unattached keeps its row
// naming its unproven owner through every move of the VM, so the next domain
// built from the rows on the new host still judges that owner and leaves the
// disk out. Each move used to re-point the row at the VM's new host, where it
// read as that host's own and was attached unjudged: two writers, if the old
// owner's qemu still ran. `lv doctor repair-owner` refuses to re-home it, and
// names fence-confirm.
//
// Mutation "moves re-point every row" (SharedRowKeepsOwner never keeps) — red
// on the migrate, reschedule and stopped re-key arms. Mutation "repair-owner
// does not refuse" — red on the repair-owner arm.
func TestFleet_AWithheldSharedDiskStaysWithheldThroughEveryMove(t *testing.T) {
	for _, arm := range []string{"migrate", "reschedule", "stopped re-key", "repair-owner"} {
		t.Run(arm, func(t *testing.T) {
			c := New(t, Options{Nodes: 4, SharedCRDT: true})
			// The upgrade has finished: pit_overlay is available, so the running
			// VM's replicas are point-in-time and failover promotes them.
			latchPITOverlay(t, c)
			ctx := context.Background()
			a, b, cn, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
			data1 := partialOnB(t, c, a, b)

			switch arm {
			case "migrate":
				if err := migrateAt(t, c, b, "db", cn.Name); err != nil {
					t.Fatalf("migrate db to %s: %v", cn.Name, err)
				}
				// cn reboots: onboot rebuilds db from its rows.
				_ = cn.Virt.DestroyDomain("db")
				rec := health.NewReconciler(cn.Name, t.TempDir(), cn.DB, cn.Virt)
				rec.StartOnbootVMs(ctx)
			case "reschedule", "stopped re-key":
				if arm == "stopped re-key" {
					if err := corrosion.UpdateVMState(ctx, b.DB, "db", "stopped", "stopped by operator"); err != nil {
						t.Fatal(err)
					}
				}
				failVictim(t, cn, b, cn, d)
				vm, err := corrosion.GetVM(ctx, cn.DB, "db")
				if err != nil || vm == nil {
					t.Fatalf("GetVM: %v", err)
				}
				for _, n := range []*Node{cn, d} {
					if n.Name == vm.HostName {
						cn = n
					}
				}
				rec := health.NewReconciler(cn.Name, t.TempDir(), cn.DB, cn.Virt)
				rec.ReconcileOnce(ctx)
			case "repair-owner":
				_, err := c.SelfClient(b).RepairVMOwner(ctx, &pb.RepairVMOwnerRequest{Name: "db", Host: b.Name})
				if err == nil || !strings.Contains(err.Error(), "`lv host fence-confirm "+a.Name+"`") {
					t.Fatalf("repair-owner = %v, want it refused naming fence-confirm", err)
				}
				if r := data1Row(t, b); r.HostName != a.Name {
					t.Fatalf("data1 row = %+v, want it still naming %s", r, a.Name)
				}
				return
			}
			if vm, err := corrosion.GetVM(ctx, cn.DB, "db"); err != nil || vm == nil || vm.HostName != cn.Name {
				t.Fatalf("db did not move to %s: %+v %v", cn.Name, vm, err)
			}
			if r := data1Row(t, cn); r.HostName != a.Name {
				t.Errorf("the %s re-pointed data1's row at %s; want it naming %s, not proven off", arm, r.HostName, a.Name)
			}
			xml := cn.Virt.DefinedXML("db")
			if xml == "" {
				t.Fatalf("db has no domain on %s after the %s", cn.Name, arm)
			}
			if strings.Contains(xml, data1) {
				t.Fatalf("db's domain on %s attaches data1 after the %s, with %s unproven:\n%s", cn.Name, arm, a.Name, xml)
			}
		})
	}
}
