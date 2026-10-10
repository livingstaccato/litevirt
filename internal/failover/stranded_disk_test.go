package failover

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A RUNNING VM with a host-local disk is restarted elsewhere under its
// failure policy, as before, but not silently: the coordinator records the
// disk it left on the failed host (vm_disk_stranded, naming the host and the
// path), writes a vm.failover.disk_stranded event and a failover.disk-stranded
// audit row, and raises the notification. A VM whose disks are all on shared
// storage took them with it, so nothing is recorded for it.
//
// Mutations: drop noteDiskStranded after the reschedule — the test is red on
// the missing record; record it for every rescheduled VM — the shared-disk
// VM gets one and the test is red.
func TestRecoverWorkloads_RecordsTheLocalDiskItLeavesBehind(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
		{Name: "good", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct {
		name, storage, path string
	}{
		{"local-vm", "local", "/var/lib/litevirt/disks/local-vm-root.qcow2"},
		{"shared-vm", "nfs", "/mnt/nfs/shared-vm-root.qcow2"},
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: v.name, HostName: "bad", State: "running", CPUActual: 1, MemActual: 512,
			Spec: `{"on_host_failure":"restart-any"}`,
		}, nil, []corrosion.DiskRecord{{
			VMName: v.name, DiskName: "root", HostName: "bad", Path: v.path, StorageType: v.storage, BackingImage: "base",
		}}); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestCoordinator("good", db)
	var notified []string
	c.OnDiskStranded = func(vm, host, detail string) { notified = append(notified, vm+"@"+host) }
	c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad", State: "fenced"})

	for _, name := range []string{"local-vm", "shared-vm"} {
		if vm, _ := corrosion.GetVM(ctx, db, name); vm == nil || vm.HostName != "good" || vm.State != "pending" {
			t.Fatalf("%s = %+v, want it rescheduled pending on good, as before", name, vm)
		}
	}
	got, err := health.StrandedDisksOf(ctx, db, "local-vm")
	if err != nil || len(got) != 1 || got[0].Host != "bad" || len(got[0].Disks) != 1 ||
		got[0].Disks[0].Path != "/var/lib/litevirt/disks/local-vm-root.qcow2" || got[0].MovedTo != "good" {
		t.Fatalf("stranded record for local-vm = %+v (err %v), want its root disk on bad", got, err)
	}
	if got, _ := health.StrandedDisksOf(ctx, db, "shared-vm"); len(got) != 0 {
		t.Fatalf("a VM on shared storage took its disks with it, yet a stranded disk is recorded: %+v", got)
	}
	evs, err := corrosion.ListVMEvents(ctx, db, "local-vm", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "vm.failover.disk_stranded" && strings.Contains(e.Detail, "bad") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no vm.failover.disk_stranded event naming bad: %+v", evs)
	}
	rows, err := db.Query(ctx, `SELECT target FROM audit_log WHERE action = 'failover.disk-stranded'`)
	if err != nil || len(rows) != 1 || rows[0].String("target") != "local-vm" {
		t.Fatalf("failover.disk-stranded audit rows = %v (err %v), want one for local-vm", rows, err)
	}
	if len(notified) != 1 || notified[0] != "local-vm@bad" {
		t.Fatalf("notifications = %q, want one for local-vm@bad", notified)
	}
}

// M8: a container relocated by restoring a backup elsewhere leaves its own
// rootfs (newer than the backup) on the failed host; that is recorded like
// an image-recreate relocation.
//
// Mutation: drop the noteRootfsStranded call in completeRestore — no record,
// red.
func TestCompleteRestore_RecordsTheRootfsLeftBehind(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ct := corrosion.ContainerRecord{HostName: "bad", Name: "web", State: "running", OnHostFailure: "image-recreate"}
	if err := corrosion.UpsertContainer(ctx, db, ct); err != nil {
		t.Fatal(err)
	}
	c := newTestCoordinator("good", db)
	c.completeRestore(ctx, &corrosion.HostRecord{Name: "bad", State: "fenced"}, ct, "good")
	got, err := health.StrandedRootfsOf(ctx, db, "web")
	if err != nil || len(got) != 1 || got[0].Host != "bad" || got[0].How != "backup-restore" || got[0].MovedTo != "good" {
		t.Fatalf("records = %+v (err %v), want the rootfs left on bad by a backup restore", got, err)
	}
}
