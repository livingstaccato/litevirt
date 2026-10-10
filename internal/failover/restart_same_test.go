package failover

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// restart-same with a host-local disk waits for its own host: a restart
// anywhere else would rebuild that disk blank from the image. The VM stays on
// the fenced host, unchanged, and the hold is recorded (condition
// vm_failover_held, a vm.failover.held event naming the host and what the
// operator can do, a failover.skip audit row, a notification). A
// restart-same VM whose disks are all shared keeps main's behaviour: it is
// rescheduled to a healthy host, its data intact.
//
// Mutations: drop the hold — local-same is rescheduled blank and the test is
// red; hold every restart-same VM (ignore the disks) — shared-same stays and
// the test is red.
func TestRecoverWorkloads_RestartSameWithALocalDiskWaitsForItsHost(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "fenced", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
		{Name: "good", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct{ name, storage, path string }{
		{"local-same", "local", "/var/lib/litevirt/disks/local-same-root.qcow2"},
		{"shared-same", "nfs", "/mnt/nfs/shared-same-root.qcow2"},
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: v.name, HostName: "bad", State: "running", CPUActual: 1, MemActual: 512,
			Spec: `{"on_host_failure":"restart-same"}`,
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

	if vm, _ := corrosion.GetVM(ctx, db, "local-same"); vm == nil || vm.HostName != "bad" || vm.State != "running" {
		t.Fatalf("local-same = %+v, want it left running on bad, waiting for its host", vm)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, db, "local-same"); len(disks) != 1 || disks[0].HostName != "bad" {
		t.Fatalf("local-same's disk rows moved: %+v", disks)
	}
	if vm, _ := corrosion.GetVM(ctx, db, "shared-same"); vm == nil || vm.HostName != "good" || vm.State != "pending" {
		t.Fatalf("shared-same = %+v, want it rescheduled to good as before", vm)
	}
	held, err := health.HeldForHostOf(ctx, db, "local-same")
	if err != nil || held == nil || held.Host != "bad" || !strings.Contains(held.Fix, "lv host superseded-disks") {
		t.Fatalf("held record = %+v (err %v), want one naming bad and the operator's path", held, err)
	}
	if h, _ := health.HeldForHostOf(ctx, db, "shared-same"); h != nil {
		t.Fatalf("shared-same was recorded held: %+v", h)
	}
	evs, err := corrosion.ListVMEvents(ctx, db, "local-same", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "vm.failover.held" && strings.Contains(e.Detail, "bad") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no vm.failover.held event naming bad: %+v", evs)
	}
	if len(notified) != 1 || notified[0] != "local-same@bad" {
		t.Fatalf("notifications = %q, want one for local-same@bad", notified)
	}
	// A second pass over the same host does not repeat the event.
	c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad", State: "fenced"})
	if len(notified) != 1 {
		t.Fatalf("a second pass notified again: %q", notified)
	}
}
