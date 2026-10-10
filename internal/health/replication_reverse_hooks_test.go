package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A reclaim of ownership moves the workload: a schedule that replicated onto the
// host that now owns it replicates back to the host that held the row (I2).

func replScheduleOnto(t *testing.T, db *corrosion.Client, key, project, target string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: "node-b", Name: "dr", Driver: "local", Target: "/dr", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetHostLabel(ctx, db, "node-b", corrosion.LabelLXCCapable, "true"); err != nil {
		t.Fatal(err)
	}
	scope := "vm"
	if project != "" {
		scope = "container"
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: key, Scope: scope, ProjectName: project, Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: target, KeepReplicas: 2,
	}); err != nil {
		t.Fatal(err)
	}
}

func replTarget(t *testing.T, db *corrosion.Client, key string) string {
	t.Helper()
	rows, err := corrosion.ListBackupSchedules(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.VMName == key {
			return r.TargetHost
		}
	}
	t.Fatalf("no schedule %s", key)
	return ""
}

func TestOwnerAssert_AReclaimSwitchesReplicationOffTheNewOwner(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, _ := ownerAssertFixture(t)
	replScheduleOnto(t, db, "vm1", "", "node-a")
	r.SetPeerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	r.assertRuntimeOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-a" {
		t.Fatal("the premise: node-a must have reclaimed vm1")
	}
	if got := replTarget(t, db, "vm1"); got != "node-b" {
		t.Fatalf("after the reclaim the schedule targets %q, want the host that held the row (node-b)", got)
	}
	if n := auditCount(t, db, "replication.reverse"); n != 1 {
		t.Fatalf("want the switch audited once, got %d", n)
	}
}

func TestCtRekey_AReclaimSwitchesReplicationOffTheNewOwner(t *testing.T) {
	ctx := context.Background()
	c, db, clock, _ := ctRekeyFixture(t)
	key := corrosion.ContainerScheduleKey("_default", "ct1")
	replScheduleOnto(t, db, key, "_default", "node-a")
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	c.assertContainerOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)
	if liveCt(t, db, "node-a", "ct1") == nil {
		t.Fatal("the premise: node-a must have re-keyed ct1")
	}
	if got := replTarget(t, db, key); got != "node-b" {
		t.Fatalf("after the re-key the schedule targets %q, want node-b", got)
	}
}
