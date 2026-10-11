package health

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
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
	rec := corrosion.BackupScheduleRecord{
		VMName: key, Scope: scope, ProjectName: project, Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: target, KeepReplicas: 2,
	}
	var err error
	if scope == "container" {
		// container_replication's data, written with its grant, and the
		// switch goes through a release gate that has passed.
		err = corrosion.UpsertContainerReplicationSchedule(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureContainerReplication), rec)
		db.SetReleaseFeatureGate(func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
			return write(ctx, capabilities.GrantForTest(t, f))
		})
	} else {
		err = corrosion.UpsertBackupSchedule(ctx, db, rec)
	}
	if err != nil {
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

// N1: a re-key is a new placement: once every host applies this build's
// statements, the re-keyed row gets a fresh placement id, so a container that
// is re-keyed back onto a host it ran on never re-enters its old segment there.
func TestCtRekey_MintsANewPlacement(t *testing.T) {
	ctx := context.Background()
	c, db, clock, _ := ctRekeyFixture(t)
	db.SetRepointReady(func(context.Context) bool { return true })
	before := corrosion.PlacementOf(liveCt(t, db, "node-b", "ct1").CreateSpec)
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	c.assertContainerOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)
	got := liveCt(t, db, "node-a", "ct1")
	if got == nil {
		t.Fatal("the premise: node-a must have re-keyed ct1")
	}
	if p := corrosion.PlacementOf(got.CreateSpec); p == "" || p == before {
		t.Fatalf("the re-keyed row's placement is %q (was %q), want a new one", p, before)
	}
	if !strings.Contains(got.CreateSpec, `"image":"alpine"`) {
		t.Fatalf("the rest of the create spec must be kept: %s", got.CreateSpec)
	}
}
