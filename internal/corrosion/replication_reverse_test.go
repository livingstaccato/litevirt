package corrosion

import (
	"context"
	"testing"
)

func reverseFixture(t *testing.T) *Client {
	t.Helper()
	db := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"host-a", "host-b", "host-c"} {
		if err := InsertHost(ctx, db, HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := SetHostLabel(ctx, db, h, LabelLXCCapable, "true"); err != nil {
			t.Fatal(err)
		}
		if err := UpsertStoragePool(ctx, db, StoragePoolRecord{HostName: h, Name: "dr", Driver: "local", Target: "/var/lib/dr", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func vmSched(vm, pool, host string) BackupScheduleRecord {
	return BackupScheduleRecord{VMName: vm, Scope: "vm", Repo: pool, Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: pool, TargetHost: host, KeepReplicas: 3, Incremental: true, AutoPromote: true}
}

func schedulesOf(t *testing.T, db *Client) map[string]BackupScheduleRecord {
	t.Helper()
	rows, err := ListBackupSchedules(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]BackupScheduleRecord{}
	for _, r := range rows {
		m[r.VMName+"|"+r.Repo] = r
	}
	return m
}

// A promoted VM runs on its old replica host: the schedule replicates back to the
// host it left, keeping everything else about it, and its checkpoint chain is reset.
func TestReverseReplicationOnMove_PromotedVMReplicatesBackToTheOldSource(t *testing.T) {
	db := reverseFixture(t)
	ctx := context.Background()
	if err := UpsertBackupSchedule(ctx, db, vmSched("web", "dr", "host-b")); err != nil {
		t.Fatal(err)
	}
	if err := SetReplicationCheckpoint(ctx, db, "web", "dr", "cp-old"); err != nil {
		t.Fatal(err)
	}
	revs, err := ReverseReplicationOnMove(ctx, db, "vm", "web", "", "host-a", "host-b")
	if err != nil || len(revs) != 1 || revs[0].Skipped != "" || revs[0].ToHost != "host-a" {
		t.Fatalf("revs=%+v err=%v", revs, err)
	}
	got := schedulesOf(t, db)["web|dr"]
	if got.TargetHost != "host-a" || got.TargetPool != "dr" || got.KeepReplicas != 3 || !got.Incremental || !got.AutoPromote || !got.Enabled {
		t.Fatalf("schedule after reversal = %+v: only the target host may change", got)
	}
	if cp, _ := GetReplicationCheckpoint(ctx, db, "web", "dr"); cp != "" {
		t.Fatalf("the old direction's checkpoint %q must be dropped", cp)
	}
}

// Moving back reverses it again: the direction follows the workload.
func TestReverseReplicationOnMove_FailbackSwitchesItBack(t *testing.T) {
	db := reverseFixture(t)
	ctx := context.Background()
	if err := UpsertBackupSchedule(ctx, db, vmSched("web", "dr", "host-b")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReverseReplicationOnMove(ctx, db, "vm", "web", "", "host-a", "host-b"); err != nil {
		t.Fatal(err)
	}
	// The VM moves back to host-a, which is now its replica target.
	if _, err := ReverseReplicationOnMove(ctx, db, "vm", "web", "", "host-b", "host-a"); err != nil {
		t.Fatal(err)
	}
	if got := schedulesOf(t, db)["web|dr"]; got.TargetHost != "host-b" {
		t.Fatalf("after failback the replica belongs on host-b again, got %q", got.TargetHost)
	}
}

// A schedule that already replicates away from where the workload went is left
// alone, as is one with no explicit target host.
func TestReverseReplicationOnMove_LeavesWhatAlreadyReplicatesAway(t *testing.T) {
	db := reverseFixture(t)
	ctx := context.Background()
	if err := UpsertBackupSchedule(ctx, db, vmSched("elsewhere", "dr", "host-c")); err != nil { // target is neither
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, db, vmSched("auto", "dr", "")); err != nil { // auto-selected peer
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, db, vmSched("web", "dr", "host-a")); err != nil { // the VM moved a->b; replica already on a
		t.Fatal(err)
	}
	for _, vm := range []string{"elsewhere", "auto", "web"} {
		revs, err := ReverseReplicationOnMove(ctx, db, "vm", vm, "", "host-a", "host-b")
		if err != nil || len(revs) != 0 {
			t.Fatalf("%s: revs=%+v err=%v, want nothing to do", vm, revs, err)
		}
	}
	s := schedulesOf(t, db)
	if s["elsewhere|dr"].TargetHost != "host-c" || s["auto|dr"].TargetHost != "" || s["web|dr"].TargetHost != "host-a" {
		t.Fatalf("a schedule was changed that did not need it: %+v", s)
	}
}

// Only the moved workload's own schedule moves: not another VM's, not a container
// of the same name, and not a fan-out schedule shared with other workloads.
func TestReverseReplicationOnMove_OnlyTheWorkloadsOwnSchedule(t *testing.T) {
	db := reverseFixture(t)
	ctx := context.Background()
	for _, r := range []BackupScheduleRecord{
		vmSched("web", "dr", "host-b"),
		vmSched("other", "dr", "host-b"),
		{VMName: ContainerScheduleKey("web"), Scope: "container", ProjectName: "_default", Repo: "dr", Cron: "0 * * * *",
			Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b"},
		{VMName: "@cluster", Scope: "cluster", Repo: "dr", Cron: "0 * * * *", Enabled: true,
			Type: "replication", TargetPool: "dr", TargetHost: "host-b"},
	} {
		if err := UpsertBackupSchedule(ctx, db, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReverseReplicationOnMove(ctx, db, "vm", "web", "", "host-a", "host-b"); err != nil {
		t.Fatal(err)
	}
	s := schedulesOf(t, db)
	if s["web|dr"].TargetHost != "host-a" {
		t.Fatalf("the VM's own schedule did not move: %+v", s["web|dr"])
	}
	for _, k := range []string{"other|dr", "@ct:web|dr", "@cluster|dr"} {
		if s[k].TargetHost != "host-b" {
			t.Errorf("%s was re-pointed by another workload's move: %+v", k, s[k])
		}
	}
}

func TestReverseReplicationOnMove_Container(t *testing.T) {
	db := reverseFixture(t)
	ctx := context.Background()
	ct := BackupScheduleRecord{VMName: ContainerScheduleKey("web"), Scope: "container", ProjectName: "prod", Repo: "dr",
		Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b", KeepReplicas: 2, AutoPromote: true}
	if err := UpsertBackupSchedule(ctx, db, ct); err != nil {
		t.Fatal(err)
	}
	// Another project's same-named container moving does not move this schedule.
	if revs, _ := ReverseReplicationOnMove(ctx, db, "container", "web", "_default", "host-a", "host-b"); len(revs) != 0 {
		t.Fatalf("another project's container reversed this schedule: %+v", revs)
	}
	revs, err := ReverseReplicationOnMove(ctx, db, "container", "web", "prod", "host-a", "host-b")
	if err != nil || len(revs) != 1 || revs[0].Skipped != "" {
		t.Fatalf("revs=%+v err=%v", revs, err)
	}
	if got := schedulesOf(t, db)["@ct:web|dr"]; got.TargetHost != "host-a" || got.KeepReplicas != 2 || !got.AutoPromote {
		t.Fatalf("container schedule after reversal = %+v", got)
	}
}

// When the old host cannot be a target the schedule is left as it was and the
// refusal is reported, never silently dropped.
func TestReverseReplicationOnMove_ReportsWhenTheOldHostCannotBeATarget(t *testing.T) {
	db := reverseFixture(t)
	ctx := context.Background()
	if err := UpsertBackupSchedule(ctx, db, vmSched("web", "dr", "host-b")); err != nil {
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, db, vmSched("lonely", "scratch", "host-b")); err != nil { // pool host-a lacks
		t.Fatal(err)
	}
	if err := UpsertStoragePool(ctx, db, StoragePoolRecord{HostName: "host-b", Name: "scratch", Driver: "local", Target: "/x", State: "active"}); err != nil {
		t.Fatal(err)
	}
	revs, err := ReverseReplicationOnMove(ctx, db, "vm", "lonely", "", "host-a", "host-b")
	if err != nil || len(revs) != 1 || revs[0].Skipped == "" {
		t.Fatalf("a pool the old host lacks must be reported: revs=%+v err=%v", revs, err)
	}
	if got := schedulesOf(t, db)["lonely|scratch"]; got.TargetHost != "host-b" {
		t.Fatalf("a refused reversal must leave the schedule alone: %+v", got)
	}
	// A host that cannot run containers cannot hold a container's replica.
	if err := SetHostLabel(ctx, db, "host-a", LabelLXCCapable, "false"); err != nil {
		t.Fatal(err)
	}
	ct := BackupScheduleRecord{VMName: ContainerScheduleKey("web"), Scope: "container", Repo: "dr", Cron: "0 * * * *",
		Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b"}
	if err := UpsertBackupSchedule(ctx, db, ct); err != nil {
		t.Fatal(err)
	}
	revs, err = ReverseReplicationOnMove(ctx, db, "container", "web", "", "host-a", "host-b")
	if err != nil || len(revs) != 1 || revs[0].Skipped == "" {
		t.Fatalf("revs=%+v err=%v", revs, err)
	}
}

// A VM and a container with the same name replicate into the same repo name
// without colliding under the (vm_name, repo) key, and a previous-release
// scheduler, which looks the key up among VMs, finds no VM of that name.
func TestContainerScheduleKey_DoesNotCollideWithAVMSchedule(t *testing.T) {
	db := reverseFixture(t)
	ctx := context.Background()
	if ScheduleKey("container", "web", "", "") == ScheduleKey("vm", "web", "", "") {
		t.Fatal("a container schedule must be keyed apart from a VM's of the same name")
	}
	if err := UpsertBackupSchedule(ctx, db, vmSched("web", "dr", "host-b")); err != nil {
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, db, BackupScheduleRecord{VMName: ScheduleKey("container", "web", "", ""), Scope: "container",
		Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-c"}); err != nil {
		t.Fatal(err)
	}
	s := schedulesOf(t, db)
	if len(s) != 2 || s["web|dr"].TargetHost != "host-b" || s["@ct:web|dr"].TargetHost != "host-c" {
		t.Fatalf("the two schedules must coexist untouched: %+v", s)
	}
	if n, ok := ContainerScheduleName("@ct:web"); !ok || n != "web" {
		t.Fatalf("name round trip: %q %v", n, ok)
	}
	if _, ok := ContainerScheduleName("web"); ok {
		t.Fatal("a VM key must not read as a container key")
	}
}
