package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// replicaSweepServer is multiPoolServer with VM web live here and its removed
// schedule web/dr (a tombstone): what lv replication schedule rm leaves.
func replicaSweepServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := multiPoolServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "running", Spec: `{"name":"web"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteBackupSchedule(ctx, s.db, "web", "dr"); err != nil {
		t.Fatal(err)
	}
	dir, err := s.replicaPoolDir(ctx, "dr")
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

var pastGrace = time.Now().Add(corrosion.ScheduleOrphanGrace + time.Hour)

// The sweep removes a removed schedule's replica, and nothing a VM still
// uses or that it cannot attribute: a replica a VM disk references (a
// --no-localize promotion boots from it), a file with no record, and a
// record whose directory is not its VM's.
//
// Mutation "no disk guard" (the sweep skips diskReferencesAnyHost): the
// referenced replica is removed; red. Mutation "no attribution check" (the
// record's name and directory not compared): the misplaced record removes
// db's replica; red.
func TestReplicaSweep_KeepsWhatAVMUsesOrNoRecordNames(t *testing.T) {
	s, dir := replicaSweepServer(t)
	ctx := context.Background()
	orphan, err := PlaceReplicaForTest(ctx, dir, "", "web", "root", "web/dr", "20261018-000000", []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	used, err := PlaceReplicaForTest(ctx, dir, "", "web", "root", "web/dr", "20261018-010000", []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "promoted", HostName: s.hostName, State: "running", Spec: `{"name":"promoted"}`},
		nil, []corrosion.DiskRecord{{VMName: "promoted", DiskName: "root", HostName: s.hostName, StorageType: "dir", StorageVolume: "dr", Path: used}}); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(filepath.Dir(orphan), "root-20261018-020000.qcow2")
	if err := os.WriteFile(stray, []byte("c"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A record copied into another VM's directory: not attributable.
	other, err := PlaceReplicaForTest(ctx, dir, "", "db", "root", "db/dr", "20261018-000000", []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	misplaced := filepath.Join(filepath.Dir(other), "root-20261018-030000.qcow2")
	rec, _ := os.ReadFile(orphan + ".json")
	_ = os.WriteFile(misplaced, []byte("e"), 0o600)
	_ = os.WriteFile(misplaced+".json", []byte(string(rec)), 0o600)

	if n := s.sweepOrphanReplicas(ctx, pastGrace); n != 1 {
		t.Errorf("removed %d, want 1 (the orphan only)", n)
	}
	if lexists(orphan) || lexists(orphan+".json") {
		t.Error("the removed schedule's replica is still there")
	}
	for _, p := range []string{used, used + ".json", stray, other, misplaced} {
		if !lexists(p) {
			t.Errorf("%s was removed", p)
		}
	}
}

// The checkpoint sweep, on the failover lease holder: a row no live schedule
// uses and not written for the grace, and a row of a VM deleted that long
// ago, are retired; a row a live fan-out schedule uses stays, however old.
//
// Mutation "in-use not judged" (the sweep skips checkpointInUse): the
// fan-out's row is retired; red.
func TestCheckpointSweep_RetiresWhatNoScheduleUses(t *testing.T) {
	s, _ := replicaSweepServer(t)
	ctx := context.Background()
	if held, _, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, time.Hour, time.Now()); err != nil || !held {
		t.Fatalf("lease: %v %v", held, err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{
		VMName: corrosion.ScheduleKey("cluster", "", "", ""), Scope: "cluster", Repo: "p1", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "p1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "gone", HostName: s.hostName, State: "stopped", Spec: `{"name":"gone"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range [][2]string{{"web", "dr"}, {"web", "p1"}, {"gone", "p2"}} {
		if err := corrosion.SetReplicationCheckpoint(ctx, s.db, r[0], r[1], "lvrepl-root-20261018-000000"); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.DeleteVM(ctx, s.db, "gone"); err != nil {
		t.Fatal(err)
	}
	s.sweepOrphanCheckpoints(ctx, time.Now())
	if rows, _ := corrosion.LiveReplicationCheckpoints(ctx, s.db, ""); len(rows) != 3 {
		t.Fatalf("within the grace %d rows are live, want all 3", len(rows))
	}
	s.sweepOrphanCheckpoints(ctx, pastGrace)
	rows, _ := corrosion.LiveReplicationCheckpoints(ctx, s.db, "")
	if len(rows) != 1 || rows[0].VMName != "web" || rows[0].Repo != "p1" {
		t.Fatalf("live rows past the grace = %+v, want only web/p1 (the cluster schedule's)", rows)
	}
}

// A vm-scoped replication schedule uses only its own VM's checkpoint, even
// when it carries a pool_name (CreateReplicationSchedule stores the
// request's pool_name whatever the scope); a pool-scoped one uses every VM's.
//
// Mutation: treat a vm-scoped row with a pool_name as a fan-out — red.
func TestCheckpointInUse_VMScopeIgnoresPoolName(t *testing.T) {
	vmRow := corrosion.BackupScheduleRecord{VMName: "vm1", Scope: "vm", PoolName: "fast", Repo: "dr", Type: "replication"}
	if !checkpointInUse([]corrosion.BackupScheduleRecord{vmRow}, "vm1", "dr") {
		t.Fatal("a vm-scoped schedule does not use its own VM's checkpoint")
	}
	if checkpointInUse([]corrosion.BackupScheduleRecord{vmRow}, "vm2", "dr") {
		t.Fatal("a vm-scoped schedule with a pool_name holds another VM's checkpoint")
	}
	poolRow := corrosion.BackupScheduleRecord{VMName: "@pool:fast", Scope: "pool", PoolName: "fast", Repo: "dr", Type: "replication"}
	if !checkpointInUse([]corrosion.BackupScheduleRecord{poolRow}, "vm2", "dr") {
		t.Fatal("a pool-scoped schedule does not hold its VMs' checkpoints")
	}
}
