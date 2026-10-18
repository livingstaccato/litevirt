// Fleet scenarios: a replication schedule's replicas, and its checkpoint
// rows, end with the schedule or with the VM.
//
// On 458db618 `lv replication schedule rm` and `lv rm` left every replica
// file on the target host's pool, and every replication_checkpoints row,
// for good: nothing removed them, and no command could.
package fleet

import (
	"context"
	"os"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// replicaFleet is three independent replicas: VM web on node-0, the
// replication target pools dr and dr2 on node-1, and node-2 to enter requests
// on. web has its own schedule into dr, and a cluster-wide schedule
// replicates into dr2; each has a replica of web on node-1 and a checkpoint
// row.
func replicaFleet(t *testing.T) (c *Cluster, ownPath, fanPath string) {
	t.Helper()
	c = New(t, Options{Nodes: 3, IndependentReplicas: true})
	ctx := context.Background()
	src, target := c.Nodes[0], c.Nodes[1]
	seedRunningVM(t, c, src, "web", "", 1, 256)
	poolDir := map[string]string{"dr": t.TempDir(), "dr2": t.TempDir()}
	for name, dir := range poolDir {
		if err := corrosion.UpsertStoragePool(ctx, target.DB, corrosion.StoragePoolRecord{
			HostName: target.Name, Name: name, Driver: "dir", Target: dir, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []corrosion.BackupScheduleRecord{
		{VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: target.Name},
		{VMName: corrosion.ScheduleKey("cluster", "", "", ""), Scope: "cluster", Repo: "dr2", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr2", TargetHost: target.Name},
	} {
		if err := corrosion.UpsertBackupSchedule(ctx, src.DB, s); err != nil {
			t.Fatal(err)
		}
	}
	for _, repo := range []string{"dr", "dr2"} {
		if err := corrosion.SetReplicationCheckpoint(ctx, src.DB, "web", repo, "lvrepl-root-20261018-000000"); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	if ownPath, err = grpcapi.PlaceReplicaForTest(ctx, poolDir["dr"], "", "web", "root", "web/dr", "20261018-000000", []byte("own")); err != nil {
		t.Fatal(err)
	}
	if fanPath, err = grpcapi.PlaceReplicaForTest(ctx, poolDir["dr2"], "", "web", "root", "@cluster/dr2", "20261018-000000", []byte("fan")); err != nil {
		t.Fatal(err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	return c, ownPath, fanPath
}

func liveCheckpoints(t *testing.T, n *Node, vm string) map[string]bool {
	t.Helper()
	rows, err := corrosion.LiveReplicationCheckpoints(context.Background(), n.DB, vm)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[r.Repo] = true
	}
	return out
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// `lv replication schedule rm web --target-pool dr` entered on node-2: the
// target host node-1 removes that schedule's replica once the removal is a
// day old, and only that one; web's checkpoint row for dr is retired at
// once, everywhere, and the cluster schedule's row stays.
//
// Mutation "no replica sweep" (sweepOrphanReplicas removes nothing): the
// replica is still there; red. Mutation "no checkpoint retirement"
// (deleteScheduleRow does not call retireScheduleCheckpoints): the dr row
// stays live; red.
func TestFleet_ReplicationScheduleRemovalCleansItsReplicasAndCheckpoint(t *testing.T) {
	c, ownPath, fanPath := replicaFleet(t)
	ctx := context.Background()
	entry, target := c.Nodes[2], c.Nodes[1]
	if _, err := c.SelfClient(entry).DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{
		VmName: "web", TargetPool: "dr", Scope: "vm",
	}); err != nil {
		t.Fatalf("DeleteReplicationSchedule: %v", err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	for _, n := range c.Nodes {
		if got := liveCheckpoints(t, n, "web"); got["dr"] || !got["dr2"] {
			t.Errorf("live checkpoint rows of web on %s = %v, want dr retired and dr2 kept", n.Name, got)
		}
	}

	if n := target.Server.SweepReplicaOrphansForTest(ctx, time.Now()); n != 0 || !exists(ownPath) {
		t.Fatalf("within the grace the sweep removed %d replica(s) (own replica there: %v), want none", n, exists(ownPath))
	}
	if n := target.Server.SweepReplicaOrphansForTest(ctx, time.Now().Add(corrosion.ScheduleOrphanGrace+time.Hour)); n != 1 {
		t.Errorf("past the grace the sweep removed %d replica(s), want 1", n)
	}
	if exists(ownPath) || exists(ownPath+".json") {
		t.Errorf("the removed schedule's replica %s, or its record, is still there", ownPath)
	}
	if !exists(fanPath) {
		t.Errorf("the cluster schedule's replica %s was removed: it is another schedule's", fanPath)
	}
}

// `lv rm web` entered on node-2: web's own schedule goes with it, every
// checkpoint row of web is retired at once, and once the delete is a day old
// node-1 removes web's replicas of every schedule, the cluster schedule's
// (still live) included.
//
// Mutation "VM gone not judged" (orphanReplica ignores the VM's tombstone):
// the cluster schedule's replica of web stays; red.
func TestFleet_VMDeleteCleansItsReplicasAndCheckpoints(t *testing.T) {
	c, ownPath, fanPath := replicaFleet(t)
	ctx := context.Background()
	entry, src, target := c.Nodes[2], c.Nodes[0], c.Nodes[1]
	if _, err := c.SelfClient(entry).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	if vm, _ := corrosion.GetVM(ctx, src.DB, "web"); vm != nil {
		t.Fatal("web is still live")
	}
	for _, n := range c.Nodes {
		if got := liveCheckpoints(t, n, "web"); len(got) != 0 {
			t.Errorf("live checkpoint rows of the deleted web on %s = %v, want none", n.Name, got)
		}
	}
	if n := target.Server.SweepReplicaOrphansForTest(ctx, time.Now()); n != 0 {
		t.Fatalf("within the grace the sweep removed %d replica(s), want none", n)
	}
	if n := target.Server.SweepReplicaOrphansForTest(ctx, time.Now().Add(corrosion.ScheduleOrphanGrace+time.Hour)); n != 2 {
		t.Errorf("past the grace the sweep removed %d replica(s), want web's 2", n)
	}
	for _, p := range []string{ownPath, fanPath} {
		if exists(p) {
			t.Errorf("the deleted VM's replica %s is still there", p)
		}
	}
}
