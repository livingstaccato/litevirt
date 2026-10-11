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
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Reverse replication: when a replicated workload ends up running on the host that
// held its replica, the schedule replicates the other way, so the host it left
// becomes the target and the replica again lives on a host the workload is not on.

// drPool creates a file pool "dr" on n and records it in every node's DB.
func drPool(t *testing.T, c *Cluster, n *Node) string {
	t.Helper()
	dir := filepath.Join(c.tmpRoot, n.Name, "data", "pools", "dr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, db := range c.Nodes {
		if err := corrosion.UpsertStoragePool(context.Background(), db.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: "dr", Driver: "local", Target: dir, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func scheduleTarget(t *testing.T, n *Node, key, repo string) string {
	t.Helper()
	rows, err := corrosion.ListBackupSchedules(context.Background(), n.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.VMName == key && r.Repo == repo {
			return r.TargetHost
		}
	}
	t.Fatalf("no schedule %s|%s", key, repo)
	return ""
}

func replicaRecordsIn(t *testing.T, pool, vm string) int {
	t.Helper()
	n := 0
	_ = filepath.WalkDir(filepath.Join(pool, ".replicas"), func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		var rec struct {
			VM string `json:"vm"`
		}
		if data, rerr := os.ReadFile(p); rerr == nil && json.Unmarshal(data, &rec) == nil && rec.VM == vm {
			n++
		}
		return nil
	})
	return n
}

func TestReplicationReverse_APromotedVMReplicatesBackToTheHostItLeft(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	vmHost, replicaHost := c.Nodes[0], c.Nodes[1]
	vmPool, replicaPool := drPool(t, c, vmHost), drPool(t, c, replicaHost)

	src := filepath.Join(c.tmpRoot, vmHost.Name, "web-root-src.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, vmHost.DB, corrosion.VMRecord{
		Name: "web", HostName: vmHost.Name, State: "running", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "web", DiskName: "root", HostName: vmHost.Name, Path: src, SizeBytes: 1 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: replicaHost.Name, KeepReplicas: 2, AutoPromote: true,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, vmHost.DB, sched); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetReplicationCheckpoint(ctx, vmHost.DB, "web", "dr", "cp-of-the-old-direction"); err != nil {
		t.Fatal(err)
	}
	if err := vmHost.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("replicate web to %s: %v", replicaHost.Name, err)
	}
	if replicaRecordsIn(t, replicaPool, "web") != 1 || replicaRecordsIn(t, vmPool, "web") != 0 {
		t.Fatal("the first replica should be on the replica host and nowhere else")
	}

	// The VM's host is lost; the replica host promotes (the operator's promote is
	// the same code path as the coordinator's). The fleet's fake makes no
	// point-in-time copy of a running VM, so the replica is recorded as not
	// point-in-time (fix/point-in-time-replicas) and the promote must accept it,
	// as tests/fleet/pit_replica_test.go does.
	st, err := c.SelfClient(replicaHost).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", TargetHost: replicaHost.Name, Force: true, AcceptNotPointInTime: true,
	})
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
		t.Fatalf("promote: %v", err)
	}

	if got := scheduleTarget(t, replicaHost, "web", "dr"); got != vmHost.Name {
		t.Fatalf("after the promotion the schedule replicates to %q, want back to %q (the host the VM left)", got, vmHost.Name)
	}
	if cp, _ := corrosion.GetReplicationCheckpoint(ctx, replicaHost.DB, "web", "dr"); cp != "" {
		t.Fatalf("the old direction's checkpoint %q survived the reversal", cp)
	}

	// And it works: the next run, from the host the VM is on now, puts a replica on
	// the host it left.
	rows, _ := corrosion.ListBackupSchedules(ctx, replicaHost.DB)
	var flipped corrosion.BackupScheduleRecord
	for _, r := range rows {
		if r.VMName == "web" {
			flipped = r
		}
	}
	if err := replicaHost.Server.RunReplication(ctx, flipped, time.Now()); err != nil {
		t.Fatalf("replicate back to %s: %v", vmHost.Name, err)
	}
	if replicaRecordsIn(t, vmPool, "web") != 1 {
		t.Fatalf("no replica reached %s after the reversal", vmHost.Name)
	}
}

func TestReplicationReverse_ALiveMigrationOntoTheReplicaHostSwitchesThenSwitchesBack(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]
	drPool(t, c, a)
	drPool(t, c, b)
	seedRunningCPUVM(t, c, a, "web", "", "")
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: b.Name, KeepReplicas: 2,
	}
	for _, n := range c.Nodes {
		if err := corrosion.UpsertBackupSchedule(ctx, n.DB, sched); err != nil {
			t.Fatal(err)
		}
	}

	// a -> b: the VM lands on its own replica target.
	if err := migrateAt(t, c, a, "web", b.Name); err != nil {
		t.Fatalf("migrate a->b: %v", err)
	}
	if got := scheduleTarget(t, a, "web", "dr"); got != a.Name {
		t.Fatalf("after a->b the replica belongs on a, schedule says %q", got)
	}

	// Failback b -> a: a is now the replica target, so it flips back to b.
	if err := migrateAt(t, c, b, "web", a.Name); err != nil {
		t.Fatalf("migrate b->a: %v", err)
	}
	if got := scheduleTarget(t, b, "web", "dr"); got != b.Name {
		t.Fatalf("after the failback the replica belongs on b again, schedule says %q", got)
	}
}

// A VM that moves somewhere that is NOT its replica host keeps replicating to it.
func TestReplicationReverse_AMoveElsewhereLeavesTheScheduleAlone(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	defer c.Stop()
	ctx := context.Background()
	a, b, third := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range []*Node{a, b, third} {
		drPool(t, c, n)
	}
	seedRunningCPUVM(t, c, a, "web", "", "")
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: third.Name, KeepReplicas: 2,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, a.DB, sched); err != nil {
		t.Fatal(err)
	}
	if err := migrateAt(t, c, a, "web", b.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := scheduleTarget(t, a, "web", "dr"); got != third.Name {
		t.Fatalf("the VM moved to %s, not its replica host; the schedule must keep targeting %s, got %q", b.Name, third.Name, got)
	}
}

// A cold move of a stopped VM (which is also how a drain moves one) onto its
// replica host switches the direction the same way a live migration does.
func TestReplicationReverse_AColdMoveOntoTheReplicaHostSwitchesIt(t *testing.T) {
	sc := newColdStoppedScenario(t)
	ctx := context.Background()
	drPool(t, sc.c, sc.src)
	drPool(t, sc.c, sc.dst)
	if err := corrosion.UpsertBackupSchedule(ctx, sc.src.DB, corrosion.BackupScheduleRecord{
		VMName: "os1", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: sc.dst.Name, KeepReplicas: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("cold migrate: %v", err)
	}
	if got := scheduleTarget(t, sc.dst, "os1", "dr"); got != sc.src.Name {
		t.Fatalf("after the cold move onto its replica host the schedule targets %q, want the host it left, %q", got, sc.src.Name)
	}
}

// A host failure the coordinator recovers by rescheduling the VM onto a survivor
// that holds one of its replicas switches that schedule back to the lost host
// (I2): it is never left replicating onto the host the VM now runs on.
func TestReplicationReverse_AFailoverRescheduleSwitchesTheScheduleItLandsOn(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, observer := range []string{a.Name, b.Name} {
		if err := a.DB.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`, observer, victim.Name, nowRFC); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "web", HostName: victim.Name, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	// One schedule onto each survivor, each into a pool the victim has too:
	// wherever the VM lands, exactly one of them must switch to the victim.
	for _, n := range []*Node{a, b} {
		pool := "dr-" + n.Name
		for _, h := range []string{n.Name, victim.Name} {
			if err := corrosion.UpsertStoragePool(ctx, a.DB, corrosion.StoragePoolRecord{HostName: h, Name: pool, Driver: "local", Target: "/" + pool, State: "active"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := corrosion.UpsertBackupSchedule(ctx, a.DB, corrosion.BackupScheduleRecord{
			VMName: "web", Scope: "vm", Repo: pool, Cron: "0 * * * *", Enabled: true,
			Type: "replication", TargetPool: pool, TargetHost: n.Name,
		}); err != nil {
			t.Fatal(err)
		}
	}
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.RunOnce(ctx)
	vm, _ := corrosion.GetVM(ctx, a.DB, "web")
	if vm == nil || vm.HostName == victim.Name {
		t.Fatalf("the premise: the VM must have been rescheduled off %s: %+v", victim.Name, vm)
	}
	other := a
	if vm.HostName == a.Name {
		other = b
	}
	if got := scheduleTarget(t, a, "web", "dr-"+vm.HostName); got != victim.Name {
		t.Fatalf("the schedule onto %s (where the VM now runs) targets %q, want the lost host %s", vm.HostName, got, victim.Name)
	}
	if got := scheduleTarget(t, a, "web", "dr-"+other.Name); got != other.Name {
		t.Fatalf("the schedule onto %s was changed: %q", other.Name, got)
	}
}
