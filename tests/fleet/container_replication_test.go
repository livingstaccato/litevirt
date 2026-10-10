package fleet

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Container replication crosses two daemons: the owner archives and streams the
// replica over peer mTLS into a repo the TARGET resolves, and on host loss the
// failover coordinator restores that replica on the target through the ordinary
// relocation. Each scenario asserts on the target's on-disk rootfs, so a replica
// that carried no bytes cannot pass.

// replCT creates container name on n with a host-failure policy (failover only
// moves a container that has one) and returns the repo path registered as "dr"
// on target.
func replCT(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName: n.Name, Name: name, Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Cpu: 1, MemoryMib: 256, OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("CreateContainer %s on %s: %v", name, n.Name, err)
	}
}

// runningRow marks the container's row running, as a started container's is.
func runningRow(t *testing.T, n *Node, name string) {
	t.Helper()
	row, err := corrosion.GetContainer(context.Background(), n.DB, n.Name, name)
	if err != nil || row == nil {
		t.Fatalf("row: %v", err)
	}
	row.State = "running"
	if err := corrosion.UpsertContainer(context.Background(), n.DB, *row); err != nil {
		t.Fatal(err)
	}
}

func drRepo(t *testing.T, target *Node) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "dr")
	if _, err := pbsstore.Init(root); err != nil {
		t.Fatal(err)
	}
	target.Server.SetBackupRepos(map[string]string{"dr": root})
	return root
}

func ctSchedule(t *testing.T, c *Cluster, owner *Node, name, targetHost string, keep int32, autoPromote bool) corrosion.BackupScheduleRecord {
	t.Helper()
	if _, err := c.SelfClient(owner).CreateReplicationSchedule(context.Background(), &pb.CreateReplicationScheduleRequest{
		VmName: name, Scope: "container", Cron: "0 * * * *", TargetHost: targetHost, TargetPool: "dr",
		KeepReplicas: keep, Enabled: true, AutoPromote: autoPromote,
	}); err != nil {
		t.Fatalf("CreateReplicationSchedule: %v", err)
	}
	rows, err := corrosion.ListBackupSchedules(context.Background(), owner.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Scope == "container" && r.VMName == corrosion.ContainerScheduleKey(name) {
			return r
		}
	}
	t.Fatal("schedule row not stored")
	return corrosion.BackupScheduleRecord{}
}

func replicaEpoch(t *testing.T, m pbsstore.Manifest) int64 {
	t.Helper()
	var spec struct {
		Replica struct {
			Epoch int64 `json:"epoch"`
		} `json:"replica"`
	}
	if err := json.Unmarshal([]byte(m.ContainerSpecJSON), &spec); err != nil {
		t.Fatal(err)
	}
	return spec.Replica.Epoch
}

func replicas(t *testing.T, repo, name string) []pbsstore.Manifest {
	t.Helper()
	r, err := pbsstore.Open(repo)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := r.ManifestsFor(context.Background(), name, "rootfs")
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func TestContainerReplication_RunsStreamToTheTargetAndKeepTheNewest(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, b)
	sched := ctSchedule(t, c, a, name, b.Name, 2, true)
	runningRow(t, a, name) // only a running container is frozen

	base := time.Now().UTC().Add(-3 * time.Minute)
	for i, payload := range []string{"gen1", "gen2", "gen3"} {
		a.CT.Seed(name, payload)
		if err := a.Server.RunReplication(ctx, sched, base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	ms := replicas(t, repo, name)
	if len(ms) != 2 {
		t.Fatalf("keep_replicas=2: the target holds %d replicas, want 2", len(ms))
	}
	for _, m := range ms {
		if m.ContainerSpecJSON == "" {
			t.Fatalf("replica carries no spec: %+v", m)
		}
	}
	if got := a.CT.FreezeCalls(); len(got) == 0 {
		t.Errorf("the container was not frozen for a point-in-time replica")
	}
	// Nothing was written to the source host's repos: the replica is on the target.
	if b.CT.Exists(name) {
		t.Errorf("a replica must not create a running copy on the target")
	}
}

// promoteVia drives the coordinator's restore of name onto target the way
// startRelocation does, with the dead host's row marked relocating.
func promoteVia(t *testing.T, coord, dead, target *Node, name, token string) (corrosion.RestoreOutcome, error) {
	t.Helper()
	ctx := context.Background()
	row, err := corrosion.GetContainer(ctx, dead.DB, dead.Name, name)
	if err != nil || row == nil {
		t.Fatalf("row on %s: %v", dead.Name, err)
	}
	marked := *row
	marked.State, marked.StateDetail = "relocating", corrosion.RelocateRestoreDetail(target.Name, token)
	if err := corrosion.UpsertContainer(ctx, coord.DB, marked); err != nil {
		t.Fatal(err)
	}
	return coord.Server.RestoreContainerFromBackup(ctx, name, target.Name, token)
}

func TestContainerReplication_FailoverRestoresTheNewestReplicaWhereItIs(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	dead, target, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, dead, name)
	drRepo(t, target)
	sched := ctSchedule(t, c, dead, name, target.Name, 3, true)
	now := time.Now().UTC()
	dead.CT.Seed(name, "old-state")
	if err := dead.Server.RunReplication(ctx, sched, now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	dead.CT.Seed(name, "newest-state")
	if err := dead.Server.RunReplication(ctx, sched, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The coordinator has no backup repo at all: the replica on the target is the
	// only thing it can restore from.
	outcome, err := promoteVia(t, coord, dead, target, name, "tok-1")
	if err != nil || outcome != corrosion.RestoreLanded {
		t.Fatalf("promotion: (%v, %v)", outcome, err)
	}
	if got := target.CT.Payload(name); got != "newest-state" {
		t.Fatalf("target payload = %q, want the newest replica's bytes", got)
	}
	moved, err := corrosion.GetContainer(ctx, target.DB, target.Name, name)
	if err != nil || moved == nil || moved.RelocateToken != "tok-1" {
		t.Fatalf("the restored row must carry the relocation token (provenance): %+v err=%v", moved, err)
	}
}

func TestContainerReplication_AReplicaIsNotPromotedUnlessTheScheduleAllowsIt(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	dead, target, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, dead, name)
	drRepo(t, target)
	sched := ctSchedule(t, c, dead, name, target.Name, 3, false) // auto_promote off
	dead.CT.Seed(name, "state")
	if err := dead.Server.RunReplication(ctx, sched, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if outcome, err := promoteVia(t, coord, dead, target, name, "tok-2"); err == nil || outcome == corrosion.RestoreLanded {
		t.Fatalf("a schedule without auto_promote must not be promoted by failover: (%v, %v)", outcome, err)
	}
	if target.CT.Exists(name) {
		t.Fatal("the container was restored onto the target anyway")
	}
}

func TestContainerReplication_ATooOldReplicaIsNotPromotedAutomatically(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	dead, target, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, dead, name)
	drRepo(t, target)
	sched := ctSchedule(t, c, dead, name, target.Name, 3, true) // hourly: the bound is about 3h
	dead.CT.Seed(name, "ancient")
	if err := dead.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-100*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if outcome, err := promoteVia(t, coord, dead, target, name, "tok-3"); err == nil || outcome == corrosion.RestoreLanded {
		t.Fatalf("a replica far past the schedule's age bound must not be promoted automatically: (%v, %v)", outcome, err)
	}
}

// A replica of an earlier ownership generation arriving after a newer one is
// refused at the target: the newer copy is never replaced by an older one, whatever
// the timestamps say.
func TestContainerReplication_AnOlderGenerationNeverReplacesANewerReplica(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, b)
	sched := ctSchedule(t, c, a, name, b.Name, 3, true)
	setEpoch := func(e int) {
		if err := a.DB.Execute(ctx, `UPDATE containers SET owner_epoch = ? WHERE host_name = ? AND name = ?`, e, a.Name, name); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	setEpoch(5)
	a.CT.Seed(name, "epoch5")
	if err := a.Server.RunReplication(ctx, sched, now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The same container, an earlier generation, a LATER wall-clock stamp.
	setEpoch(4)
	a.CT.Seed(name, "epoch4")
	if err := a.Server.RunReplication(ctx, sched, now.Add(-time.Minute)); err == nil {
		t.Fatal("a replica of an earlier ownership generation must be refused by the target")
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("the target holds %d replicas, want only the epoch-5 one", len(ms))
	}
	// And a later generation supersedes the earlier one.
	setEpoch(6)
	a.CT.Seed(name, "epoch6")
	if err := a.Server.RunReplication(ctx, sched, now); err != nil {
		t.Fatal(err)
	}
	// The earlier generation's replica is superseded and goes, keep_replicas or not.
	if ms = replicas(t, repo, name); len(ms) != 1 || replicaEpoch(t, ms[0]) != 6 {
		t.Fatalf("the epoch-6 replica must replace the epoch-5 one, got %d replica(s)", len(ms))
	}
}

// End to end: the host holding the container is fenced, and the coordinator
// brings it up on the host that holds its replica, from the replica's bytes,
// rather than wherever placement alone would have put it.
func TestContainerReplication_FencedHostsContainerComesUpOnTheReplicaHost(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	victim, coordNode, replicaHost := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, victim, name)
	drRepo(t, replicaHost)
	sched := ctSchedule(t, c, victim, name, replicaHost.Name, 2, true)
	victim.CT.Seed(name, "replicated-state")
	if err := victim.Server.RunReplication(ctx, sched, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	runningRow(t, victim, name) // a container that is not running is not a failover candidate
	// Make the replica host the LESS attractive candidate, so only the replica
	// preference can explain the container landing there.
	if err := corrosion.UpsertContainer(ctx, replicaHost.DB, corrosion.ContainerRecord{
		HostName: replicaHost.Name, Name: "ballast", Image: "docker.io/library/alpine:3.19", State: "running",
		OnHostFailure: "none", MemMiB: 1024,
	}); err != nil {
		t.Fatal(err)
	}

	// Relocation by restore needs a survivor at this build's schema.
	if err := coordNode.DB.Execute(ctx, `UPDATE hosts SET schema_version = ?`, corrosion.CurrentSchemaVersion); err != nil {
		t.Fatal(err)
	}
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, o := range []*Node{coordNode, replicaHost} {
		if err := coordNode.DB.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`, o.Name, victim.Name, nowRFC); err != nil {
			t.Fatal(err)
		}
	}
	coord := failover.NewCoordinator(coordNode.Name, coordNode.DB)
	coord.Restorer = coordNode.Server
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.RunOnce(ctx)

	host, rec := findContainer(t, c, name)
	if rec == nil || host != replicaHost.Name {
		t.Fatalf("container is on %q (row %+v), want the replica host %q", host, rec, replicaHost.Name)
	}
	if got := replicaHost.CT.Payload(name); got != "replicated-state" {
		t.Fatalf("replica host payload = %q, want the replica's bytes (a recreate would be empty)", got)
	}
}
