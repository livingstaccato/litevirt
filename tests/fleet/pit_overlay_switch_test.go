// Fleet scenario: layer 2 of the point-in-time copy (an external-snapshot
// overlay) is the pit_overlay feature of the release token, behind the real
// release gate on real checkers, latching over real Pings, with the used
// record travelling between independent replicas and acknowledged over the
// real RPC.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// latchPITOverlay wires the daemon's release-feature gate on every node and
// latches the release token, so pit_overlay is available everywhere: the
// upgrade has finished.
func latchPITOverlay(t *testing.T, c *Cluster) {
	t.Helper()
	gates := enforceGate(t, c) // a healthy cluster: the execution gate passes
	wireReleaseFeatures(t, c, gates)
	latchFailoverScope(t, c, gates)
	latchReleaseToken(t, c, gates)
	reseedPeers(context.Background(), c, gates)
}

// reseedPeers marks every node's peers freshly healthy in its checker, after
// one quorum reading has taken in the stall.
func reseedPeers(ctx context.Context, c *Cluster, gates map[string]*health.Checker) {
	for _, n := range c.Nodes {
		gates[n.Name].QuorumProof(ctx)
		peers := map[string]bool{}
		for _, o := range c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
}

// usedFirstSnapshotter is the node's libvirt fake as layer 2 sees it, looking
// at every node's replica at the instant each overlay is made.
type usedFirstSnapshotter struct {
	*libvirtfake.Fake
	nodes     []*Node
	snapshots int
	// writer is the node that makes the overlay.
	writer string
	// lacking names, per snapshot, the nodes whose replica did not hold the
	// pit_overlay used record when the overlay was made — or, on the writer,
	// did not hold it acknowledged (every recipient answered that it holds
	// it; the acknowledged copy reaches them after).
	lacking [][]string
}

func (s *usedFirstSnapshotter) SnapshotDiskExternal(domain, diskPath, overlay string) (bool, error) {
	ctx := context.Background()
	var lacking []string
	for _, n := range s.nodes {
		present, acked, err := corrosion.ReleaseFeatureState(ctx, n.DB, capabilities.ReleaseToken, string(capabilities.FeaturePITOverlay))
		if err != nil || !present || (n.Name == s.writer && !acked) {
			lacking = append(lacking, n.Name)
		}
	}
	s.snapshots++
	s.lacking = append(s.lacking, lacking)
	return s.Fake.SnapshotDiskExternal(domain, diskPath, overlay)
}

func pitUsedAnywhere(t *testing.T, c *Cluster) []string {
	t.Helper()
	var on []string
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeaturePITOverlay)) {
			on = append(on, n.Name)
		}
	}
	return on
}

// replicaMarks is each replica record's not-point-in-time mark in pool dir, by
// file.
func replicaMarks(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	_ = filepath.WalkDir(filepath.Join(dir, ".replicas"), func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || filepath.Ext(p) != ".json" {
			return nil
		}
		data, _ := os.ReadFile(p)
		var rec struct {
			File           string `json:"file"`
			NotPointInTime bool   `json:"not_point_in_time"`
		}
		if json.Unmarshal(data, &rec) == nil && rec.File != "" {
			out[rec.File] = rec.NotPointInTime
		}
		return nil
	})
	return out
}

func countMarks(m map[string]bool) (pit, notPIT int) {
	for _, np := range m {
		if np {
			notPIT++
		} else {
			pit++
		}
	}
	return pit, notPIT
}

// TestFleet_PITOverlay_TheReleaseGateComesFirst walks layer 2 through a
// rolling upgrade:
//
//  1. a host still on the previous build (modelled, as the release-token
//     scenarios do, by one that advertises nothing): the release token
//     cannot latch, the running VM's replica takes main's path (the -U copy,
//     marked), and no overlay is made and NOTHING is recorded on any replica
//     — a rollback below the release stays possible;
//  2. every host upgraded and the token latched, but this copy cannot place
//     an overlay (its pool is a tmpfs): a cheap local refusal, so the gate is
//     never asked and still nothing is recorded;
//  3. the overlay can be placed: the used record is written, acknowledged by
//     every replication recipient over the real RPC, and so on EVERY replica
//     before the first overlay exists; the replica is point-in-time.
//
// Mutations: "gate removed" (the window opened without WithReleaseFeature and
// the writers' Check), "grant before the local refusals" — red.
func TestFleet_PITOverlay_TheReleaseGateComesFirst(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 256})
	// The execution gate passes (the VM's owner may act), as on a healthy
	// cluster: enforceGate seeds each checker's peers.
	gates := enforceGate(t, c)
	wireReleaseFeatures(t, c, gates)
	latchFailoverScope(t, c, gates)
	a, old := c.Nodes[0], c.Nodes[2]

	dr := filepath.Join(c.tmpRoot, a.Name, "data", "dr")
	if err := os.MkdirAll(dr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, a.DB, corrosion.StoragePoolRecord{
		HostName: a.Name, Name: "dr", Driver: "local", Target: dr, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(c.tmpRoot, a.Name, "pit-root.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pit", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "pit", HostName: a.Name, State: "running", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "pit", DiskName: "root", HostName: a.Name, Path: src, SizeBytes: 1 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
	a.Virt.SetState("pit", libvirtfake.StateRunning)
	snap := &usedFirstSnapshotter{Fake: a.Virt, nodes: c.Nodes, writer: a.Name}
	a.Server.SetPointInTimeSnapshotter(snap)
	sched := corrosion.BackupScheduleRecord{
		VMName: "pit", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: a.Name, KeepReplicas: 10,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, a.DB, sched); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-time.Hour)
	run := func(i int) {
		t.Helper()
		if err := a.Server.RunReplication(ctx, sched, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("replication run %d: %v", i, err)
		}
	}

	// 1. Mid-roll.
	old.Server.SetWALQuarantined(func() bool { return true })
	if gates[a.Name].Enforced(ctx, capabilities.ReleaseToken) {
		t.Fatalf("the release token latched across %s", old.Name)
	}
	run(0)
	if snap.snapshots != 0 || pitoverlay.Present(src) {
		t.Fatal("an overlay was made before the release token latched")
	}
	if on := pitUsedAnywhere(t, c); len(on) != 0 {
		t.Fatalf("pit_overlay recorded used on %v before the latch: a rollback would quarantine", on)
	}
	if pit, notPIT := countMarks(replicaMarks(t, dr)); pit != 0 || notPIT != 1 {
		t.Fatalf("replicas: %d point-in-time, %d not; want main's one marked copy", pit, notPIT)
	}

	// 2. Upgraded and latched, but no overlay can be placed here.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	latchReleaseToken(t, c, gates)
	// The latch's wait reads as a stall to each checker's stall guard, which
	// then credits no peer until it is probed again; the fleet's checkers
	// never probe, so seed them afresh, as enforceGate did (the cluster is
	// healthy throughout).
	reseedPeers(ctx, c, gates)
	restoreVolatile := pitoverlay.SetVolatileOKForTest(false)
	restoreFS := pitoverlay.SetDirFSTypeForTest(pitoverlay.FSTmpfs)
	run(1)
	restoreFS()
	restoreVolatile()
	if snap.snapshots != 0 {
		t.Fatal("an overlay was made on a tmpfs")
	}
	if on := pitUsedAnywhere(t, c); len(on) != 0 {
		t.Fatalf("pit_overlay recorded used on %v by a copy that refused locally", on)
	}

	// 3. The first overlay.
	run(2)
	if snap.snapshots != 1 {
		t.Fatalf("snapshots = %d after the latch, want 1", snap.snapshots)
	}
	if len(snap.lacking[0]) != 0 {
		t.Fatalf("the first overlay was made while %v did not hold the used record (the writer: acknowledged)", snap.lacking[0])
	}
	if pitoverlay.Present(src) {
		t.Error("the overlay was not committed back and removed")
	}
	if pit, _ := countMarks(replicaMarks(t, dr)); pit != 1 {
		t.Fatalf("point-in-time replicas = %d after the latch, want 1", pit)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeaturePITOverlay)) {
			t.Errorf("%s does not hold the pit_overlay used record", n.Name)
		}
	}
}

// I1 of the switch review, at recovery level: once pit_overlay is used, a
// VM whose host died is never restarted on a peer whose own Ping says it is
// WAL-quarantined (rolled back below the release, possibly to a build that
// knows nothing of overlays) — even though no HA monitor has recorded it
// isolated yet. The VM is pinned there, so with the peer filtered it stays put
// rather than land on it (without the filter it lands there: the mutation).
//
// Mutation "reported quarantine ignored" (pitOverlaySafeTargets) — red.
func TestFleet_PITOverlay_RecoveryNeverPicksAQuarantinedPeer(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	latchPITOverlay(t, c)
	target, victim, coordNode := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.RecordReleaseFeatureUse(ctx, coordNode.DB, capabilities.ReleaseToken, string(capabilities.FeaturePITOverlay), coordNode.Name, true); err != nil {
		t.Fatalf("record pit_overlay used: %v", err)
	}
	shared := filepath.Join(c.tmpRoot, "nfs")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(shared, "pq-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, coordNode.DB, corrosion.VMRecord{
		Name: "pq", HostName: victim.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"pq","cpu":1,"memory_mib":256,"on_host_failure":"restart-any","placement":{"host":"` + target.Name + `"}}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pq", DiskName: "root", HostName: victim.Name, Path: disk,
		SizeBytes: 1 << 20, StorageType: "nfs", StorageVolume: "nfs", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// The target was rolled back: its Ping reports the quarantine at once.
	target.Server.SetWALQuarantined(func() bool { return true })
	if epoch, _, _ := corrosion.HostIsolation(ctx, coordNode.DB, target.Name); epoch != 0 {
		t.Fatal("setup: the target is already recorded isolated")
	}

	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, o := range []*Node{target, coordNode} {
		if err := coordNode.DB.Execute(ctx, `INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`, o.Name, victim.Name, nowRFC); err != nil {
			t.Fatal(err)
		}
	}
	fc := failover.NewCoordinator(coordNode.Name, coordNode.DB)
	fc.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	// As the daemon wires it: the coordinator's own node's cached Ping.
	fc.PeerRecoveryExclusions = coordNode.Server.PeerRecoveryExclusions
	fc.RunOnce(ctx)

	if vm, _ := corrosion.GetVM(ctx, coordNode.DB, "pq"); vm == nil || vm.HostName == target.Name {
		t.Fatalf("pq after the failover = %+v: restarted on %s, which reports itself WAL-quarantined", vm, target.Name)
	}
}
