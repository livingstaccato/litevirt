package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Round 9 (restore-pool-rereview-4.md): store identities that move, records
// that survive a copy of the data directory, replicas whose record is cut off
// by a partition, and stores mounted at different paths.

func nfsLine(dir, source string) string {
	return fmt.Sprintf("40 1 0:60 / %s rw,nosuid,nodev,noexec,nosymfollow,relatime - nfs4 %s rw,vers=4.2", dir, source)
}

// NC1: a NAS re-IP done as a rolling remount. h1 moves to the new address
// after h2 had counted both hosts on the old one; h1's replicas made since
// are still matched on h2 — and by record once h2 has moved too.
func TestPoolRound9_ARollingNASReIPKeepsReplicasPromotable(t *testing.T) {
	src := map[string]string{"h1": "10.0.0.5:/vm", "h2": "10.0.0.5:/vm"}
	h1, h2, ms := twoHostsOnMount(t, func(host, dir string) string { return nfsLine(dir, src[host]) },
		map[string]map[string]string{"h1": {"nfs_export": "10.0.0.5:/vm"}, "h2": {"nfs_export": "10.0.0.5:/vm"}})
	ms.as("h2")
	if _, ok := h2.storeRecordsEpoch(context.Background(), sharedStoreOf(ms.dir).ID); !ok {
		t.Fatal("no epoch on the old address")
	}
	src["h1"] = "10.0.0.9:/vm" // h1 remounts on the new address
	ms.as("h1")
	h1.MarkPoolRecords(context.Background())
	time.Sleep(10 * time.Millisecond)
	replicateOnH1(t, h1, ms)
	reps := stampedReplicas(t, ms.dir, "cvm-root")
	if len(reps) != 1 {
		t.Fatalf("cvm's replicas = %v", reps)
	}
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	setFor(t, &poolRecordsEpochNegTTL, 0)
	setFor(t, &poolRecordsEpochTTL, 0)
	ms.as("h2")
	if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); !slices.Equal(got, reps) {
		t.Errorf("mid re-IP, h2 (old address) sees cvm's replicas %v, want h1's %v", got, reps)
	}
	src["h2"] = "10.0.0.9:/vm"
	ms.as("h2")
	h2.MarkPoolRecords(context.Background())
	m, err := h2.loadPoolUploads(context.Background(), ms.dir)
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := h2.poolUploadOf(m, filepath.Join(ms.dir, reps[0])); !ok || u.VM != "cvm" {
		t.Errorf("after the re-IP h2 does not hold h1's record: %+v %v", u, ok)
	}
	if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); !slices.Equal(got, reps) {
		t.Errorf("after the re-IP h2 sees cvm's replicas %v, want %v", got, reps)
	}
}

// NC2: a copy of the data directory and its pools (rsync -a, cp -a, a
// restore), or a remount without stable inode numbers, gives every file a
// new inode. A project still sees and deletes its uploads.
func TestPoolRound9_UploadsStayOwnedAfterACopyOfTheDataDir(t *testing.T) {
	s, disks := disksPoolServer(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", poolRBACPathFor("", "default"))
	if err := uploadAs(pat, s, "default", "pats.qcow2", "x"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(disks, poolUploadsSubdir, "pats.qcow2")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	// What rsync -a does: a new file, the same bytes and times.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	hold := filepath.Join(disks, "hold")
	if err := os.WriteFile(hold, nil, 0o644); err != nil { // keep the old inode number taken
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if got := listNames(t, s, pat, "default"); !slices.Contains(got, "pats.qcow2") {
		t.Errorf("after a copy of the data directory pat's listing %v lacks pat's upload", got)
	}
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "default", Filename: "pats.qcow2"}); err != nil {
		t.Errorf("pat deleting its own upload after the copy: %v", err)
	}
}

// partitionedWriter is twoHostsOnOneExport with cvm's replication on h1 and
// one recorded replica, then h1 cut off: observers last saw it at lastSeen.
func partitionedWriter(t *testing.T, lastSeen time.Time, healthy bool) (h1, h2 *Server, dir string) {
	t.Helper()
	h1, h2, dir = twoHostsOnOneExport(t)
	insertPromotableVM(t, h1, "cvm", "bravo", "h1", "root")
	sched := corrosion.BackupScheduleRecord{
		VMName: "cvm", Scope: "vm", Repo: "shared", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", KeepReplicas: 5,
	}
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, sched); err != nil {
		t.Fatal(err)
	}
	sched.TargetHost = "h1"
	if err := h1.RunReplication(adminCtx(), sched, time.Now().Add(-90*time.Minute)); err != nil {
		t.Fatal(err)
	}
	status := "unhealthy"
	if healthy {
		status = "healthy"
	}
	if err := h1.db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"h2", "h1", status, 5, lastSeen.UTC().Format(time.RFC3339Nano), h1.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostResources(context.Background(), h1.db, "h2", 16, 65536, 1000); err != nil {
		t.Fatal(err)
	}
	if !healthy {
		if err := corrosion.UpdateHostState(context.Background(), h1.db, "h1", "fenced"); err != nil {
			t.Fatal(err)
		}
	}
	return h1, h2, dir
}

// lateReplica writes, as h1 would have during the partition, a newer
// replica whose record never reached h2.
func lateReplica(t *testing.T, dir string, stamp, mtime time.Time) string {
	t.Helper()
	name := "cvm-root-" + stamp.UTC().Format(replicaStampLayout) + ".qcow2"
	p := filepath.Join(dir, name)
	writeQcow2(t, p)
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return name
}

// NI1: h1 kept writing replicas to the NAS while partitioned from the
// majority, and their records never arrived. Failover on h2 promotes the
// newest of them, not the older recorded one, and says so.
func TestPoolRound9_AReplicaWrittenDuringAPartitionIsPromoted(t *testing.T) {
	_, h2, dir := partitionedWriter(t, time.Now().Add(time.Minute), false)
	late := lateReplica(t, dir, time.Now().Add(-5*time.Minute), time.Now())
	if err := h2.AutoPromoteReplica(context.Background(), "cvm", "", 0); err != nil {
		t.Fatalf("failover of cvm on h2: %v", err)
	}
	if !promotedFrom(dir, "cvm", late) {
		t.Errorf("cvm was not promoted from %s, the replica h1 wrote during the partition", late)
	}
	evs, err := corrosion.ListVMEvents(context.Background(), h2.db, "cvm", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(evs, func(e corrosion.VMEventRecord) bool {
		return e.Type == "replica.unrecorded" && strings.Contains(e.Detail, late)
	}) {
		t.Errorf("no event names %s as promoted without its record", late)
	}
}

// NI1, the bounds: a file named like cvm's newest replica is still refused
// when it postdates the moment h1 was last seen, or while h1 is live.
func TestPoolRound9_APlantedFileOutsideThePartitionIsRefused(t *testing.T) {
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	t.Run("after the writer was last seen", func(t *testing.T) {
		_, h2, dir := partitionedWriter(t, time.Now().Add(-time.Hour), false)
		late := lateReplica(t, dir, time.Now().Add(-5*time.Minute), time.Now())
		if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); slices.Contains(got, late) {
			t.Errorf("a file made after h1 was last seen was taken: %v", got)
		}
	})
	t.Run("older than the writer's recorded replicas", func(t *testing.T) {
		_, h2, dir := partitionedWriter(t, time.Now().Add(time.Minute), false)
		late := lateReplica(t, dir, time.Now().Add(-3*time.Hour), time.Now())
		if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); slices.Contains(got, late) {
			t.Errorf("a file stamped before h1's newest recorded replica was taken: %v", got)
		}
	})
	t.Run("writer live", func(t *testing.T) {
		_, h2, dir := partitionedWriter(t, time.Now().Add(time.Minute), true)
		late := lateReplica(t, dir, time.Now().Add(-5*time.Minute), time.Now())
		if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); slices.Contains(got, late) {
			t.Errorf("an unrecorded file was taken while h1 is live: %v", got)
		}
	})
}

// NI2: h2 mounts the store at another path. h1's prune never deletes the
// replica h2's live web-dr uses there.
func TestPoolRound9_PruneKeepsAReplicaUsedUnderAnotherMountPath(t *testing.T) {
	h1, _, dir := twoHostsOnOneExport(t)
	insertPromotableVM(t, h1, "web", "acme", "h1", "root")
	old, newer := "web-root-20261001-120000.qcow2", "web-root-20261002-120000.qcow2"
	for _, n := range []string{old, newer} {
		p := filepath.Join(dir, n)
		writeQcow2(t, p)
		setPast(t, p, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	}
	if err := corrosion.InsertVM(adminCtx(), h1.db, corrosion.VMRecord{Name: "web-dr", Project: "acme", HostName: "h2", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "root", HostName: "h2", Path: "/var/lib/litevirt/promoted/web-dr-root.qcow2",
			BackingImage: "/mnt/nas-b/" + old, StorageType: "local", StorageVolume: "shared"}}); err != nil {
		t.Fatal(err)
	}
	k := replicaKey{VM: "web", Disk: "root", Project: "acme"}
	h1.pruneLocalReplicas(context.Background(), dir, k, 1)
	if _, err := os.Stat(filepath.Join(dir, old)); err != nil {
		t.Errorf("h1's prune removed the replica h2's web-dr is backed by under another mount path: %v", err)
	}
}

// (7): a replicate-volume copy whose record cannot be written is kept, and
// the operator is told so in the final status.
func TestPoolRound9_AnUnrecordedCopyIsReportedInTheStream(t *testing.T) {
	s, own := ownPoolServer(t)
	if err := os.Mkdir(filepath.Join(s.dataDir, "pool-uploads.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "web", DiskName: "root", TargetPool: "pa"}, rec); err != nil {
		t.Fatalf("replicate-volume: %v", err)
	}
	if _, err := os.Stat(filepath.Join(own, "web-root.qcow2")); err != nil {
		t.Errorf("the copy was not kept: %v", err)
	}
	last := rec.Sent[len(rec.Sent)-1]
	if !strings.Contains(last.GetStatus(), "not recorded") {
		t.Errorf("final status %q does not say the copy is not recorded", last.GetStatus())
	}
}

// NC1: a host that moves back to an identity is counted on it only from the
// move back: what it wrote under the other identity meanwhile (recorded
// there, not here) is matched by its name, not refused.
func TestPoolRound9_AHostMovingBackIsCountedFromTheMove(t *testing.T) {
	src := map[string]string{"h1": "10.0.0.5:/vm", "h2": "10.0.0.5:/vm"}
	h1, h2, ms := twoHostsOnMount(t, func(host, dir string) string { return nfsLine(dir, src[host]) },
		map[string]map[string]string{"h1": {"nfs_export": "10.0.0.5:/vm"}, "h2": {"nfs_export": "10.0.0.5:/vm"}})
	setFor(t, &poolRecordsEpochNegTTL, 0)
	setFor(t, &poolRecordsEpochTTL, 0)
	src["h1"] = "10.0.0.9:/vm"
	replicateOnH1(t, h1, ms)
	reps := stampedReplicas(t, ms.dir, "cvm-root")
	time.Sleep(10 * time.Millisecond)
	src["h1"] = "10.0.0.5:/vm" // and back
	ms.as("h1")
	h1.MarkPoolRecords(context.Background())
	ms.as("h2")
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); len(reps) != 1 || !slices.Equal(got, reps) {
		t.Errorf("h2 sees cvm's replicas %v, want %v, written while h1 was away", got, reps)
	}
}
