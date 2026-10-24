package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// preFixTakeover is a VM db taken over by a --no-localize promotion from the
// replica it returns, whose row records no backing_disk: as every takeover
// before the takeover recorded one wrote it, and as such rows still are after
// an upgrade. The replica's schedule is db/test.
func preFixTakeover(t *testing.T) (s *Server, poolDir, replica string) {
	t.Helper()
	s = testServer(t)
	poolDir = setPromoteVMRows(t, s, "db", nil)
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "dr", Driver: "local", Target: poolDir})
	name := seedReplica(t, poolDir, "", "db", "root", stamp(30*time.Minute), "raw", 1<<20)
	replica = filepath.Join(replicaOwnerDir(poolDir, "", "db"), name)
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true},
		&streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
	root := diskRowsOf(t, s, "db")["root"]
	if info, err := qcow2.Info(root.Path); err != nil || info.BackingFile != replica {
		t.Fatalf("the promoted disk %s does not read the replica %s (info %+v, err %v)", root.Path, replica, info, err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE vm_disks SET backing_disk = NULL WHERE vm_name = 'db'`); err != nil {
		t.Fatal(err)
	}
	return s, poolDir, replica
}

// Review B-1: a replica a running VM reads through its overlay's header is
// never deleted as pool content, whatever the row records — and a header
// that cannot be read keeps it too.
//
// Mutation "rows only" (replicaChainUser not asked by deleteAreaReplica) —
// red: the replica is deleted, the reviewer's probe.
func TestReplicaChainGuard_APoolContentDeleteKeepsAReplicaAHeaderReads(t *testing.T) {
	s, _, replica := preFixTakeover(t)
	del := func() error {
		_, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{
			PoolName: "dr", Filename: filepath.Base(replica), ReplicaVm: "db"})
		return err
	}
	if err := del(); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("delete of the replica the promoted VM reads = %v, want FailedPrecondition", err)
	}
	if !lexists(replica) || !lexists(replica+".json") {
		t.Fatal("the replica the promoted VM reads, or its record, is gone")
	}

	// Its overlay's header cannot be read: kept, not judged unused.
	live := diskRowsOf(t, s, "db")["root"].Path
	if err := os.Chmod(live, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(live, 0o600) })
	if f, err := os.Open(live); err == nil {
		f.Close()
		t.Skip("running with privileges that read a mode-0 file")
	}
	if err := del(); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot tell whether a disk reads") {
		t.Errorf("delete with the overlay's header unreadable = %v, want FailedPrecondition: cannot tell", err)
	}
	if !lexists(replica) {
		t.Error("the replica was deleted while whether a disk reads it could not be told")
	}
}

// Review B-1: neither a schedule's prune nor the orphan sweep removes the
// replica a VM reads through its overlay's header; each still removes one no
// disk reads.
//
// Mutation "rows only" in pruneRecordedReplicas — red on the prune; in
// sweepPoolReplicas — red on the sweep.
func TestReplicaChainGuard_PruneAndSweepKeepAReplicaAHeaderReads(t *testing.T) {
	ctx := context.Background()
	s, poolDir, replica := preFixTakeover(t)
	newer := filepath.Join(replicaOwnerDir(poolDir, "", "db"), seedReplica(t, poolDir, "", "db", "root", stamp(20*time.Minute), "raw", 1<<10))
	newest := filepath.Join(replicaOwnerDir(poolDir, "", "db"), seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<10))

	n, err := s.pruneRecordedReplicas(ctx, "dr", "", "db", "root", "db/test", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !lexists(replica) {
		t.Fatal("the schedule's prune removed the replica the promoted VM reads")
	}
	if n != 1 || lexists(newer) || !lexists(newest) {
		t.Errorf("prune removed %d; newer there=%v newest there=%v; want only the newer, unread one removed", n, lexists(newer), lexists(newest))
	}

	if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{
		VMName: "db", Scope: "vm", Repo: "test", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteBackupSchedule(ctx, s.db, "db", "test"); err != nil {
		t.Fatal(err)
	}
	if got := s.sweepPoolReplicas(ctx, "dr", poolDir, pastGrace); got != 1 {
		t.Errorf("sweep removed %d, want 1 (the newest, which no disk reads)", got)
	}
	if !lexists(replica) {
		t.Error("the orphan sweep removed the replica the promoted VM reads")
	}
	if lexists(newest) {
		t.Error("the orphan sweep kept a replica no disk reads")
	}
}

// Review B-1, the pool's top level: a replica an earlier layout kept there,
// under a VM's overlay in the same directory with no backing recorded, is
// kept by the top-level prune and the pool content delete.
//
// Mutation "rows only" in pruneTopLevelReplicas — red on the prune; in
// DeleteStoragePoolContent's top-level path — red on the delete.
func TestReplicaChainGuard_ATopLevelReplicaAHeaderReadsIsKept(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "dr", Driver: "local", Target: poolDir})
	k := replicaKey{VM: "db", Disk: "root", Project: "_default"}
	var reps []string
	for _, ago := range []time.Duration{30 * time.Minute, 20 * time.Minute, 10 * time.Minute} {
		p := filepath.Join(poolDir, "db-root-"+stampAgo(ago)+".raw")
		if err := os.WriteFile(p, make([]byte, 1<<10), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.recordPoolReplica(ctx, "dr", k, p); err != nil {
			t.Fatal(err)
		}
		reps = append(reps, p)
	}
	read := reps[0]
	live := filepath.Join(poolDir, "db-promoted-"+filepath.Base(read)+".qcow2")
	if err := qcow2.CreateWithBackingFormat(live, read, "raw", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vm_disks SET host_name = ?, path = ?, storage_volume = 'dr', backing_disk = NULL WHERE vm_name = 'db'`,
		s.hostName, live); err != nil {
		t.Fatal(err)
	}

	_, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(read)})
	if status.Code(err) != codes.FailedPrecondition || !lexists(read) {
		t.Errorf("top-level delete of the replica db reads = %v (there=%v), want FailedPrecondition and kept", err, lexists(read))
	}

	if n := s.pruneTopLevelReplicas(ctx, poolDir, k, 1); n != 1 {
		t.Errorf("top-level prune removed %d, want 1 (the middle one)", n)
	}
	if !lexists(read) || lexists(reps[1]) || !lexists(reps[2]) {
		t.Errorf("after the prune: read=%v middle=%v newest=%v; want the read and the newest kept",
			lexists(read), lexists(reps[1]), lexists(reps[2]))
	}
}
