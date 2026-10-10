package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// failingBackupSource refuses to open a backup session, which is how the
// incremental path fails in the field: old libvirt, a lost bitmap, a stopped
// domain.
type failingBackupSource struct{}

func (failingBackupSource) BeginBackup(string, string, string, string) (BackupReader, error) {
	return nil, errors.New("cannot open backup session")
}
func (failingBackupSource) GCCheckpoints(string, string, []string) error { return nil }
func (failingBackupSource) DeleteCheckpoint(string, string) error        { return nil }

var _ BackupSource = failingBackupSource{}

// seedReplicationVM puts a VM, its root disk and a target pool in the store and
// returns the pool directory.
func seedReplicationVM(t *testing.T, s *Server, vmName, state string) string {
	t.Helper()
	ctx := context.Background()
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "root.qcow2")
	// A real qcow2: a VM disk is one, and the copy names -f qcow2.
	if err := qcow2.Create(srcPath, 1<<20, nil); err != nil {
		t.Fatalf("create source: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: vmName, HostName: s.hostName, State: state, Spec: `{}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: vmName, HostName: s.hostName, DiskName: "root", Path: srcPath, StorageType: "dir",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return replicaPoolDir(t, s, "dr")
}

// When the safe mechanism fails on a RUNNING source, the run does not quietly
// produce the unsafe copy instead.
//
// A full `qemu-img convert -U` of a running disk reads an image the guest
// still has open with no snapshot: the result is smeared across the copy and is
// not point-in-time. The full copy that follows a failed incremental is now
// copyVMDiskConsistent's (pit_copy.go): a backup session or an external
// snapshot. Only when neither can be made — as here, with no session and no
// snapshotter — is it main's -U copy, and then never silently: the replica's
// record says it is not point-in-time (so promotion treats it as the last
// choice) and an event says why. Nothing main produced is refused
// (owner decision D2).
func TestRunReplication_NoSilentDowngradeOnARunningSource(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.SetBackupSource(failingBackupSource{})
	dir := seedReplicationVM(t, s, "web-1", "running")

	err := s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "web-1", Type: "replication", TargetPool: "dr",
		Incremental: true, KeepReplicas: 3,
	}, time.Now())
	if err != nil {
		t.Fatalf("RunReplication refused the copy main made: %v", err)
	}
	recs, lerr := listReplicaRecords(dir, "", "web-1")
	if lerr != nil || len(recs) != 1 || !recs[0].NotPointInTime {
		t.Fatalf("records %+v (%v): the -U copy must be recorded as not point-in-time", recs, lerr)
	}
	if !slices.Contains(pitEventTypes(t, s, "web-1"), "disk.replica_not_point_in_time") {
		t.Errorf("the downgrade was silent: events %v", pitEventTypes(t, s, "web-1"))
	}
}

// A STOPPED source has no such problem — nothing is writing the image — so the
// full copy is still allowed. Without this, refusing every fallback would pass
// the test above.
func TestRunReplication_AStoppedSourceStillFallsBack(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir() // where the replica's record is written
	s.SetBackupSource(failingBackupSource{})
	dir := seedReplicationVM(t, s, "web-2", "stopped")
	fake := libvirtfake.New()
	fake.SetState("web-2", libvirtfake.StateShutdown)
	s.virt = fake

	if err := s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "web-2", Type: "replication", TargetPool: "dr",
		Incremental: true, KeepReplicas: 3,
	}, time.Now()); err != nil {
		t.Fatalf("RunReplication on a stopped source: %v", err)
	}
	if left := promotableIn(t, dir, "web-2", "root"); len(left) != 1 {
		t.Errorf("stopped-source fallback produced %v, want one replica", left)
	}
	if recs, _ := listReplicaRecords(dir, "", "web-2"); len(recs) != 1 || recs[0].NotPointInTime {
		t.Errorf("records %+v: a shut-off source's plain copy is point-in-time", recs)
	}
}

// "stopped" in the store is not "shut off". The coarse libvirt state folds
// paused and pm-suspended domains into "stopped", and qemu still holds their
// images open: resuming the guest mid-copy smears a plain copy exactly as a
// running source does. So the plain copy asks libvirt for the state REASON and
// runs only for a genuine shut-off; a paused source takes the point-in-time
// layers, and here, where none is available, a copy marked not point-in-time.
func TestRunReplication_APausedSourceDoesNotFallBack(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.SetBackupSource(failingBackupSource{})
	dir := seedReplicationVM(t, s, "web-3", "stopped")
	fake := libvirtfake.New()
	fake.SetState("web-3", libvirtfake.StatePaused)
	s.virt = fake

	if err := s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "web-3", Type: "replication", TargetPool: "dr",
		Incremental: true, KeepReplicas: 3,
	}, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	recs, err := listReplicaRecords(dir, "", "web-3")
	if err != nil || len(recs) != 1 || !recs[0].NotPointInTime {
		t.Fatalf("records %+v (%v): a paused source's plain copy is not point-in-time and must be marked", recs, err)
	}
}
