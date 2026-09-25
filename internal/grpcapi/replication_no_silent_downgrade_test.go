package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
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
	if err := os.WriteFile(srcPath, []byte("source image"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
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

// When the safe mechanism fails on a RUNNING source, the run fails. It does not
// quietly produce the unsafe copy instead.
//
// The incremental path exists because a full `qemu-img convert -U` of a running
// disk reads an image the guest still has open with no snapshot: the result is
// smeared across the copy and is not point-in-time. Falling through to it on
// failure means an operator who asked for the safe mechanism silently gets the
// unsafe one — and the replica it produces is then eligible for promotion, so
// the downgrade surfaces as a corrupt guest during a failover.
func TestRunReplication_NoSilentDowngradeOnARunningSource(t *testing.T) {
	s := testServer(t)
	s.SetBackupSource(failingBackupSource{})
	dir := seedReplicationVM(t, s, "web-1", "running")

	err := s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "web-1", Type: "replication", TargetPool: "dr",
		Incremental: true, KeepReplicas: 3,
	}, time.Now())

	if err == nil {
		t.Fatal("RunReplication succeeded; the incremental session failed, so it fell back to the unsafe full copy")
	}
	if !errors.Is(err, errUnsafeFullCopyFallback) {
		t.Errorf("error %v is not errUnsafeFullCopyFallback; the refusal has to be distinguishable from any other failure", err)
	}
	if left := promotableIn(t, dir, "web-1", "root"); len(left) != 0 {
		t.Errorf("a replica was produced anyway: %v", left)
	}
}

// A STOPPED source has no such problem — nothing is writing the image — so the
// full copy is still allowed. Without this, refusing every fallback would pass
// the test above.
func TestRunReplication_AStoppedSourceStillFallsBack(t *testing.T) {
	s := testServer(t)
	s.SetBackupSource(failingBackupSource{})
	dir := seedReplicationVM(t, s, "web-2", "stopped")

	if err := s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "web-2", Type: "replication", TargetPool: "dr",
		Incremental: true, KeepReplicas: 3,
	}, time.Now()); err != nil {
		t.Fatalf("RunReplication on a stopped source: %v", err)
	}
	if left := promotableIn(t, dir, "web-2", "root"); len(left) != 1 {
		t.Errorf("stopped-source fallback produced %v, want one replica", left)
	}
}
