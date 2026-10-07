package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Post-breaker fix 3 (diskiso-rereview-7.md).

// A pin that cannot be written never fails the backup: it completes, and the
// operator is warned in its progress, in a VM event and in the log.
func TestBackupSnapshot_AnUnwritablePinWarnsAndBacksUp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through directory permissions")
	}
	s := pruneServer(t)
	ctx := context.Background()
	publishVersion(t, s, "ubuntu", "A ", "")
	disk, err := s.images.CreateOverlayDisk("vm1", "root", "ubuntu", "1M")
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: s.hostName, Path: disk, BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	repoDir := t.TempDir()
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"r": repoDir})
	imgDir := s.images.ImageDir()
	if err := os.Chmod(imgDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(imgDir, 0o755) })

	const ts = "2026-10-07T12:00:00Z"
	st := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	if err := s.BackupSnapshot(&pb.BackupSnapshotRequest{VmName: "vm1", DiskName: "root", RepoPath: "r", Timestamp: ts}, st); err != nil {
		t.Fatalf("the backup failed on a pin it could not write: %v", err)
	}
	repo, err := pbsstore.Open(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetManifest("vm1", ts, "root"); err != nil {
		t.Fatalf("no manifest: %v", err)
	}
	warned := false
	for _, p := range st.Sent {
		if strings.Contains(p.Status, "could not pin") {
			warned = true
		}
	}
	if !warned {
		t.Error("the backup's progress does not warn that its base is unpinned")
	}
	evs, err := corrosion.ListVMEvents(ctx, s.db, "vm1", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "backup.base_unpinned" && e.Result == "warning" {
			found = true
		}
	}
	if !found {
		t.Error("no backup.base_unpinned VM event")
	}
}

// ownLayer's replica guard: project b's recorded replica sits beside project
// a's disk — same owner directory, same stem, no disk row of its own. It does
// not answer to a's record, so the raw file below it that a's record names as
// backing_disk is not reached through it.
func TestDiskChainRule_AnotherProjectsReplicaBesideTheDiskDoesNotInherit(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	pool := t.TempDir()
	registerPool(t, s, "dr", "dir", "", pool, "")
	registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
	x := filepath.Join(pool, "x.raw")
	if err := os.WriteFile(x, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	layerBytes := filepath.Join(t.TempDir(), "l.qcow2")
	if err := qcow2.CreateWithBackingFormat(layerBytes, x, "raw", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(layerBytes)
	layer, err := publishRecordedReplica(ctx, pool, newReplicaRecord("b", "bvm", "root", "bvm/dr", "20261013-000000", "qcow2"),
		func(tmp string) error { return os.WriteFile(tmp, b, 0o600) })
	if err != nil {
		t.Fatal(err)
	}
	if rec, ok := replicaRecordFor(layer); !ok || rec.Project != "b" {
		t.Fatalf("fixture: %s is not project b's recorded replica", layer)
	}
	self := diskStem(layer) + ".snap1"
	if err := qcow2.CreateWithBacking(self, layer, 0, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "av", Cpu: 1, MemoryMib: 256, Project: "a"})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "av", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "av", DiskName: "root", HostName: s.hostName, Path: self, SizeBytes: 1 << 20,
			StorageType: "dir", StorageVolume: "dr", BackingDisk: x}}); err != nil {
		t.Fatal(err)
	}
	err = s.MoveVolume(&pb.MoveVolumeRequest{VmName: "av", DiskName: "root", TargetPool: "fast"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "raw backing") {
		t.Errorf("move: got %v, want FailedPrecondition naming the raw backing", err)
	}
}
