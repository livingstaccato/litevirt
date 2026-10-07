package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A restore writes into <data_dir>/disks, the directory that holds the
// pool-less disks of every project on the host. These tests pin that a project
// Operator cannot use a restore to replace another project's disk there: not by
// naming its file as target_path, and not through the live-restore overlay.

const restoreTS = "2026-10-05T10:00:00Z"

// restoreFixture is a host holding project B's VM disk in <data_dir>/disks and
// a backup of project A's own VM in a registered repo named "r".
type restoreFixture struct {
	s       *Server
	victim  string // project B's VM disk file
	alice   context.Context
	content []byte // the victim's bytes before the attack
}

func newRestoreFixture(t *testing.T) *restoreFixture {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}

	// Project B's VM "db", stopped, its root disk a plain file in disks/.
	victim := filepath.Join(disks, "db-root.qcow2")
	content := bytes.Repeat([]byte("project-b-data "), 64)
	if err := os.WriteFile(victim, content, 0o600); err != nil {
		t.Fatal(err)
	}
	specB, _ := json.Marshal(&pb.VMSpec{Name: "db", Project: "b"})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "db", HostName: "host-a", State: "stopped", Project: "b", Spec: string(specB)},
		nil,
		[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: "host-a", Path: victim, SizeBytes: int64(len(content)), StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM db: %v", err)
	}

	// Project A's own VM "web" and a backup of it.
	own := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(own, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	specA, _ := json.Marshal(&pb.VMSpec{Name: "web", Project: "a"})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", HostName: "host-a", State: "stopped", Project: "a", Spec: string(specA)},
		nil,
		[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: "host-a", Path: own, SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM web: %v", err)
	}
	repoDir := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"r": repoDir})
	if err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "web", DiskName: "root", RepoPath: "r", Timestamp: restoreTS,
	}, &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("BackupSnapshot: %v", err)
	}

	alice := grantUser(t, s, "alice", "/projects/a", "Operator")
	return &restoreFixture{s: s, victim: victim, alice: alice, content: content}
}

func (f *restoreFixture) assertVictimIntact(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(f.victim)
	if err != nil {
		t.Fatalf("project B's disk is gone: %v", err)
	}
	if !bytes.Equal(got, f.content) {
		t.Fatalf("project B's disk %s was replaced by a project-A restore (%d bytes, was %d)", f.victim, len(got), len(f.content))
	}
}

// C1, RestoreFromBackup: project A's Operator names project B's disk file as
// the restore target. The restore must be refused and B's disk left as it was.
func TestRestoreFromBackup_ProjectOperatorCannotReplaceAnotherProjectsDisk(t *testing.T) {
	f := newRestoreFixture(t)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS,
		TargetPath: "db-root.qcow2",
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("restore over another project's disk: got %v, want PermissionDenied", err)
	}
	f.assertVictimIntact(t)
}

// C1, RestoreLive: the same attack through the live-restore overlay, which
// would leave B's VM booting a qcow2 backed by A's NBD export.
func TestRestoreLive_ProjectOperatorCannotReplaceAnotherProjectsDisk(t *testing.T) {
	f := newRestoreFixture(t)
	ctx, cancel := context.WithCancel(f.alice)
	cancel() // the handler returns once the overlay is placed instead of serving
	err := f.s.RestoreLive(&pb.RestoreLiveRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS,
		TargetPath: "db-root.qcow2",
	}, &progressStream[pb.RestoreLiveProgress]{ctx: ctx})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("live restore over another project's disk: got %v, want PermissionDenied", err)
	}
	f.assertVictimIntact(t)
}

// Rule 1 binds admins too: an admin may name a target, but an existing file
// there is a refusal, not a replacement.
func TestRestoreFromBackup_AdminTargetNeverReplacesAnExistingFile(t *testing.T) {
	f := newRestoreFixture(t)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS,
		TargetPath: f.victim,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("admin restore onto an existing file: got %v, want AlreadyExists", err)
	}
	f.assertVictimIntact(t)
}

func TestRestoreLive_AdminTargetNeverReplacesAnExistingFile(t *testing.T) {
	f := newRestoreFixture(t)
	ctx, cancel := context.WithCancel(adminCtx())
	cancel()
	err := f.s.RestoreLive(&pb.RestoreLiveRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS,
		TargetPath: f.victim,
	}, &progressStream[pb.RestoreLiveProgress]{ctx: ctx})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("admin live restore onto an existing file: got %v, want AlreadyExists", err)
	}
	f.assertVictimIntact(t)
}

// With no target the daemon writes a fresh file of its own and says where.
func TestRestoreFromBackup_NoTargetWritesAFreshDaemonNamedFile(t *testing.T) {
	f := newRestoreFixture(t)
	st := &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice}
	if err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS,
	}, st); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	last := st.Sent[len(st.Sent)-1]
	if last.Phase != pb.RestoreFromBackupProgress_DONE || last.TargetPath == "" {
		t.Fatalf("DONE frame = %+v, want the written path", last)
	}
	if filepath.Dir(last.TargetPath) != filepath.Join(f.s.dataDir, "disks") || last.TargetPath == f.victim {
		t.Errorf("restored to %q, want a new file in <data_dir>/disks", last.TargetPath)
	}
	if fi, err := os.Stat(last.TargetPath); err != nil || fi.Size() == 0 {
		t.Errorf("restored file %q: %v", last.TargetPath, err)
	}
	f.assertVictimIntact(t)
}

func TestRestoreLive_NoTargetWritesAFreshDaemonNamedOverlay(t *testing.T) {
	f := newRestoreFixture(t)
	ctx, cancel := context.WithCancel(f.alice)
	cancel()
	st := &progressStream[pb.RestoreLiveProgress]{ctx: ctx}
	if err := f.s.RestoreLive(&pb.RestoreLiveRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS,
	}, st); err != nil {
		t.Fatalf("RestoreLive: %v", err)
	}
	var overlay string
	for _, p := range st.Sent {
		if p.Phase == pb.RestoreLiveProgress_READY {
			overlay = p.TargetPath
		}
	}
	if overlay == "" || filepath.Dir(overlay) != filepath.Join(f.s.dataDir, "disks") || overlay == f.victim {
		t.Fatalf("overlay at %q, want a new file in <data_dir>/disks", overlay)
	}
	if _, err := qcow2.Info(overlay); err != nil {
		t.Errorf("overlay %q is not a qcow2: %v", overlay, err)
	}
	f.assertVictimIntact(t)
}

// in_place restores over the caller's own stopped VM disk, the path taken
// from its record.
func TestRestoreFromBackup_InPlaceReplacesOwnStoppedDisk(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New() // no domain defined: nothing can hold the disk open
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	own := disks[0].Path
	if err := os.WriteFile(own, []byte("changed since the backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice}
	if err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, InPlace: true,
	}, st); err != nil {
		t.Fatalf("in-place restore of own stopped VM: %v", err)
	}
	if got := st.Sent[len(st.Sent)-1].TargetPath; got != own {
		t.Errorf("in-place restore wrote %q, want the record's path %q", got, own)
	}
	if _, err := qcow2.Info(own); err != nil {
		t.Errorf("own disk was not restored from the backup: %v", err)
	}
	f.assertVictimIntact(t)
}

// in_place refuses a VM that may hold its disk open.
func TestRestoreFromBackup_InPlaceRefusesARunningVM(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	if err := corrosion.UpdateVMState(ctx, f.s.db, "web", "running", ""); err != nil {
		t.Fatalf("UpdateVMState: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	before, _ := os.ReadFile(disks[0].Path)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-place restore of a running VM: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(disks[0].Path); !bytes.Equal(before, after) {
		t.Error("a running VM's disk was replaced")
	}
}

// in_place never crosses projects: B now owns the name A's backup was taken
// under. Not for an Operator, and not for an admin either.
func TestRestoreFromBackup_InPlaceNeverReplacesAnotherProjectsDisk(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	// A's "web" is gone and B created a VM of the same name whose disk is the victim.
	if err := corrosion.DeleteVM(ctx, f.s.db, "web"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	bWeb := filepath.Join(f.s.dataDir, "disks", "web-root.qcow2")
	if err := os.WriteFile(bWeb, f.content, 0o600); err != nil {
		t.Fatal(err)
	}
	specB, _ := json.Marshal(&pb.VMSpec{Name: "web", Project: "b"})
	if err := corrosion.InsertVM(ctx, f.s.db,
		corrosion.VMRecord{Name: "web", HostName: "host-a", State: "stopped", Project: "b", Spec: string(specB)},
		nil,
		[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: "host-a", Path: bWeb, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.victim = bWeb
	for name, ctx := range map[string]context.Context{"operator": f.alice, "admin": adminCtx()} {
		err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
			RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, InPlace: true,
		}, &progressStream[pb.RestoreFromBackupProgress]{ctx: ctx})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: in-place restore of project A's backup over project B's VM: got %v, want PermissionDenied", name, err)
		}
	}
	f.assertVictimIntact(t)
}

// The placement itself refuses, so a file that appears after the existence
// check is not replaced either.
func TestPlaceNoClobber_RefusesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	tmp, dst := filepath.Join(dir, "tmp"), filepath.Join(dir, "dst")
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := placeNoClobber(tmp, dst); status.Code(err) != codes.AlreadyExists {
		t.Errorf("placeNoClobber over a file: got %v, want AlreadyExists", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "old" {
		t.Errorf("dst = %q, want it untouched", got)
	}
}
