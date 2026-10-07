package grpcapi

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 2 of the disk-isolation review: N-C1, N-I1, N-I3.

func needQemuImg(t *testing.T) {
	t.Helper()
	if !qemuImgAvailable() {
		if os.Getenv("CI") != "" {
			t.Fatal("qemu-img is required in CI")
		}
		t.Skip("qemu-img not installed")
	}
}

func runQemuImg(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("qemu-img", args...).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img %v: %v: %s", args, err, out)
	}
}

// craftedHeader writes, as plain bytes, a qcow2 image whose backing file is
// backing and whose external data file is dataFile — what a guest can write
// to sector 0 of its own disk. Returns the bytes' path.
func craftedHeader(t *testing.T, backing, dataFile string) string {
	t.Helper()
	dir := t.TempDir()
	img := filepath.Join(dir, "crafted.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", backing, "-F", "qcow2",
		"-o", "data_file="+dataFile, img, "1M")
	return img
}

// N-C1. An incremental replica is raw guest content. Promotion's localize
// step converted it without naming a format, so qemu-img probed it, found
// the guest's qcow2 header and read the backing and data files the guest
// named. The promoted disk must hold the replica's raw bytes and name no
// other file.
func TestPromoteLocalize_RawReplicaIsNotProbed(t *testing.T) {
	needQemuImg(t)
	f := newPoolFixture(t)
	ctx := context.Background()

	victim := filepath.Join(t.TempDir(), "victim.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", victim, "1M")
	secret := filepath.Join(t.TempDir(), "secret.bin")
	crafted := craftedHeader(t, victim, secret)
	if err := os.WriteFile(secret, bytes.Repeat([]byte("SECRET!!"), 1<<17), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(crafted)
	if err != nil {
		t.Fatal(err)
	}
	// Guest content is whole sectors.
	raw = append(raw, make([]byte, (512-len(raw)%512)%512)...)

	rec := newReplicaRecord("a", "web", "1", "web/dr", "20261012-000000", "raw")
	if _, err := publishRecordedReplica(ctx, f.dr, rec, func(tmp string) error {
		return os.WriteFile(tmp, raw, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", Replica: rec.File, NewName: "web-dr",
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: f.alice}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web-dr")
	if len(disks) != 1 {
		t.Fatalf("promoted disks = %+v", disks)
	}
	live := disks[0].Path
	info, err := qcow2.Info(live)
	if err != nil {
		t.Fatalf("promoted disk: %v", err)
	}
	if info.BackingFile != "" {
		t.Errorf("the promoted disk names backing file %q", info.BackingFile)
	}
	if int64(info.VirtualSize) != int64(len(raw)) {
		t.Errorf("promoted disk virtual size %d, want the raw replica's %d bytes", info.VirtualSize, len(raw))
	}
	back := filepath.Join(t.TempDir(), "back.raw")
	runQemuImg(t, "convert", "-f", "qcow2", "-O", "raw", live, back)
	got, _ := os.ReadFile(back)
	if !bytes.Equal(got, raw) {
		t.Errorf("the promoted disk does not hold the replica's raw bytes (%d bytes, secret leaked: %v)",
			len(got), bytes.Contains(got, []byte("SECRET!!")))
	}
}

// N-I1. A disk-file backup is a container the daemon wrote, but the bytes come
// from a repository. An input that keeps its data in an external file must be
// refused BEFORE qemu-img opens it: qemu-img copies the data file's contents
// into a perfectly standalone output.
func TestRestoreInPlace_DiskFileWithExternalDataIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.bin")
	img := filepath.Join(dir, "disk-file")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-o", "data_file="+secret, img, "1M")
	if err := os.WriteFile(secret, bytes.Repeat([]byte("SECRET!!"), 1<<17), 0o600); err != nil {
		t.Fatal(err)
	}
	const ts = "2026-10-06T13:00:00Z"
	pushAs(t, f, img, ts, pbsstore.ContentDiskFile)
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	before, _ := os.ReadFile(disks[0].Path)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-place restore of a disk file with an external data file: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(disks[0].Path); !bytes.Equal(before, after) {
		t.Error("the disk was replaced")
	}
}

// N-I1. The image-store check is on the RESOLVED backing path: a symlink in
// the image store pointing outside it is not a base in the store.
func TestRestoreInPlace_DiskFileBackedThroughASymlinkIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	outside := filepath.Join(t.TempDir(), "other-project.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", outside, "1M")
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(images, "base.qcow2")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), "disk-file")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", link, "-F", "qcow2", img)
	const ts = "2026-10-06T14:00:00Z"
	pushAs(t, f, img, ts, pbsstore.ContentDiskFile)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("disk file backed through a symlink out of the image store: got %v, want FailedPrecondition", err)
	}
}

// N-I1. The base image in the store must itself be standalone: one that
// names its own backing file outside is not followed.
func TestRestoreInPlace_DiskFileOnANonStandaloneBaseIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	outside := filepath.Join(t.TempDir(), "other-project.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", outside, "1M")
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(images, "base.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", outside, "-F", "qcow2", base)
	img := filepath.Join(t.TempDir(), "disk-file")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", img)
	const ts = "2026-10-06T15:00:00Z"
	pushAs(t, f, img, ts, pbsstore.ContentDiskFile)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("disk file on a base that is not standalone: got %v, want FailedPrecondition", err)
	}
}

// A backup that is an overlay, of a disk that is now standalone (flattened by
// a move since): the two disagree on whether the disk is backed, so the
// in-place restore refuses and says why — it never takes the base from the
// backup's own header.
func TestRestoreInPlace_DiskFileBackedButTheDiskIsNowStandaloneIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(images, "ubuntu.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", base, "1M")
	img := filepath.Join(t.TempDir(), "disk-file")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", img)
	const ts = "2026-10-06T16:00:00Z"
	pushAs(t, f, img, ts, pbsstore.ContentDiskFile)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "now standalone") {
		t.Errorf("overlay backup of a now-standalone disk: got %v, want FailedPrecondition naming the disagreement", err)
	}
}

// N-I3. One shared pool, mounted at different paths on different hosts: a
// --no-localize promotion on the other host records the replica under ITS
// mount path. This host's prune must still see it.
func TestPrune_SeesReferencesThroughAnotherHostsMountPath(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	pinned := seedOwnReplica(t, f, "web", "1") // 20261003
	newer := newReplicaRecord("a", "web", "1", "web/dr", "20261004-000000", "qcow2")
	if _, err := publishRecordedReplica(ctx, f.dr, newer, func(tmp string) error {
		return os.WriteFile(tmp, []byte("newer"), 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	_, pinnedPath, _ := recordedReplica(f.dr, "a", "web", pinned)
	rel, err := filepath.Rel(f.dr, pinnedPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("rel %q %v", rel, err)
	}
	// The same pool, as the other host has it: mounted at /srv/dr.
	if err := corrosion.UpsertStoragePool(ctx, f.s.db, corrosion.StoragePoolRecord{
		HostName: "other-host", Name: "dr", Driver: "dir", Target: "/srv/dr", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, f.s.db, corrosion.VMRecord{Name: "web-dr", HostName: "other-host", State: "running", Project: "a"}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "1", HostName: "other-host", Path: "/srv/dr/web-dr-promoted.qcow2",
			StorageVolume: "dr", BackingDisk: filepath.Join("/srv/dr", rel)}}); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.pruneRecordedReplicas(ctx, "dr", "a", "web", "1", "web/dr", 1); err != nil || n != 0 {
		t.Errorf("pruned %d (%v), want 0: the replica backs a VM on the other host, at its own mount path", n, err)
	}
	if _, err := os.Stat(pinnedPath); err != nil {
		t.Errorf("the replica the other host's VM runs from is gone: %v", err)
	}
}

// An NFS pool is one pool wherever it is mounted: its identity is the export,
// not this host's mount path or the pool's name on that host.
func TestPoolIdentity_NFSIsTheExport(t *testing.T) {
	x := corrosion.StoragePoolRecord{HostName: "x", Name: "dr", Driver: "nfs", Source: "Filer:/exports/dr/", Target: "/mnt/dr"}
	y := corrosion.StoragePoolRecord{HostName: "y", Name: "backup", Driver: "nfs", Source: "filer:/exports/dr", Target: "/srv/dr"}
	other := corrosion.StoragePoolRecord{HostName: "y", Name: "dr", Driver: "nfs", Source: "filer:/exports/other", Target: "/mnt/dr"}
	if poolIdentity(x) != poolIdentity(y) {
		t.Errorf("one export, two mounts: %q != %q", poolIdentity(x), poolIdentity(y))
	}
	if poolIdentity(x) == poolIdentity(other) {
		t.Errorf("two exports under one name are one pool: %q", poolIdentity(x))
	}
	if !samePoolOnHost([]corrosion.StoragePoolRecord{y}, poolIdentity(x), "/srv/dr") || samePoolOnHost([]corrosion.StoragePoolRecord{y}, poolIdentity(x), "/srv/elsewhere") {
		t.Error("samePoolOnHost does not match the export's mount on the other host exactly")
	}
}

// The receiver is proved BEFORE the full replica's local copy is made: a run
// against a host that cannot say whether it records replicas spends nothing
// on it. The source here cannot even be copied, so a copy-first order fails
// on the copy.
func TestReplicateCrossHost_ProvesTheReceiverBeforeCopying(t *testing.T) {
	f := newPoolFixture(t)
	old := &unsureReceiver{}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return old, func() {}, nil
	}
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	unreadable := &corrosion.DiskRecord{DiskName: "1", Path: filepath.Join(t.TempDir(), "missing.qcow2"), StorageType: "local"}
	err := f.s.replicateCrossHost(ctx, corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 1,
	}, vm, unreadable, "old-host", "20261012-000000")
	if err == nil || !strings.Contains(err.Error(), "records replicas") {
		t.Errorf("replicating to an old receiver: got %v, want the receiver refused before any local copy", err)
	}
}
