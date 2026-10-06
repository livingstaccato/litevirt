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

// Fix round 2, restored workflows: in-place restore of backed disks (linked
// clones, --no-localize promotions, disks created from an image) and of
// backups written before content formats were recorded.

// backedVM is a stopped project-A VM whose disk at path is an overlay on
// backing, recorded with rec. Its disk-file backup is pushed at ts.
func backedVM(t *testing.T, f *restoreFixture, name, path string, rec corrosion.DiskRecord) {
	t.Helper()
	spec, _ := json.Marshal(&pb.VMSpec{Name: name, Project: "a"})
	rec.VMName, rec.DiskName, rec.HostName, rec.Path = name, "root", f.s.hostName, path
	if err := corrosion.InsertVM(context.Background(), f.s.db,
		corrosion.VMRecord{Name: name, HostName: f.s.hostName, State: "stopped", Project: "a", Spec: string(spec)},
		nil, []corrosion.DiskRecord{rec}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

func pushVM(t *testing.T, f *restoreFixture, vm, path, ts, format, bitmap string) {
	t.Helper()
	var id *pbsstore.BaseIdentity
	if format == pbsstore.ContentDiskFile {
		id = overlayBaseIdentity(path) // what BackupSnapshot records
	}
	pushVMWithIdentity(t, f, vm, path, ts, format, bitmap, id)
}

// pushVMWithIdentity is pushVM with the manifest's base identity given.
func pushVMWithIdentity(t *testing.T, f *restoreFixture, vm, path, ts, format, bitmap string, id *pbsstore.BaseIdentity) {
	t.Helper()
	repo, err := pbsstore.Open(f.s.backupRepos["r"])
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: vm, Project: "a"})
	opts := pbsstore.PushOptions{
		VMName: vm, DiskName: "root", Timestamp: ts, VMSpecJSON: string(spec), ContentFormat: format, BitmapName: bitmap,
		BaseIdentity: id,
	}
	if _, err := pbsstore.PushFile(context.Background(), repo, path, opts); err != nil {
		t.Fatalf("PushFile: %v", err)
	}
}

// guestView returns what a guest sees on a qcow2 (its raw content).
func guestView(t *testing.T, path string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "view.raw")
	runQemuImg(t, "convert", "-f", "qcow2", "-O", "raw", path, out)
	b, _ := os.ReadFile(out)
	return b
}

// overlayWithData makes an overlay on base (format baseFmt) holding data.
func overlayWithData(t *testing.T, path, base, baseFmt string, data []byte) {
	t.Helper()
	raw := filepath.Join(t.TempDir(), "data.raw")
	if err := os.WriteFile(raw, data, 0o600); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "convert", "-q", "-f", "raw", "-O", "qcow2", "-B", base, "-F", baseFmt, raw, path)
}

func inPlace(f *restoreFixture, vm, ts string) error {
	return f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: vm, DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
}

// requireRestoredOnto checks the restored disk is an overlay naming exactly
// backing, and shows the guest want.
func requireRestoredOnto(t *testing.T, disk, backing string, want []byte) {
	t.Helper()
	info, err := qcow2.Info(disk)
	if err != nil {
		t.Fatalf("restored disk: %v", err)
	}
	rb, _ := filepath.EvalSymlinks(backing)
	if info.BackingFile != rb {
		t.Errorf("restored disk names backing %q, want the disk's own %q", info.BackingFile, rb)
	}
	if err := qcow2.AssertNoExternalData(disk); err != nil {
		t.Error(err)
	}
	if got := guestView(t, disk); !bytes.Equal(got, want) {
		t.Errorf("restored guest content differs (%d vs %d bytes)", len(got), len(want))
	}
}

// A linked clone: its disk is an overlay on another VM's disk (the template's)
// in <data_dir>/disks. In place, the restored image is an overlay on that same
// base, and the guest sees the backed-up content.
func TestRestoreInPlace_LinkedClone(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	disks := filepath.Join(f.s.dataDir, "disks")
	base := filepath.Join(disks, "tpl-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", base, "1M")
	disk := filepath.Join(disks, "lc-root.qcow2")
	templateRow(t, f, "tpl", base)
	content := bytes.Repeat([]byte("linked clone data "), 1<<16/18)
	content = append(content, make([]byte, 1<<20-len(content))...)
	overlayWithData(t, disk, base, "qcow2", content)
	backedVM(t, f, "lc", disk, corrosion.DiskRecord{StorageType: "local", BackingDisk: base})

	const ts = "2026-10-07T10:00:00Z"
	pushVM(t, f, "lc", disk, ts, pbsstore.ContentDiskFile, "")
	// The disk has changed since the backup: it is an empty overlay again.
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", disk)
	if err := inPlace(f, "lc", ts); err != nil {
		t.Fatalf("in-place restore of a linked clone: %v", err)
	}
	requireRestoredOnto(t, disk, base, content)
}

// A --no-localize promotion: the disk is an overlay on a RAW replica in its
// pool's replica area.
func TestRestoreInPlace_NoLocalizePromotedVM(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	pool := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "dr", Driver: "dir", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	rec := newReplicaRecord("a", "pr", "root", "pr/dr", "20261007-000000", "raw")
	replica, err := publishRecordedReplica(ctx, pool, rec, func(tmp string) error {
		return os.WriteFile(tmp, make([]byte, 1<<20), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(pool, "pr-promoted-root-20261007-000000.qcow2")
	content := bytes.Repeat([]byte("promoted "), 1<<20/9)
	content = append(content, make([]byte, 1<<20-len(content))...)
	overlayWithData(t, disk, replica, "raw", content)
	backedVM(t, f, "pr", disk, corrosion.DiskRecord{StorageType: "dir", StorageVolume: "dr", BackingDisk: replica})

	const ts = "2026-10-07T11:00:00Z"
	pushVM(t, f, "pr", disk, ts, pbsstore.ContentDiskFile, "")
	if err := inPlace(f, "pr", ts); err != nil {
		t.Fatalf("in-place restore of a --no-localize promoted VM: %v", err)
	}
	requireRestoredOnto(t, disk, replica, content)
}

// A pool disk created from an image: its header names the image by bare name
// and its record names the image (backing_image); the backing is the image in
// the image store.
func TestRestoreInPlace_PoolDiskFromImage(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	pool := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "dr", Driver: "dir", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(images, "ubuntu.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", img, "1M")
	disk := filepath.Join(pool, "im-root.qcow2")
	content := bytes.Repeat([]byte("from an image "), 1<<20/14)
	content = append(content, make([]byte, 1<<20-len(content))...)
	overlayWithData(t, disk, img, "qcow2", content)
	backedVM(t, f, "im", disk, corrosion.DiskRecord{StorageType: "dir", StorageVolume: "dr", BackingImage: "ubuntu"})

	const ts = "2026-10-07T12:00:00Z"
	pushVM(t, f, "im", disk, ts, pbsstore.ContentDiskFile, "")
	if err := inPlace(f, "im", ts); err != nil {
		t.Fatalf("in-place restore of a pool disk created from an image: %v", err)
	}
	requireRestoredOnto(t, disk, img, content)
}

// The backup's own header never decides the backing: a disk-file whose
// header names another project's disk is re-pointed to the restored disk's
// own base, and nothing of the other disk is read.
func TestRestoreInPlace_BackupHeaderNeverChoosesTheBacking(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	disks := filepath.Join(f.s.dataDir, "disks")
	base := filepath.Join(disks, "tpl-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", base, "1M")
	templateRow(t, f, "tpl", base)
	disk := filepath.Join(disks, "lc-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", disk)
	backedVM(t, f, "lc", disk, corrosion.DiskRecord{StorageType: "local", BackingDisk: base})

	// Another project's disk with content, and a forged container on it.
	other := filepath.Join(t.TempDir(), "other.qcow2")
	secret := bytes.Repeat([]byte("PROJECT-B "), 1<<20/10)
	secret = append(secret, make([]byte, 1<<20-len(secret))...)
	raw := filepath.Join(t.TempDir(), "secret.raw")
	if err := os.WriteFile(raw, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "convert", "-q", "-f", "raw", "-O", "qcow2", raw, other)
	forged := filepath.Join(t.TempDir(), "forged.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", other, "-F", "qcow2", forged)
	const ts = "2026-10-07T13:00:00Z"
	pushVMWithIdentity(t, f, "lc", forged, ts, pbsstore.ContentDiskFile, "", nil)
	if err := inPlace(f, "lc", ts); err != nil {
		t.Fatalf("in-place restore: %v", err)
	}
	if got := guestView(t, disk); bytes.Contains(got, []byte("PROJECT-B")) {
		t.Error("the restored disk reads the other project's data the backup's header named")
	}
	requireRestoredOnto(t, disk, base, make([]byte, 1<<20))

	// qemu-img never even opens what the header names: a header naming a
	// file that does not exist restores just the same.
	ghost := filepath.Join(t.TempDir(), "ghost.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", ghost, "1M")
	forged2 := filepath.Join(t.TempDir(), "forged2.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", ghost, "-F", "qcow2", forged2)
	if err := os.Remove(ghost); err != nil {
		t.Fatal(err)
	}
	const ts2 = "2026-10-07T13:30:00Z"
	pushVMWithIdentity(t, f, "lc", forged2, ts2, pbsstore.ContentDiskFile, "", nil)
	if err := inPlace(f, "lc", ts2); err != nil {
		t.Fatalf("in-place restore of a backup whose header names a missing file: %v", err)
	}
	requireRestoredOnto(t, disk, base, make([]byte, 1<<20))
}

// Backups written before content formats: the format is established from
// what the daemon wrote into the manifest — a guest-content backup always
// carries its checkpoint (BitmapName), a disk-file backup never does — never
// from the bytes. A container archive is refused with a clear message.
func TestRestoreInPlace_LegacyBackupsAreClassifiedFromTheirManifest(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	own := disks[0].Path

	// Legacy guest content: raw bytes, which happen to look like a qcow2
	// header naming B's disk. Read as raw, they are the guest's data.
	crafted := filepath.Join(t.TempDir(), "guest")
	if err := qcow2.CreateWithBacking(crafted, f.victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(crafted)
	b = append(b, make([]byte, (512-len(b)%512)%512)...)
	if err := os.WriteFile(crafted, b, 0o600); err != nil {
		t.Fatal(err)
	}
	const raw = "2026-10-07T14:00:00Z"
	pushVM(t, f, "web", crafted, raw, "", "cp-root-1")
	if err := inPlace(f, "web", raw); err != nil {
		t.Fatalf("legacy guest-content backup: %v", err)
	}
	if err := qcow2.AssertStandalone(own); err != nil {
		t.Errorf("legacy raw backup rebuilt non-standalone: %v", err)
	}
	if got := guestView(t, own); !bytes.Equal(got, b) {
		t.Errorf("legacy raw backup: the guest does not see its own bytes (%d vs %d)", len(got), len(b))
	}

	// Legacy disk file of the (standalone) disk: no checkpoint recorded.
	file := filepath.Join(t.TempDir(), "file.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", file, "1M")
	const df = "2026-10-07T15:00:00Z"
	pushVM(t, f, "web", file, df, "", "")
	if err := inPlace(f, "web", df); err != nil {
		t.Fatalf("legacy disk-file backup: %v", err)
	}

	// A container archive is neither.
	repo, _ := pbsstore.Open(f.s.backupRepos["r"])
	const ct = "2026-10-07T16:00:00Z"
	if _, err := pbsstore.PushFile(context.Background(), repo, file, pbsstore.PushOptions{
		VMName: "web", DiskName: "root", Timestamp: ct, ContainerSpecJSON: `{"name":"web","project":"a"}`,
	}); err != nil {
		t.Fatal(err)
	}
	err := inPlace(f, "web", ct)
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("container archive in place: got %v, want FailedPrecondition", err)
	}
	f.assertVictimIntact(t)
}

// A pool listing shows the caller's own replicas again — from their records,
// with the VM and disk they belong to — and never another project's.
func TestListPoolContents_ShowsOnlyTheCallersReplicas(t *testing.T) {
	f := newPoolFixture(t)
	f.grantPoolWrite(t) // pool read too
	ctx := context.Background()
	mine := seedOwnReplica(t, f, "web", "1")
	theirs := newReplicaRecord("b", "web-1", "root", "web-1/dr", "20261005-000000", "qcow2")
	if _, err := publishRecordedReplica(ctx, f.dr, theirs, func(tmp string) error {
		return os.WriteFile(tmp, []byte("b"), 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := f.s.ListStoragePoolContents(f.alice, &pb.ListStoragePoolContentsRequest{PoolName: "dr"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var sawMine bool
	for _, c := range resp.GetContents() {
		if c.GetReplicaVm() == "web" && c.GetName() == mine && c.GetReplicaDisk() == "1" {
			sawMine = true
		}
		if c.GetReplicaVm() == "web-1" || c.GetName() == theirs.File {
			t.Errorf("project A's listing shows project B's replica %+v", c)
		}
	}
	if !sawMine {
		t.Errorf("project A's listing does not show its own replica %s: %+v", mine, resp.GetContents())
	}
}

// The disk's own backing is accepted only inside the image store or the
// disk's pool directory: a record naming a base elsewhere is refused, not
// followed.
func TestRestoreInPlace_DisksOwnBackingOutsideItsPoolIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", elsewhere, "1M")
	disk := filepath.Join(f.s.dataDir, "disks", "lc-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", elsewhere, "-F", "qcow2", disk)
	backedVM(t, f, "lc", disk, corrosion.DiskRecord{StorageType: "local", BackingDisk: elsewhere})
	const ts = "2026-10-07T17:00:00Z"
	pushVM(t, f, "lc", disk, ts, pbsstore.ContentDiskFile, "")
	before, _ := os.ReadFile(disk)
	if err := inPlace(f, "lc", ts); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-place restore of a disk backed outside its pool: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(disk); !bytes.Equal(before, after) {
		t.Error("the disk was replaced")
	}
}
