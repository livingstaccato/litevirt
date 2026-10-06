package grpcapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 3: I-1 (raw-backed VMs move and replicate again), I-2 (the
// restore's backing never comes from a stale record or a guess), I-3 (a
// backed restore needs the base it was taken on; images under a disk cannot be
// replaced).

// promotedVMInPool is project a's VM "pr" whose root disk is a --no-localize
// promotion's overlay on a raw replica in pool "dr" (dir), as the daemon
// records it. The replica's bytes are guest content that parses as a qcow2
// header naming victim.
func promotedVMInPool(t *testing.T, s *Server, victim string) (pool, overlay string, raw []byte) {
	t.Helper()
	pool = t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "dr", Driver: "dir", Target: pool, Project: "", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	overlay, replica, raw := promotedOverRawReplica(t, pool, victim)
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "pr", HostName: s.hostName, State: "stopped", Project: "a", Spec: `{"name":"pr"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "pr", DiskName: "root", HostName: s.hostName, Path: overlay,
			SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr", BackingDisk: replica}}); err != nil {
		t.Fatal(err)
	}
	return pool, overlay, raw
}

// I-1: ReplicateVolume of a --no-localize promoted VM works again, and the
// copy holds the guest's view — the replica read as raw, never parsed.
func TestReplicateVolume_PromotedVMOnARawReplica(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	victim := victimDisk(t)
	_, _, raw := promotedVMInPool(t, s, victim)
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "pr", DiskName: "root", TargetPool: "dr"}, rec); err != nil {
		t.Fatalf("ReplicateVolume of a promoted VM: %v", err)
	}
	got := guestView(t, rec.Sent[len(rec.Sent)-1].TargetPath)
	if bytes.Contains(got, []byte("PROJECT-B")) || !bytes.Equal(got, raw) {
		t.Error("the copy does not hold the guest's view of the promoted disk")
	}
}

// I-1: the offline move of a --no-localize promoted VM works again.
func TestMoveVolume_PromotedVMOnARawReplica(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	victim := victimDisk(t)
	_, _, raw := promotedVMInPool(t, s, victim)
	other := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "fast", Driver: "dir", Target: other, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"fast": {Driver: "dir", Target: other}})
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "pr", DiskName: "root", TargetPool: "fast"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("MoveVolume of a promoted VM: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "pr")
	if got := guestView(t, disks[0].Path); !bytes.Equal(got, raw) {
		t.Error("the moved disk does not hold the guest's view")
	}
	// The moved disk is standalone, so its record no longer names a backing.
	if disks[0].BackingDisk != "" || disks[0].BackingImage != "" {
		t.Errorf("a flattened disk still records backing %q/%q", disks[0].BackingDisk, disks[0].BackingImage)
	}
}

// I-1: a scheduled full replica of a --no-localize promoted VM works again.
func TestRunReplication_PromotedVMOnARawReplica(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	victim := victimDisk(t)
	pool, _, raw := promotedVMInPool(t, s, victim)
	if err := s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "pr", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 2,
	}, time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RunReplication of a promoted VM: %v", err)
	}
	recs, _ := listReplicaRecords(pool, "a", "pr")
	if len(recs) != 1 {
		t.Fatalf("records of pr = %+v", recs)
	}
	path := filepath.Join(replicaOwnerDir(pool, "a", "pr"), recs[0].File)
	if got := guestView(t, path); !bytes.Equal(got, raw) {
		t.Error("the replica does not hold the guest's view")
	}
}

// I-1: a raw backing that is NOT the disk record's own backing_disk is refused.
func TestConvertVMDisk_RefusesARawBackingTheRecordDoesNotName(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	victim := victimDisk(t)
	_, overlay, _ := promotedVMInPool(t, s, victim)
	d := corrosion.DiskRecord{VMName: "pr", DiskName: "root", Path: overlay, StorageVolume: "dr"} // no backing_disk
	err := s.convertVMDisk(context.Background(), &d, filepath.Join(t.TempDir(), "x.qcow2"), func(*pb.MoveVolumeProgress) error { return nil })
	if err == nil {
		t.Error("a raw backing the record does not name was accepted")
	}
}

// I-2: a move flattened the disk, but its record still names the replica it
// was promoted from. The in-place restore of a backup of the (standalone) disk
// stays standalone: it is never rebuilt onto the stale record's base, and the
// replica's bytes are never declared qcow2.
func TestRestoreInPlace_StaleBackingRecordIsNeverUsed(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	victim := victimDisk(t)
	pool := t.TempDir()
	_, replica, _ := promotedOverRawReplica(t, pool, victim)
	disk := filepath.Join(pool, "st-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", disk, "1M") // flattened since
	if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "dr", Driver: "dir", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	backedVM(t, f, "st", disk, corrosion.DiskRecord{StorageType: "dir", StorageVolume: "dr", BackingDisk: replica})
	const ts = "2026-10-08T10:00:00Z"
	pushVM(t, f, "st", disk, ts, pbsstore.ContentDiskFile, "")
	if err := inPlace(f, "st", ts); err != nil {
		t.Fatalf("in-place restore of a standalone backup: %v", err)
	}
	info, err := qcow2.Info(disk)
	if err != nil || info.BackingFile != "" {
		t.Fatalf("the restored disk names backing %q (%q): rebuilt onto a stale record's base", info.BackingFile, info.BackingFormat)
	}
}

// I-2: the record and the disk's own header disagree on the backing: refuse.
func TestRestoreInPlace_RecordDisagreeingWithTheImageIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	disks := filepath.Join(f.s.dataDir, "disks")
	baseA := filepath.Join(disks, "tpla-root.qcow2")
	baseB := filepath.Join(disks, "tplb-root.qcow2")
	for _, b := range []string{baseA, baseB} {
		runQemuImg(t, "create", "-q", "-f", "qcow2", b, "1M")
	}
	templateRow(t, f, "tpla", baseA)
	templateRow(t, f, "tplb", baseB)
	disk := filepath.Join(disks, "lc-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", baseA, "-F", "qcow2", disk)
	backedVM(t, f, "lc", disk, corrosion.DiskRecord{StorageType: "local", BackingDisk: baseB})
	const ts = "2026-10-08T11:00:00Z"
	pushVM(t, f, "lc", disk, ts, pbsstore.ContentDiskFile, "")
	before, _ := os.ReadFile(disk)
	if err := inPlace(f, "lc", ts); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("record and image disagree: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(disk); !bytes.Equal(before, after) {
		t.Error("the disk was replaced")
	}
}

// I-3: the image a disk was created from was replaced (same name, new data)
// after the backup. The backed restore refuses, naming both bases.
func TestRestoreInPlace_ABaseChangedSinceTheBackupIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(images, "ubuntu.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", img, "1M")
	disk := filepath.Join(f.s.dataDir, "disks", "im-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", img, "-F", "qcow2", disk)
	backedVM(t, f, "im", disk, corrosion.DiskRecord{StorageType: "local", BackingImage: "ubuntu"})
	const ts = "2026-10-08T12:00:00Z"
	pushVM(t, f, "im", disk, ts, pbsstore.ContentDiskFile, "")
	// Re-pulled under the same name: different bytes.
	other := filepath.Join(t.TempDir(), "other.raw")
	if err := os.WriteFile(other, bytes.Repeat([]byte("NEW BASE "), 1<<20/9+1)[:1<<20], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(img); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "convert", "-q", "-f", "raw", "-O", "qcow2", other, img)
	before, _ := os.ReadFile(disk)
	if err := inPlace(f, "im", ts); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("backed restore onto a changed base: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(disk); !bytes.Equal(before, after) {
		t.Error("the disk was replaced")
	}
}

// I-3: an image any disk is built on cannot be replaced by an import.
func TestImportImage_NeverReplacesAnImageADiskIsBuiltOn(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	img := s.images.ImagePath("ubuntu")
	if err := qcow2.Create(img, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(img)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "v", HostName: "other-host", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "v", DiskName: "root", HostName: "other-host", Path: "/x/v-root.qcow2", BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	stream := &mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{
		{Name: "ubuntu", Format: "qcow2", Chunk: []byte("replacement")},
	}}
	if err := s.ImportImage(stream); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("import over an image a disk is built on: got %v, want FailedPrecondition", err)
	}
	if got, _ := os.ReadFile(img); !bytes.Equal(got, want) {
		t.Error("the image under a disk was replaced")
	}
}

// I-3: ... nor by a pull.
func TestPullImage_NeverReplacesAnImageADiskIsBuiltOn(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	img := s.images.ImagePath("ubuntu")
	if err := qcow2.Create(img, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(img)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "v", HostName: "other-host", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "v", DiskName: "root", HostName: "other-host", Path: "/x/v-root.qcow2", BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("replacement")) }))
	defer srv.Close()
	err := s.PullImage(&pb.PullImageRequest{Name: "ubuntu", SourceUrl: srv.URL + "/u.qcow2"}, &streamRecorder[pb.PullProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("pull over an image a disk is built on: got %v, want FailedPrecondition", err)
	}
	if got, _ := os.ReadFile(img); !bytes.Equal(got, want) {
		t.Error("the image under a disk was replaced")
	}
}

// templateRow records base as the root disk of a stopped template VM, which
// is what a linked clone's base is.
func templateRow(t *testing.T, f *restoreFixture, name, base string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), f.s.db,
		corrosion.VMRecord{Name: name, HostName: f.s.hostName, State: "stopped", Project: "a", IsTemplate: true}, nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: f.s.hostName, Path: base, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
}

// I-3: a backup that does not record its base's identity (taken before the
// manifest recorded it) is restored onto an image only if the image cannot
// have changed — and an image can, so it is refused, saying why.
func TestRestoreInPlace_UnrecordedImageBaseIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(images, "ubuntu.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", img, "1M")
	disk := filepath.Join(f.s.dataDir, "disks", "im-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", img, "-F", "qcow2", disk)
	backedVM(t, f, "im", disk, corrosion.DiskRecord{StorageType: "local", BackingImage: "ubuntu"})
	const ts = "2026-10-08T13:00:00Z"
	pushVMWithIdentity(t, f, "im", disk, ts, pbsstore.ContentDiskFile, "", nil)
	err := inPlace(f, "im", ts)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not record the identity of its base") {
		t.Errorf("unrecorded image base: got %v, want FailedPrecondition saying the base is unrecorded", err)
	}
}
