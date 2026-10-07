package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 1 of the disk-isolation review: C-1, C-2, I1, I3.

// C-1. A running VM's backup holds raw guest bytes. A guest can make those
// bytes start with a qcow2 header naming a backing file — another project's
// disk. Restored in place as-is, libvirt opens the file as qcow2 and the guest
// reads through the chain it chose. The restored disk must never name a
// backing file.
func TestRestoreInPlace_GuestPlantedQcow2HeaderIsNotABackingChain(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()

	// The guest's raw content: a qcow2 header whose backing file is B's disk.
	crafted := filepath.Join(t.TempDir(), "guest-content")
	if err := qcow2.CreateWithBacking(crafted, f.victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	const ts = "2026-10-06T10:00:00Z"
	specA, _ := json.Marshal(&pb.VMSpec{Name: "web", Project: "a"})
	repo, err := pbsstore.Open(f.s.backupRepos["r"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pbsstore.PushFile(ctx, repo, crafted, pbsstore.PushOptions{
		VMName: "web", DiskName: "root", Timestamp: ts, VMSpecJSON: string(specA),
	}); err != nil {
		t.Fatalf("PushFile: %v", err)
	}

	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	own := disks[0].Path
	_ = f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})

	if info, err := qcow2.Info(own); err == nil && info.BackingFile != "" {
		t.Errorf("the restored disk names backing file %q: the guest chose it", info.BackingFile)
	}
	f.assertVictimIntact(t)
}

// C-2. VM create names a disk "<vm>-<disk>.qcow2". Project A's VM "a" with
// disk "b-root" is the same file as project B's VM "a-b" disk "root". The
// create must be refused and B's disk left as it was.
func TestCreateVM_NeverReplacesAnotherVMsDisk(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	victim := s.images.DiskPath("a-b", "root")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("project-b "), 100)
	if err := os.WriteFile(victim, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "a-b", HostName: "test-host", State: "stopped", Project: "b"},
		nil, []corrosion.DiskRecord{{VMName: "a-b", DiskName: "root", HostName: "test-host", Path: victim, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}

	req := disklessCreateRequest("a")
	req.Spec.Disks = []*pb.DiskSpec{{Name: "b-root", Size: "1M"}}
	_, err := s.CreateVM(ctx, req)
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("create onto another VM's disk file: got %v, want FailedPrecondition", err)
	}
	if got, _ := os.ReadFile(victim); !bytes.Equal(got, want) {
		t.Errorf("project B's disk was replaced (%d bytes)", len(got))
	}
}

// C-2. A clone lands at "<target>-<disk>.qcow2" in <data_dir>/disks the same way.
func TestCloneVM_NeverReplacesAnotherVMsDisk(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	victim := s.images.DiskPath("a-b", "root")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("project-b "), 100)
	if err := os.WriteFile(victim, want, 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "tpl", DiskName: "b-root", HostName: "test-host", Path: src, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"linked", "full"} {
		_, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "a", Mode: mode})
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s clone onto another VM's disk file: got %v, want FailedPrecondition", mode, err)
		}
		if got, _ := os.ReadFile(victim); !bytes.Equal(got, want) {
			t.Fatalf("%s clone replaced project B's disk (%d bytes)", mode, len(got))
		}
	}
}

// I1. An entry node on an older build does not know UploadStoragePoolContent's
// old replica field (5), keeps it as an unknown field and forwards it under
// its own host certificate. The owner must refuse such an upload outright,
// never write a replica record from it.
func TestUpload_ForwardedReplicaFieldIsRefused(t *testing.T) {
	f := newPoolFixture(t)
	rec := &pb.ReplicaRecord{Project: "b", Vm: "web-1", Disk: "root", Schedule: "web-1/dr",
		File: "root-29991231-235959.qcow2", Format: "qcow2", Taken: "29991231-235959"}
	head, err := proto.Marshal(&pb.UploadStoragePoolContentRequest{PoolName: "dr", Filename: rec.File})
	if err != nil {
		t.Fatal(err)
	}
	recBytes, _ := proto.Marshal(rec)
	head = protowire.AppendTag(head, 5, protowire.BytesType)
	head = protowire.AppendBytes(head, recBytes)
	var first pb.UploadStoragePoolContentRequest
	if err := proto.Unmarshal(head, &first); err != nil {
		t.Fatal(err)
	}

	st := &fakeUploadStream{ctx: peerCtxFor(t, f.s, "old-entry"), msgs: []*pb.UploadStoragePoolContentRequest{
		&first, {Chunk: []byte("A's image, as B's newest replica")},
	}}
	if err := f.s.UploadStoragePoolContent(st); status.Code(err) != codes.InvalidArgument {
		t.Errorf("forwarded upload carrying field 5: got %v, want InvalidArgument", err)
	}
	if recs, _ := listReplicaRecords(f.dr, "b", "web-1"); len(recs) != 0 {
		t.Errorf("a replica record was written for project B from an upload: %+v", recs)
	}
	if _, err := os.Lstat(filepath.Join(f.dr, rec.File)); err == nil {
		t.Errorf("the refused upload left %s in the pool", rec.File)
	}
}

// I3. On a shared pool the replica a --no-localize promotion boots from is
// referenced by a disk row of ANOTHER host. Pruning on this host must see it.
func TestPrune_SeesDiskReferencesFromOtherHosts(t *testing.T) {
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
	if err := corrosion.InsertVM(ctx, f.s.db, corrosion.VMRecord{Name: "web-dr", HostName: "other-host", State: "running", Project: "a"}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "1", HostName: "other-host", Path: "/mnt/dr/web-dr.qcow2", BackingDisk: pinnedPath}}); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.pruneRecordedReplicas(ctx, "dr", "a", "web", "1", "web/dr", 1); err != nil || n != 0 {
		t.Errorf("pruned %d (%v), want 0: the replica backs a VM on another host", n, err)
	}
	if _, err := os.Stat(pinnedPath); err != nil {
		t.Errorf("the replica a VM on another host runs from is gone: %v", err)
	}
}

// I3. An in-place restore must not replace a file a disk on another host uses
// (a linked clone's base on shared storage).
func TestRestoreInPlace_SeesDiskReferencesFromOtherHosts(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	own := disks[0].Path
	before, _ := os.ReadFile(own)
	if err := corrosion.InsertVM(ctx, f.s.db, corrosion.VMRecord{Name: "clone", HostName: "other-host", State: "running", Project: "a"}, nil,
		[]corrosion.DiskRecord{{VMName: "clone", DiskName: "root", HostName: "other-host", Path: "/shared/clone-root.qcow2", BackingDisk: own}}); err != nil {
		t.Fatal(err)
	}
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-place restore of a base another host's clone uses: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(own); !bytes.Equal(before, after) {
		t.Error("the shared base was replaced")
	}
}

// I2. A receiver on an older build has no ListReplicas, and its
// PushReplicaIncrement (and upload) would write the bytes as a bare name in
// its pool root, where they are an orphan or, worse, match another project's
// old by-name replica set. The sender proves the receiver records replicas
// before it sends a single byte.
type oldReceiver struct {
	pb.LiteVirtClient
	sent int
}

func (o *oldReceiver) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method ListReplicas")
}
func (o *oldReceiver) PushReplica(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaRequest, pb.PushReplicaResponse], error) {
	return &countingStream[pb.PushReplicaRequest, pb.PushReplicaResponse]{n: &o.sent}, nil
}
func (o *oldReceiver) PushReplicaIncrement(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	return &countingStream[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse]{n: &o.sent}, nil
}
func (o *oldReceiver) UploadStoragePoolContent(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	return &countingStream[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse]{n: &o.sent}, nil
}

type countingStream[Req, Resp any] struct {
	grpc.ClientStream
	n *int
}

func (c *countingStream[Req, Resp]) Send(*Req) error { *c.n++; return nil }
func (c *countingStream[Req, Resp]) CloseAndRecv() (*Resp, error) {
	var r Resp
	return &r, nil
}

func TestReplicationToAnOldReceiverSendsNothing(t *testing.T) {
	f := newPoolFixture(t)
	old := &oldReceiver{}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return old, func() {}, nil
	}
	ctx := context.Background()

	rec := newReplicaRecord("a", "web", "1", "web/dr", "20261010-000000", "raw")
	if err := f.s.applyIncrementRemote(ctx, "old-host", "dr", rec, "", 4,
		bytes.NewReader([]byte("data")), [][2]int64{{0, 4}}); err == nil {
		t.Error("an incremental push to a receiver that cannot record replicas succeeded")
	}
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	if err := f.s.replicateCrossHost(ctx, corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 1,
	}, vm, &disks[0], "old-host", "20261010-000000"); err == nil {
		t.Error("a full replica to a receiver that cannot record replicas succeeded")
	}
	if old.sent != 0 {
		t.Errorf("%d message(s) were sent to a receiver that cannot record replicas; want none", old.sent)
	}
}

// pushAs records content at path as a backup of (web, root) at ts with the
// given content format.
func pushAs(t *testing.T, f *restoreFixture, path, ts, format string) {
	t.Helper()
	repo, err := pbsstore.Open(f.s.backupRepos["r"])
	if err != nil {
		t.Fatal(err)
	}
	specA, _ := json.Marshal(&pb.VMSpec{Name: "web", Project: "a"})
	if _, err := pbsstore.PushFile(context.Background(), repo, path, pbsstore.PushOptions{
		VMName: "web", DiskName: "root", Timestamp: ts, VMSpecJSON: string(specA), ContentFormat: format,
	}); err != nil {
		t.Fatalf("PushFile: %v", err)
	}
}

// C-1, the recorded guest-content case: the same planted header in a backup
// that says it is raw guest content is restored in place as the guest's data
// — inside a fresh qcow2 that names no backing file.
func TestRestoreInPlace_GuestContentIsRebuiltAsAStandaloneImage(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	crafted := filepath.Join(t.TempDir(), "guest-content")
	if err := qcow2.CreateWithBacking(crafted, f.victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(crafted)
	const ts = "2026-10-06T11:00:00Z"
	pushAs(t, f, crafted, ts, pbsstore.ContentGuestRaw)

	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	own := disks[0].Path
	if err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice}); err != nil {
		t.Fatalf("in-place restore of a guest-content backup: %v", err)
	}
	info, err := qcow2.Info(own)
	if err != nil {
		t.Fatalf("the restored disk is not a qcow2: %v", err)
	}
	if info.BackingFile != "" {
		t.Errorf("the restored disk names backing file %q", info.BackingFile)
	}
	if int64(info.VirtualSize) != fi.Size() {
		t.Errorf("restored virtual size %d, want the guest content's %d bytes", info.VirtualSize, fi.Size())
	}
	f.assertVictimIntact(t)
}

// C-1, the disk-file case: a backed-up image file whose backing file is
// outside this host's image store is refused, not followed.
func TestRestoreInPlace_DiskFileBackedOutsideTheImageStoreIsRefused(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	// A real qcow2 outside the image store — another project's disk image —
	// so following the backing file would succeed and read it.
	outside := filepath.Join(t.TempDir(), "other-project.qcow2")
	if err := qcow2.Create(outside, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "disk-file")
	if err := qcow2.CreateWithBacking(file, outside, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	const ts = "2026-10-06T12:00:00Z"
	pushAs(t, f, file, ts, pbsstore.ContentDiskFile)
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	before, _ := os.ReadFile(disks[0].Path)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: ts, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-place restore of a disk file backed outside the image store: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(disks[0].Path); !bytes.Equal(before, after) {
		t.Error("the disk was replaced")
	}
}

// AssertStandalone refuses a backing file and an external data file.
func TestAssertStandalone(t *testing.T) {
	dir := t.TempDir()
	plain, backed := filepath.Join(dir, "plain.qcow2"), filepath.Join(dir, "backed.qcow2")
	if err := qcow2.Create(plain, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(backed, plain, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.AssertStandalone(plain); err != nil {
		t.Errorf("a standalone image was refused: %v", err)
	}
	if err := qcow2.AssertStandalone(backed); err == nil {
		t.Error("an image with a backing file passed")
	}
	// Set the external-data-file incompatible feature bit (bit 2, header byte 79).
	data, _ := os.ReadFile(plain)
	data[79] |= 1 << 2
	ext := filepath.Join(dir, "ext.qcow2")
	if err := os.WriteFile(ext, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.AssertStandalone(ext); err == nil {
		t.Error("an image with an external data file passed")
	}
}

// m9. The replica area is never followed through a symlink: a pool whose
// ".replicas" points elsewhere lists nothing and takes no replica.
func TestReplicaArea_SymlinkIsNeverFollowed(t *testing.T) {
	pool, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(pool, replicaAreaDir)); err != nil {
		t.Fatal(err)
	}
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20261011-000000", "qcow2")
	if _, err := publishRecordedReplica(context.Background(), pool, rec, func(tmp string) error {
		return os.WriteFile(tmp, []byte("x"), 0o600)
	}); err == nil {
		t.Error("a replica was published through a symlinked replica area")
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Errorf("the symlink target received %d entries", len(ents))
	}
	if recs, err := listReplicaRecords(pool, "a", "web"); err == nil || len(recs) != 0 {
		t.Errorf("listing through a symlinked area = %v, %v; want an error and nothing", recs, err)
	}
}

// m4. An in-place restore writes into a pool only through the pool write
// check: a disk recorded in a refused pool (here one aimed at the data dir)
// takes no restore.
func TestRestoreInPlace_RefusedPoolTakesNoRestore(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "legacy", Driver: "dir", Target: f.s.dataDir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	d := disks[0]
	d.StorageVolume, d.StorageType = "legacy", "dir"
	if err := corrosion.UpdateDiskPlacement(ctx, f.s.db, "web", "root", f.s.hostName, d.Path, "dir", "legacy"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(d.Path)
	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-place restore into a refused pool: got %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(d.Path); !bytes.Equal(before, after) {
		t.Error("the disk in a refused pool was replaced")
	}
}
