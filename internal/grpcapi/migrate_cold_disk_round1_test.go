package grpcapi

// Review round 1 of the stopped-VM cold migration: a target too old to take
// it, free space on both ends, the size a target accepts, a placement that
// cannot overwrite, the disk format taken from the domain definition, and the
// scratch files a crash leaves.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// oldTargetPeer is a target built before stopped-VM cold migration: it has no
// ReceiveMigrationDisk, and its EnsureFirmwareState requires a bundle.
type oldTargetPeer struct {
	pb.LiteVirtClient
	ensureCalls int
}

type unimplementedDiskUp struct{ grpc.ClientStream }

func (unimplementedDiskUp) Send(*pb.ReceiveMigrationDiskRequest) error { return io.EOF }
func (unimplementedDiskUp) CloseAndRecv() (*pb.ReceiveMigrationDiskResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method ReceiveMigrationDisk for service litevirt.v1.LiteVirt")
}

func (p *oldTargetPeer) ReceiveMigrationDisk(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ReceiveMigrationDiskRequest, pb.ReceiveMigrationDiskResponse], error) {
	return unimplementedDiskUp{}, nil
}

func (p *oldTargetPeer) EnsureFirmwareState(_ context.Context, req *pb.EnsureFirmwareStateRequest, _ ...grpc.CallOption) (*pb.EnsureFirmwareStateResponse, error) {
	p.ensureCalls++
	if len(req.Bundle) == 0 {
		// The old build's first check, verbatim.
		return nil, status.Error(codes.InvalidArgument, "vm_name and a non-empty firmware bundle are required")
	}
	return &pb.EnsureFirmwareStateResponse{}, nil
}

func (p *oldTargetPeer) RollbackFirmwareState(context.Context, *pb.RollbackFirmwareStateRequest, ...grpc.CallOption) (*pb.RollbackFirmwareStateResponse, error) {
	return &pb.RollbackFirmwareStateResponse{}, nil
}

// oldTargetSource is a source holding stopped VM os1 with one disk of the
// given storage type, whose peer is an old target.
func oldTargetSource(t *testing.T, storageType string) (*Server, *libvirtfake.Fake, *oldTargetPeer, string) {
	t.Helper()
	ctx := adminCtx()
	s := testServerWithLocks(t)
	s.hostName = "src-host"
	s.SetHostDiskRootForTest(t.TempDir())
	fake := libvirtfake.New()
	s.virt = fake
	p := "/var/lib/litevirt/disks/os1-root.qcow2"
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "os1", HostName: s.hostName, Spec: `{"name":"os1"}`, State: "stopped",
	}, nil, []corrosion.DiskRecord{
		{VMName: "os1", DiskName: "root", HostName: s.hostName, Path: p, StorageType: storageType, SizeBytes: 4096},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>os1</name><devices><disk type='file' device='disk'>` +
		`<driver name='qemu' type='raw'/><source file='` + p + `'/><target dev='vda'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	sp := s.hostDiskFile(p)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, []byte("source disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	peer := &oldTargetPeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	return s, fake, peer, p
}

func assertSourceUntouched(t *testing.T, s *Server, fake *libvirtfake.Fake, p string) {
	t.Helper()
	vm, _ := corrosion.GetVM(adminCtx(), s.db, "os1")
	if vm == nil || vm.HostName != s.hostName || vm.State != "stopped" {
		t.Errorf("VM row after the refusal = %+v, want it on %s, stopped", vm, s.hostName)
	}
	if !fake.DomainExists("os1") {
		t.Error("the source domain was removed by a refused migration")
	}
	if got, err := os.ReadFile(s.hostDiskFile(p)); err != nil || string(got) != "source disk" {
		t.Errorf("source disk after the refusal = %q, %v", got, err)
	}
}

func coldMove(s *Server, ctx context.Context) error {
	vm, _ := corrosion.GetVM(ctx, s.db, "os1")
	return s.coldMigrateStoppedVM(ctx, vm, &corrosion.HostRecord{Name: "old-target"}, firmwareSpec{},
		&migrationAbort{armed: true}, func(pb.MigratePhase, float32, float32) error { return nil })
}

// A target without ReceiveMigrationDisk refuses the copy as too old, and the
// source keeps everything.
//
// Mutation: drop the Unimplemented mapping — the refusal is Unimplemented and
// goes red.
func TestColdMigrateStoppedVM_OldTargetCannotTakeTheDisks(t *testing.T) {
	s, fake, peer, p := oldTargetSource(t, "local")
	err := coldMove(s, adminCtx())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("cold move to an old target = %v, want FailedPrecondition telling to upgrade it", err)
	}
	if peer.ensureCalls != 0 {
		t.Errorf("the domain was defined on the old target (%d calls) after the copy was refused", peer.ensureCalls)
	}
	assertSourceUntouched(t, s, fake, p)
}

// A shared-disk-only VM copies nothing, so the old target's first answer is
// its bundle-required refusal of the define. That is reported as a target too
// old, not as a firmware bundle the VM does not have.
//
// Mutation: drop the InvalidArgument mapping — the refusal names the firmware
// bundle and goes red.
func TestColdMigrateStoppedVM_OldTargetCannotDefineWithoutABundle(t *testing.T) {
	s, fake, peer, p := oldTargetSource(t, "nfs")
	err := coldMove(s, adminCtx())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "upgrade") ||
		strings.Contains(err.Error(), "firmware bundle") {
		t.Fatalf("bundle-less define on an old target = %v, want FailedPrecondition telling to upgrade it", err)
	}
	if peer.ensureCalls != 1 {
		t.Errorf("EnsureFirmwareState calls = %d, want 1", peer.ensureCalls)
	}
	assertSourceUntouched(t, s, fake, p)
}

// A header claiming more bytes than the disk's record allows is refused before
// anything is written.
//
// Mutation: drop the size bound — the file is written and goes red.
func TestReceiveMigrationDisk_RefusesASizeBeyondItsRecord(t *testing.T) {
	f := newColdDiskFixture(t)
	if err := corrosion.UpdateDiskSize(adminCtx(), f.dst.db, "os1", "root", 1<<20); err != nil {
		t.Fatal(err)
	}
	huge := int64(1 << 40)
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: huge},
		{Sha256: strings.Repeat("0", 64)},
	}}
	err := f.dst.ReceiveMigrationDisk(srv)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "record") {
		t.Fatalf("oversized copy = %v, want FailedPrecondition naming the record", err)
	}
	if left := scratchLeft(t, filepath.Dir(f.path)); len(left) > 0 {
		t.Fatalf("scratch files left: %v", left)
	}
}

// The target refuses a copy its filesystem cannot hold with headroom left: a
// full filesystem pauses every thin-provisioned guest on it.
//
// Mutation: drop the target's free-space check — the copy proceeds and goes red.
func TestReceiveMigrationDisk_RefusesWithoutFreeSpace(t *testing.T) {
	f := newColdDiskFixture(t)
	f.dst.diskSpaceOverride = func(string) (uint64, uint64, error) { return 2 << 30, 100 << 30, nil }
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: 1 << 20},
		{Sha256: strings.Repeat("0", 64)},
	}}
	err := f.dst.ReceiveMigrationDisk(srv)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "free") {
		t.Fatalf("copy onto a nearly full filesystem = %v, want FailedPrecondition naming free space", err)
	}
	if left := scratchLeft(t, filepath.Dir(f.path)); len(left) > 0 {
		t.Fatalf("scratch files left: %v", left)
	}
}

// The source refuses to flatten an overlay its filesystem cannot hold a full
// copy of with headroom left.
//
// Mutation: drop the source's free-space check — the flatten runs and goes red.
func TestStreamColdDisk_RefusesFlattenWithoutFreeSpace(t *testing.T) {
	f := newColdDiskFixture(t)
	const size = 1 << 20
	base := filepath.Join(t.TempDir(), "base.qcow2")
	if err := qcow2.Create(base, size, nil); err != nil {
		t.Fatal(err)
	}
	sp := f.src.hostDiskFile(f.path)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(sp, base, size, nil); err != nil {
		t.Fatal(err)
	}
	f.src.diskSpaceOverride = func(string) (uint64, uint64, error) { return 1 << 30, 10 << 30, nil }
	err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "qcow2")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "free") {
		t.Fatalf("flatten on a nearly full filesystem = %v, want FailedPrecondition naming free space", err)
	}
	if len(f.client.up.frames) != 0 {
		t.Error("frames were sent after the refusal")
	}
}

// The received file is placed by a call that fails if the path holds a file,
// so "never overwrites a file it did not create" holds even against one that
// appears after the check.
//
// Mutation: place with os.Rename — the existing file is replaced and goes red.
func TestPlaceColdDisk_NeverReplaces(t *testing.T) {
	dir := t.TempDir()
	tmp, dst := filepath.Join(dir, "tmp"), filepath.Join(dir, "dst")
	if err := os.WriteFile(tmp, []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("there first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := placeColdDisk(tmp, dst); err == nil {
		t.Fatal("placeColdDisk replaced an existing file")
	}
	if got, _ := os.ReadFile(dst); string(got) != "there first" {
		t.Fatalf("existing file now holds %q", got)
	}
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}
	if err := placeColdDisk(tmp, dst); err != nil {
		t.Fatalf("placeColdDisk onto a free path: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "copy" {
		t.Fatalf("placed file holds %q", got)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("the scratch name still exists after placement (stat: %v)", err)
	}
}

// The format comes from the domain definition, not the file: a raw disk is
// guest data, and a guest can write a qcow2 header naming any host file as its
// backing. Flattening that would copy the host file into the disk.
//
// Mutation: decide by the file header (ignore format) — the raw disk is
// flattened and goes red.
func TestStreamColdDisk_RawDiskIsNeverFlattened(t *testing.T) {
	f := newColdDiskFixture(t)
	secret := filepath.Join(t.TempDir(), "host-secret.qcow2")
	if err := qcow2.Create(secret, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	sp := f.src.hostDiskFile(f.path)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	// What a guest wrote into its raw disk: a qcow2 header backed by a host file.
	if err := qcow2.CreateWithBacking(sp, secret, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(sp)
	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("streamColdDisk: %v", err)
	}
	if got, _ := os.ReadFile(f.path); string(got) != string(want) {
		t.Fatal("a raw disk was not copied byte for byte")
	}
}

// domainDiskFormats reads each file-backed disk's driver type, and a disk the
// definition does not name is refused rather than guessed.
func TestDomainDiskFormats(t *testing.T) {
	got, err := domainDiskFormats(`<domain><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/d/a.qcow2'/></disk>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='/d/b.img'/></disk>` +
		`<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='/d/ci.iso'/></disk>` +
		`</devices></domain>`)
	if err != nil {
		t.Fatal(err)
	}
	if got["/d/a.qcow2"] != "qcow2" || got["/d/b.img"] != "raw" {
		t.Fatalf("formats = %v", got)
	}

	s := testServer(t)
	_, err = s.copyColdDisksToTarget(adminCtx(), "t1", "os1",
		[]corrosion.DiskRecord{{VMName: "os1", DiskName: "root", Path: "/d/missing.qcow2", StorageType: "local"}},
		got, &migrationAbort{}, func(pb.MigratePhase, float32, float32) error { return nil })
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "domain definition") {
		t.Fatalf("copy of a disk the definition does not name = %v, want FailedPrecondition", err)
	}
}

// Scratch files a crash left in a disk-artifact root — a partial receive, a
// partial flatten and its convert temp — are removed at startup, and nothing
// else is.
//
// Mutation: make the sweep a no-op — the scratch files stay and go red.
func TestSweepColdMigrationScratch(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	scratch := []string{
		".os1-root.qcow2.receiving-123456",
		".os1-root.qcow2.coldmig-0b6c1f8e-1f0a-4c55-9d2b-0a3a4c5d6e7f",
		".os1-root.qcow2.coldmig-0b6c1f8e-1f0a-4c55-9d2b-0a3a4c5d6e7f.tmp",
	}
	keep := []string{"os1-root.qcow2", "os1-root.qcow2.receiving-123456", ".hidden-disk.qcow2"}
	for _, n := range append(append([]string{}, scratch...), keep...) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.SweepColdMigrationScratch()
	for _, n := range scratch {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("scratch %s survived the sweep", n)
		}
	}
	for _, n := range keep {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s was removed by the sweep: %v", n, err)
		}
	}
}
