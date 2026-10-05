package grpcapi

// The disk copy of a stopped VM's cold migration: the source streams each
// host-local disk file (streamColdDisk) into the target's ReceiveMigrationDisk.
// The end-to-end move — ownership, the domain, rollback — is
// tests/fleet/migrate_cold_stopped_test.go; these pin the copy's own rules.

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// diskRecvStream feeds recorded frames to ReceiveMigrationDisk.
type diskRecvStream struct {
	grpc.ServerStream
	ctx    context.Context
	frames []*pb.ReceiveMigrationDiskRequest
	i      int
	resp   *pb.ReceiveMigrationDiskResponse
}

func (d *diskRecvStream) Context() context.Context { return d.ctx }
func (d *diskRecvStream) Recv() (*pb.ReceiveMigrationDiskRequest, error) {
	if d.i >= len(d.frames) {
		return nil, io.EOF
	}
	f := d.frames[d.i]
	d.i++
	return f, nil
}
func (d *diskRecvStream) SendAndClose(r *pb.ReceiveMigrationDiskResponse) error {
	d.resp = r
	return nil
}

// loopDiskUp is the source's client stream: it records what the source sends
// and, on CloseAndRecv, runs the target's handler over it as a peer.
type loopDiskUp struct {
	grpc.ClientStream
	dst    *Server
	ctx    context.Context
	frames []*pb.ReceiveMigrationDiskRequest
}

func (u *loopDiskUp) Send(m *pb.ReceiveMigrationDiskRequest) error {
	u.frames = append(u.frames, proto.Clone(m).(*pb.ReceiveMigrationDiskRequest))
	return nil
}
func (u *loopDiskUp) CloseAndRecv() (*pb.ReceiveMigrationDiskResponse, error) {
	srv := &diskRecvStream{ctx: u.ctx, frames: u.frames}
	err := u.dst.ReceiveMigrationDisk(srv)
	return srv.resp, err
}

type loopDiskClient struct {
	pb.LiteVirtClient
	up *loopDiskUp
}

func (c *loopDiskClient) ReceiveMigrationDisk(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ReceiveMigrationDiskRequest, pb.ReceiveMigrationDiskResponse], error) {
	return c.up, nil
}

// diskPeerCtx is a trusted peer daemon calling in, as a migration source does
// (daemon-to-daemon mTLS authenticates as admin).
func diskPeerCtx(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx := context.WithValue(peerCtxFor(t, s, "peer1"), ctxKeyUsername, "admin")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

type coldDiskFixture struct {
	src, dst *Server
	path     string // the disk's recorded path
	client   *loopDiskClient
	disk     corrosion.DiskRecord
	peer     context.Context // the source calling the target
}

// newColdDiskFixture is a source and a target that each hold the VM's row
// (stopped, owned by the source) with one host-local disk recorded at a path in
// the target's disks dir. They share one filesystem, so the source's files are
// rooted apart (SetHostDiskRootForTest).
func newColdDiskFixture(t *testing.T) *coldDiskFixture {
	t.Helper()
	ctx := adminCtx()
	src := testServer(t)
	src.hostName = "src-host"
	src.SetHostDiskRootForTest(t.TempDir())
	dst := testServer(t)
	dst.hostName = "dst-host"
	dst.dataDir = t.TempDir()
	p := filepath.Join(dst.dataDir, "disks", "os1-root.qcow2")
	disk := corrosion.DiskRecord{VMName: "os1", DiskName: "root", HostName: src.hostName, Path: p, StorageType: "local"}
	for _, s := range []*Server{src, dst} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: "os1", HostName: src.hostName, State: "stopped", Spec: `{"name":"os1"}`,
		}, nil, []corrosion.DiskRecord{disk}); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
	}
	peer := diskPeerCtx(t, dst)
	up := &loopDiskUp{dst: dst, ctx: peer}
	return &coldDiskFixture{src: src, dst: dst, path: p, client: &loopDiskClient{up: up}, disk: disk, peer: peer}
}

func (f *coldDiskFixture) writeSource(t *testing.T, data []byte) {
	t.Helper()
	sp := f.src.hostDiskFile(f.path)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func scratchLeft(t *testing.T, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var left []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".receiving-") {
			left = append(left, e.Name())
		}
	}
	return left
}

// A disk arrives byte for byte, the zero range it skips included, and is
// recorded as this attempt's, so a failed attempt's cleanup may remove it.
//
// Mutation: send the all-zero chunks' frames with the wrong offset (drop the
// off += n for them) — the content comparison goes red.
func TestReceiveMigrationDisk_CopiesTheFile(t *testing.T) {
	f := newColdDiskFixture(t)
	data := make([]byte, 2*coldDiskChunk+777)
	for i := range data[:coldDiskChunk] {
		data[i] = byte(i*7 + 1)
	}
	for i := 2 * coldDiskChunk; i < len(data); i++ {
		data[i] = byte(i)
	}
	f.writeSource(t, data)

	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk); err != nil {
		t.Fatalf("streamColdDisk: %v", err)
	}
	got, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatalf("target file: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("target holds %d bytes that differ from the source's %d", len(got), len(data))
	}
	for _, fr := range f.client.up.frames {
		if len(fr.Data) > 0 && allZero(fr.Data) {
			t.Fatalf("an all-zero chunk at %d was sent", fr.Offset)
		}
	}
	if !f.dst.migrationStubs.owns("os1", f.path) {
		t.Error("the received disk is not recorded as the migration's, so a failed attempt could not remove it")
	}
}

// A qcow2 overlay arrives flattened: its backing file is not part of the copy,
// and the target may not hold it.
//
// Mutation: stream the overlay as it is (skip the Convert) — the target file
// names a backing file and goes red.
func TestStreamColdDisk_FlattensABackedOverlay(t *testing.T) {
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
		t.Fatalf("create overlay: %v", err)
	}
	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk); err != nil {
		t.Fatalf("streamColdDisk: %v", err)
	}
	info, err := qcow2.Info(f.path)
	if err != nil {
		t.Fatalf("target image: %v", err)
	}
	if info.BackingFile != "" {
		t.Fatalf("target image is backed by %q; a cold copy must leave a standalone image", info.BackingFile)
	}
	if info.VirtualSize != size {
		t.Errorf("target virtual size = %d, want %d", info.VirtualSize, size)
	}
	// The scratch flatten is gone from the source.
	ents, _ := os.ReadDir(filepath.Dir(sp))
	for _, e := range ents {
		if strings.Contains(e.Name(), ".coldmig-") {
			t.Errorf("flatten scratch %s left on the source", e.Name())
		}
	}
}

// A file the target already has at the path, and did not create for this
// migration, is refused and left as it is: it may be the VM's disk from an
// earlier stay.
//
// Mutation: drop the existing-file check — the file is overwritten and goes red.
func TestReceiveMigrationDisk_RefusesAFileItDidNotCreate(t *testing.T) {
	f := newColdDiskFixture(t)
	f.writeSource(t, []byte("new contents"))
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte("kept from an earlier stay"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("copy over an existing file = %v, want FailedPrecondition", err)
	}
	if got, _ := os.ReadFile(f.path); string(got) != "kept from an earlier stay" {
		t.Fatalf("existing file now holds %q", got)
	}
}

// A copy whose digest does not match never takes the disk's path, and leaves
// no scratch file behind.
//
// Mutation: skip the digest comparison — the corrupt file is placed and goes red.
func TestReceiveMigrationDisk_DigestMismatchPlacesNothing(t *testing.T) {
	f := newColdDiskFixture(t)
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: 4},
		{Offset: 0, Data: []byte("abcd")},
		{Sha256: strings.Repeat("0", 64)},
	}}
	err := f.dst.ReceiveMigrationDisk(srv)
	if status.Code(err) != codes.DataLoss {
		t.Fatalf("mismatched digest = %v, want DataLoss", err)
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatalf("a copy that failed its digest took the disk's path (stat: %v)", err)
	}
	if left := scratchLeft(t, filepath.Dir(f.path)); len(left) > 0 {
		t.Fatalf("scratch files left: %v", left)
	}
}

// Only a peer daemon writes a disk this way, and never one of a VM that lives
// on this host.
func TestReceiveMigrationDisk_Refusals(t *testing.T) {
	t.Run("not a peer", func(t *testing.T) {
		f := newColdDiskFixture(t)
		srv := &diskRecvStream{ctx: adminCtx(), frames: []*pb.ReceiveMigrationDiskRequest{
			{VmName: "os1", Path: f.path, SizeBytes: 0},
		}}
		if err := f.dst.ReceiveMigrationDisk(srv); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("operator call = %v, want PermissionDenied", err)
		}
	})
	t.Run("VM lives here", func(t *testing.T) {
		f := newColdDiskFixture(t)
		if err := corrosion.UpdateVMHost(adminCtx(), f.dst.db, "os1", f.dst.hostName, "stopped"); err != nil {
			t.Fatalf("UpdateVMHost: %v", err)
		}
		srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
			{VmName: "os1", Path: f.path, SizeBytes: 0},
		}}
		if err := f.dst.ReceiveMigrationDisk(srv); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("copy onto the VM's own host = %v, want FailedPrecondition", err)
		}
	})
	t.Run("not one of the VM's disks", func(t *testing.T) {
		f := newColdDiskFixture(t)
		srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
			{VmName: "os1", Path: filepath.Join(f.dst.dataDir, "disks", "other.qcow2"), SizeBytes: 0},
		}}
		if err := f.dst.ReceiveMigrationDisk(srv); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("copy to a path the VM has no disk at = %v, want InvalidArgument", err)
		}
	})
}

// The refusals that send an operator to cold migration name the flag the CLI
// has: --cold. There is no --strategy flag.
func TestMigrateVM_StoppedVMIsSteeredToCold(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "os1", s.hostName, "stopped", `{"name":"os1"}`)
	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "os1", TargetHost: "t1"}, &mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("live migration of a stopped VM = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "--cold") || strings.Contains(err.Error(), "--strategy") {
		t.Fatalf("refusal should name --cold, got: %v", err)
	}
}

// A VM whose row says stopped but whose domain is active here is not moved:
// a running guest would write into the disk being copied.
//
// Mutation: drop the DomainIsActive check — the move proceeds and goes red.
func TestColdMigrateStoppedVM_RefusesAnActiveDomain(t *testing.T) {
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "os1", HostName: s.hostName, Spec: `{"name":"os1"}`, State: "stopped",
	}, nil, []corrosion.DiskRecord{
		{VMName: "os1", DiskName: "root", HostName: s.hostName, Path: "/srv/os1-root.qcow2", StorageType: "nfs"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("os1", libvirtfake.StateRunning)
	vm, _ := corrosion.GetVM(ctx, s.db, "os1")
	err := s.coldMigrateStoppedVM(ctx, vm, &corrosion.HostRecord{Name: "t1"}, firmwareSpec{}, &migrationAbort{},
		func(pb.MigratePhase, float32, float32) error { return nil })
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "active") {
		t.Fatalf("cold move of a VM whose domain is active = %v, want FailedPrecondition naming it", err)
	}
}

// A Secure-Boot/vTPM VM is never defined on a target without its firmware
// bundle — that would boot it with a fresh TPM. The bundle-less define is for
// VMs without firmware state only.
//
// Mutation: drop the firmware-VM check — the define goes through and goes red.
func TestEnsureFirmwareState_FirmwareVMNeedsItsBundle(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	insertTestVMWithSpec(t, adminCtx(), s.db, "fw", "src-host", "stopped", `{"name":"fw","tpm":true,"uuid":"u1"}`)
	_, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{
		VmName: "fw", DomainXml: `<domain type='kvm'><name>fw</name></domain>`, AttemptId: "a1",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bundle-less define of a firmware VM = %v, want InvalidArgument", err)
	}
	if s.virt.DomainExists("fw") {
		t.Fatal("a firmware VM was defined without its firmware")
	}
}

// The bundle-less define of a VM without firmware state, and its rollback,
// never touch name-keyed firmware files here: there is no firmware of the
// attempt's, and such a file may be another VM's (a same-name VM deleted with
// --keep-disks keeps its vars and marker).
//
// Mutation: wipe unconditionally in EnsureFirmwareState's refusal, or in
// RollbackFirmwareState — the vars file is removed and goes red.
func TestColdDefineWithoutFirmware_LeavesNameKeyedFiles(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	insertTestVMWithSpec(t, adminCtx(), s.db, "os1", "src-host", "stopped", `{"name":"os1"}`)
	nv := lv.NvramPath(s.dataDir, "os1")
	if err := os.MkdirAll(filepath.Dir(nv), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nv, []byte("kept vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	xml := `<domain type='kvm'><name>os1</name></domain>`

	fake.FailDefineDomain = func(string) error { return errors.New("define fails") }
	if _, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{VmName: "os1", DomainXml: xml, AttemptId: "a1"}); err == nil {
		t.Fatal("EnsureFirmwareState with a failing define succeeded")
	}
	if _, err := os.Stat(nv); err != nil {
		t.Fatalf("a failed bundle-less define removed name-keyed vars: %v", err)
	}

	fake.FailDefineDomain = nil
	resp, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{VmName: "os1", DomainXml: xml, AttemptId: "a2"})
	if err != nil || !resp.GetDomainDefined() {
		t.Fatalf("bundle-less define = %v %v, want the domain defined", resp, err)
	}
	rb, err := s.RollbackFirmwareState(adminCtx(), &pb.RollbackFirmwareStateRequest{VmName: "os1", AttemptId: "a2"})
	if err != nil || !rb.GetRemoved() {
		t.Fatalf("rollback = %v %v, want the attempt's domain removed", rb, err)
	}
	if fake.DomainExists("os1") {
		t.Fatal("rollback left the attempt's domain defined")
	}
	if _, err := os.Stat(nv); err != nil {
		t.Fatalf("rollback of a bundle-less define removed name-keyed vars: %v", err)
	}
}
