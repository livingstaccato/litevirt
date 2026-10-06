package grpcapi

// The cold move of a stopped Secure Boot + vTPM VM with a host-local disk:
// the disk is streamed, the firmware bundle (UEFI vars + swtpm tree) carried,
// and the domain defined on the target, as for any stopped VM. The fleet
// scenarios (tests/fleet/drain_cold_firmware_test.go) drive it through drain
// and `lv migrate --cold`, but the fleet's nodes share one swtpm root, a
// process-wide path; here each host has its own, so the vTPM state can be seen
// to leave one and arrive at the other.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// twoHostPeer is the source's client to the target: every call runs the
// target's handler as a trusted peer, with the swtpm root switched to the
// target's for its duration (the calls are synchronous, so the source's own
// reads and wipes see its own root).
type twoHostPeer struct {
	pb.LiteVirtClient
	dst      *Server
	peer     context.Context
	srcSwtpm string
	dstSwtpm string
}

func (p *twoHostPeer) onTarget() func() {
	lv.SetSwtpmBaseForTest(p.dstSwtpm)
	return func() { lv.SetSwtpmBaseForTest(p.srcSwtpm) }
}

func (p *twoHostPeer) ReceiveMigrationDisk(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ReceiveMigrationDiskRequest, pb.ReceiveMigrationDiskResponse], error) {
	return &loopDiskUp{dst: p.dst, ctx: p.peer}, nil
}

func (p *twoHostPeer) EnsureFirmwareState(_ context.Context, req *pb.EnsureFirmwareStateRequest, _ ...grpc.CallOption) (*pb.EnsureFirmwareStateResponse, error) {
	defer p.onTarget()()
	return p.dst.EnsureFirmwareState(p.peer, req)
}

func (p *twoHostPeer) RollbackFirmwareState(_ context.Context, req *pb.RollbackFirmwareStateRequest, _ ...grpc.CallOption) (*pb.RollbackFirmwareStateResponse, error) {
	defer p.onTarget()()
	return p.dst.RollbackFirmwareState(p.peer, req)
}

func (p *twoHostPeer) CleanupMigrationArtifacts(_ context.Context, req *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	defer p.onTarget()()
	return p.dst.CleanupMigrationArtifacts(p.peer, req)
}

// Mutation: restore coldMoveDisks' refusal of a firmware VM with a host-local
// disk — the move is refused ("has a host-local disk") and nothing arrives.
func TestColdMigrateStoppedVM_CarriesFirmwareWithAHostLocalDisk(t *testing.T) {
	const uuid = "11111111-2222-4333-8444-555555555555"
	ctx := adminCtx()
	spec := `{"name":"os1","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"` + uuid + `"}`

	src := testServerWithLocks(t)
	src.hostName = "src-host"
	src.SetHostDiskRootForTest(t.TempDir())
	srcVirt := libvirtfake.New()
	src.virt = srcVirt
	dst := testServerWithLocks(t)
	dst.hostName = "dst-host"
	dstVirt := libvirtfake.New()
	dst.virt = dstVirt
	// One firmware layout, as every host of a real cluster has; the two test
	// hosts' dataDirs differ only because they share one filesystem.
	layout := t.TempDir()
	src.SetFirmwareLayoutDirForTest(layout)
	dst.SetFirmwareLayoutDirForTest(layout)

	p := filepath.Join(dst.dataDir, "disks", "os1-root.raw")
	for _, s := range []*Server{src, dst} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: "os1", HostName: src.hostName, State: "stopped", Spec: spec,
		}, nil, []corrosion.DiskRecord{
			{VMName: "os1", DiskName: "root", HostName: src.hostName, Path: p, SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda"},
		}); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
	}
	if err := srcVirt.DefineDomain(`<domain type='kvm'><name>os1</name><uuid>` + uuid + `</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + p + `'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatal(err)
	}

	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	disk := []byte("os1's root disk, host-local")
	vars := []byte("os1's UEFI vars")
	tpm := []byte("os1's TPM state, sealing its BitLocker key")
	write(src.hostDiskFile(p), disk)
	write(lv.NvramPath(src.dataDir, "os1"), vars)
	srcSwtpm, dstSwtpm := t.TempDir(), t.TempDir()
	t.Cleanup(lv.SetSwtpmBaseForTest(srcSwtpm))
	write(filepath.Join(srcSwtpm, uuid, "tpm2", "tpm2-00.permall"), tpm)

	peer := &twoHostPeer{dst: dst, peer: diskPeerCtx(t, dst), srcSwtpm: srcSwtpm, dstSwtpm: dstSwtpm}
	src.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return peer, func() {}, nil
	}

	vm, _ := corrosion.GetVM(ctx, src.db, "os1")
	if err := src.coldMigrateStoppedVM(ctx, vm, &corrosion.HostRecord{Name: dst.hostName}, parseFirmwareSpec(vm.Spec),
		&migrationAbort{armed: true}, func(pb.MigratePhase, float32, float32) error { return nil }); err != nil {
		t.Fatalf("cold move of a stopped Secure Boot + vTPM VM with a host-local disk: %v", err)
	}

	same := func(what, path string, want []byte) {
		t.Helper()
		if got, err := os.ReadFile(path); err != nil || string(got) != string(want) {
			t.Errorf("%s on the target = %q (err %v), want %q", what, got, err, want)
		}
	}
	same("disk", p, disk)
	same("UEFI vars", lv.NvramPath(dst.dataDir, "os1"), vars)
	same("swtpm state", filepath.Join(dstSwtpm, uuid, "tpm2", "tpm2-00.permall"), tpm)
	gone := func(what, path string) {
		t.Helper()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s is still on the source (stat: %v)", what, err)
		}
	}
	gone("disk", src.hostDiskFile(p))
	gone("UEFI vars", lv.NvramPath(src.dataDir, "os1"))
	gone("swtpm state", filepath.Join(srcSwtpm, uuid))

	if !dstVirt.DomainExists("os1") {
		t.Error("the domain is not defined on the target")
	}
	if srcVirt.DomainExists("os1") {
		t.Error("the domain is still defined on the source")
	}
	moved, _ := corrosion.GetVM(ctx, src.db, "os1")
	if moved == nil || moved.HostName != dst.hostName || moved.State != "stopped" {
		t.Errorf("VM row after the move = %+v, want on %s, stopped", moved, dst.hostName)
	}
	disks, _ := corrosion.GetVMDisks(ctx, src.db, "os1")
	if len(disks) != 1 || disks[0].HostName != dst.hostName {
		t.Errorf("disk rows after the move = %+v, want one naming %s", disks, dst.hostName)
	}
}
