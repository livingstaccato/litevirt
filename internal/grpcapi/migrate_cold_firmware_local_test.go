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
	"errors"
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
	// afterEnsure, if set, runs once the target's EnsureFirmwareState has
	// answered — the point between the define and the handoff.
	afterEnsure func()
}

func (p *twoHostPeer) onTarget() func() {
	lv.SetSwtpmBaseForTest(p.dstSwtpm)
	return func() { lv.SetSwtpmBaseForTest(p.srcSwtpm) }
}

func (p *twoHostPeer) ReceiveMigrationDisk(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ReceiveMigrationDiskRequest, pb.ReceiveMigrationDiskResponse], error) {
	return &loopDiskUp{dst: p.dst, ctx: p.peer}, nil
}

func (p *twoHostPeer) EnsureFirmwareState(_ context.Context, req *pb.EnsureFirmwareStateRequest, _ ...grpc.CallOption) (*pb.EnsureFirmwareStateResponse, error) {
	restore := p.onTarget()
	resp, err := p.dst.EnsureFirmwareState(p.peer, req)
	restore()
	if p.afterEnsure != nil {
		p.afterEnsure()
	}
	return resp, err
}

func (p *twoHostPeer) RollbackFirmwareState(_ context.Context, req *pb.RollbackFirmwareStateRequest, _ ...grpc.CallOption) (*pb.RollbackFirmwareStateResponse, error) {
	defer p.onTarget()()
	return p.dst.RollbackFirmwareState(p.peer, req)
}

func (p *twoHostPeer) CleanupMigrationArtifacts(_ context.Context, req *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	defer p.onTarget()()
	return p.dst.CleanupMigrationArtifacts(p.peer, req)
}

const fwLocalUUID = "11111111-2222-4333-8444-555555555555"

// fwLocalMove is a source and a target, each with its own swtpm root, and a
// stopped Secure Boot + vTPM VM os1 on the source with one host-local disk,
// its UEFI vars and its swtpm tree.
type fwLocalMove struct {
	src, dst           *Server
	srcVirt, dstVirt   *libvirtfake.Fake
	peer               *twoHostPeer
	p                  string // the disk's recorded path
	srcSwtpm, dstSwtpm string
	disk, vars, tpm    []byte
}

func newFWLocalMove(t *testing.T) *fwLocalMove {
	t.Helper()
	ctx := adminCtx()
	spec := `{"name":"os1","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"` + fwLocalUUID + `"}`
	f := &fwLocalMove{
		disk: []byte("os1's root disk, host-local"),
		vars: []byte("os1's UEFI vars"),
		tpm:  []byte("os1's TPM state, sealing its BitLocker key"),
	}
	f.src = testServerWithLocks(t)
	f.src.hostName = "src-host"
	f.src.SetHostDiskRootForTest(t.TempDir())
	f.srcVirt = libvirtfake.New()
	f.src.virt = f.srcVirt
	f.dst = testServerWithLocks(t)
	f.dst.hostName = "dst-host"
	f.dstVirt = libvirtfake.New()
	f.dst.virt = f.dstVirt
	// One firmware layout, as every host of a real cluster has; the two test
	// hosts' dataDirs differ only because they share one filesystem.
	layout := t.TempDir()
	f.src.SetFirmwareLayoutDirForTest(layout)
	f.dst.SetFirmwareLayoutDirForTest(layout)

	f.p = filepath.Join(f.dst.dataDir, "disks", "os1-root.raw")
	for _, s := range []*Server{f.src, f.dst} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: "os1", HostName: f.src.hostName, State: "stopped", Spec: spec,
		}, nil, []corrosion.DiskRecord{
			{VMName: "os1", DiskName: "root", HostName: f.src.hostName, Path: f.p, SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda"},
		}); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
	}
	if err := f.srcVirt.DefineDomain(`<domain type='kvm'><name>os1</name><uuid>` + fwLocalUUID + `</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + f.p + `'/><target dev='vda'/></disk>` +
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
	write(f.src.hostDiskFile(f.p), f.disk)
	write(lv.NvramPath(f.src.dataDir, "os1"), f.vars)
	f.srcSwtpm, f.dstSwtpm = t.TempDir(), t.TempDir()
	t.Cleanup(lv.SetSwtpmBaseForTest(f.srcSwtpm))
	write(f.srcTPMFile(), f.tpm)

	f.peer = &twoHostPeer{dst: f.dst, peer: diskPeerCtx(t, f.dst), srcSwtpm: f.srcSwtpm, dstSwtpm: f.dstSwtpm}
	f.src.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return f.peer, func() {}, nil
	}
	return f
}

func (f *fwLocalMove) srcTPMFile() string {
	return filepath.Join(f.srcSwtpm, fwLocalUUID, "tpm2", "tpm2-00.permall")
}
func (f *fwLocalMove) dstTPMFile() string {
	return filepath.Join(f.dstSwtpm, fwLocalUUID, "tpm2", "tpm2-00.permall")
}

// move runs the cold move as MigrateVM runs it: with its abort armed, and the
// abort's undo run if the move fails before the handoff disarmed it.
func (f *fwLocalMove) move(ctx context.Context) error {
	vm, _ := corrosion.GetVM(ctx, f.src.db, "os1")
	abort := &migrationAbort{armed: true}
	err := f.src.coldMigrateStoppedVM(ctx, vm, &corrosion.HostRecord{Name: f.dst.hostName}, parseFirmwareSpec(vm.Spec),
		abort, func(pb.MigratePhase, float32, float32) error { return nil })
	if abort.armed {
		f.src.undoMigrationAttempt(ctx, "os1", f.dst.hostName, abort)
	}
	return err
}

// Mutation: restore coldMoveDisks' refusal of a firmware VM with a host-local
// disk — the move is refused ("has a host-local disk") and nothing arrives.
func TestColdMigrateStoppedVM_CarriesFirmwareWithAHostLocalDisk(t *testing.T) {
	f := newFWLocalMove(t)
	ctx := adminCtx()
	if err := f.move(ctx); err != nil {
		t.Fatalf("cold move of a stopped Secure Boot + vTPM VM with a host-local disk: %v", err)
	}

	same := func(what, path string, want []byte) {
		t.Helper()
		if got, err := os.ReadFile(path); err != nil || string(got) != string(want) {
			t.Errorf("%s on the target = %q (err %v), want %q", what, got, err, want)
		}
	}
	same("disk", f.p, f.disk)
	same("UEFI vars", lv.NvramPath(f.dst.dataDir, "os1"), f.vars)
	same("swtpm state", f.dstTPMFile(), f.tpm)
	gone := func(what, path string) {
		t.Helper()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s is still on the source (stat: %v)", what, err)
		}
	}
	gone("disk", f.src.hostDiskFile(f.p))
	gone("UEFI vars", lv.NvramPath(f.src.dataDir, "os1"))
	gone("swtpm state", filepath.Join(f.srcSwtpm, fwLocalUUID))

	if !f.dstVirt.DomainExists("os1") {
		t.Error("the domain is not defined on the target")
	}
	if f.srcVirt.DomainExists("os1") {
		t.Error("the domain is still defined on the source")
	}
	moved, _ := corrosion.GetVM(ctx, f.src.db, "os1")
	if moved == nil || moved.HostName != f.dst.hostName || moved.State != "stopped" {
		t.Errorf("VM row after the move = %+v, want on %s, stopped", moved, f.dst.hostName)
	}
	disks, _ := corrosion.GetVMDisks(ctx, f.src.db, "os1")
	if len(disks) != 1 || disks[0].HostName != f.dst.hostName {
		t.Errorf("disk rows after the move = %+v, want one naming %s", disks, f.dst.hostName)
	}
}

// A move that fails AFTER the disk was copied — the target's define fails, or
// the request is cancelled between the define and the handoff — leaves the
// source as it was and the target clean: the disk copy, the vars, the swtpm
// tree and the domain are all taken back there. Two rollbacks compose here for
// the first time: abandonFirmwareTarget (domain and firmware) inside the move,
// then MigrateVM's abort (the copied disk), which the target refuses while the
// domain is still defined.
//
// Mutations: skip abandonFirmwareTarget on a failed handoff — the cancelled
// case keeps the domain, the firmware and the disk copy on the target; drop
// the abort's target cleanup (cleanupFailedMigrationTarget) — both cases keep
// the disk copy. (Dropping only createdStubs does not: the target also removes
// a disk it recorded receiving for the attempt, from its own ledger.)
func TestColdMigrateStoppedVM_FirmwareWithAHostLocalDiskRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(f *fwLocalMove, cancel func())
	}{
		{"define fails", func(f *fwLocalMove, _ func()) {
			f.dstVirt.FailDefineDomain = func(string) error { return errors.New("injected define failure") }
		}},
		{"cancelled before the handoff", func(f *fwLocalMove, cancel func()) {
			f.peer.afterEnsure = cancel
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFWLocalMove(t)
			ctx, cancel := context.WithCancel(adminCtx())
			defer cancel()
			tc.set(f, cancel)
			// The disk must have arrived before the failure, or nothing here
			// tests its rollback: look when the target's define has answered.
			copied := false
			then := f.peer.afterEnsure
			f.peer.afterEnsure = func() {
				copied = fileExists(f.p)
				if then != nil {
					then()
				}
			}
			if err := f.move(ctx); err == nil {
				t.Fatal("the move succeeded; want it to fail after the disk copy")
			}
			if !copied {
				t.Fatal("the disk was not on the target when the define answered; the failure came before the copy")
			}

			kept := func(what, path string, want []byte) {
				t.Helper()
				if got, err := os.ReadFile(path); err != nil || string(got) != string(want) {
					t.Errorf("%s on the source = %q (err %v), want it intact", what, got, err)
				}
			}
			kept("disk", f.src.hostDiskFile(f.p), f.disk)
			kept("UEFI vars", lv.NvramPath(f.src.dataDir, "os1"), f.vars)
			kept("swtpm state", f.srcTPMFile(), f.tpm)
			if !f.srcVirt.DomainExists("os1") {
				t.Error("the domain is gone from the source")
			}

			clean := func(what, path string) {
				t.Helper()
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("%s was left on the target (stat: %v)", what, err)
				}
			}
			clean("the disk copy", f.p)
			clean("the UEFI vars", lv.NvramPath(f.dst.dataDir, "os1"))
			clean("the swtpm tree", filepath.Join(f.dstSwtpm, fwLocalUUID))
			if f.dstVirt.DomainExists("os1") {
				t.Error("the domain was left defined on the target")
			}

			vm, _ := corrosion.GetVM(adminCtx(), f.src.db, "os1")
			if vm == nil || vm.HostName != f.src.hostName || vm.State != "stopped" {
				t.Errorf("VM row after the failed move = %+v, want on %s, stopped", vm, f.src.hostName)
			}
			disks, _ := corrosion.GetVMDisks(adminCtx(), f.src.db, "os1")
			if len(disks) != 1 || disks[0].HostName != f.src.hostName {
				t.Errorf("disk rows after the failed move = %+v, want one naming %s", disks, f.src.hostName)
			}
		})
	}
}
