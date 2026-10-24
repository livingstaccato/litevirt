package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A stopped plain UEFI (or BIOS) VM "pv" moving cold from src to dst, over the
// firmwareTargetPeer harness, each host with a libvirt nvram dir of its own.
type plainVarsFixture struct {
	*fwRollbackFixture
	srcVars, dstVars string
}

const plainVarsUUID = "dddddddd-4444-4444-8444-dddddddddddd"

func newPlainVarsFixture(t *testing.T, firmware string) *plainVarsFixture {
	t.Helper()
	ctx := adminCtx()
	spec := `{"name":"pv","firmware":"` + firmware + `","uuid":"` + plainVarsUUID + `"}`

	src := testServerWithLocks(t)
	src.hostName = "src-host"
	src.SetFirmwareStore(&lv.FirmwareStore{DataDir: src.dataDir, SwtpmBase: filepath.Join(t.TempDir(), "swtpm")})
	srcVirt := libvirtfake.New()
	src.virt = srcVirt
	if err := srcVirt.DefineDomain(`<domain type='kvm'><name>pv</name><uuid>` + plainVarsUUID + `</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, src.db, corrosion.VMRecord{
		Name: "pv", HostName: src.hostName, Spec: spec, State: "stopped",
	}, nil, []corrosion.DiskRecord{
		{VMName: "pv", DiskName: "root", HostName: src.hostName, Path: "/srv/pv-root.qcow2", StorageType: "nfs"},
	}); err != nil {
		t.Fatal(err)
	}

	dst := testServer(t)
	dst.hostName = fwRollbackDst
	dst.dataDir = t.TempDir()
	dst.SetFirmwareStore(&lv.FirmwareStore{DataDir: dst.dataDir, SwtpmBase: filepath.Join(t.TempDir(), "swtpm")})
	dstVirt := libvirtfake.New()
	dst.virt = dstVirt
	insertTestVMWithSpec(t, ctx, dst.db, "pv", src.hostName, "stopped", spec)

	srcCtx := context.WithValue(peerCtxFor(t, dst, src.hostName), ctxKeyUsername, "admin")
	srcCtx = context.WithValue(srcCtx, ctxKeyRole, "admin")
	peer := &firmwareTargetPeer{dst: dst, srcFP: src.firmwareLayoutFingerprint(), srcCtx: srcCtx}
	src.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return peer, func() {}, nil
	}
	f := &plainVarsFixture{fwRollbackFixture: &fwRollbackFixture{
		src: src, dst: dst, srcVirt: srcVirt, dstVirt: dstVirt, peer: peer,
		fwSpec: parseFirmwareSpec(spec), targetHostName: fwRollbackDst,
	}}
	for _, s := range []*Server{src, dst} {
		dir := filepath.Join(t.TempDir(), "libvirt-nvram")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		s.SetLibvirtNvramDir(dir)
	}
	f.srcVars, f.dstVars = src.libvirtVarsPath("pv"), dst.libvirtVarsPath("pv")
	return f
}

func (f *plainVarsFixture) move(ctx context.Context, t *testing.T) error {
	t.Helper()
	vm, err := corrosion.GetVM(adminCtx(), f.src.db, "pv")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	return f.src.coldMigrateStoppedVM(ctx, vm, &corrosion.HostRecord{Name: f.targetHostName}, f.fwSpec, &migrationAbort{},
		func(pb.MigratePhase, float32, float32) error { return nil })
}

func writeVarsFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fileIs(p, want string) bool {
	b, err := os.ReadFile(p)
	return err == nil && string(b) == want
}

// A target too old to know libvirt_vars never echoes the hash. The source must
// refuse the move rather than let the VM boot there from a fresh template and
// then delete its own, only, copy. The target's domain is rolled back, the
// source's file is intact and the message says to upgrade.
//
// Mutation: disable the refusal at the end of ensureFirmwareStateOnTarget; the
// move goes through (and this test goes red).
func TestColdMove_OlderTargetThatDoesNotEchoTheVarsHashIsRefused(t *testing.T) {
	f := newPlainVarsFixture(t, "uefi")
	f.peer.ignoreVars = true
	writeVarsFile(t, f.srcVars, "the VM's only vars")

	err := f.move(adminCtx(), t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "Upgrade") {
		t.Fatalf("cold move to a target that ignores libvirt_vars = %v, want FailedPrecondition naming the upgrade", err)
	}
	if !fileIs(f.srcVars, "the VM's only vars") {
		t.Error("the source's vars were touched by a refused move")
	}
	if f.dstVirt.DomainExists("pv") {
		t.Error("the target still holds the domain the refused attempt defined")
	}
	if got := f.owner2(t); got != f.src.hostName {
		t.Errorf("owner = %q after a refusal, want the source", got)
	}
	if len(f.peer.sawVars) == 0 || f.peer.sawVars[0] == 0 {
		t.Errorf("the request carried no vars (%v); the scenario needs them sent", f.peer.sawVars)
	}
}

func (f *plainVarsFixture) owner2(t *testing.T) string {
	t.Helper()
	vm, err := corrosion.GetVM(adminCtx(), f.src.db, "pv")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	return vm.HostName
}

// A BIOS VM has no libvirt-managed vars. A stale file under its name is not
// its state: it is not sent, a new target writes nothing, and an older target
// does not refuse the move over it.
//
// Mutation: drop the hasNvram() condition before readSourceLibvirtVars; the
// stale file is sent and the older target refuses.
func TestColdMove_ABIOSVMsStaleVarsAreNeitherSentNorARefusal(t *testing.T) {
	for _, old := range []bool{false, true} {
		name := "new target"
		if old {
			name = "older target"
		}
		t.Run(name, func(t *testing.T) {
			f := newPlainVarsFixture(t, "bios")
			f.peer.ignoreVars = old
			writeVarsFile(t, f.srcVars, "a stale file")
			if err := f.move(adminCtx(), t); err != nil {
				t.Fatalf("cold move of a BIOS VM: %v", err)
			}
			for _, n := range f.peer.sawVars {
				if n != 0 {
					t.Errorf("a BIOS VM's stale vars were sent (%d bytes)", n)
				}
			}
			if _, err := os.Stat(f.dstVars); !os.IsNotExist(err) {
				t.Errorf("the target holds vars for a BIOS VM (stat: %v)", err)
			}
			if !fileIs(f.srcVars, "a stale file") {
				t.Error("the source's file was touched; it is not part of this move")
			}
			if got := f.owner2(t); got != fwRollbackDst {
				t.Errorf("owner = %q, want the target", got)
			}
		})
	}
}

// A target rollback removes the vars file the failed attempt wrote and nothing
// else: not a file that was there before the attempt (that one is set aside by
// the write, and stays so), and not one the attempt did not write.
//
// Mutations: disable the removal in RollbackFirmwareState (the first case goes
// red); remove unconditionally, without the ledger's vars flag (the second goes
// red).
func TestRollbackFirmwareState_RemovesOnlyTheVarsTheAttemptWrote(t *testing.T) {
	cancelAfterEnsure := func(f *plainVarsFixture, before func()) context.Context {
		ctx, cancel := context.WithCancel(adminCtx())
		t.Cleanup(cancel)
		f.peer.afterEnsure = func(r *pb.EnsureFirmwareStateResponse, err error) (*pb.EnsureFirmwareStateResponse, error) {
			if before != nil {
				before()
			}
			cancel()
			return nil, status.Error(codes.Canceled, context.Canceled.Error())
		}
		return ctx
	}
	t.Run("the attempt wrote it", func(t *testing.T) {
		f := newPlainVarsFixture(t, "uefi")
		writeVarsFile(t, f.srcVars, "source vars")
		writeVarsFile(t, f.dstVars, "target's earlier file")
		ctx := cancelAfterEnsure(f, func() {
			if !fileIs(f.dstVars, "source vars") {
				t.Errorf("the attempt did not write the source's vars to the target")
			}
		})
		if err := f.move(ctx, t); err == nil {
			t.Fatal("the cancelled move reported success")
		}
		if f.dstVirt.DomainExists("pv") {
			t.Error("the target kept the domain")
		}
		if _, err := os.Stat(f.dstVars); !os.IsNotExist(err) {
			t.Errorf("the vars the attempt wrote are still on the target (stat: %v)", err)
		}
		aside, _ := filepath.Glob(f.dstVars + ".superseded-*")
		if len(aside) != 1 || !fileIs(aside[0], "target's earlier file") {
			t.Errorf("the target's earlier file: set-aside copies = %v, want one holding its bytes", aside)
		}
		if !fileIs(f.srcVars, "source vars") {
			t.Error("the source's vars were touched")
		}
	})
	t.Run("the attempt did not write it", func(t *testing.T) {
		f := newPlainVarsFixture(t, "uefi") // no vars on the source: none sent
		ctx := cancelAfterEnsure(f, func() {
			// Something else puts a file there after the target answered.
			writeVarsFile(t, f.dstVars, "not the attempt's")
		})
		if err := f.move(ctx, t); err == nil {
			t.Fatal("the cancelled move reported success")
		}
		if f.dstVirt.DomainExists("pv") {
			t.Error("the target kept the domain")
		}
		if !fileIs(f.dstVars, "not the attempt's") {
			t.Error("a rollback removed a vars file its attempt did not write")
		}
	})
}

// The source removes its copy only while it is still what the target
// confirmed: a file changed after the handoff is kept.
//
// Mutation: drop the hash comparison in removeMigratedSourceVars.
func TestColdMove_SourceKeepsVarsChangedAfterTheTargetConfirmedThem(t *testing.T) {
	f := newPlainVarsFixture(t, "uefi")
	writeVarsFile(t, f.srcVars, "confirmed bytes")
	f.src.coldMoveAfterHandoff = func(string) { writeVarsFile(t, f.srcVars, "written after the confirmation") }
	if err := f.move(adminCtx(), t); err != nil {
		t.Fatalf("cold move: %v", err)
	}
	if !fileIs(f.dstVars, "confirmed bytes") {
		t.Errorf("the target's vars are not the confirmed bytes")
	}
	if !fileIs(f.srcVars, "written after the confirmation") {
		t.Error("the source removed a file that is no longer the copy the target confirmed")
	}
}
