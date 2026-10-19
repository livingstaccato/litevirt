package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// fwLiveTarget is a target host "dst-host" holding os1's row, owned by the
// source "src-host", with the same OVMF files as the source and a dataDir of
// its own.
type fwLiveTarget struct {
	s     *Server
	store *lv.FirmwareStore
	row   *corrosion.VMRecord
	peer  context.Context // src-host, as the row's host
}

func newFWLiveTarget(t *testing.T, src *fwLiveFixture) *fwLiveTarget {
	t.Helper()
	d := testServer(t)
	d.hostName = "dst-host"
	d.dataDir = t.TempDir()
	store := &lv.FirmwareStore{DataDir: d.dataDir, SwtpmBase: t.TempDir()}
	d.SetFirmwareStore(store)
	fake := libvirtfake.New()
	fake.SetFirmwareStore(store)
	d.virt = fake
	fwmig.Wire(fake, store)
	d.SetFirmwarePaths(src.s.firmware)
	spec, _ := json.Marshal(src.spec)
	insertTestVMWithSpec(t, adminCtx(), d.db, "os1", "src-host", "running", string(spec))
	row, err := corrosion.GetVM(context.Background(), d.db, "os1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	peer := context.WithValue(peerCtxFor(t, d, "src-host"), ctxKeyUsername, "admin")
	return &fwLiveTarget{s: d, store: store, row: row, peer: context.WithValue(peer, ctxKeyRole, "admin")}
}

// probeRuntime is fwFloorRuntime as a host's probe reads it: the OVMF content
// fingerprint over that host's own dataDir.
func probeRuntime(t *testing.T, s *Server) lv.FirmwareRuntime {
	t.Helper()
	rt := fwFloorRuntime
	var err error
	if rt.OVMFFingerprint, err = lv.OVMFContentFingerprint(s.firmware, s.fw().DataDir); err != nil {
		t.Fatal(err)
	}
	return rt
}

// A well-formed live move of os1 between two hosts with the same firmware
// code passes stage A on the source, Prepare's runtime comparison on the
// target, and stage B on the source's reading of the target's answer: the
// runtime each side builds is the one the other compares. The two hosts have
// dataDirs of their own (as fleet nodes do) and one firmware layout, so a
// fingerprint that embeds a host's own dataDir fails here.
//
// Mutations: Prepare comparing or answering in another format than stage A
// sends; either fingerprint half over the host's own dataDir — red.
func TestLiveFirmwareMove_StagesAndPrepareAgree(t *testing.T) {
	src := newFWLiveFixture(t)
	dst := newFWLiveTarget(t, src)
	layout := t.TempDir()
	src.s.SetFirmwareLayoutDirForTest(layout)
	dst.s.SetFirmwareLayoutDirForTest(layout)

	srcRT := probeRuntime(t, src.s)
	src.code.installed.Runtime, src.code.running = srcRT, srcRT
	dstRT := probeRuntime(t, dst.s)
	if srcRT.OVMFFingerprint == dstRT.OVMFFingerprint {
		t.Fatal("the probes' own fingerprints are equal: the hosts' dataDirs do not differ, and the test proves nothing")
	}
	dstHost := &stubFWCode{installed: lv.InstalledFirmwareCode{Runtime: dstRT}}
	dst.s.SetLiveFirmwareHost(dstHost)

	src.m.vm.CreatedAt = dst.row.CreatedAt
	a, err := src.stageA(t)
	if err != nil {
		t.Fatalf("stage A: %v", err)
	}
	resp, err := dst.s.PrepareLiveFirmwareTarget(dst.peer, &pb.PrepareLiveFirmwareTargetRequest{
		VmName: "os1", Uuid: a.uuid, CreatedAt: dst.row.CreatedAt, AttemptId: fwLiveAttempt1,
		ProtocolVersion: liveFirmwareProtocolVersion, SrcRuntime: a.runtime, SrcApplicability: a.applicability,
		SourceDomainActive: true, Nvram: []byte("os1's UEFI vars"),
	})
	if err != nil {
		t.Fatalf("Prepare refused a well-formed move: %v", err)
	}
	for who, rt := range map[string]*pb.FirmwareRuntime{"src_runtime": a.runtime, "dst_runtime": resp.GetDstRuntime()} {
		if _, _, ok := splitLiveFirmwareFingerprint(rt.GetOvmfFingerprint()); !ok {
			t.Fatalf("%s fingerprint %q is not the live firmware format", who, rt.GetOvmfFingerprint())
		}
	}
	if src.code.checks != 1 || dstHost.checks != 1 {
		t.Fatalf("host checks: source %d, target %d; want one each, through SetLiveFirmwareHost", src.code.checks, dstHost.checks)
	}
	if err := liveFirmwareStageB("os1", "dst-host", a, resp, nil); err != nil {
		t.Fatalf("stage B refused the target's answer: %v", err)
	}
	if _, ok, err := fwmig.New(dst.s.dataDir).GetHoldFor("os1", fwmig.Binding{UUID: a.uuid, CreatedAt: dst.row.CreatedAt, Attempt: fwLiveAttempt1}); !ok || err != nil {
		t.Fatalf("the target holds nothing: %v %v", ok, err)
	}
}
