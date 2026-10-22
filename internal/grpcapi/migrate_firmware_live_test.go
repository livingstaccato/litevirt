package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The source half of a live firmware move (spec §6.1), driven through
// MigrateVM between two Servers over one database (as the fleet's shared CRDT
// is): the source "src-host" and the target "dst-host", each with its own
// firmware store and libvirt fake. The source's peer calls reach the target's
// handlers through fwlPeer; its libvirt lands a FirmwareLive migrate on the
// target's fake (libvirtfake.LandFirmwareLive).

const fwlVM = "os1"

var (
	fwlPermall = []byte("os1's TPM state, sealing its disk key")
	fwlNvram   = []byte("os1's UEFI vars, with its enrolled keys")
)

// fwlLog is the order the move's steps were taken in.
type fwlLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *fwlLog) add(s string) {
	l.mu.Lock()
	l.steps = append(l.steps, s)
	l.mu.Unlock()
}

func (l *fwlLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.steps...)
}

func (l *fwlLog) has(s string) bool {
	for _, x := range l.get() {
		if x == s {
			return true
		}
	}
	return false
}

// fwlPeer is the target as the source's peer client reaches it: the live
// firmware RPCs run the target Server's handlers as the source's mTLS peer;
// host admission, EnsureDisks and the CPU check are answered here.
type fwlPeer struct {
	*fakeDestPeer
	r *fwlRig

	mu            sync.Mutex
	unimplemented map[string]bool
	// actionErr, when set, fails a forwarded doctor action (not a read)
	// before it reaches the target, as a transport would.
	actionErr error
	// prepareAfter replaces Prepare's answer after the handler ran.
	prepareAfter func(*pb.PrepareLiveFirmwareTargetResponse, error) (*pb.PrepareLiveFirmwareTargetResponse, error)
	// abortAnswer, when set, answers Abort in place of the handler.
	abortAnswer func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error)
	aborts      []*pb.AbortLiveFirmwareTargetRequest
	// verifyAnswer and releaseAnswer, when set, answer in place of the
	// handler; call runs the handler.
	verifyAnswer  func(call func() (*pb.VerifyLiveFirmwareTargetResponse, error)) (*pb.VerifyLiveFirmwareTargetResponse, error)
	releaseAnswer func(call func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error)
	// dialErr, when set, fails the source's dial of the target.
	dialErr func() error
	// readAnswer, when set, rewrites the target's answer to a doctor read.
	readAnswer func(*pb.FirmwareMoveDoctorResponse) *pb.FirmwareMoveDoctorResponse
	ensures    []*pb.EnsureDisksRequest
	ensureTLS  bool
	cpuChecks  int
	cleanups   int
	coldCalls  int
}

func (p *fwlPeer) refuse(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unimplemented[name] {
		return status.Errorf(codes.Unimplemented, "unknown method %s", name)
	}
	return nil
}

func (p *fwlPeer) ReserveHostCapacity(ctx context.Context, req *pb.ReserveHostCapacityRequest, o ...grpc.CallOption) (*pb.ReserveHostCapacityResponse, error) {
	return p.fakeDestPeer.ReserveHostCapacity(ctx, req, o...)
}

func (p *fwlPeer) ReleaseHostCapacity(ctx context.Context, req *pb.ReleaseHostCapacityRequest, o ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.fakeDestPeer.ReleaseHostCapacity(ctx, req, o...)
}

func (p *fwlPeer) CleanupMigrationArtifacts(context.Context, *pb.CleanupMigrationArtifactsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	p.mu.Lock()
	p.cleanups++
	p.mu.Unlock()
	return &emptypb.Empty{}, nil
}

func (p *fwlPeer) CheckCPUCompatibility(context.Context, *pb.CheckCPUCompatibilityRequest, ...grpc.CallOption) (*pb.CheckCPUCompatibilityResponse, error) {
	p.mu.Lock()
	p.cpuChecks++
	p.mu.Unlock()
	return &pb.CheckCPUCompatibilityResponse{Runnable: true}, nil
}

func (p *fwlPeer) EnsureDisks(_ context.Context, req *pb.EnsureDisksRequest, _ ...grpc.CallOption) (*pb.EnsureDisksResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensures = append(p.ensures, req)
	resp := &pb.EnsureDisksResponse{MigrationTlsReady: req.GetWantMigrationTls() && p.ensureTLS, InstallerIsoResolved: map[string]string{}}
	for _, d := range req.GetDisks() {
		resp.CreatedPaths = append(resp.CreatedPaths, d.GetPath())
	}
	for _, iso := range req.GetInstallerIsoPaths() {
		resp.InstallerIsoResolved[iso] = iso
	}
	return resp, nil
}

// EnsureFirmwareState is the cold move's: a live move never sends it.
func (p *fwlPeer) EnsureFirmwareState(context.Context, *pb.EnsureFirmwareStateRequest, ...grpc.CallOption) (*pb.EnsureFirmwareStateResponse, error) {
	p.mu.Lock()
	p.coldCalls++
	p.mu.Unlock()
	return nil, status.Error(codes.Internal, "fwlPeer: a cold firmware move was attempted")
}

func (p *fwlPeer) PrepareLiveFirmwareTarget(_ context.Context, req *pb.PrepareLiveFirmwareTargetRequest, _ ...grpc.CallOption) (*pb.PrepareLiveFirmwareTargetResponse, error) {
	p.r.log.add("prepare")
	if err := p.refuse("PrepareLiveFirmwareTarget"); err != nil {
		return nil, err
	}
	resp, err := p.r.dst.PrepareLiveFirmwareTarget(p.r.peer, req)
	if p.prepareAfter != nil {
		return p.prepareAfter(resp, err)
	}
	return resp, err
}

func (p *fwlPeer) VerifyLiveFirmwareTarget(_ context.Context, req *pb.VerifyLiveFirmwareTargetRequest, _ ...grpc.CallOption) (*pb.VerifyLiveFirmwareTargetResponse, error) {
	p.r.log.add("verify")
	if st, _ := p.r.dstFake.RawState(fwlVM); st != libvirtfake.StatePaused {
		p.r.log.add("verify:target-not-paused:" + string(st))
	}
	if err := p.refuse("VerifyLiveFirmwareTarget"); err != nil {
		return nil, err
	}
	call := func() (*pb.VerifyLiveFirmwareTargetResponse, error) {
		return p.r.dst.VerifyLiveFirmwareTarget(p.r.peer, req)
	}
	p.mu.Lock()
	answer := p.verifyAnswer
	p.mu.Unlock()
	if answer != nil {
		return answer(call)
	}
	return call()
}

func (p *fwlPeer) ReleaseLiveFirmwareTarget(_ context.Context, req *pb.ReleaseLiveFirmwareTargetRequest, _ ...grpc.CallOption) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
	p.r.log.add("release")
	if err := p.refuse("ReleaseLiveFirmwareTarget"); err != nil {
		return nil, err
	}
	call := func() (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return p.r.dst.ReleaseLiveFirmwareTarget(p.r.peer, req)
	}
	p.mu.Lock()
	answer := p.releaseAnswer
	p.mu.Unlock()
	if answer != nil {
		return answer(call)
	}
	return call()
}

func (p *fwlPeer) AbortLiveFirmwareTarget(_ context.Context, req *pb.AbortLiveFirmwareTargetRequest, _ ...grpc.CallOption) (*pb.AbortLiveFirmwareTargetResponse, error) {
	p.r.log.add("abort:" + req.GetMode().String())
	p.mu.Lock()
	p.aborts = append(p.aborts, req)
	answer := p.abortAnswer
	p.mu.Unlock()
	if err := p.refuse("AbortLiveFirmwareTarget"); err != nil {
		return nil, err
	}
	if answer != nil {
		return answer(req)
	}
	return p.r.dst.AbortLiveFirmwareTarget(p.r.peer, req)
}

// fwlCaptureVirt records the parameters the source hands libvirt.
type fwlCaptureVirt struct {
	*libvirtfake.Fake
	mu  *sync.Mutex
	got *[]lv.MigrateParams
	// after, when set, runs once libvirt's migrate returned.
	after *func()
	// onResumeSource, when set, runs as the source guest is resumed (§7 M1p).
	onResumeSource *func()
	// onUndefineLeftover, when set, runs as the source cleanup undefines the
	// moved VM's leftover definition (§6.7 step 3).
	onUndefineLeftover *func()
}

func (v fwlCaptureVirt) UndefineFirmwareMoveLeftover(name, uuid, attempt string) error {
	if v.onUndefineLeftover != nil && *v.onUndefineLeftover != nil {
		(*v.onUndefineLeftover)()
	}
	return v.Fake.UndefineFirmwareMoveLeftover(name, uuid, attempt)
}

func (v fwlCaptureVirt) ResumeFirmwareMoveSource(name, uuid, attempt string) error {
	if v.onResumeSource != nil && *v.onResumeSource != nil {
		(*v.onResumeSource)()
	}
	return v.Fake.ResumeFirmwareMoveSource(name, uuid, attempt)
}

func (v fwlCaptureVirt) MigrateToTarget(name, uri string, p lv.MigrateParams) error {
	v.mu.Lock()
	*v.got = append(*v.got, p)
	v.mu.Unlock()
	err := v.Fake.MigrateToTarget(name, uri, p)
	if v.after != nil && *v.after != nil {
		(*v.after)()
	}
	return err
}

// fwlRig is os1 (Secure Boot + vTPM) running on src-host, eligible for a live
// move to dst-host: memory-only over the tunnel (a shared disk), or a storage
// copy (one host-local disk, --with-storage).
type fwlRig struct {
	t        *testing.T
	src, dst *Server
	srcFake  *libvirtfake.Fake
	dstFake  *libvirtfake.Fake
	srcStore *lv.FirmwareStore
	dstStore *lv.FirmwareStore
	peerC    *fwlPeer
	peer     context.Context // src-host, as the target sees it
	log      *fwlLog
	params   []lv.MigrateParams
	paramsMu sync.Mutex
	// afterMigrate runs once libvirt's migrate returned on the source.
	afterMigrate func()
	// onResumeSource runs as the source guest is resumed (§7 M1p).
	onResumeSource func()
	// onUndefineLeftover runs as the source cleanup undefines the leftover.
	onUndefineLeftover func()
	sbOnly             bool
	storage            bool
	spec               map[string]any
}

type fwlOpts struct {
	storage bool
	// liveXMLExtra is appended inside <devices> of the running definition.
	liveXMLExtra string
	cpuMode      string
	// sbOnly is a Secure Boot VM without a vTPM: no permall anywhere.
	sbOnly bool
}

func newFwlRig(t *testing.T, o fwlOpts) *fwlRig {
	t.Helper()
	r := &fwlRig{t: t, log: &fwlLog{}, storage: o.storage, sbOnly: o.sbOnly}
	layout := t.TempDir()

	r.src = testServerWithLocks(t)
	r.src.hostName = "src-host"
	r.srcStore = &lv.FirmwareStore{DataDir: r.src.dataDir, SwtpmBase: t.TempDir()}
	r.src.SetFirmwareStore(r.srcStore)
	r.srcFake = libvirtfake.New()
	r.srcFake.SetFirmwareStore(r.srcStore)
	fwmig.Wire(r.srcFake, r.srcStore)
	r.src.virt = fwlCaptureVirt{Fake: r.srcFake, mu: &r.paramsMu, got: &r.params, after: &r.afterMigrate, onResumeSource: &r.onResumeSource,
		onUndefineLeftover: &r.onUndefineLeftover}
	setFWTestFirmwarePaths(t, r.src)
	r.src.SetFirmwareLayoutDirForTest(layout)
	r.src.SetLiveFirmwareHost(&stubFWCode{installed: lv.InstalledFirmwareCode{Runtime: fwFloorRuntime}, running: fwFloorRuntime})
	r.src.SetMigrationTLS(func() (bool, error) { return true, nil })

	r.dst = testServerWithLocks(t)
	r.dst.db = r.src.db
	r.dst.hostName = "dst-host"
	r.dstStore = &lv.FirmwareStore{DataDir: r.dst.dataDir, SwtpmBase: t.TempDir()}
	r.dst.SetFirmwareStore(r.dstStore)
	r.dstFake = libvirtfake.New()
	r.dstFake.SetFirmwareStore(r.dstStore)
	fwmig.Wire(r.dstFake, r.dstStore)
	r.dst.virt = r.dstFake
	r.dst.SetFirmwarePaths(r.src.firmware)
	r.dst.SetFirmwareLayoutDirForTest(layout)
	r.dst.SetLiveFirmwareHost(&stubFWCode{installed: lv.InstalledFirmwareCode{Runtime: fwFloorRuntime}})
	r.dst.db.MarkReplicaCaughtUpForTests("test")

	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, r.src.db, corrosion.HostRecord{Name: "dst-host", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CPUTotal: 8, MemTotal: 16384}); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{corrosion.LabelTPMCapable, corrosion.LabelSecureBootCapable, corrosion.LabelFwLiveMigrate} {
		if err := corrosion.SetHostLabel(ctx, r.src.db, "dst-host", l, "true"); err != nil {
			t.Fatal(err)
		}
	}
	r.peer = context.WithValue(context.WithValue(peerCtxFor(t, r.dst, "src-host"), ctxKeyUsername, "admin"), ctxKeyRole, "admin")

	r.spec = map[string]any{"name": fwlVM, "secure_boot": true, "tpm": !o.sbOnly, "firmware": "uefi", "uuid": fwLiveUUID}
	if o.cpuMode != "" {
		r.spec["cpu_mode"] = o.cpuMode
	}
	spec, _ := json.Marshal(r.spec)
	disk := corrosion.DiskRecord{VMName: fwlVM, DiskName: "root", Path: "/srv/nfs/os1-root.qcow2", StorageType: "nfs", TargetDev: "vda", SizeBytes: 1 << 20}
	if o.storage {
		disk.Path, disk.StorageType = filepath.Join(r.src.dataDir, "disks", "os1-root.qcow2"), "local"
	}
	if err := corrosion.InsertVM(ctx, r.src.db, corrosion.VMRecord{Name: fwlVM, HostName: "src-host", State: "running",
		CPUActual: 1, MemActual: 1024, Spec: string(spec)}, nil, []corrosion.DiskRecord{disk}); err != nil {
		t.Fatal(err)
	}

	x := fwLiveDomainXML(fwLiveUUID, r.src.firmware.SecbootCode, r.srcStore.NvramPath(fwlVM), !o.sbOnly, "yes")
	if o.liveXMLExtra != "" {
		x = strings.Replace(x, "</devices>", o.liveXMLExtra+"</devices>", 1)
	}
	r.srcFake.SetInactiveXML(fwlVM, x)
	r.srcFake.SetActiveXML(fwlVM, x)
	r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
	if !o.sbOnly {
		r.write(filepath.Join(r.srcStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall"), fwlPermall)
	}
	r.write(r.srcStore.NvramPath(fwlVM), fwlNvram)

	r.srcFake.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		r.log.add("migrate")
		return r.dstFake.LandFirmwareLive(r.srcFake, name, p)
	}
	r.dstFake.OnRunning = func(name string) { r.log.add("target-running") }
	r.src.fwLive.stepHook = func(step string) { r.log.add(step) }

	r.peerC = &fwlPeer{fakeDestPeer: &fakeDestPeer{leaseID: "dst-lease"}, r: r, ensureTLS: true, unimplemented: map[string]bool{}}
	r.src.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		r.peerC.mu.Lock()
		dialErr := r.peerC.dialErr
		r.peerC.mu.Unlock()
		if dialErr != nil {
			if err := dialErr(); err != nil {
				return nil, nil, err
			}
		}
		return r.peerC, func() {}, nil
	}

	ob, of := fwLiveRetryBackoff, fwLiveRetryFor
	fwLiveRetryBackoff, fwLiveRetryFor = 5*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { fwLiveRetryBackoff, fwLiveRetryFor = ob, of })
	return r
}

func (r *fwlRig) write(p string, b []byte) {
	r.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *fwlRig) migrate() error {
	return r.src.MigrateVM(&pb.MigrateVMRequest{VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
		WithStorage: r.storage}, &mockMigrateStream{ctx: adminCtx()})
}

func (r *fwlRig) marker() (fwmig.Marker, bool) {
	r.t.Helper()
	m, ok, err := fwmig.New(r.src.dataDir).GetMarker(fwlVM)
	if err != nil {
		r.t.Fatalf("GetMarker: %v", err)
	}
	return m, ok
}

// markerAtCleanup records the marker as it is when the source cleanup is
// called: the cleanup removes it.
func (r *fwlRig) markerAtCleanup() *fwmig.Marker {
	var at fwmig.Marker
	r.src.fwLive.stepHook = func(step string) {
		r.log.add(step)
		if step == "cleanup" {
			at, _ = r.marker()
		}
	}
	return &at
}

func (r *fwlRig) hold() (fwmig.Hold, bool) {
	r.t.Helper()
	h, ok, err := fwmig.New(r.dst.dataDir).GetHold(fwlVM)
	if err != nil {
		r.t.Fatalf("GetHold: %v", err)
	}
	return h, ok
}

func (r *fwlRig) row() *corrosion.VMRecord {
	r.t.Helper()
	vm, err := corrosion.GetVM(context.Background(), r.src.db, fwlVM)
	if err != nil || vm == nil {
		r.t.Fatalf("GetVM: %v %v", vm, err)
	}
	return vm
}

func (r *fwlRig) aborts() []*pb.AbortLiveFirmwareTargetRequest {
	r.peerC.mu.Lock()
	defer r.peerC.mu.Unlock()
	return append([]*pb.AbortLiveFirmwareTargetRequest(nil), r.peerC.aborts...)
}

func (r *fwlRig) migrateParams() []lv.MigrateParams {
	r.paramsMu.Lock()
	defer r.paramsMu.Unlock()
	return append([]lv.MigrateParams(nil), r.params...)
}

// requireSourceIntact: the source's firmware state is as it was, and its
// guest still runs there.
func (r *fwlRig) requireSourceIntact(why string) {
	r.t.Helper()
	if b, _ := os.ReadFile(filepath.Join(r.srcStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")); !r.sbOnly && !bytes.Equal(b, fwlPermall) {
		r.t.Errorf("%s: the source permall is %q", why, b)
	}
	if b, _ := os.ReadFile(r.srcStore.NvramPath(fwlVM)); !bytes.Equal(b, fwlNvram) {
		r.t.Errorf("%s: the source NVRAM is %q", why, b)
	}
}

// requireUndone: the move was undone before cutover — Abort PRE_CUTOVER
// sent, no hold left on the target, no marker on the source, the guest
// running on the source with its row, its state intact.
func (r *fwlRig) requireUndone(why string) {
	r.t.Helper()
	ab := r.aborts()
	if len(ab) == 0 || ab[0].GetMode() != pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER {
		r.t.Errorf("%s: aborts %v, want Abort PRE_CUTOVER", why, ab)
	}
	if _, ok := r.hold(); ok {
		r.t.Errorf("%s: the target still holds the attempt", why)
	}
	if m, ok := r.marker(); ok {
		r.t.Errorf("%s: the source marker is left (%s)", why, m.Phase)
	}
	if vm := r.row(); vm.HostName != "src-host" || vm.State != "running" {
		r.t.Errorf("%s: row is %s on %s, want running on src-host", why, vm.State, vm.HostName)
	}
	if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		r.t.Errorf("%s: the source domain is %q, want running", why, st)
	}
	r.requireSourceIntact(why)
}

// The happy flow, in its order (spec §6.1): Prepare, the migration (the
// target guest arrives paused), Verify of the paused guest, the commit,
// Release (the only resume), and the cleanup call once the NVRAM is
// confirmed; the source's state is still whole when cleanup is called.
//
// Mutations: resume or release before Verify (or before the commit); commit
// before Verify; skip the NVRAM confirmation — red.
func TestMigrateVM_FirmwareLive_HappyPathOrder(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	var atCleanup struct {
		marker fwmig.Marker
		ok     bool
	}
	r.src.fwLive.stepHook = func(step string) {
		r.log.add(step)
		switch step {
		case "commit":
			if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StatePaused {
				r.log.add("commit:target-not-paused")
			}
			// The paused guest holds the source's TPM state, byte for byte
			// (once it runs, its swtpm writes the state back).
			if b, _ := os.ReadFile(filepath.Join(r.dstStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")); !bytes.Equal(b, fwlPermall) {
				r.log.add("commit:target-permall-differs")
			}
		case "cleanup":
			atCleanup.marker, atCleanup.ok = r.marker()
			r.requireSourceIntact("at the cleanup call")
		}
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v (steps %v)", err, r.log.get())
	}
	want := []string{"prepare", "migrate", "verify", "commit", "release", "target-running", "cleanup"}
	if got := r.log.get(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("steps %v, want %v", got, want)
	}
	if !atCleanup.ok || atCleanup.marker.Phase != fwmig.PhaseReleased {
		t.Errorf("at the cleanup call the marker is %+v (present %v), want released", atCleanup.marker.Phase, atCleanup.ok)
	}
	if m := atCleanup.marker; m.SrcStopReason != fwmig.StopReasonMigrated || m.SrcPermallSHA256 != fwtSHA(fwlPermall) ||
		m.SrcNvramSHA256 != fwtSHA(fwlNvram) || m.Route != fwmig.RouteTunnelled {
		t.Errorf("marker %+v: want reason migrated, the source's final hashes and the tunnelled route", m)
	}
	if _, ok := r.hold(); ok {
		t.Error("the target still holds the attempt after a confirmed release")
	}
	if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		t.Errorf("target domain %q, want running", st)
	}
	if b, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM)); !bytes.Equal(b, fwlNvram) {
		t.Errorf("target NVRAM %q, want the source's final", b)
	}
	if vm := r.row(); vm.HostName != "dst-host" || vm.State != "running" {
		t.Errorf("row %s on %s, want running on dst-host", vm.State, vm.HostName)
	}
	// The source cleanup ran (§6.7, T-22 pins its order).
	r.requireCleanedUp("after the happy flow")
}

// T-3b: a live firmware move hands libvirt FirmwareLive and Paused, though
// the guest needs no paused NIC hand-over.
//
// Mutation: armed.apply overwrites Paused with the NIC need; drop
// FirmwareLive from the params — red.
func TestMigrateVM_FirmwareLive_ParamsPausedWithoutNICPause(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	if r.src.needsPausedStart(context.Background(), fwlVM, true) {
		t.Fatal("the rig's guest needs a paused NIC hand-over; the test proves nothing")
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	ps := r.migrateParams()
	if len(ps) != 1 {
		t.Fatalf("libvirt was asked %d times, want once", len(ps))
	}
	if p := ps[0]; !p.FirmwareLive || !p.Paused || !p.Live {
		t.Fatalf("params FirmwareLive=%v Paused=%v Live=%v, want all true", p.FirmwareLive, p.Paused, p.Live)
	}
}

// T-29: a live firmware move takes the live path at every branch that used
// to send a firmware VM cold (spec §6.0): the CPU preflight runs, a host-local
// disk is copied (WithStorage), EnsureDisks is asked about the running
// domain, and the cold move is never attempted.
//
// Mutation: revert any one of those lines to fwVM — red.
func TestMigrateVM_FirmwareLive_TakesLivePath(t *testing.T) {
	iso := filepath.Join(t.TempDir(), "installer.iso")
	if err := os.WriteFile(iso, []byte("iso"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newFwlRig(t, fwlOpts{storage: true, cpuMode: "host-passthrough",
		liveXMLExtra: `<disk type='file' device='cdrom'><source file='` + iso + `'/><target dev='sdc'/></disk>`})
	at := r.markerAtCleanup()
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move with storage: %v (steps %v)", err, r.log.get())
	}
	p := r.peerC
	if p.cpuChecks == 0 {
		t.Error("the CPU preflight was not run for a live firmware move")
	}
	if p.coldCalls != 0 {
		t.Error("the cold firmware move was attempted")
	}
	if len(p.ensures) == 0 || !p.ensures[0].GetInstallerIsoRuntime() || len(p.ensures[0].GetDisks()) != 1 {
		t.Errorf("EnsureDisks %v: want the running domain's installer ISO and the host-local disk's stub", p.ensures)
	}
	ps := r.migrateParams()
	if len(ps) != 1 || !ps[0].WithStorage || !ps[0].Live || !ps[0].FirmwareLive {
		t.Fatalf("params %+v: want one live firmware migrate with storage", ps)
	}
	if m := *at; m.Route != fwmig.RouteStorageCopy || len(m.CreatedStubs) != 1 {
		t.Errorf("marker route %s, stubs %v: want storage_copy and the stub EnsureDisks created", m.Route, m.CreatedStubs)
	}
}

// T-29, memory-only: a live firmware move over the tunnel asks EnsureDisks
// about the running domain too (its installer ISO).
//
// Mutation: revert the memory-only EnsureDisks line to fwVM — red.
func TestMigrateVM_FirmwareLive_TakesLivePathMemoryOnly(t *testing.T) {
	iso := filepath.Join(t.TempDir(), "installer.iso")
	if err := os.WriteFile(iso, []byte("iso"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newFwlRig(t, fwlOpts{liveXMLExtra: `<disk type='file' device='cdrom'><source file='` + iso + `'/><target dev='sdc'/></disk>`})
	at := r.markerAtCleanup()
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v (steps %v)", err, r.log.get())
	}
	p := r.peerC
	if len(p.ensures) == 0 || !p.ensures[0].GetInstallerIsoRuntime() || len(p.ensures[0].GetDisks()) != 0 {
		t.Errorf("EnsureDisks %v: want the running domain's installer ISO and no stub", p.ensures)
	}
	if m := *at; m.Route != fwmig.RouteTunnelled {
		t.Errorf("marker route %s, want tunnelled", m.Route)
	}
}

// T-12: a target whose build lacks the live firmware RPCs refuses the move
// with today's cold-only text, naming the build; nothing is left on either
// host and no abort is sent.
//
// Mutation: treat Unimplemented as OK, or abort it — red.
func TestMigrateVM_FirmwareLive_UnimplementedTargetRefusesNoWrite(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.unimplemented["PrepareLiveFirmwareTarget"] = true
	err := r.migrate()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "runs a build without live firmware migration") ||
		!strings.Contains(err.Error(), "--cold") {
		t.Fatalf("got %v, want the cold-only refusal naming the target's build", err)
	}
	if len(r.aborts()) != 0 {
		t.Errorf("aborts were sent to a target that has none: %v", r.aborts())
	}
	if _, ok := r.marker(); ok {
		t.Error("a marker is left on the source")
	}
	if _, ok := r.hold(); ok {
		t.Error("the target holds something")
	}
	if len(r.migrateParams()) != 0 {
		t.Error("libvirt was asked to migrate")
	}
	if vm := r.row(); vm.State != "running" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s", vm.State, vm.HostName)
	}
}

// Stage B refuses the target's answer after the target wrote its hold: the
// move is aborted before cutover (§7 P2), the target's attempt state deleted
// (rule D: prepared, source active), the marker removed, and the refusal
// names the cold move (merge review m-2).
//
// Mutation: return stage B's refusal without the abort — red.
func TestMigrateVM_FirmwareLive_StageBRefusalAbortsAndUnmarks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.prepareAfter = func(resp *pb.PrepareLiveFirmwareTargetResponse, err error) (*pb.PrepareLiveFirmwareTargetResponse, error) {
		if err != nil {
			return nil, err
		}
		resp.DstRuntime.Qemu = "9.9.9"
		return resp, nil
	}
	err := r.migrate()
	requireRefusal(t, err, "qemu differs")
	r.requireUndone("after a stage B refusal")
	if fwtExists(r.dstStore.NvramPath(fwlVM)) {
		t.Error("the NVRAM Prepare materialised is left on the target")
	}
}

// A Prepare that fails after the target wrote its hold is aborted before
// cutover too, and its error carries the cold move (merge review m-2).
//
// Mutation: pass the Prepare error through without the abort, or without the
// cold text — red.
func TestMigrateVM_FirmwareLive_PrepareErrorAfterHoldAborts(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.prepareAfter = func(resp *pb.PrepareLiveFirmwareTargetResponse, err error) (*pb.PrepareLiveFirmwareTargetResponse, error) {
		if err != nil {
			return nil, err
		}
		return nil, status.Error(codes.Internal, "the target failed after its hold write")
	}
	err := r.migrate()
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "failed after its hold write") || !strings.Contains(err.Error(), "--cold") {
		t.Fatalf("got %v, want the target's Internal error with the cold move", err)
	}
	r.requireUndone("after a Prepare error")
}

// Stage C refuses the resolved route (a storage copy the target cannot
// encrypt): aborted before cutover, the stubs cleaned up, the marker removed.
//
// Mutation: skip stage C, or return without the abort — red.
func TestMigrateVM_FirmwareLive_StageCRefusalAborts(t *testing.T) {
	r := newFwlRig(t, fwlOpts{storage: true})
	r.src.allowPlaintextStorageMigration = true // stage C refuses it for firmware anyway
	r.peerC.ensureTLS = false
	err := r.migrate()
	requireRefusal(t, err, "would not be encrypted")
	r.requireUndone("after a stage C refusal")
	if r.peerC.cleanups == 0 {
		t.Error("the stubs EnsureDisks created were not cleaned up")
	}
	if len(r.migrateParams()) != 0 {
		t.Error("libvirt was asked to migrate")
	}
}

// An abort before cutover that the target does not answer parks the move as
// target_unreachable, with its condition: the target may still hold the
// attempt, so the marker keeps vetoing.
//
// Mutation: remove the marker without an answer — red.
func TestMigrateVM_FirmwareLive_AbortUnansweredParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.prepareAfter = func(resp *pb.PrepareLiveFirmwareTargetResponse, err error) (*pb.PrepareLiveFirmwareTargetResponse, error) {
		resp.DstRuntime.Qemu = "9.9.9"
		return resp, err
	}
	r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	_ = r.migrate()
	m, ok := r.marker()
	if !ok || m.Phase != fwmig.PhaseTargetUnreachable || m.ParkedFrom != fwmig.PhasePreparing {
		t.Fatalf("marker %+v (present %v), want parked target_unreachable from preparing (stage B refused)", m, ok)
	}
	requireFwmigCondition(t, r.src, condFwmigTargetUnreachable)
	if vm := r.row(); vm.State != "running" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s, want running on src-host", vm.State, vm.HostName)
	}
}

// D2-9 M-6: Abort answers OK (it holds nothing of the attempt) while a
// domain of the VM is defined on the target. That is not "nothing held":
// the move parks.
//
// Mutation: read !refused alone — red.
func TestMigrateVM_FirmwareLive_AbortWithTargetDomainParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.prepareAfter = func(resp *pb.PrepareLiveFirmwareTargetResponse, err error) (*pb.PrepareLiveFirmwareTargetResponse, error) {
		resp.DstRuntime.Qemu = "9.9.9"
		return resp, err
	}
	r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		return &pb.AbortLiveFirmwareTargetResponse{TargetDomain: &pb.TargetDomain{Present: true, State: "paused"}}, nil
	}
	_ = r.migrate()
	// D2-12a review m-4: a reachable target that holds a domain is not
	// "unreachable"; the park is decided from the answer.
	if m, ok := r.marker(); !ok || m.Phase != fwmig.PhaseTargetRan {
		t.Fatalf("marker %+v (present %v), want parked target_ran: the target has a domain of the VM", m, ok)
	}
}

// D2-9 M-4: a target setup that outlasts liveFirmwareStep4Limit is not
// started — the target's hold sweep may have disposed of the hold — and is
// undone before cutover.
//
// Mutation: drop the limit check — red.
func TestMigrateVM_FirmwareLive_Step4OverLimitAborts(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	old := liveFirmwareStep4Limit
	liveFirmwareStep4Limit = -time.Second
	t.Cleanup(func() { liveFirmwareStep4Limit = old })
	err := r.migrate()
	requireRefusal(t, err, "setting up the target took")
	if len(r.migrateParams()) != 0 {
		t.Fatal("libvirt was asked to migrate after the limit")
	}
	r.requireUndone("after the setup outlasted its limit")
}

// The migration call fails with the source guest still running: the move is
// aborted before cutover and its marker removed once the target answered,
// the row back to running.
//
// Mutation: leave the marker; skip the abort — red.
func TestMigrateVM_FirmwareLive_MigrateErrorSourceRunningAborts(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.srcFake.FailMigrateToTarget = func(string, string) error { return errors.New("injected migration failure") }
	if err := r.migrate(); err == nil {
		t.Fatal("the move succeeded; the scenario needs libvirt to fail it")
	}
	r.requireUndone("after the migration failed")
}

// A Verify that does not MATCH never commits: the move parks with both copies
// kept (here TARGET_RAN, the guard failing), the row still on the source and
// Release never sent.
//
// Mutation: commit on any verdict — red.
func TestMigrateVM_FirmwareLive_NoCommitWithoutMatch(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.dstFake.OnRunning = nil
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning) // the guard failed
		return nil
	}
	err := r.migrate()
	if err == nil {
		t.Fatal("the move succeeded with a target guest that ran")
	}
	if m, ok := r.marker(); !ok || m.Phase != fwmig.PhaseTargetRan || m.ParkedFrom != fwmig.PhaseCutover {
		t.Fatalf("marker %+v, want parked target_ran from cutover", m)
	}
	if r.log.has("commit") || r.log.has("release") {
		t.Fatalf("steps %v: committed or released without a MATCH", r.log.get())
	}
	if vm := r.row(); vm.HostName != "src-host" {
		t.Errorf("row on %s, want src-host", vm.HostName)
	}
	r.requireSourceIntact("after a TARGET_RAN verdict")
}

// T-23: an adopted live firmware migration (the client went away during the
// copy) verifies before it commits, and releases only after the commit.
//
// Mutation: commit an adopted firmware move without Verify — red.
func TestAdoptedFirmwareMigration_VerifiesBeforeCommit(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	proceed := make(chan struct{})
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		cancel() // the client goes away mid-copy
		<-proceed
		return land(name, uri, p)
	}
	err := r.src.MigrateVM(&pb.MigrateVMRequest{VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE},
		&mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("got %v, want the adopted move's DeadlineExceeded", err)
	}
	close(proceed)
	deadline := time.Now().Add(10 * time.Second)
	for !r.log.has("cleanup") {
		if time.Now().After(deadline) {
			t.Fatalf("the adopted move never reached cleanup: steps %v", r.log.get())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// "cleanup" is logged as the cleanup starts. The adopter goes on after it
	// (it removes the marker, retains the source's files, records the event)
	// and drops the per-VM lock as its last act, so taking the lock is how this
	// test waits for it: returning earlier let it write into the rig's
	// t.TempDir directories while they were being removed ("directory not
	// empty").
	r.src.lockVM(fwlVM)()
	want := []string{"prepare", "migrate", "verify", "commit", "release", "target-running", "cleanup"}
	if got := r.log.get(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("steps %v, want %v", got, want)
	}
}

// requireFwmigCondition: s raised code for os1, open.
func requireFwmigCondition(t *testing.T, s *Server, code string) {
	t.Helper()
	c, found, err := corrosion.GetHealthCondition(context.Background(), s.db, firmwareMigrationEvaluator, code, "vm", fwlVM)
	if err != nil || !found || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition %s: %+v found=%v err=%v, want it open", code, c, found, err)
	}
}

// N1: the released guest's NVRAM never becomes the source's final NVRAM
// (it wrote a variable at once): the move parks as nvram_unconfirmed, the
// source state kept, and the cleanup is not called.
//
// Mutation: take a release without nvram_confirmed as confirmed — red.
func TestMigrateVM_FirmwareLive_NvramUnconfirmedParks(t *testing.T) {
	fwvFast(t, 5*time.Millisecond, 100*time.Millisecond)
	r := newFwlRig(t, fwlOpts{})
	r.dstFake.OnRunning = func(string) {
		r.log.add("target-running")
		r.write(r.dstStore.NvramPath(fwlVM), []byte("a variable the guest wrote at once"))
	}
	if err := r.migrate(); err == nil {
		t.Fatal("the move reported success with its NVRAM unconfirmed")
	}
	if m, ok := r.marker(); !ok || m.Phase != fwmig.PhaseNvramUnconfirmed || m.ParkedFrom != fwmig.PhaseCommitted {
		t.Fatalf("marker %+v (present %v), want parked nvram_unconfirmed from committed", m, ok)
	}
	if r.log.has("cleanup") {
		t.Fatal("the cleanup was called with the NVRAM unconfirmed")
	}
	requireFwmigCondition(t, r.src, condFwmigNvramUnconfirmed)
	r.requireSourceIntact("with the NVRAM unconfirmed")
}

// §7 M1b: the migration call fails after the guest left the source (its
// domain is inactive): the move goes on to Verify, and commits on MATCH.
//
// Mutation: treat every migration error as a failure on the source — red.
func TestMigrateVM_FirmwareLive_MigrateErrorSourceInactiveVerifies(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
		return errors.New("injected confirm-phase failure")
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v (steps %v)", err, r.log.get())
	}
	want := []string{"prepare", "migrate", "verify", "commit", "release", "target-running", "cleanup"}
	if got := r.log.get(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("steps %v, want %v", got, want)
	}
	if len(r.aborts()) != 0 {
		t.Fatalf("aborted a move whose guest left the source: %v", r.aborts())
	}
}

// Step 7 (D2-12a review m-3): a migration that returned with the source
// domain still active and running is not a cutover but §7 M1: Abort
// PRE_CUTOVER, then (the target holds the landed guest paused under a
// prepared hold) the automatic DISCARD; the marker goes, the row is running,
// and Verify is never called. Never source_state_suspect, whose
// --accept-source would write the row stopped over a running guest.
//
// Mutation: park source_state_suspect for an active source; skip the active
// check — red.
func TestMigrateVM_FirmwareLive_SourceStillActiveIsM1(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.afterMigrate = func() { r.srcFake.SetState(fwlVM, libvirtfake.StateRunning) }
	if err := r.migrate(); err == nil {
		t.Fatal("the move succeeded with the source domain still active")
	}
	if r.log.has("verify") || r.log.has("commit") {
		t.Fatalf("steps %v: verified or committed with the source active", r.log.get())
	}
	requireAbortModes(t, r, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED)
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v, want it removed after the discard", m)
	}
	if vm := r.row(); vm.HostName != "src-host" || vm.State != "running" {
		t.Errorf("row %s on %s, want running on src-host", vm.State, vm.HostName)
	}
	r.requireSourceIntact("after the source stayed active")
}
