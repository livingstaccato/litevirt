package grpcapi

// A cold firmware migration defines the VM's domain on the target
// (EnsureFirmwareState) before the ownership handoff commits. Every way the
// attempt can fail in between — the request cancelled while the define was in
// flight, or after it — must take back what THIS attempt created there, or the
// retry is refused over "already-defined domain". It must not take back
// anything else: a domain the target already held is not this attempt's to
// remove, and neither is one a target too old to report what it created may or
// may not have made.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const (
	fwRollbackUUID = "cccccccc-3333-4333-8333-cccccccccccc"
	fwRollbackVM   = "fw"
	fwRollbackDst  = "dst-host"
)

// firmwareTargetPeer is the source's peer connection to the target: each RPC
// runs on the target Server as the peer's mTLS identity (admin) would.
type firmwareTargetPeer struct {
	pb.LiteVirtClient
	dst   *Server
	srcFP string // the source's firmware layout fingerprint

	// oldBuild makes the target a build from before attempt-scoped rollback:
	// it ignores attempt_id, replies with what decodes as an empty response,
	// and does not implement RollbackFirmwareState.
	oldBuild bool

	mu sync.Mutex
	// srcCtx is the source daemon calling the target: a trusted peer.
	srcCtx context.Context
	// afterEnsure, if set, sees the target's EnsureFirmwareState result and
	// decides what reaches the source (e.g. a cancellation that loses it).
	afterEnsure    func(*pb.EnsureFirmwareStateResponse, error) (*pb.EnsureFirmwareStateResponse, error)
	rollbacks      int
	cleanupUndefs  int
	ensureAttempts []string
}

func (p *firmwareTargetPeer) EnsureFirmwareState(_ context.Context, req *pb.EnsureFirmwareStateRequest, _ ...grpc.CallOption) (*pb.EnsureFirmwareStateResponse, error) {
	r := proto.Clone(req).(*pb.EnsureFirmwareStateRequest)
	// The two test servers share one filesystem, so their dataDirs (part of
	// the layout fingerprint) must differ. Translate the fingerprint as two
	// identically laid-out hosts would compute it.
	if r.SourceFirmwareFingerprint == p.srcFP {
		r.SourceFirmwareFingerprint = p.dst.firmwareLayoutFingerprint()
	}
	if p.oldBuild {
		r.AttemptId = "" // an unknown field to an older build
	}
	p.mu.Lock()
	p.ensureAttempts = append(p.ensureAttempts, req.AttemptId)
	hook := p.afterEnsure
	p.mu.Unlock()
	resp, err := p.dst.EnsureFirmwareState(p.srcCtx, r)
	if p.oldBuild && err == nil {
		resp = &pb.EnsureFirmwareStateResponse{} // google.protobuf.Empty on the wire
	}
	if hook != nil {
		return hook(resp, err)
	}
	return resp, err
}

func (p *firmwareTargetPeer) RollbackFirmwareState(_ context.Context, req *pb.RollbackFirmwareStateRequest, _ ...grpc.CallOption) (*pb.RollbackFirmwareStateResponse, error) {
	p.mu.Lock()
	p.rollbacks++
	p.mu.Unlock()
	if p.oldBuild {
		return nil, status.Error(codes.Unimplemented, "unknown method RollbackFirmwareState")
	}
	return p.dst.RollbackFirmwareState(adminCtx(), req)
}

func (p *firmwareTargetPeer) CleanupMigrationArtifacts(_ context.Context, req *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	p.mu.Lock()
	if req.UndefineDomain {
		p.cleanupUndefs++
	}
	p.mu.Unlock()
	return p.dst.CleanupMigrationArtifacts(adminCtx(), req)
}

type fwRollbackFixture struct {
	src, dst       *Server
	srcVirt        *libvirtfake.Fake
	dstVirt        *libvirtfake.Fake
	peer           *firmwareTargetPeer
	fwSpec         firmwareSpec
	targetHostName string
}

const fwRollbackSpec = `{"name":"fw","secure_boot":true,"firmware":"uefi","uuid":"` + fwRollbackUUID + `"}`

func newFWRollbackFixture(t *testing.T) *fwRollbackFixture {
	t.Helper()
	t.Cleanup(lv.SetSwtpmBaseForTest(filepath.Join(t.TempDir(), "swtpm")))
	ctx := adminCtx()

	src := testServerWithLocks(t)
	src.hostName = "src-host"
	srcVirt := libvirtfake.New()
	src.virt = srcVirt
	if err := srcVirt.DefineDomain(`<domain type='kvm'><name>fw</name><uuid>` + fwRollbackUUID + `</uuid></domain>`); err != nil {
		t.Fatalf("define source domain: %v", err)
	}
	writeNvram(t, src.dataDir, "source-vars")
	if err := corrosion.InsertVM(ctx, src.db, corrosion.VMRecord{
		Name: fwRollbackVM, HostName: src.hostName, Spec: fwRollbackSpec, State: "stopped",
	}, nil, []corrosion.DiskRecord{
		{VMName: fwRollbackVM, DiskName: "root", HostName: src.hostName, Path: "/srv/fw-root.qcow2", StorageType: "nfs"},
	}); err != nil {
		t.Fatalf("InsertVM (source): %v", err)
	}

	dst := testServer(t)
	dst.hostName = fwRollbackDst
	dst.dataDir = t.TempDir()
	dstVirt := libvirtfake.New()
	dst.virt = dstVirt
	// The VM row is replicated to the target, still naming the source.
	insertTestVMWithSpec(t, ctx, dst.db, fwRollbackVM, src.hostName, "stopped", fwRollbackSpec)

	srcCtx := context.WithValue(peerCtxFor(t, dst, src.hostName), ctxKeyUsername, "admin")
	srcCtx = context.WithValue(srcCtx, ctxKeyRole, "admin")
	peer := &firmwareTargetPeer{dst: dst, srcFP: src.firmwareLayoutFingerprint(), srcCtx: srcCtx}
	src.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return peer, func() {}, nil
	}
	return &fwRollbackFixture{
		src: src, dst: dst, srcVirt: srcVirt, dstVirt: dstVirt, peer: peer,
		fwSpec:         parseFirmwareSpec(fwRollbackSpec),
		targetHostName: fwRollbackDst,
	}
}

func writeNvram(t *testing.T, dataDir, content string) {
	t.Helper()
	p := lv.NvramPath(dataDir, fwRollbackVM)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fwRollbackFixture) migrate(ctx context.Context, t *testing.T) error {
	t.Helper()
	vm, err := corrosion.GetVM(adminCtx(), f.src.db, fwRollbackVM)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	return f.src.coldMigrateStoppedVM(ctx, vm, &corrosion.HostRecord{Name: f.targetHostName}, f.fwSpec, &migrationAbort{},
		func(pb.MigratePhase, float32, float32) error { return nil })
}

func (f *fwRollbackFixture) owner(t *testing.T) string {
	t.Helper()
	vm, err := corrosion.GetVM(adminCtx(), f.src.db, fwRollbackVM)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	return vm.HostName
}

func (f *fwRollbackFixture) dstNvram(t *testing.T) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(lv.NvramPath(f.dst.dataDir, fwRollbackVM))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

// cancelOnEnsure cancels the request once the target has answered
// EnsureFirmwareState. lose decides whether the answer reaches the source
// (the cancellation raced it) or is lost to the cancellation.
func cancelOnEnsure(cancel context.CancelFunc, lose bool) func(*pb.EnsureFirmwareStateResponse, error) (*pb.EnsureFirmwareStateResponse, error) {
	return func(resp *pb.EnsureFirmwareStateResponse, err error) (*pb.EnsureFirmwareStateResponse, error) {
		cancel()
		if lose {
			return nil, status.Error(codes.Canceled, context.Canceled.Error())
		}
		return resp, err
	}
}

// Test 1. The request is cancelled after the target defined the domain and
// before the handoff committed: the target's domain and firmware are removed,
// the source still owns the VM, and a retry migrates it.
//
// Mutation: never clean up the target on a pre-commit failure — the domain is
// left defined and the retry is refused over it.
func TestColdMigrateFirmwareVM_CancelledBeforeCommitRemovesWhatItDefined(t *testing.T) {
	for _, tc := range []struct {
		name string
		lose bool
	}{
		{"answer lost to the cancellation", true},
		{"answer received, then cancelled", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFWRollbackFixture(t)
			ctx, cancel := context.WithCancel(adminCtx())
			defer cancel()
			f.peer.afterEnsure = cancelOnEnsure(cancel, tc.lose)

			if err := f.migrate(ctx, t); err == nil {
				t.Fatal("a migration cancelled before its handoff committed reported success")
			}
			if f.dstVirt.DomainExists(fwRollbackVM) {
				t.Error("the target still holds the domain this attempt defined")
			}
			if _, ok := f.dstNvram(t); ok {
				t.Error("the target still holds the firmware state this attempt wrote")
			}
			if got := f.owner(t); got != f.src.hostName {
				t.Fatalf("owner = %q after a pre-commit failure, want the source %q", got, f.src.hostName)
			}
			if !f.srcVirt.DomainExists(fwRollbackVM) || !lv.HasNvram(f.src.dataDir, fwRollbackVM) {
				t.Fatal("the source lost its domain or firmware on a failed attempt")
			}

			f.peer.afterEnsure = nil
			if err := f.migrate(adminCtx(), t); err != nil {
				t.Fatalf("retry after the cancelled attempt: %v", err)
			}
			if got := f.owner(t); got != fwRollbackDst {
				t.Fatalf("owner after retry = %q, want %q", got, fwRollbackDst)
			}
			if !f.dstVirt.DomainExists(fwRollbackVM) {
				t.Error("the retry did not define the domain on the target")
			}
			if got, ok := f.dstNvram(t); !ok || got != "source-vars" {
				t.Errorf("target firmware after retry = %q (present=%v), want the source's vars", got, ok)
			}
		})
	}
}

// Test 2. The domain was already defined on the target before this attempt,
// and the attempt fails: the domain and its firmware are left exactly as
// they were. Whether or not the target's refusal reached the source, it is
// not this attempt's domain.
//
// Mutation: clean up the target on every pre-commit failure (the old
// undefine-whatever-is-there rollback) — the pre-existing domain is removed.
func TestColdMigrateFirmwareVM_FailureLeavesAPreexistingTargetDomain(t *testing.T) {
	for _, tc := range []struct {
		name string
		lose bool
	}{
		{"refusal received", false},
		{"refusal lost to a cancellation", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFWRollbackFixture(t)
			const theirs = `<domain type='kvm'><name>fw</name><uuid>` + fwRollbackUUID + `</uuid><description>theirs</description></domain>`
			if err := f.dstVirt.DefineDomain(theirs); err != nil {
				t.Fatalf("pre-define target domain: %v", err)
			}
			writeNvram(t, f.dst.dataDir, "target-vars")

			ctx, cancel := context.WithCancel(adminCtx())
			defer cancel()
			if tc.lose {
				f.peer.afterEnsure = cancelOnEnsure(cancel, true)
			}
			if err := f.migrate(ctx, t); err == nil {
				t.Fatal("migrating onto a target that already defines the domain reported success")
			}
			if !f.dstVirt.DomainExists(fwRollbackVM) {
				t.Fatal("the failed attempt undefined a domain that was on the target before it")
			}
			if x, _ := f.dstVirt.DumpXML(fwRollbackVM); !strings.Contains(x, "theirs") {
				t.Errorf("the target's pre-existing domain was replaced: %s", x)
			}
			if got, ok := f.dstNvram(t); !ok || got != "target-vars" {
				t.Errorf("the target's pre-existing firmware = %q (present=%v), want it untouched", got, ok)
			}
			if got := f.owner(t); got != f.src.hostName {
				t.Fatalf("owner = %q, want the source %q", got, f.src.hostName)
			}
		})
	}
}

// Test 3. The success path: the target holds the domain and the source's
// firmware, the source's copy is gone, the VM is the target's, and nothing
// on the target was rolled back.
func TestColdMigrateFirmwareVM_SuccessKeepsTheTargetDomain(t *testing.T) {
	f := newFWRollbackFixture(t)
	if err := f.migrate(adminCtx(), t); err != nil {
		t.Fatalf("cold firmware migration: %v", err)
	}
	if got := f.owner(t); got != fwRollbackDst {
		t.Fatalf("owner = %q, want %q", got, fwRollbackDst)
	}
	if !f.dstVirt.DomainExists(fwRollbackVM) {
		t.Error("the target does not hold the migrated domain")
	}
	if got, ok := f.dstNvram(t); !ok || got != "source-vars" {
		t.Errorf("target firmware = %q (present=%v), want the source's vars", got, ok)
	}
	if f.srcVirt.DomainExists(fwRollbackVM) || lv.HasNvram(f.src.dataDir, fwRollbackVM) {
		t.Error("the source still holds the domain or firmware after a committed migration")
	}
	f.peer.mu.Lock()
	defer f.peer.mu.Unlock()
	if f.peer.rollbacks != 0 || f.peer.cleanupUndefs != 0 {
		t.Errorf("a successful migration rolled the target back (rollbacks=%d undefines=%d)",
			f.peer.rollbacks, f.peer.cleanupUndefs)
	}
	if len(f.peer.ensureAttempts) != 1 || f.peer.ensureAttempts[0] == "" {
		t.Errorf("EnsureFirmwareState attempt ids = %q, want one non-empty id", f.peer.ensureAttempts)
	}
}

// Test 4. A target built before attempt-scoped rollback reports nothing about
// what it created, and has no RollbackFirmwareState. The source cannot tell
// its domain from one that was there already, so it undefines nothing — and
// says which domain it may have left behind, so the operator can clear it
// before the retry that would otherwise be refused over it.
//
// Mutation: treat an unreported creation as this attempt's and clean up
// through CleanupMigrationArtifacts — the domain is undefined.
func TestColdMigrateFirmwareVM_OlderTargetIsLeftAloneAndTheLeftoverNamed(t *testing.T) {
	for _, tc := range []struct {
		name string
		lose bool
	}{
		{"answer received, then cancelled", false},
		{"answer lost to the cancellation", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFWRollbackFixture(t)
			f.peer.oldBuild = true
			ctx, cancel := context.WithCancel(adminCtx())
			defer cancel()
			f.peer.afterEnsure = cancelOnEnsure(cancel, tc.lose)

			err := f.migrate(ctx, t)
			if err == nil {
				t.Fatal("a cancelled migration reported success")
			}
			if !f.dstVirt.DomainExists(fwRollbackVM) {
				t.Fatal("the source undefined a domain on an older target that never said it created it")
			}
			if _, ok := f.dstNvram(t); !ok {
				t.Error("the source wiped firmware on an older target that never said it wrote it")
			}
			f.peer.mu.Lock()
			undefs := f.peer.cleanupUndefs
			f.peer.mu.Unlock()
			if undefs != 0 {
				t.Errorf("CleanupMigrationArtifacts was asked to undefine the domain %d time(s)", undefs)
			}
			msg := err.Error()
			if !strings.Contains(msg, `"`+fwRollbackVM+`"`) || !strings.Contains(msg, fwRollbackDst) ||
				!strings.Contains(msg, "undefine") {
				t.Errorf("error should name the domain %q possibly left on %s and say to undefine it, got: %v",
					fwRollbackVM, fwRollbackDst, err)
			}
			if got := f.owner(t); got != f.src.hostName {
				t.Fatalf("owner = %q, want the source %q", got, f.src.hostName)
			}
		})
	}
}

// The target removes a domain only for the attempt that defined it: a rollback
// naming any other attempt, or one arriving after the VM's row has come to
// name this host, leaves the domain and its firmware.
//
// Mutation: drop the attempt match (or the lives-here check) in
// RollbackFirmwareState — the domain is removed.
func TestRollbackFirmwareState_RemovesOnlyItsOwnAttempt(t *testing.T) {
	for _, tc := range []struct {
		name      string
		attempt   string
		rowHere   bool
		wantGone  bool
		wantError bool
	}{
		{name: "same attempt", attempt: "attempt-a", wantGone: true},
		{name: "another attempt", attempt: "attempt-b"},
		{name: "same attempt, VM now lives here", attempt: "attempt-a", rowHere: true},
		{name: "no attempt", attempt: "", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFWRollbackFixture(t)
			src := nvramBundle(t, f.dst.dataDir)
			if _, err := f.dst.EnsureFirmwareState(f.peer.srcCtx, &pb.EnsureFirmwareStateRequest{
				VmName: fwRollbackVM, Uuid: fwRollbackUUID, Bundle: src, AttemptId: "attempt-a",
				DomainXml: `<domain type='kvm'><name>fw</name><uuid>` + fwRollbackUUID + `</uuid></domain>`,
			}); err != nil {
				t.Fatalf("EnsureFirmwareState: %v", err)
			}
			// The row comes to name this host after the define: the handoff
			// committed before the rollback arrived.
			if tc.rowHere {
				if err := f.dst.db.Execute(context.Background(),
					`UPDATE vms SET host_name = ? WHERE name = ?`, fwRollbackDst, fwRollbackVM); err != nil {
					t.Fatalf("set owner: %v", err)
				}
			}
			resp, err := f.dst.RollbackFirmwareState(adminCtx(), &pb.RollbackFirmwareStateRequest{
				VmName: fwRollbackVM, Uuid: fwRollbackUUID, AttemptId: tc.attempt,
			})
			if tc.wantError {
				if status.Code(err) != codes.InvalidArgument {
					t.Fatalf("rollback with no attempt id: err = %v, want InvalidArgument", err)
				}
			} else if err != nil {
				t.Fatalf("RollbackFirmwareState: %v", err)
			}
			if got := resp.GetRemoved(); got != tc.wantGone {
				t.Errorf("removed = %v, want %v", got, tc.wantGone)
			}
			_, nvram := f.dstNvram(t)
			if exists := f.dstVirt.DomainExists(fwRollbackVM); exists == tc.wantGone || nvram == tc.wantGone {
				t.Errorf("domain present=%v firmware present=%v, want both %v", exists, nvram, !tc.wantGone)
			}
		})
	}
}
