package grpcapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const (
	fwtVM   = "fw1"
	fwtUUID = "6f1c2b3a-1111-4222-8333-444455556666"
	fwtA1   = "a1a1a1a1-0000-4000-8000-000000000001"
	fwtA2   = "a2a2a2a2-0000-4000-8000-000000000002"
	fwtSrc  = "src"
)

// fwtRuntime is the target's installed runtime as its probe reads it (the
// probe's own OVMF fingerprint, which the RPC form replaces).
var fwtRuntime = lv.FirmwareRuntime{Libvirt: "10.0.0", QEMU: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3",
	OVMFFingerprint: strings.Repeat("ab", 32)}

type fwtFixture struct {
	t     *testing.T
	s     *Server
	fake  *libvirtfake.Fake
	store *lv.FirmwareStore
	recs  *fwmig.Records
	row   *corrosion.VMRecord
	peer  context.Context // the source, which the row names
}

const fwtSpecSBTPM = `{"name":"fw1","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"` + fwtUUID + `"}`
const fwtSpecBIOSTPM = `{"name":"fw1","tpm":true,"firmware":"bios","uuid":"` + fwtUUID + `"}`

// newFwtFixture is a target host "dst" holding the row of fw1, owned by the
// source "src", with the firmware move guard wired over its own store.
func newFwtFixture(t *testing.T, spec string) *fwtFixture {
	t.Helper()
	s := testServer(t)
	s.hostName = "dst"
	s.dataDir = t.TempDir()
	store := &lv.FirmwareStore{DataDir: s.dataDir, SwtpmBase: t.TempDir()}
	s.SetFirmwareStore(store)
	fake := libvirtfake.New()
	fake.SetFirmwareStore(store)
	s.virt = fake
	fwmig.Wire(fake, store)
	setFWTestFirmwarePaths(t, s)
	s.db.MarkReplicaCaughtUpForTests("test")
	insertTestVMWithSpec(t, adminCtx(), s.db, fwtVM, fwtSrc, "migrating", spec)
	row, err := corrosion.GetVM(context.Background(), s.db, fwtVM)
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	s.SetLiveFirmwareHost(&stubFWCode{installed: lv.InstalledFirmwareCode{Runtime: fwtRuntime}})
	peer := context.WithValue(peerCtxFor(t, s, fwtSrc), ctxKeyUsername, "admin")
	peer = context.WithValue(peer, ctxKeyRole, "admin")
	return &fwtFixture{t: t, s: s, fake: fake, store: store, recs: fwmig.New(s.dataDir), row: row, peer: peer}
}

var fwtNvram = []byte("source-nvram-T0")

// srcRuntime is what a source with this host's firmware code sends: the same
// builder, pbFirmwareRuntime.
func (f *fwtFixture) srcRuntime() *pb.FirmwareRuntime {
	f.t.Helper()
	rt, err := f.s.pbFirmwareRuntime(fwtRuntime)
	if err != nil {
		f.t.Fatal(err)
	}
	return rt
}

func (f *fwtFixture) prepareReq(attempt string, active bool) *pb.PrepareLiveFirmwareTargetRequest {
	app := liveFirmwareApplicability(parseFirmwareSpec(f.row.Spec))
	req := &pb.PrepareLiveFirmwareTargetRequest{
		VmName: fwtVM, Uuid: fwtUUID, CreatedAt: f.row.CreatedAt, AttemptId: attempt, ProtocolVersion: 1,
		SrcRuntime: f.srcRuntime(), SrcApplicability: app,
		SourceDomainActive: active,
	}
	if app.Uefi {
		req.Nvram = fwtNvram
	}
	return req
}

func (f *fwtFixture) binding(attempt string) fwmig.Binding {
	return fwmig.Binding{UUID: fwtUUID, CreatedAt: f.row.CreatedAt, Attempt: attempt}
}

// putHold writes a hold directly, with its NVRAM and swtpm tree on disk.
func (f *fwtFixture) putHold(h fwmig.Hold, nvram, permall []byte) fwmig.Hold {
	f.t.Helper()
	if h.VM == "" {
		h.VM = fwtVM
	}
	if h.Source == "" {
		h.Source = fwtSrc
	}
	if h.Since.IsZero() {
		h.Since = time.Now().UTC()
	}
	if h.NvramMaterialised == "" {
		h.NvramMaterialised = fwmig.NvramDone
	}
	h.TPM, h.UEFI, h.SwtpmAbsentAtPrepare = true, true, true
	if nvram != nil {
		f.writeFile(f.store.NvramPath(h.VM), nvram)
	}
	if permall != nil {
		f.writeFile(f.permallPath(), permall)
	}
	if err := f.recs.PutHold(h); err != nil {
		f.t.Fatalf("PutHold: %v", err)
	}
	return h
}

func (f *fwtFixture) permallPath() string {
	return filepath.Join(f.store.SwtpmDir(fwtUUID), "tpm2", "tpm2-00.permall")
}

func (f *fwtFixture) writeFile(p string, b []byte) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// defineDomain defines fw1 here (with its uuid) in state st.
func (f *fwtFixture) defineDomain(st libvirtfake.State) {
	f.t.Helper()
	if err := f.fake.DefineDomain(`<domain type='kvm'><name>` + fwtVM + `</name><uuid>` + fwtUUID + `</uuid><devices></devices></domain>`); err != nil {
		f.t.Fatalf("DefineDomain: %v", err)
	}
	f.fake.SetState(fwtVM, st)
}

func (f *fwtFixture) quarantine(attempt string) string {
	p, err := f.recs.QuarantinePath(fwtVM, attempt)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func fwtExists(p string) bool { _, err := os.Lstat(p); return err == nil }

func fwtRead(p string) []byte { b, _ := os.ReadFile(p); return b }

// snapshotDir is every file under dir with its content, for "wrote nothing".
func fwtSnapshot(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err == nil && !e.IsDir() {
				out[p] = string(fwtRead(p))
			}
			return nil
		})
	}
	return out
}

func fwtSameSnapshot(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func fwtSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// T-9: every refusal of Prepare items 1 to 5 writes nothing: no hold, no
// NVRAM, no quarantine, and a hold already there is left byte for byte.
//
// Mutations: write the hold before item 3 — the domain-defined row goes red;
// drop any one check — its row answers OK and goes red.
func TestPrepareLiveFirmwareTarget_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context
		want  codes.Code
		text  string
	}{
		{"1 host check fails (config off)", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			f.s.SetLiveFirmwareHost(&stubFWCode{checkErr: errors.New("migration.live_firmware is off")})
			return f.peer
		}, codes.FailedPrecondition, "migration.live_firmware is off"},
		{"1 no host check", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			f.s.SetLiveFirmwareHost(nil)
			return f.peer
		}, codes.FailedPrecondition, "cannot check"},
		{"1 runtime differs (qemu)", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			req.SrcRuntime.Qemu = "8.2.1"
			return f.peer
		}, codes.FailedPrecondition, "qemu differs: source runs 8.2.1, target has 8.2.2"},
		{"1 runtime differs (ovmf)", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			l, _, _ := splitLiveFirmwareFingerprint(req.SrcRuntime.OvmfFingerprint)
			req.SrcRuntime.OvmfFingerprint = liveFWLayoutPrefix + l + " " + liveFWOVMFPrefix + strings.Repeat("cd", 32)
			return f.peer
		}, codes.FailedPrecondition, "ovmf_fingerprint (OVMF content) differs"},
		{"1 runtime differs (layout)", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			_, o, _ := splitLiveFirmwareFingerprint(req.SrcRuntime.OvmfFingerprint)
			req.SrcRuntime.OvmfFingerprint = liveFWLayoutPrefix + strings.Repeat("cd", 32) + " " + liveFWOVMFPrefix + o
			return f.peer
		}, codes.FailedPrecondition, "firmware layout (dataDir and OVMF paths) differs"},
		{"1 runtime in the probe's raw format", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			req.SrcRuntime.OvmfFingerprint = fwtRuntime.OVMFFingerprint
			return f.peer
		}, codes.FailedPrecondition, "not readable"},
		{"1 runtime not sent", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			req.SrcRuntime = nil
			return f.peer
		}, codes.FailedPrecondition, "src_runtime"},
		{"1 applicability differs", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			req.SrcApplicability.Tpm = false
			return f.peer
		}, codes.FailedPrecondition, "tpm=false"},
		{"2 row names this host", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			if err := f.s.db.Execute(context.Background(), `UPDATE vms SET host_name = ? WHERE name = ?`, "dst", fwtVM); err != nil {
				t.Fatal(err)
			}
			return f.peer
		}, codes.FailedPrecondition, "lives on dst"},
		{"2 caller is not the row's host", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			ctx := context.WithValue(peerCtxFor(t, f.s, "other"), ctxKeyUsername, "admin")
			return context.WithValue(ctx, ctxKeyRole, "admin")
		}, codes.PermissionDenied, "owned by src"},
		{"2 incarnation differs", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			req.CreatedAt = "2001-01-01T00:00:00Z"
			return f.peer
		}, codes.FailedPrecondition, "incarnation"},
		{"2 uuid not the row's", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			req.Uuid = "00000000-1111-4222-8333-444455556666"
			return f.peer
		}, codes.InvalidArgument, "not the recorded uuid"},
		{"3 domain defined here", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			f.defineDomain(libvirtfake.StateShutdown)
			return f.peer
		}, codes.FailedPrecondition, "a domain of that name is defined"},
		{"4 prepared hold, source not active", func(f *fwtFixture, req *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared, NvramT0SHA256: fwtSHA([]byte("old"))}, []byte("old"), nil)
			req.SourceDomainActive = false
			return f.peer
		}, codes.FailedPrecondition, fwtA1},
		{"4 released_unconfirmed hold", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldReleasedUnconfirmed}, []byte("old"), []byte("tpm"))
			return f.peer
		}, codes.FailedPrecondition, "released_unconfirmed"},
		{"5 stray NVRAM", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			f.writeFile(f.store.NvramPath(fwtVM), []byte("someone else's"))
			return f.peer
		}, codes.FailedPrecondition, "no firmware move hold accounts for it"},
		{"5 stray swtpm tree", func(f *fwtFixture, _ *pb.PrepareLiveFirmwareTargetRequest) context.Context {
			f.writeFile(f.permallPath(), []byte("someone else's"))
			return f.peer
		}, codes.FailedPrecondition, fwtUUID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFwtFixture(t, fwtSpecSBTPM)
			req := f.prepareReq(fwtA2, true)
			ctx := c.setup(f, req)
			before := fwtSnapshot(t, f.s.dataDir, f.store.SwtpmBase)
			_, err := f.s.PrepareLiveFirmwareTarget(ctx, req)
			if status.Code(err) != c.want || !strings.Contains(err.Error(), c.text) {
				t.Fatalf("Prepare = %v, want %v naming %q", err, c.want, c.text)
			}
			if after := fwtSnapshot(t, f.s.dataDir, f.store.SwtpmBase); !fwtSameSnapshot(before, after) {
				t.Fatalf("a refused Prepare wrote:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// Prepare holds a SB+TPM VM: the hold is written, then the NVRAM
// materialised through the hold's exempt entry point, its hash recorded.
//
// Mutation: materialise before the hold write — the guard refuses it with
// no record, and this goes red.
func TestPrepareLiveFirmwareTarget_HoldsThenMaterialises(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	resp, err := f.s.PrepareLiveFirmwareTarget(f.peer, f.prepareReq(fwtA1, true))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !resp.SwtpmAbsent || resp.TargetDomain.GetPresent() || !resp.DstApplicability.GetTpm() || !resp.DstApplicability.GetUefi() ||
		resp.DstRuntime.GetQemu() != "8.2.2" || !resp.DstRuntime.GetLiveFirmwareEnabled() {
		t.Fatalf("response %+v", resp)
	}
	// The answer is built as stage A builds src_runtime (pbFirmwareRuntime).
	if want, _ := f.s.liveFirmwareFingerprint(); resp.DstRuntime.GetOvmfFingerprint() != want {
		t.Fatalf("dst_runtime fingerprint %q, want the live firmware fingerprint %q", resp.DstRuntime.GetOvmfFingerprint(), want)
	}
	h, ok, err := f.recs.GetHoldFor(fwtVM, f.binding(fwtA1))
	if err != nil || !ok {
		t.Fatalf("hold: %v %v", ok, err)
	}
	if h.State != fwmig.HoldPrepared || h.Source != fwtSrc || h.NvramMaterialised != fwmig.NvramDone ||
		h.NvramT0SHA256 != fwtSHA(fwtNvram) || !h.SwtpmAbsentAtPrepare || !h.TPM || !h.UEFI {
		t.Fatalf("hold %+v", h)
	}
	if got := fwtRead(f.store.NvramPath(fwtVM)); !bytes.Equal(got, fwtNvram) {
		t.Fatalf("NVRAM %q, want the request's", got)
	}
	if fwtExists(f.store.SwtpmDir(fwtUUID)) {
		t.Fatal("Prepare created the swtpm tree")
	}
	if f.fake.DomainExists(fwtVM) {
		t.Fatal("Prepare defined a domain")
	}
}

// A BIOS VM with a vTPM has no NVRAM: none is sent, none is written, and the
// hold says so. NVRAM bytes for it are refused before anything is written.
func TestPrepareLiveFirmwareTarget_BIOSTPMNoNvram(t *testing.T) {
	f := newFwtFixture(t, fwtSpecBIOSTPM)
	bad := f.prepareReq(fwtA1, true)
	bad.Nvram = []byte("x")
	if _, err := f.s.PrepareLiveFirmwareTarget(f.peer, bad); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("NVRAM for a BIOS VM: %v", err)
	}
	if _, err := f.s.PrepareLiveFirmwareTarget(f.peer, f.prepareReq(fwtA1, true)); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	h, _, _ := f.recs.GetHold(fwtVM)
	if h.UEFI || h.NvramMaterialised != fwmig.NvramNo || h.NvramT0SHA256 != "" || fwtExists(f.store.NvramPath(fwtVM)) {
		t.Fatalf("hold %+v, nvram on disk %v", h, fwtExists(f.store.NvramPath(fwtVM)))
	}
}

// T-35 (Prepare half): libvirt-guests, read live by the host check, refuses
// with nothing written.
//
// Mutation: skip the host check (read the label instead) — red.
func TestPrepare_LibvirtGuestsRefused(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	host := &stubFWCode{checkErr: errors.New("libvirt-guests: ON_SHUTDOWN=suspend saves guests")}
	f.s.SetLiveFirmwareHost(host)
	_, err := f.s.PrepareLiveFirmwareTarget(f.peer, f.prepareReq(fwtA1, true))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "libvirt-guests") || host.checks != 1 {
		t.Fatalf("Prepare = %v (checks %d)", err, host.checks)
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); ok || fwtExists(f.store.NvramPath(fwtVM)) {
		t.Fatal("a refused Prepare wrote")
	}
}

// T-10: a prepared hold of this incarnation, from the caller, with the source
// active, is deleted (rule D), then the new attempt is held.
//
// Mutation: quarantine it instead — the no-quarantine check goes red.
func TestPrepare_DeletesOnlyPreparedWithActiveSource(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared, NvramT0SHA256: fwtSHA([]byte("old"))},
		[]byte("old"), []byte("old-tpm"))
	if _, err := f.s.PrepareLiveFirmwareTarget(f.peer, f.prepareReq(fwtA2, true)); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if fwtExists(f.quarantine(fwtA1)) {
		t.Fatal("a prepared hold with its source active was quarantined, not deleted")
	}
	if fwtExists(f.permallPath()) {
		t.Fatal("rule D left the swtpm tree the old attempt's incoming migration made")
	}
	if got := fwtRead(f.store.NvramPath(fwtVM)); !bytes.Equal(got, fwtNvram) {
		t.Fatalf("NVRAM %q, want the new attempt's", got)
	}
	if _, ok, err := f.recs.GetHoldFor(fwtVM, f.binding(fwtA2)); !ok || err != nil {
		t.Fatalf("new hold: %v %v", ok, err)
	}
}

// T-10: a hold past prepared (mismatch, verified, resuming), or of another
// incarnation, is quarantined with every file kept, then the attempt is held.
//
// Mutation: rule D for a mismatch hold — red (the guard refuses it, and the
// quarantine is missing).
func TestPrepare_QuarantinesMismatchOrVerified(t *testing.T) {
	for _, c := range []struct {
		name  string
		state fwmig.HoldState
		other bool // another incarnation
	}{
		{"mismatch", fwmig.HoldMismatch, false},
		{"verified", fwmig.HoldVerified, false},
		{"resuming", fwmig.HoldResuming, false},
		{"prepared, another incarnation", fwmig.HoldPrepared, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFwtFixture(t, fwtSpecSBTPM)
			b := f.binding(fwtA1)
			if c.other {
				b.CreatedAt = "2001-01-01T00:00:00Z"
			}
			f.putHold(fwmig.Hold{Binding: b, State: c.state, NvramT0SHA256: fwtSHA([]byte("old"))}, []byte("old"), []byte("old-tpm"))
			if _, err := f.s.PrepareLiveFirmwareTarget(f.peer, f.prepareReq(fwtA2, true)); err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			q := f.quarantine(fwtA1)
			if string(fwtRead(filepath.Join(q, "nvram"))) != "old" ||
				string(fwtRead(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall"))) != "old-tpm" {
				t.Fatalf("quarantine %s does not hold the old state", q)
			}
			if !strings.Contains(string(fwtRead(filepath.Join(q, "hold.json"))), fwtA1) ||
				!strings.Contains(string(fwtRead(filepath.Join(q, "reason.txt"))), fwtSHA([]byte("old"))) {
				t.Fatal("quarantine has no hold record or reason with the hashes")
			}
			if _, ok, err := f.recs.GetHoldFor(fwtVM, f.binding(fwtA2)); !ok || err != nil {
				t.Fatalf("new hold: %v %v", ok, err)
			}
		})
	}
}

// T-10: a hold written pending, whose NVRAM landed before the hold was
// updated, accounts for that file: rule D removes it, and item 5 does not
// refuse.
//
// Mutation: rule D only for nvram_materialised=done — item 5 refuses, red.
func TestPrepare_PendingMaterialisationAccounted(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared, NvramMaterialised: fwmig.NvramPending},
		[]byte("half"), nil)
	if _, err := f.s.PrepareLiveFirmwareTarget(f.peer, f.prepareReq(fwtA2, true)); err != nil {
		t.Fatalf("Prepare over a pending hold: %v", err)
	}
	if got := fwtRead(f.store.NvramPath(fwtVM)); !bytes.Equal(got, fwtNvram) {
		t.Fatalf("NVRAM %q", got)
	}
}

func (f *fwtFixture) abort(ctx context.Context, attempt string, mode pb.FirmwareAbortMode, active bool, b fwmig.Binding) (*pb.AbortLiveFirmwareTargetResponse, error) {
	return f.s.AbortLiveFirmwareTarget(ctx, &pb.AbortLiveFirmwareTargetRequest{
		VmName: fwtVM, Uuid: b.UUID, CreatedAt: b.CreatedAt, AttemptId: attempt, Mode: mode, SourceDomainActive: active,
	})
}

const (
	preCutover = pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER
	discard    = pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED
)

// T-20: PRE_CUTOVER deletes (rule D) only a prepared hold whose source
// attests its domain active; without that it quarantines.
//
// Mutation: rule D without source_domain_active — the inactive row goes red.
func TestAbort_PreCutover_RuleDOnlyPrepared(t *testing.T) {
	for _, active := range []bool{true, false} {
		f := newFwtFixture(t, fwtSpecSBTPM)
		f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared}, []byte("t0"), []byte("tpm"))
		resp, err := f.abort(f.peer, fwtA1, preCutover, active, f.binding(fwtA1))
		if err != nil || resp.Refused {
			t.Fatalf("active=%v: Abort = %+v, %v", active, resp, err)
		}
		if _, ok, _ := f.recs.GetHold(fwtVM); ok {
			t.Fatalf("active=%v: hold kept", active)
		}
		q := f.quarantine(fwtA1)
		if active {
			if fwtExists(f.store.NvramPath(fwtVM)) || fwtExists(f.permallPath()) || fwtExists(q) {
				t.Fatal("rule D did not delete exactly the attempt's files")
			}
		} else if string(fwtRead(filepath.Join(q, "nvram"))) != "t0" || string(fwtRead(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall"))) != "tpm" {
			t.Fatal("without an active source the state was not quarantined")
		}
	}
}

// T-20: a domain defined here refuses PRE_CUTOVER, keeping the hold, and the
// refusal carries the domain and the hold's state (§7 M1 decides from them).
//
// Mutation: dispose with a domain present — red.
func TestAbort_PreCutover_RefusesWithDomain(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.defineDomain(libvirtfake.StatePaused)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared}, []byte("t0"), []byte("tpm"))
	resp, err := f.abort(f.peer, fwtA1, preCutover, true, f.binding(fwtA1))
	if err != nil || !resp.Refused || resp.HoldState != "prepared" ||
		!resp.TargetDomain.GetPresent() || resp.TargetDomain.GetState() != "paused" || resp.TargetDomain.GetUuid() != fwtUUID {
		t.Fatalf("Abort = %+v, %v", resp, err)
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); !ok || !fwtExists(f.store.NvramPath(fwtVM)) || !f.fake.DomainExists(fwtVM) {
		t.Fatal("a refused abort disposed of something")
	}
}

// T-20: every hold past prepared is quarantined by PRE_CUTOVER, whatever
// the source says.
//
// Mutation: rule D for any state with an active source — red.
func TestAbort_PreCutover_QuarantinesNonPrepared(t *testing.T) {
	for _, st := range []fwmig.HoldState{fwmig.HoldVerified, fwmig.HoldMismatch, fwmig.HoldResuming} {
		f := newFwtFixture(t, fwtSpecSBTPM)
		f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: st}, []byte("t0"), []byte("tpm"))
		if resp, err := f.abort(f.peer, fwtA1, preCutover, true, f.binding(fwtA1)); err != nil || resp.Refused {
			t.Fatalf("%s: Abort = %+v, %v", st, resp, err)
		}
		if string(fwtRead(filepath.Join(f.quarantine(fwtA1), "nvram"))) != "t0" {
			t.Fatalf("%s: not quarantined", st)
		}
	}
}

// T-20: Abort binds to the hold, not the row: after the VM was deleted and
// recreated on the source (a new incarnation in the row), an owed DISCARD with
// the hold's own binding lands; one with the row's binding touches nothing.
//
// Mutation: compare with the current row — red.
func TestAbort_BindsToHoldIncarnationNotRow(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	old := fwmig.Binding{UUID: fwtUUID, CreatedAt: "2001-01-01T00:00:00Z", Attempt: fwtA1} // the hold's incarnation, gone from the row
	f.putHold(fwmig.Hold{Binding: old, State: fwmig.HoldPrepared}, []byte("t0"), []byte("tpm"))
	if resp, err := f.abort(f.peer, fwtA1, discard, false, f.binding(fwtA1)); err != nil || resp.Refused {
		t.Fatalf("row-bound abort: %+v %v", resp, err)
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); !ok {
		t.Fatal("an abort bound to the row's incarnation acted on the hold of another")
	}
	if resp, err := f.abort(f.peer, fwtA1, discard, false, old); err != nil || resp.Refused {
		t.Fatalf("hold-bound abort: %+v %v", resp, err)
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); ok || string(fwtRead(filepath.Join(f.quarantine(fwtA1), "nvram"))) != "t0" {
		t.Fatal("the owed DISCARD did not land")
	}
}

// T-20: with no hold for the attempt, Abort touches nothing, though a domain
// and state of that name are here. A DISCARD whose domain has the owed uuid
// while the row names the caller (an owed one, after its hold went) is
// refused, and the domain put under a leftover record (D2-18 re-review 1
// I-1); a pre-cutover abort answers OK.
//
// Mutation: act on a domain or files found by name — red.
func TestAbort_NoHoldTouchesNothingByName(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.defineDomain(libvirtfake.StatePaused)
	f.writeFile(f.store.NvramPath(fwtVM), []byte("theirs"))
	f.writeFile(f.permallPath(), []byte("theirs"))
	for _, mode := range []pb.FirmwareAbortMode{preCutover, discard} {
		resp, err := f.abort(f.peer, fwtA1, mode, true, f.binding(fwtA1))
		if err != nil || resp.Refused != (mode == discard) {
			t.Fatalf("%v: %+v %v", mode, resp, err)
		}
	}
	if l, ok, err := f.recs.GetLeftover(fwtVM); err != nil || !ok || l.Attempt != fwtA1 {
		t.Fatalf("leftover record %+v %v %v, want one of the owed attempt", l, ok, err)
	}
	if err := f.recs.RemoveLeftover(fwtVM); err != nil {
		t.Fatal(err)
	}
	// A hold of another attempt is not this attempt's either.
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA2), State: fwmig.HoldPrepared}, nil, nil)
	for _, mode := range []pb.FirmwareAbortMode{preCutover, discard} {
		if resp, err := f.abort(f.peer, fwtA1, mode, true, f.binding(fwtA1)); err != nil || resp.Refused {
			t.Fatalf("%v: %+v %v", mode, resp, err)
		}
	}
	if st, _ := f.fake.DomainStateReason(fwtVM); st.Reason != "paused" || string(fwtRead(f.store.NvramPath(fwtVM))) != "theirs" ||
		string(fwtRead(f.permallPath())) != "theirs" {
		t.Fatalf("something found by name was touched (domain %+v)", st)
	}
	if _, ok, _ := f.recs.GetHoldFor(fwtVM, f.binding(fwtA2)); !ok {
		t.Fatal("another attempt's hold went")
	}
}

// Only the hold's own source may abort it.
func TestAbort_OnlyTheHoldsSource(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared}, []byte("t0"), nil)
	other := context.WithValue(peerCtxFor(t, f.s, "other"), ctxKeyUsername, "admin")
	if _, err := f.abort(other, fwtA1, preCutover, true, f.binding(fwtA1)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Abort from another host: %v", err)
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); !ok {
		t.Fatal("hold went")
	}
}

// fwtDiscardOrderVirt checks, as the discard runs, that the state is still where the
// domain names it: the quarantine comes after the undefine.
type fwtDiscardOrderVirt struct {
	*libvirtfake.Fake
	onDiscard func()
}

func (o fwtDiscardOrderVirt) DiscardFirmwareMoveTarget(name, uuid, attempt string) error {
	o.onDiscard()
	return o.Fake.DiscardFirmwareMoveTarget(name, uuid, attempt)
}

// T-21b: DISCARD takes the paused domain away (undefine keeping its state)
// BEFORE it quarantines the state, and moves the state, deleting nothing.
//
// Mutations: quarantine before the undefine — the at-discard check goes red;
// delete instead of move — the quarantine check goes red.
func TestAbort_Discard_UndefineBeforeQuarantine(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.defineDomain(libvirtfake.StatePaused)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldMismatch}, []byte("t0"), []byte("tpm"))
	called := false
	f.s.virt = fwtDiscardOrderVirt{Fake: f.fake, onDiscard: func() {
		called = true
		if !fwtExists(f.store.NvramPath(fwtVM)) || !fwtExists(f.permallPath()) || fwtExists(f.quarantine(fwtA1)) {
			t.Error("the state was moved before the domain was discarded")
		}
	}}
	resp, err := f.abort(f.peer, fwtA1, discard, false, f.binding(fwtA1))
	if err != nil || resp.Refused || !called {
		t.Fatalf("DISCARD = %+v, %v (discard called %v)", resp, err, called)
	}
	if f.fake.DomainExists(fwtVM) || resp.TargetDomain.GetPresent() {
		t.Fatal("the held domain is still defined")
	}
	q := f.quarantine(fwtA1)
	if string(fwtRead(filepath.Join(q, "nvram"))) != "t0" || string(fwtRead(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall"))) != "tpm" {
		t.Fatal("the state is not in the quarantine")
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); ok {
		t.Fatal("hold kept")
	}
	c, found, _ := corrosion.GetHealthCondition(context.Background(), f.s.db, firmwareMigrationEvaluator, condFwmigQuarantine, "vm", fwtVM)
	if !found || c.Lifecycle != corrosion.ConditionConfirmed || c.Severity != corrosion.SeverityWarning || !strings.Contains(c.Evidence, q) {
		t.Fatalf("quarantine condition %+v", c)
	}
}

// T-21b: DISCARD never stops a running guest: refused, hold and domain kept.
//
// Mutation: discard a running domain — red.
func TestAbort_Discard_RefusesRunningDomain(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.defineDomain(libvirtfake.StateRunning)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldVerified}, []byte("t0"), []byte("tpm"))
	resp, err := f.abort(f.peer, fwtA1, discard, false, f.binding(fwtA1))
	if err != nil || !resp.Refused || resp.HoldState != "verified" || resp.TargetDomain.GetState() != "running" {
		t.Fatalf("DISCARD = %+v, %v", resp, err)
	}
	if st, _ := f.fake.DomainStateReason(fwtVM); st.State != "running" {
		t.Fatalf("domain %+v", st)
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); !ok || fwtExists(f.quarantine(fwtA1)) {
		t.Fatal("a refused discard disposed of the hold")
	}
}

// T-21b: DISCARD removes the stubs the request names that this host's ledger
// records making for the VM, and leaves any other file.
//
// Mutation: remove every named stub — the unrecorded one goes, red.
func TestAbort_Discard_RemovesOnlyItsOwnStubs(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared}, []byte("t0"), nil)
	mine := filepath.Join(f.s.dataDir, "disks", "fw1-root.qcow2")
	theirs := filepath.Join(f.s.dataDir, "disks", "fw1-data.qcow2")
	f.writeFile(mine, []byte("stub"))
	f.writeFile(theirs, []byte("disk"))
	f.s.recordMade(context.Background(), &f.s.migrationStubs, fwtVM, mine)
	resp, err := f.s.AbortLiveFirmwareTarget(f.peer, &pb.AbortLiveFirmwareTargetRequest{
		VmName: fwtVM, Uuid: fwtUUID, CreatedAt: f.row.CreatedAt, AttemptId: fwtA1, Mode: discard,
		CreatedStubs: []string{mine, theirs},
	})
	if err != nil || resp.Refused {
		t.Fatalf("DISCARD = %+v, %v", resp, err)
	}
	if fwtExists(mine) || !fwtExists(theirs) {
		t.Fatalf("stub removed %v, other file kept %v", !fwtExists(mine), fwtExists(theirs))
	}
}

// T-26: the sweep quarantines (never deletes) a hold with no domain past
// heldStaleAfter whose row is gone, recreated, or not migrating and names
// another host; it keeps a fresh one and one whose move is in flight.
//
// Mutations: rule D in the sweep — the quarantine checks go red; no age test —
// the fresh row goes red; dispose of a migrating row's hold — red.
func TestHoldSweep_QuarantinesStaleDomainless(t *testing.T) {
	stale := time.Now().Add(-3 * time.Hour)
	cases := []struct {
		name  string
		since time.Time
		setup func(f *fwtFixture, b *fwmig.Binding)
		want  bool // quarantined
	}{
		{"row not migrating, names another host", stale, func(f *fwtFixture, _ *fwmig.Binding) {
			f.setRow("running", fwtSrc)
		}, true},
		{"row recreated", stale, func(_ *fwtFixture, b *fwmig.Binding) { b.CreatedAt = "2001-01-01T00:00:00Z" }, true},
		{"row gone", stale, func(f *fwtFixture, _ *fwmig.Binding) {
			if err := f.s.db.Execute(context.Background(), `DELETE FROM vms WHERE name = ?`, fwtVM); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"fresh", time.Now().Add(-time.Hour), func(f *fwtFixture, _ *fwmig.Binding) { f.setRow("running", fwtSrc) }, false},
		{"move in flight", stale, func(*fwtFixture, *fwmig.Binding) {}, false},
		{"row names this host", stale, func(f *fwtFixture, _ *fwmig.Binding) { f.setRow("running", "dst") }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFwtFixture(t, fwtSpecSBTPM)
			b := f.binding(fwtA1)
			c.setup(f, &b)
			f.putHold(fwmig.Hold{Binding: b, State: fwmig.HoldPrepared, Since: c.since}, []byte("t0"), []byte("tpm"))
			f.s.FirmwareHoldSweepOnce(context.Background(), time.Now())
			_, held, _ := f.recs.GetHold(fwtVM)
			q := f.quarantine(fwtA1)
			if c.want {
				if held || string(fwtRead(filepath.Join(q, "nvram"))) != "t0" || string(fwtRead(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall"))) != "tpm" {
					t.Fatalf("not quarantined (hold kept %v)", held)
				}
				return
			}
			if !held || fwtExists(q) || string(fwtRead(f.store.NvramPath(fwtVM))) != "t0" {
				t.Fatalf("disposed of (hold kept %v)", held)
			}
		})
	}
}

func (f *fwtFixture) setRow(state, host string) {
	f.t.Helper()
	if err := f.s.db.Execute(context.Background(), `UPDATE vms SET state = ?, host_name = ? WHERE name = ?`, state, host, fwtVM); err != nil {
		f.t.Fatal(err)
	}
}

// T-26: the sweep never deletes: a stale prepared hold, the case rule D
// would take, keeps every byte in the quarantine; and a released_unconfirmed
// hold stays until an operator resolves it.
//
// Mutation: rule D in the sweep — red.
func TestHoldSweep_NeverDeletes(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.setRow("running", fwtSrc)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared, Since: time.Now().Add(-3 * time.Hour)}, []byte("t0"), []byte("tpm"))
	f.s.FirmwareHoldSweepOnce(context.Background(), time.Now())
	if q := f.quarantine(fwtA1); string(fwtRead(filepath.Join(q, "nvram"))) != "t0" {
		t.Fatal("the sweep did not keep the state")
	}

	g := newFwtFixture(t, fwtSpecSBTPM)
	g.setRow("running", fwtSrc)
	g.putHold(fwmig.Hold{Binding: g.binding(fwtA1), State: fwmig.HoldReleasedUnconfirmed, Since: time.Now().Add(-3 * time.Hour)}, []byte("t1"), []byte("tpm"))
	g.s.FirmwareHoldSweepOnce(context.Background(), time.Now())
	if _, ok, _ := g.recs.GetHold(fwtVM); !ok || fwtExists(g.quarantine(fwtA1)) {
		t.Fatal("the sweep disposed of a released_unconfirmed hold")
	}
}

// T-26: a hold with a domain is never disposed of by the sweep, however old;
// past firmwareHeldConditionAfter it raises firmware_migration_held naming
// the source and attempt, and resolves it once the hold is gone.
//
// Mutations: dispose of a hold with a domain — red; raise held at once — the
// fresh check goes red; never resolve — red.
func TestHoldSweep_KeepsDomainHold(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.setRow("running", fwtSrc)
	f.defineDomain(libvirtfake.StatePaused)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldVerified, Since: time.Now().Add(-time.Minute)}, []byte("t0"), []byte("tpm"))
	ctx := context.Background()
	held := func() corrosion.HealthCondition {
		c, _, _ := corrosion.GetHealthCondition(ctx, f.s.db, firmwareMigrationEvaluator, condFwmigHeld, "vm", fwtVM)
		return c
	}
	f.s.FirmwareHoldSweepOnce(ctx, time.Now())
	if held().Lifecycle != "" {
		t.Fatal("held raised before firmwareHeldConditionAfter")
	}
	f.s.FirmwareHoldSweepOnce(ctx, time.Now().Add(3*time.Hour))
	if _, ok, _ := f.recs.GetHold(fwtVM); !ok || fwtExists(f.quarantine(fwtA1)) || !f.fake.DomainExists(fwtVM) {
		t.Fatal("the sweep disposed of a hold with a domain")
	}
	c := held()
	if c.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(c.Evidence, fwtA1) || !strings.Contains(c.Evidence, `"source":"src"`) {
		t.Fatalf("held condition %+v", c)
	}
	if err := f.recs.RemoveHold(fwtVM); err != nil {
		t.Fatal(err)
	}
	f.s.FirmwareHoldSweepOnce(ctx, time.Now().Add(3*time.Hour))
	if held().Lifecycle != corrosion.ConditionResolved {
		t.Fatal("held not resolved once the hold went")
	}
}

// §6.9: while a live firmware move's hold names the VM here, the cold
// migration helpers leave it: EnsureFirmwareState and RollbackFirmwareState
// refuse naming the attempt, CleanupMigrationArtifacts leaves the domain and
// the state.
//
// Mutations: drop any one hunk — its row goes red (the guard alone turns
// Ensure and Cleanup into Internal errors, and Rollback into a no-op).
func TestFirmwareMoveHold_ColdTargetHelpersLeaveIt(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.defineDomain(libvirtfake.StateShutdown)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldVerified}, []byte("t0"), []byte("tpm"))
	_, err := f.s.EnsureFirmwareState(f.peer, &pb.EnsureFirmwareStateRequest{VmName: fwtVM, Uuid: fwtUUID, Bundle: []byte("x"), AttemptId: "c1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwtA1) {
		t.Fatalf("EnsureFirmwareState = %v", err)
	}
	f.s.firmwareTargets.add(fwtVM, "c1", fwtUUID)
	_, err = f.s.RollbackFirmwareState(f.peer, &pb.RollbackFirmwareStateRequest{VmName: fwtVM, Uuid: fwtUUID, AttemptId: "c1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwtA1) {
		t.Fatalf("RollbackFirmwareState = %v", err)
	}
	if _, err := f.s.CleanupMigrationArtifacts(f.peer, &pb.CleanupMigrationArtifactsRequest{
		VmName: fwtVM, UndefineDomain: true, FirmwareUuid: fwtUUID,
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts = %v", err)
	}
	if !f.fake.DomainExists(fwtVM) || string(fwtRead(f.store.NvramPath(fwtVM))) != "t0" || string(fwtRead(f.permallPath())) != "tpm" {
		t.Fatal("a cold helper touched the held VM")
	}
}

// The condition helper raises each of the move's codes confirmed, at its
// default severity unless told otherwise, naming everything it is given, and
// resolves it; an unknown code is refused.
//
// Mutations: default every code to critical — the warning rows go red; drop
// a field from the evidence — red; resolve nothing — red.
func TestFirmwareMigrationConditions_EveryCode(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	warn := map[string]bool{condFwmigDiscardOwed: true, condFwmigQuarantine: true, condFwmigHeld: true}
	codesAll := []string{condFwmigUnverified, condFwmigSourceStateMissing, condFwmigSourceStateSuspect, condFwmigTargetRan,
		condFwmigSourcePaused, condFwmigDiscardOwed, condFwmigTargetUnreachable, condFwmigNvramUnconfirmed, condFwmigHeld, condFwmigQuarantine,
		condFwmigCleanupFailed, condFwmigVFMissing}
	if len(firmwareMigrationConditionSeverity) != len(codesAll) {
		t.Fatalf("%d codes known, %d listed", len(firmwareMigrationConditionSeverity), len(codesAll))
	}
	for _, code := range codesAll {
		err := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{Code: code, VM: "v1", Attempt: fwtA1, Source: "s1", Target: "t1",
			Hashes: map[string]string{"src_permall_sha256": "h1"}, Paths: []string{"/q"}, Detail: "d", Action: "act"})
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		c, found, _ := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, code, "vm", "v1")
		want := corrosion.SeverityCritical
		if warn[code] {
			want = corrosion.SeverityWarning
		}
		if !found || c.Lifecycle != corrosion.ConditionConfirmed || c.Severity != want {
			t.Fatalf("%s: %+v", code, c)
		}
		for _, w := range []string{fwtA1, `"source":"s1"`, `"target":"t1"`, "h1", "/q", `"action":"act"`} {
			if !strings.Contains(c.Evidence, w) {
				t.Fatalf("%s: evidence %s lacks %s", code, c.Evidence, w)
			}
		}
		if err := s.resolveFirmwareMigrationCondition(ctx, code, "v1"); err != nil {
			t.Fatal(err)
		}
		if c, _, _ := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, code, "vm", "v1"); c.Lifecycle != corrosion.ConditionResolved {
			t.Fatalf("%s not resolved", code)
		}
	}
	if err := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{Code: condFwmigDiscardOwed, VM: "v2", Severity: corrosion.SeverityCritical}); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, condFwmigDiscardOwed, "vm", "v2"); c.Severity != corrosion.SeverityCritical {
		t.Fatal("severity override ignored")
	}
	if err := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{Code: "firmware_migration_bogus", VM: "v1"}); err == nil {
		t.Fatal("an unknown code was raised")
	}
}

// The sweep judges a stale hold's row only from a replica that has caught up
// with a peer, as DeletedVMMarkerSweepTick does: after a long outage every
// hold is stale on the first pass while the replica is at its stalest. A hold
// with a domain still raises firmware_migration_held from a stale replica.
//
// Mutation: drop the ReplicaCaughtUp gate — the stale-replica pass
// quarantines, red.
func TestHoldSweep_WaitsForReplicaCatchUp(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	if err := f.s.db.Execute(context.Background(), `DELETE FROM vms WHERE name = ?`, fwtVM); err != nil {
		t.Fatal(err)
	}
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldPrepared, Since: time.Now().Add(-3 * time.Hour)}, []byte("t0"), []byte("tpm"))
	f.s.db.MarkReplicaStale("test: no peer exchange yet")
	f.s.FirmwareHoldSweepOnce(context.Background(), time.Now())
	if _, ok, _ := f.recs.GetHold(fwtVM); !ok || fwtExists(f.quarantine(fwtA1)) {
		t.Fatal("the sweep disposed of a hold from a replica that has not caught up")
	}
	f.s.db.MarkReplicaCaughtUpForTests("test")
	f.s.FirmwareHoldSweepOnce(context.Background(), time.Now())
	if _, ok, _ := f.recs.GetHold(fwtVM); ok || string(fwtRead(filepath.Join(f.quarantine(fwtA1), "nvram"))) != "t0" {
		t.Fatal("the caught-up sweep did not quarantine the abandoned hold")
	}
}

// DISCARD refuses once the commit has landed — the row names this host, for
// the hold's incarnation — so a stray DISCARD never takes the owner's held
// domain away; the hold, the domain and the state stay.
//
// Mutation: drop the row check before DiscardFirmwareMoveTarget — red.
func TestAbort_Discard_RefusesAfterCommit(t *testing.T) {
	for _, st := range []fwmig.HoldState{fwmig.HoldVerified, fwmig.HoldResuming} {
		t.Run(string(st), func(t *testing.T) {
			f := newFwtFixture(t, fwtSpecSBTPM)
			f.defineDomain(libvirtfake.StatePaused)
			f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: st}, []byte("t0"), []byte("tpm"))
			f.setRow("running", "dst")
			resp, err := f.abort(f.peer, fwtA1, discard, false, f.binding(fwtA1))
			if err != nil || !resp.Refused || !strings.Contains(resp.Detail, "names dst") {
				t.Fatalf("DISCARD after the commit = %+v, %v", resp, err)
			}
			if !f.fake.DomainExists(fwtVM) {
				t.Fatal("the owner's held domain was discarded")
			}
			if _, ok, _ := f.recs.GetHold(fwtVM); !ok || fwtExists(f.quarantine(fwtA1)) || string(fwtRead(f.store.NvramPath(fwtVM))) != "t0" {
				t.Fatal("a refused discard disposed of the hold")
			}
		})
	}
}

// The DISCARD refusal is bound to the hold's incarnation: a row that names
// this host for ANOTHER incarnation (the VM was recreated here) is not this
// attempt's commit, and an owed DISCARD of the old attempt with no domain
// left still quarantines its hold.
//
// Mutation: refuse whenever the row names this host — red.
func TestAbort_Discard_OtherIncarnationHereStillLands(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	b := f.binding(fwtA1)
	b.CreatedAt = "2001-01-01T00:00:00Z"
	f.putHold(fwmig.Hold{Binding: b, State: fwmig.HoldMismatch}, []byte("t0"), []byte("tpm"))
	f.setRow("running", "dst")
	resp, err := f.abort(f.peer, fwtA1, discard, false, b)
	if err != nil || resp.Refused {
		t.Fatalf("DISCARD of another incarnation's hold = %+v, %v", resp, err)
	}
	if _, ok, _ := f.recs.GetHold(fwtVM); ok || string(fwtRead(filepath.Join(f.quarantine(fwtA1), "nvram"))) != "t0" {
		t.Fatal("the old attempt's hold was not quarantined")
	}
}
