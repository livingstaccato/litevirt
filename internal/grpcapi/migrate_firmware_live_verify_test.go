package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

var (
	fwvT0      = []byte("target-nvram-T0")    // what Prepare materialised
	fwvFinal   = []byte("source-nvram-final") // the source's final NVRAM
	fwvPermall = []byte("tpm2-permall-final") // the migrated (and source final) permall
)

// fwvFast shortens the NVRAM confirmation poll for one test.
func fwvFast(t *testing.T, every, total time.Duration) {
	t.Helper()
	oe, of := releaseNvramPollEvery, releaseNvramPollFor
	releaseNvramPollEvery, releaseNvramPollFor = every, total
	t.Cleanup(func() { releaseNvramPollEvery, releaseNvramPollFor = oe, of })
}

// newFwvFixture is a target "dst" holding fw1 (Secure Boot + vTPM) for
// attempt a1 from "src" in hold state st, with the permall the migration
// copied and the NVRAM Prepare materialised (T0). dom is its domain here
// (StateNoDomain: none). committed: the row names dst, running (the commit
// landed); else it names src, migrating.
func newFwvFixture(t *testing.T, st fwmig.HoldState, dom libvirtfake.State, committed bool) *fwtFixture {
	t.Helper()
	f := newFwtFixture(t, fwtSpecSBTPM)
	fwvFast(t, 5*time.Millisecond, 300*time.Millisecond)
	if dom != libvirtfake.StateNoDomain {
		f.defineDomain(dom)
	}
	h := fwmig.Hold{Binding: f.binding(fwtA1), State: st, NvramT0SHA256: fwtSHA(fwvT0)}
	if st != fwmig.HoldPrepared && st != fwmig.HoldMismatch {
		h.VerifiedPermallSHA256 = fwtSHA(fwvPermall)
	}
	f.putHold(h, fwvT0, fwvPermall)
	if committed {
		f.setRowDetail(f.s.hostName, "running", "")
	}
	return f
}

// setRowDetail sets the row's host, state and state detail, and re-reads it.
func (f *fwtFixture) setRowDetail(host, state, detail string) {
	f.t.Helper()
	if err := f.s.db.Execute(context.Background(), `UPDATE vms SET host_name = ?, state = ?, state_detail = ? WHERE name = ?`,
		host, state, detail, fwtVM); err != nil {
		f.t.Fatal(err)
	}
	row, err := corrosion.GetVM(context.Background(), f.s.db, fwtVM)
	if err != nil || row == nil {
		f.t.Fatalf("GetVM: %v", err)
	}
	f.row = row
}

func (f *fwtFixture) getRow() *corrosion.VMRecord {
	f.t.Helper()
	row, err := corrosion.GetVM(context.Background(), f.s.db, fwtVM)
	if err != nil || row == nil {
		f.t.Fatalf("GetVM: %v", err)
	}
	return row
}

func (f *fwtFixture) verify(src string) (*pb.VerifyLiveFirmwareTargetResponse, error) {
	return f.s.VerifyLiveFirmwareTarget(f.peer, &pb.VerifyLiveFirmwareTargetRequest{
		VmName: fwtVM, Uuid: fwtUUID, AttemptId: fwtA1, SrcPermallSha256: src})
}

func (f *fwtFixture) releaseReq() *pb.ReleaseLiveFirmwareTargetRequest {
	return &pb.ReleaseLiveFirmwareTargetRequest{VmName: fwtVM, Uuid: fwtUUID, AttemptId: fwtA1, CreatedAt: f.row.CreatedAt,
		SrcNvramSha256: fwtSHA(fwvFinal), NvramFinal: fwvFinal}
}

func (f *fwtFixture) release(req *pb.ReleaseLiveFirmwareTargetRequest) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
	return f.s.ReleaseLiveFirmwareTarget(f.peer, req)
}

// hold is fw1's hold here, if any.
func (f *fwtFixture) hold() (fwmig.Hold, bool) {
	f.t.Helper()
	h, ok, err := f.recs.GetHold(fwtVM)
	if err != nil {
		f.t.Fatalf("GetHold: %v", err)
	}
	return h, ok
}

func (f *fwtFixture) holdState() fwmig.HoldState {
	f.t.Helper()
	h, ok := f.hold()
	if !ok {
		return "(none)"
	}
	return h.State
}

func (f *fwtFixture) domState() libvirtfake.State {
	st, ok := f.fake.RawState(fwtVM)
	if !ok {
		return libvirtfake.StateNoDomain
	}
	return st
}

// onResume runs fn when the fake resumes fw1 (before the resume itself; an
// error fails it), as QEMU writes the migrated pflash on resume.
func (f *fwtFixture) onResume(fn func() error) {
	f.fake.FailResumeDomain = func(name string) error {
		if name != fwtVM {
			return nil
		}
		return fn()
	}
}

// writeNvramOnResume makes the resume write b to the NVRAM, after delay (in
// the background) or at once.
func (f *fwtFixture) writeNvramOnResume(b []byte, delay time.Duration) {
	var wg sync.WaitGroup
	f.t.Cleanup(wg.Wait)
	f.onResume(func() error {
		if delay == 0 {
			f.writeFile(f.store.NvramPath(fwtVM), b)
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(delay)
			_ = os.WriteFile(f.store.NvramPath(fwtVM), b, 0o600)
		}()
		return nil
	})
}

// fwvState is everything Verify and a refused Release must leave alone.
type fwvState struct {
	files map[string]string
	hold  fwmig.HoldState
	dom   libvirtfake.State
	row   string
}

func (f *fwtFixture) state() fwvState {
	f.t.Helper()
	row := f.getRow()
	return fwvState{
		files: fwtSnapshot(f.t, f.store.SwtpmBase, f.s.dataDir),
		hold:  f.holdState(), dom: f.domState(),
		row: row.HostName + "/" + row.State + "/" + row.StateDetail,
	}
}

func (f *fwtFixture) requireUnchanged(before fwvState) {
	f.t.Helper()
	after := f.state()
	if !fwtSameSnapshot(before.files, after.files) {
		f.t.Errorf("files changed:\n before %v\n after  %v", before.files, after.files)
	}
	if before.hold != after.hold || before.dom != after.dom || before.row != after.row {
		f.t.Errorf("state changed: hold %s -> %s, domain %s -> %s, row %s -> %s",
			before.hold, after.hold, before.dom, after.dom, before.row, after.row)
	}
}

// ── T-14: Verify (spec §6.5) ──
//
// Mutations: treat an empty src hash as nothing to compare (EmptyHashTPM);
// skip the paused check (TargetRan); omit TargetDomain (NotHeldWithDomain,
// NotRunning); compare without recording the verdict (Match, Mismatch).

func TestVerify_Match(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	resp, err := f.verify(fwtSHA(fwvPermall))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != verdictMatch || resp.DstPermallSha256 != fwtSHA(fwvPermall) {
		t.Fatalf("verdict %v dst %s, want MATCH with the permall hash (%s)", resp.Verdict, resp.DstPermallSha256, resp.Detail)
	}
	if td := resp.TargetDomain; td == nil || !td.Present || td.State != "paused" || !strings.EqualFold(td.Uuid, fwtUUID) {
		t.Errorf("TargetDomain %+v, want the paused domain of the hold's uuid", td)
	}
	h, _ := f.hold()
	if h.State != fwmig.HoldVerified || h.VerifiedPermallSHA256 != fwtSHA(fwvPermall) {
		t.Errorf("hold %s verified %q, want verified with the permall hash", h.State, h.VerifiedPermallSHA256)
	}
	if f.domState() != libvirtfake.StatePaused {
		t.Errorf("Verify left the guest %s", f.domState())
	}
}

func TestVerify_Mismatch(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	resp, err := f.verify(fwtSHA([]byte("another permall")))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != verdictMismatch || resp.DstPermallSha256 != fwtSHA(fwvPermall) {
		t.Fatalf("verdict %v dst %s, want MISMATCH naming the target's hash", resp.Verdict, resp.DstPermallSha256)
	}
	if f.holdState() != fwmig.HoldMismatch || f.domState() != libvirtfake.StatePaused {
		t.Errorf("hold %s domain %s, want mismatch and still paused", f.holdState(), f.domState())
	}
	if string(fwtRead(f.permallPath())) != string(fwvPermall) {
		t.Error("Verify changed the target permall")
	}
	// A mismatch stays one: an equal hash later does not hide it.
	if resp, err := f.verify(fwtSHA(fwvPermall)); err != nil || resp.Verdict != verdictMismatch {
		t.Errorf("after a mismatch, an equal hash: %v %v, want MISMATCH", resp.GetVerdict(), err)
	}
}

func TestVerify_MissingPermall(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	if err := os.Remove(f.permallPath()); err != nil {
		t.Fatal(err)
	}
	resp, err := f.verify(fwtSHA(fwvPermall))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != verdictMismatch || f.holdState() != fwmig.HoldMismatch {
		t.Errorf("verdict %v hold %s, want MISMATCH / mismatch for a TPM VM with no permall here", resp.Verdict, f.holdState())
	}
}

func TestVerify_NotRunning(t *testing.T) {
	for _, dom := range []libvirtfake.State{libvirtfake.StateShutdown, libvirtfake.StateNoDomain} {
		t.Run(string(dom), func(t *testing.T) {
			f := newFwvFixture(t, fwmig.HoldPrepared, dom, false)
			before := f.state()
			resp, err := f.verify(fwtSHA(fwvPermall))
			if err != nil {
				t.Fatal(err)
			}
			if resp.Verdict != verdictNotRunning {
				t.Errorf("verdict %v, want NOT_RUNNING", resp.Verdict)
			}
			if resp.TargetDomain == nil || resp.TargetDomain.Present != (dom != libvirtfake.StateNoDomain) {
				t.Errorf("TargetDomain %+v does not describe the domain", resp.TargetDomain)
			}
			f.requireUnchanged(before)
		})
	}
}

func TestVerify_TargetRan(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StateRunning, false)
	before := f.state()
	resp, err := f.verify(fwtSHA(fwvPermall))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != verdictTargetRan || resp.TargetDomain.GetState() != "running" {
		t.Errorf("verdict %v domain %+v, want TARGET_RAN with the running domain", resp.Verdict, resp.TargetDomain)
	}
	f.requireUnchanged(before)
}

func TestVerify_NotHeldWithDomain(t *testing.T) {
	t.Run("no hold", func(t *testing.T) {
		f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
		if err := f.recs.RemoveHold(fwtVM); err != nil {
			t.Fatal(err)
		}
		before := f.state()
		resp, err := f.verify(fwtSHA(fwvPermall))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Verdict != verdictNotHeld || !resp.TargetDomain.GetPresent() || resp.TargetDomain.GetState() != "paused" {
			t.Errorf("verdict %v domain %+v, want NOT_HELD with the paused domain filled", resp.Verdict, resp.TargetDomain)
		}
		f.requireUnchanged(before)
	})
	t.Run("another attempt", func(t *testing.T) {
		f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
		before := f.state()
		resp, err := f.s.VerifyLiveFirmwareTarget(f.peer, &pb.VerifyLiveFirmwareTargetRequest{
			VmName: fwtVM, Uuid: fwtUUID, AttemptId: fwtA2, SrcPermallSha256: fwtSHA(fwvPermall)})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Verdict != verdictNotHeld || !resp.TargetDomain.GetPresent() {
			t.Errorf("verdict %v domain %+v, want NOT_HELD with the domain filled", resp.Verdict, resp.TargetDomain)
		}
		f.requireUnchanged(before)
	})
}

func TestVerify_EmptyHashTPM(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	before := f.state()
	resp, err := f.verify("")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != verdictBadRequest {
		t.Errorf("verdict %v, want BAD_REQUEST for a vTPM VM without src_permall_sha256", resp.Verdict)
	}
	f.requireUnchanged(before)
}

// A Secure Boot VM without a vTPM has no permall to compare: an empty hash is
// what its source sends, and the paused domain of the hold matches.
func TestVerify_SBOnlyMatchesWithoutPermall(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	h, _ := f.hold()
	h.TPM = false
	if err := f.recs.PutHold(h); err != nil {
		t.Fatal(err)
	}
	resp, err := f.verify("")
	if err != nil || resp.Verdict != verdictMatch {
		t.Fatalf("SB-only: %v %v, want MATCH", resp.GetVerdict(), err)
	}
	if f.holdState() != fwmig.HoldVerified {
		t.Errorf("hold %s, want verified", f.holdState())
	}
}

func TestVerify_IdempotentVerified(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	for i := 0; i < 2; i++ {
		resp, err := f.verify(fwtSHA(fwvPermall))
		if err != nil || resp.Verdict != verdictMatch {
			t.Fatalf("verify %d: %v %v, want MATCH", i, resp.GetVerdict(), err)
		}
	}
	if f.holdState() != fwmig.HoldVerified {
		t.Fatalf("hold %s, want verified", f.holdState())
	}
	// The permall changed after it was verified: no longer a match.
	f.writeFile(f.permallPath(), []byte("written after verify"))
	resp, err := f.verify(fwtSHA([]byte("written after verify")))
	if err != nil || resp.Verdict != verdictMismatch {
		t.Errorf("verified hold, permall changed: %v %v, want MISMATCH", resp.GetVerdict(), err)
	}
}

// Verify reads: no NVRAM comparison while paused (the NVRAM is T0 or
// anything), no domain or file change, only the hold's verdict.
func TestVerify_NoWrite(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	f.writeFile(f.store.NvramPath(fwtVM), []byte("whatever the paused NVRAM holds"))
	files := fwtSnapshot(t, f.store.SwtpmBase)
	nvram := string(fwtRead(f.store.NvramPath(fwtVM)))
	resp, err := f.verify(fwtSHA(fwvPermall))
	if err != nil || resp.Verdict != verdictMatch {
		t.Fatalf("%v %v, want MATCH whatever the paused NVRAM holds", resp.GetVerdict(), err)
	}
	if !fwtSameSnapshot(files, fwtSnapshot(t, f.store.SwtpmBase)) || string(fwtRead(f.store.NvramPath(fwtVM))) != nvram {
		t.Error("Verify wrote firmware state")
	}
	if f.domState() != libvirtfake.StatePaused {
		t.Errorf("Verify left the guest %s", f.domState())
	}
}

func TestVerify_OnlyTheHoldsSource(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldPrepared, libvirtfake.StatePaused, false)
	before := f.state()
	_, err := f.s.VerifyLiveFirmwareTarget(peerCtxFor(t, f.s, "other"), &pb.VerifyLiveFirmwareTargetRequest{
		VmName: fwtVM, Uuid: fwtUUID, AttemptId: fwtA1, SrcPermallSha256: fwtSHA(fwvPermall)})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("another peer: %v, want PermissionDenied", err)
	}
	f.requireUnchanged(before)
}

// ── T-15: Release preconditions (spec §6.6) ──
//
// Mutations: drop the row check (RefusesUncommitted, IdempotentAfterRun);
// treat an empty NVRAM hash as nothing to confirm (EmptyNvramHashUEFI);
// require a hold on retry (IdempotentAfterRun, CrashBetweenResumeAndHoldUpdate);
// resume before writing resuming (Resumes, ResumeFailedRetries); treat
// resuming + paused as refused (ResumeFailedRetries).

func TestRelease_RefusesUnverified(t *testing.T) {
	for _, st := range []fwmig.HoldState{fwmig.HoldPrepared, fwmig.HoldMismatch} {
		t.Run(string(st), func(t *testing.T) {
			f := newFwvFixture(t, st, libvirtfake.StatePaused, true)
			before := f.state()
			if _, err := f.release(f.releaseReq()); status.Code(err) != codes.FailedPrecondition {
				t.Errorf("hold %s: %v, want FailedPrecondition", st, err)
			}
			f.requireUnchanged(before)
		})
	}
}

func TestRelease_RefusesUncommitted(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, false)
	before := f.state()
	_, err := f.release(f.releaseReq())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "has not committed") {
		t.Errorf("row names the source: %v, want FailedPrecondition (not committed)", err)
	}
	f.requireUnchanged(before)
}

func TestRelease_EmptyNvramHashUEFI(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
	before := f.state()
	req := f.releaseReq()
	req.SrcNvramSha256 = ""
	resp, err := f.release(req)
	if err != nil || resp.Verdict != verdictBadRequest {
		t.Errorf("%v %v, want BAD_REQUEST for a UEFI VM without src_nvram_sha256", resp.GetVerdict(), err)
	}
	f.requireUnchanged(before)
}

// The happy path: NIC firewall in force, the hold resuming BEFORE the resume,
// the guest resumed, any NIC hand-over record dropped, the NVRAM confirmed,
// the hold removed.
func TestRelease_Resumes(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
	if err := f.s.putHeld(heldGuest{VM: fwtVM, UUID: fwtUUID, CreatedAt: f.row.CreatedAt, Source: fwtSrc, Since: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	var atResume fwmig.HoldState
	f.onResume(func() error {
		atResume = f.holdState()
		f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
		return nil
	})
	resp, err := f.release(f.releaseReq())
	if err != nil {
		t.Fatal(err)
	}
	if atResume != fwmig.HoldResuming {
		t.Errorf("the hold was %s when the guest resumed, want resuming", atResume)
	}
	if !resp.NvramConfirmed || resp.NvramSha256 != fwtSHA(fwvFinal) || resp.Verdict != pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED {
		t.Errorf("resp %+v, want confirmed with the source's final hash", resp)
	}
	if f.domState() != libvirtfake.StateRunning {
		t.Errorf("guest %s, want running", f.domState())
	}
	if _, ok := f.hold(); ok {
		t.Error("the hold outlived a confirmed release")
	}
	if g, ok, _ := f.s.getHeld(fwtVM); ok {
		t.Errorf("the NIC hand-over record outlived the release: %+v", g)
	}
}

// A guest whose NIC guards cannot be put in force here is not resumed, and
// its hold is not moved to resuming.
func TestRelease_ArmsNICsBeforeResume(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
	ctx := context.Background()
	f.s.db.SetClusterPolicyGate(func() bool { return true })
	f.s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	if err := corrosion.PutNICGuard(ctx, f.s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		corrosion.NICGuardRecord{VMName: fwtVM, MAC: "52:54:00:00:00:01", Mode: corrosion.NICGuardOn}, "t"); err != nil {
		t.Fatal(err)
	}
	f.s.SetFirewallReconciler(&inForceArmer{inForce: false})
	before := f.state()
	if _, err := f.release(f.releaseReq()); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("guards not in force: %v, want FailedPrecondition", err)
	}
	f.requireUnchanged(before)
}

func TestRelease_IdempotentAfterRun(t *testing.T) {
	setup := func(t *testing.T) *fwtFixture {
		f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StateRunning, true)
		if err := f.recs.RemoveHold(fwtVM); err != nil {
			t.Fatal(err)
		}
		f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
		return f
	}
	t.Run("retry completes", func(t *testing.T) {
		f := setup(t)
		resp, err := f.release(f.releaseReq())
		if err != nil || !resp.NvramConfirmed || resp.Verdict != pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED {
			t.Fatalf("%+v %v, want a confirmed release", resp, err)
		}
		if f.domState() != libvirtfake.StateRunning {
			t.Errorf("guest %s, want running", f.domState())
		}
	})
	for name, mut := range map[string]func(*fwtFixture, *pb.ReleaseLiveFirmwareTargetRequest){
		"request uuid not the domain's": func(_ *fwtFixture, r *pb.ReleaseLiveFirmwareTargetRequest) {
			r.Uuid = "00000000-1111-4222-8333-444455556666"
		},
		"request incarnation not the row's": func(_ *fwtFixture, r *pb.ReleaseLiveFirmwareTargetRequest) {
			r.CreatedAt = "2001-01-01T00:00:00Z"
		},
		"running domain not the request's uuid": func(f *fwtFixture, _ *pb.ReleaseLiveFirmwareTargetRequest) {
			f.fake.SetInactiveXML(fwtVM, `<domain type='kvm'><name>`+fwtVM+`</name><uuid>00000000-1111-4222-8333-444455556666</uuid><devices></devices></domain>`)
		},
		"row names another host": func(f *fwtFixture, _ *pb.ReleaseLiveFirmwareTargetRequest) {
			f.setRowDetail(fwtSrc, "running", "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			req := f.releaseReq()
			mut(f, req)
			before := f.state()
			if _, err := f.release(req); status.Code(err) != codes.FailedPrecondition {
				t.Errorf("%v, want FailedPrecondition", err)
			}
			f.requireUnchanged(before)
		})
	}
}

// A target restart between the resume and the next hold write leaves the
// hold resuming with the guest running: a retry completes the hand-over.
func TestRelease_CrashBetweenResumeAndHoldUpdate(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldResuming, libvirtfake.StateRunning, true)
	f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
	resp, err := f.release(f.releaseReq())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict == verdictTargetRan || !resp.NvramConfirmed {
		t.Errorf("resp %+v, want the hand-over completed, not TARGET_RAN", resp)
	}
	if _, ok := f.hold(); ok {
		t.Error("the hold outlived the completed hand-over")
	}
}

func TestRelease_RunningWithVerifiedHoldIsTargetRan(t *testing.T) {
	for _, st := range []fwmig.HoldState{fwmig.HoldVerified, fwmig.HoldPrepared} {
		t.Run(string(st), func(t *testing.T) {
			f := newFwvFixture(t, st, libvirtfake.StateRunning, true)
			before := f.state()
			resp, err := f.release(f.releaseReq())
			if err != nil || resp.Verdict != verdictTargetRan {
				t.Errorf("%v %v, want TARGET_RAN", resp.GetVerdict(), err)
			}
			if resp.GetTargetDomain().GetState() != "running" {
				t.Errorf("TargetDomain %+v, want the running domain", resp.GetTargetDomain())
			}
			f.requireUnchanged(before)
		})
	}
}

// Release step 2a: the resume failed with the hold already resuming; a
// retry resumes.
func TestRelease_ResumeFailedRetries(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
	f.onResume(func() error { return errors.New("injected: resume failed") })
	if _, err := f.release(f.releaseReq()); err == nil {
		t.Fatal("a failed resume answered OK")
	}
	if f.holdState() != fwmig.HoldResuming || f.domState() != libvirtfake.StatePaused {
		t.Fatalf("after a failed resume: hold %s domain %s, want resuming and paused", f.holdState(), f.domState())
	}
	f.writeNvramOnResume(fwvFinal, 0)
	resp, err := f.release(f.releaseReq())
	if err != nil || !resp.NvramConfirmed {
		t.Fatalf("retry: %+v %v, want a confirmed release", resp, err)
	}
	if f.domState() != libvirtfake.StateRunning {
		t.Errorf("guest %s after the retry, want running", f.domState())
	}
	if _, ok := f.hold(); ok {
		t.Error("the hold outlived the retried release")
	}
}

// Release step 2b: resuming, and the guest is shut off (the target host went
// down after the resume began). It never ran: H1 hands the firmware over.
func TestRelease_ResumingShutOffRunsH1Checks(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldResuming, libvirtfake.StateShutdown, true)
	resp, err := f.release(f.releaseReq())
	if err != nil || !resp.NvramConfirmed || resp.Verdict != pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED {
		t.Fatalf("%+v %v, want H1 to hand the firmware over", resp, err)
	}
	if string(fwtRead(f.store.NvramPath(fwtVM))) != string(fwvFinal) {
		t.Error("H1 did not push the source's final NVRAM")
	}
	if row := f.getRow(); row.State != "stopped" || row.HostName != "dst" {
		t.Errorf("row %s on %s, want stopped on dst", row.State, row.HostName)
	}
	if f.domState() != libvirtfake.StateShutdown {
		t.Errorf("guest %s, want left shut off", f.domState())
	}
	if _, ok := f.hold(); ok {
		t.Error("the hold outlived H1")
	}
}

// Release step 2b, the guest ran: its NVRAM is the source's final (written
// on resume), not T0. That is target_ran, with nothing written.
func TestRelease_ResumingShutOffAfterRunParksTargetRan(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldResuming, libvirtfake.StateShutdown, true)
	f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
	before := f.state()
	resp, err := f.release(f.releaseReq())
	if err != nil || resp.Verdict != verdictTargetRan {
		t.Fatalf("%v %v, want TARGET_RAN", resp.GetVerdict(), err)
	}
	f.requireUnchanged(before)
}

// ── T-16: NVRAM confirmation (spec §6.6 step 6) ──
//
// Mutations: one read only (NvramPollsThenConfirms); remove the hold when
// unconfirmed (UnconfirmedKeepsStartVeto); allow OpStop for
// released_unconfirmed (UnconfirmedRefusesStop).

func TestRelease_NvramPollsThenConfirms(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
	fwvFast(t, 5*time.Millisecond, 5*time.Second)
	f.writeNvramOnResume(fwvFinal, 60*time.Millisecond)
	resp, err := f.release(f.releaseReq())
	if err != nil || !resp.NvramConfirmed || resp.NvramSha256 != fwtSHA(fwvFinal) {
		t.Fatalf("%+v %v, want the NVRAM confirmed once it is written", resp, err)
	}
	if _, ok := f.hold(); ok {
		t.Error("the hold outlived a confirmed release")
	}
}

// unconfirmedRelease releases a guest whose NVRAM never becomes the source's
// final one.
func unconfirmedRelease(t *testing.T) *fwtFixture {
	t.Helper()
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
	fwvFast(t, 5*time.Millisecond, 50*time.Millisecond)
	f.writeNvramOnResume([]byte("a variable the guest wrote"), 0)
	resp, err := f.release(f.releaseReq())
	if err != nil {
		t.Fatal(err)
	}
	if resp.NvramConfirmed || resp.NvramSha256 != fwtSHA([]byte("a variable the guest wrote")) {
		t.Fatalf("resp %+v, want unconfirmed with the target's hash", resp)
	}
	if f.holdState() != fwmig.HoldReleasedUnconfirmed || f.domState() != libvirtfake.StateRunning {
		t.Fatalf("hold %s guest %s, want released_unconfirmed and running", f.holdState(), f.domState())
	}
	return f
}

func TestRelease_UnconfirmedKeepsStartVeto(t *testing.T) {
	f := unconfirmedRelease(t)
	f.fake.SetState(fwtVM, libvirtfake.StateShutdown) // the guest powered off
	if err := f.fake.StartDomain(fwtVM); !errors.Is(err, lv.ErrFirmwareMoveInFlight) {
		t.Errorf("start under released_unconfirmed: %v, want refused", err)
	}
	if f.domState() != libvirtfake.StateShutdown {
		t.Errorf("guest %s, want still off", f.domState())
	}
}

func TestRelease_UnconfirmedRefusesStop(t *testing.T) {
	f := unconfirmedRelease(t)
	for name, stop := range map[string]func(string) error{"destroy": f.fake.DestroyDomain, "shutdown": f.fake.ShutdownDomain} {
		if err := stop(fwtVM); !errors.Is(err, lv.ErrFirmwareMoveInFlight) {
			t.Errorf("%s under released_unconfirmed: %v, want refused", name, err)
		}
	}
	if f.domState() != libvirtfake.StateRunning {
		t.Errorf("guest %s, want still running", f.domState())
	}
}

// ── T-31: H1, a held guest found shut off at Release (spec §7 H1) ──
//
// Each refusal parks the move (TARGET_RAN, or NOT_RUNNING for an absent
// domain) with nothing written; the row is set stopped only on the pass.
// Mutation: skip any one check (one sub-test each).

func TestRelease_H1(t *testing.T) {
	type tc struct {
		hold      fwmig.HoldState
		committed bool
		setup     func(f *fwtFixture, req *pb.ReleaseLiveFirmwareTargetRequest)
		want      pb.FirmwareVerdict
		text      string
	}
	refusals := map[string]tc{
		"WrongNvramFinalHash": {fwmig.HoldVerified, true, func(_ *fwtFixture, r *pb.ReleaseLiveFirmwareTargetRequest) {
			r.NvramFinal = []byte("not the source's final NVRAM")
		}, verdictTargetRan, "nvram_final hashes"},
		"NoNvramFinal": {fwmig.HoldVerified, true, func(_ *fwtFixture, r *pb.ReleaseLiveFirmwareTargetRequest) {
			r.NvramFinal = nil
		}, verdictTargetRan, "no nvram_final"},
		"PermallChanged": {fwmig.HoldVerified, true, func(f *fwtFixture, _ *pb.ReleaseLiveFirmwareTargetRequest) {
			f.writeFile(f.permallPath(), []byte("the TPM was written after Verify"))
		}, verdictTargetRan, "permall"},
		"PermallMissing": {fwmig.HoldVerified, true, func(f *fwtFixture, _ *pb.ReleaseLiveFirmwareTargetRequest) {
			_ = os.Remove(f.permallPath())
		}, verdictTargetRan, "permall"},
		"NvramNotT0": {fwmig.HoldVerified, true, func(f *fwtFixture, _ *pb.ReleaseLiveFirmwareTargetRequest) {
			f.writeFile(f.store.NvramPath(fwtVM), []byte("a variable the guest wrote"))
		}, verdictTargetRan, "it ran"},
		// A pushed-looking NVRAM (the source's final) without H1's own row
		// record is what a resume writes: the guest ran.
		"NvramIsFinalWithoutH1Row": {fwmig.HoldVerified, true, func(f *fwtFixture, _ *pb.ReleaseLiveFirmwareTargetRequest) {
			f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
		}, verdictTargetRan, "it ran"},
		"DomainAbsent": {fwmig.HoldVerified, true, nil, verdictNotRunning, "held_domain_absent"},
		// Reached through step 2b (resuming): step 3 already refuses a
		// verified hold whose row is not here.
		"RowNotTarget": {fwmig.HoldResuming, false, nil, verdictTargetRan, "row names src"},
		"DomainOtherUUID": {fwmig.HoldVerified, true, func(f *fwtFixture, _ *pb.ReleaseLiveFirmwareTargetRequest) {
			f.fake.SetInactiveXML(fwtVM, `<domain type='kvm'><name>`+fwtVM+`</name><uuid>00000000-1111-4222-8333-444455556666</uuid><devices></devices></domain>`)
		}, verdictTargetRan, "uuid"},
	}
	for name, c := range refusals {
		t.Run(name, func(t *testing.T) {
			dom := libvirtfake.StateShutdown
			if name == "DomainAbsent" {
				dom = libvirtfake.StateNoDomain
			}
			f := newFwvFixture(t, c.hold, dom, c.committed)
			req := f.releaseReq()
			if c.setup != nil {
				c.setup(f, req)
			}
			before := f.state()
			resp, err := f.release(req)
			if err != nil || resp.Verdict != c.want || !strings.Contains(resp.Detail, c.text) {
				t.Fatalf("%v %q %v, want %v naming %q", resp.GetVerdict(), resp.GetDetail(), err, c.want, c.text)
			}
			if resp.NvramConfirmed {
				t.Error("a refused H1 reported the NVRAM confirmed")
			}
			f.requireUnchanged(before)
		})
	}
	t.Run("Pushes", func(t *testing.T) {
		f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StateShutdown, true)
		resp, err := f.release(f.releaseReq())
		if err != nil || !resp.NvramConfirmed || resp.Verdict != pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED {
			t.Fatalf("%+v %v, want H1 to pass", resp, err)
		}
		if string(fwtRead(f.store.NvramPath(fwtVM))) != string(fwvFinal) {
			t.Error("the source's final NVRAM was not pushed")
		}
		if string(fwtRead(f.permallPath())) != string(fwvPermall) {
			t.Error("H1 changed the verified permall")
		}
		row := f.getRow()
		if row.State != "stopped" || row.HostName != "dst" || row.StateDetail != h1StoppedDetail("dst") {
			t.Errorf("row %s on %s (%q), want stopped on dst with %q", row.State, row.HostName, row.StateDetail, h1StoppedDetail("dst"))
		}
		if f.domState() != libvirtfake.StateShutdown {
			t.Errorf("guest %s, want left off for `lv start`", f.domState())
		}
		if _, ok := f.hold(); ok {
			t.Error("the hold outlived H1")
		}
	})
	// H1 records the row, pushes the NVRAM, then removes the hold. A crash
	// after the push leaves the hold and an NVRAM that is no longer T0; since
	// H1's row write the hold refused every start, so a retry completes.
	t.Run("RetryAfterPushBeforeHoldRemoval", func(t *testing.T) {
		f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StateShutdown, true)
		f.setRowDetail("dst", "stopped", h1StoppedDetail("dst"))
		f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
		resp, err := f.release(f.releaseReq())
		if err != nil || !resp.NvramConfirmed || resp.Verdict != pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED {
			t.Fatalf("%+v %v, want the retry to complete H1", resp, err)
		}
		if _, ok := f.hold(); ok {
			t.Error("the hold outlived the retried H1")
		}
	})
}

// ── T-17 (NIC paths): nothing but Release resumes a held guest (spec §6.9, §10) ──
//
// For holds verified, resuming and released_unconfirmed, each of
// ArmNICFirewall{resume} (with and without a NIC hand-over record), the NIC
// held-guest sweep and ResumeHeldVM refuses, naming the move, and the guest
// stays paused. Mutation: remove one check (one sub-test each).

func TestHeldFirmwareGuest_NoNICResumePath(t *testing.T) {
	want := "held for firmware verification of attempt " + fwtA1 + " from " + fwtSrc
	putNICRecord := func(f *fwtFixture) {
		if err := f.s.putHeld(heldGuest{VM: fwtVM, UUID: fwtUUID, CreatedAt: f.row.CreatedAt, Source: fwtSrc,
			Since: time.Now().UTC().Format(time.RFC3339)}); err != nil {
			f.t.Fatal(err)
		}
	}
	paths := map[string]func(t *testing.T, f *fwtFixture) string{
		"ArmNICFirewall held branch": func(t *testing.T, f *fwtFixture) string {
			putNICRecord(f)
			_, err := f.s.ArmNICFirewall(f.peer, &pb.ArmNICFirewallRequest{VmName: fwtVM, Resume: true})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("%v, want FailedPrecondition", err)
			}
			if _, ok, _ := f.s.getHeld(fwtVM); !ok {
				t.Error("the NIC hand-over record was dropped")
			}
			return errText(err)
		},
		"ArmNICFirewall not-held branch": func(t *testing.T, f *fwtFixture) string {
			_, err := f.s.ArmNICFirewall(f.peer, &pb.ArmNICFirewallRequest{VmName: fwtVM, Resume: true})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("%v, want FailedPrecondition", err)
			}
			return errText(err)
		},
		"sweep": func(t *testing.T, f *fwtFixture) string {
			putNICRecord(f)
			ctx := context.Background()
			f.s.ResumeHeldGuestsOnce(ctx)
			if _, ok, _ := f.s.getHeld(fwtVM); !ok {
				t.Error("the sweep dropped the NIC hand-over record")
			}
			row, ok, err := corrosion.GetHealthCondition(ctx, f.s.db, FirewallEvaluator, CondFirewallHeld, "host", f.s.hostName)
			if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
				t.Errorf("the sweep reported nothing: %+v %v %v", row, ok, err)
			}
			return row.Evidence
		},
		"ResumeHeldVM": func(t *testing.T, f *fwtFixture) string {
			_, err := f.s.ResumeHeldVM(adminCtx(), &pb.ResumeHeldVMRequest{VmName: fwtVM})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("%v, want FailedPrecondition", err)
			}
			return errText(err)
		},
	}
	for _, st := range []fwmig.HoldState{fwmig.HoldVerified, fwmig.HoldResuming, fwmig.HoldReleasedUnconfirmed} {
		for name, path := range paths {
			t.Run(string(st)+"/"+name, func(t *testing.T) {
				f := newFwvFixture(t, st, libvirtfake.StatePaused, true)
				text := path(t, f)
				if !strings.Contains(text, want) {
					t.Errorf("%q does not say %q", text, want)
				}
				if f.domState() != libvirtfake.StatePaused {
					t.Errorf("the held guest is %s, want paused", f.domState())
				}
				if f.holdState() != st {
					t.Errorf("hold %s, want %s", f.holdState(), st)
				}
			})
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// A hold that cannot be read holds: no NIC path resumes the guest.
//
// Mutation: let an unreadable hold through firmwareMoveHeld - red.
func TestHeldFirmwareGuest_UnreadableHoldRefuses(t *testing.T) {
	f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
	f.writeFile(filepath.Join(f.s.dataDir, fwmig.HoldDir, fwtVM+".json"), []byte("{not json"))
	_, err := f.s.ArmNICFirewall(f.peer, &pb.ArmNICFirewallRequest{VmName: fwtVM, Resume: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "held for firmware verification") {
		t.Errorf("%v, want FailedPrecondition naming the firmware hold", err)
	}
	if f.domState() != libvirtfake.StatePaused {
		t.Errorf("guest %s, want paused", f.domState())
	}
}
