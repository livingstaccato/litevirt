package grpcapi

import (
	"context"
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
	"github.com/litevirt/litevirt/internal/vfio"
)

// The source's failure matrix of a live firmware move (spec §7), driven
// through MigrateVM on the fwlRig: the target's real handlers answer unless a
// test replaces one answer.

const (
	modePre     = pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER
	modeDiscard = pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED
)

// requireAbortModes: the source sent exactly these aborts, in this order.
func requireAbortModes(t *testing.T, r *fwlRig, want ...pb.FirmwareAbortMode) {
	t.Helper()
	var got []string
	for _, a := range r.aborts() {
		got = append(got, a.GetMode().String())
	}
	var w []string
	for _, m := range want {
		w = append(w, m.String())
	}
	if strings.Join(got, ",") != strings.Join(w, ",") {
		t.Fatalf("aborts %v, want %v", got, w)
	}
}

// requireMarker: the source marker is parked in phase from from.
func requireMarker(t *testing.T, r *fwlRig, phase, from fwmig.Phase) fwmig.Marker {
	t.Helper()
	m, ok := r.marker()
	if !ok || m.Phase != phase || m.ParkedFrom != from {
		t.Fatalf("marker %+v (present %v), want %s from %s", m, ok, phase, from)
	}
	return m
}

// requireNoFwmigCondition: s raised no open code for os1.
func requireNoFwmigCondition(t *testing.T, s *Server, code string) {
	t.Helper()
	c, found, err := corrosion.GetHealthCondition(context.Background(), s.db, firmwareMigrationEvaluator, code, "vm", fwlVM)
	if err != nil {
		t.Fatal(err)
	}
	if found && c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %s is open: %+v", code, c)
	}
}

// confirmPhaseFailure makes libvirt land the guest paused on the target and
// then fail the migration with the source still running (§7 M1, K-3).
func (r *fwlRig) confirmPhaseFailure(sourceState libvirtfake.State) {
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		r.srcFake.SetState(fwlVM, sourceState)
		return errors.New("injected confirm-phase failure")
	}
}

func (r *fwlRig) quarantined() bool {
	_, err := os.Stat(filepath.Join(r.dst.dataDir, fwmig.QuarantineDir))
	if err != nil {
		return false
	}
	ents, _ := os.ReadDir(filepath.Join(r.dst.dataDir, fwmig.QuarantineDir))
	return len(ents) > 0
}

// T-36: §7 M1 with a Confirm-phase failure. The source still runs; the target
// holds the landed guest paused under a prepared hold. The source decides
// from Abort PRE_CUTOVER's refusal (domain + hold_state), never from Verify,
// and discards the target's copy at once: marker removed, row running, the
// target's copy quarantined. The SB-only VM (no permall anywhere) takes the
// same path.
//
// Mutations: park instead of DISCARD; decide via Verify — red.
func TestM1_TargetDomainPreparedHoldDiscardsAndUnmarks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sbOnly bool
	}{{"sb_tpm", false}, {"sb_only", true}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFwlRig(t, fwlOpts{sbOnly: tc.sbOnly})
			r.confirmPhaseFailure(libvirtfake.StateRunning)
			if err := r.migrate(); err == nil {
				t.Fatal("the move succeeded; the scenario needs libvirt to fail it")
			}
			requireAbortModes(t, r, modePre, modeDiscard)
			if m, ok := r.marker(); ok {
				t.Fatalf("marker left %+v, want it removed after the discard", m)
			}
			if _, ok := r.hold(); ok {
				t.Error("the target still holds the attempt")
			}
			if r.dstFake.DomainExists(fwlVM) {
				t.Error("the target's domain is still defined")
			}
			if !r.quarantined() {
				t.Error("the target's copy was not quarantined")
			}
			if vm := r.row(); vm.HostName != "src-host" || vm.State != "running" {
				t.Errorf("row %s on %s, want running on src-host", vm.State, vm.HostName)
			}
			if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
				t.Errorf("source domain %q, want running", st)
			}
			r.requireSourceIntact("after the M1 discard")
			if tc.sbOnly && fwtExists(filepath.Join(r.srcStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")) {
				t.Error("the SB-only rig has a permall")
			}
		})
	}
}

// T-36: before cutover the source never sends Verify: the abort's answer is
// all M1 decides from (call order: PRE_CUTOVER, then DISCARD, no verify).
//
// Mutation: decide via Verify — red.
func TestM1_NeverCallsVerifyBeforeCutover(t *testing.T) {
	r := newFwlRig(t, fwlOpts{sbOnly: true})
	r.confirmPhaseFailure(libvirtfake.StateRunning)
	_ = r.migrate()
	for _, s := range r.log.get() {
		if s == "verify" {
			t.Fatalf("steps %v: Verify was called before cutover", r.log.get())
		}
	}
	requireAbortModes(t, r, modePre, modeDiscard)
}

// T-36: the target refuses the DISCARD (its domain runs): park target_ran,
// nothing deleted, the source keeps running with its row.
//
// Mutation: DISCARD a running target, or remove the marker anyway — red.
func TestM1_DiscardRefusedParksTargetRan(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.confirmPhaseFailure(libvirtfake.StateRunning)
	r.peerC.abortAnswer = func(req *pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		if req.GetMode() == modeDiscard {
			return &pb.AbortLiveFirmwareTargetResponse{Refused: true, HoldState: "prepared",
				TargetDomain: &pb.TargetDomain{Present: true, State: "running"}, Detail: "its domain is running here"}, nil
		}
		return r.dst.AbortLiveFirmwareTarget(r.peer, req)
	}
	_ = r.migrate()
	requireAbortModes(t, r, modePre, modeDiscard)
	requireMarker(t, r, fwmig.PhaseTargetRan, fwmig.PhaseMigrating)
	requireFwmigCondition(t, r.src, condFwmigTargetRan)
	if _, ok := r.hold(); !ok {
		t.Error("the target's hold is gone")
	}
	if vm := r.row(); vm.HostName != "src-host" || vm.State != "running" {
		t.Errorf("row %s on %s, want running on src-host", vm.State, vm.HostName)
	}
	r.requireSourceIntact("after a refused discard")
}

// M1 where the target's domain already RUNS at the abort: no DISCARD is sent
// (a running guest is never discarded), the move parks target_ran.
//
// Mutation: discard whatever the domain's state — red.
func TestM1_RunningTargetNotDiscarded(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		return errors.New("injected confirm-phase failure")
	}
	_ = r.migrate()
	requireAbortModes(t, r, modePre)
	requireMarker(t, r, fwmig.PhaseTargetRan, fwmig.PhaseMigrating)
}

// M1 where the abort's refusal shows a domain under a hold that is not
// prepared: not this attempt's untouched copy, so no DISCARD; park
// target_ran.
//
// Mutation: discard whatever the hold's state — red.
func TestM1_NonPreparedHoldNotDiscarded(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.confirmPhaseFailure(libvirtfake.StateRunning)
	r.peerC.abortAnswer = func(req *pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		if req.GetMode() == modePre {
			return &pb.AbortLiveFirmwareTargetResponse{Refused: true, HoldState: string(fwmig.HoldMismatch),
				TargetDomain: &pb.TargetDomain{Present: true, State: "paused"}}, nil
		}
		return r.dst.AbortLiveFirmwareTarget(r.peer, req)
	}
	_ = r.migrate()
	requireAbortModes(t, r, modePre)
	requireMarker(t, r, fwmig.PhaseTargetRan, fwmig.PhaseMigrating)
}

// M1 with the DISCARD unanswered: park target_unreachable (fence resolution
// applies), the source still running.
//
// Mutation: remove the marker without an answer — red.
func TestM1_DiscardUnansweredParksUnreachable(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.confirmPhaseFailure(libvirtfake.StateRunning)
	r.peerC.abortAnswer = func(req *pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		if req.GetMode() == modeDiscard {
			return nil, status.Error(codes.Unavailable, "connection refused")
		}
		return r.dst.AbortLiveFirmwareTarget(r.peer, req)
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseMigrating)
	if vm := r.row(); vm.State != "running" {
		t.Errorf("row %s, want running (the source guest runs)", vm.State)
	}
}

// §7 M1p: the migration failed and left the source guest paused; the target
// holds nothing. The source resumes FIRST (ResumeFirmwareMoveSource), while
// its marker still vetoes and the row still says migrating; then the row is
// restored, then the marker removed.
//
// Mutation: leave it paused; remove the marker before the resume — red.
func TestM1p_ResumesSourceFirstThenUnmarks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.srcFake.FailMigrateToTarget = func(string, string) error {
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		return errors.New("injected failure that left the guest paused")
	}
	var atResume struct {
		marker bool
		row    string
	}
	r.onResumeSource = func() {
		_, atResume.marker = r.marker()
		atResume.row = r.row().State
	}
	if err := r.migrate(); err == nil {
		t.Fatal("the move succeeded; the scenario needs libvirt to fail it")
	}
	if !atResume.marker || atResume.row != "migrating" {
		t.Fatalf("at the resume: marker present %v, row %q; want the marker and row migrating (resume first)", atResume.marker, atResume.row)
	}
	requireAbortModes(t, r, modePre)
	if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		t.Fatalf("source domain %q, want resumed", st)
	}
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v", m)
	}
	if vm := r.row(); vm.State != "running" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s, want running on src-host", vm.State, vm.HostName)
	}
}

// §7 M1p with the target holding a domain: park source_paused, both guests
// paused; nothing resumed; the row stays migrating (D2-12a review m-2).
//
// Mutation: resume the source anyway; restore the row to error — red.
func TestM1p_TargetDomainParksSourcePaused(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.confirmPhaseFailure(libvirtfake.StatePaused)
	resumed := false
	r.onResumeSource = func() { resumed = true }
	_ = r.migrate()
	requireAbortModes(t, r, modePre)
	requireMarker(t, r, fwmig.PhaseSourcePaused, fwmig.PhaseMigrating)
	requireFwmigCondition(t, r.src, condFwmigSourcePaused)
	if resumed {
		t.Fatal("the source guest was resumed with a domain on the target")
	}
	if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StatePaused {
		t.Errorf("source domain %q, want paused", st)
	}
	if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StatePaused {
		t.Errorf("target domain %q, want paused", st)
	}
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating while parked", vm.State)
	}
}

// §7 M1p, a crash between the resume and the marker removal: the marker
// (migrating) and a running source are left. Handling it again is M1: the
// abort answers that the target holds nothing, and the marker goes.
//
// Mutation: keep the marker when the target answered nothing held — red.
func TestM1p_CrashAfterResumeRecoveredAsM1(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := fwmig.Marker{VM: fwlVM, Binding: fwmig.Binding{UUID: fwLiveUUID, CreatedAt: r.row().CreatedAt, Attempt: newLiveFirmwareAttemptID()},
		Target: "dst-host", Route: fwmig.RouteTunnelled, Phase: fwmig.PhaseMigrating, TPM: true, UEFI: true, Since: time.Now().UTC()}
	if err := r.src.fwRecords().PutMarker(m); err != nil {
		t.Fatal(err)
	}
	run := &liveFirmwareRun{target: corrosion.HostRecord{Name: "dst-host"}, marker: m}
	unmark, keepRow := r.src.liveFirmwareMigrateFailed(context.Background(), run, errors.New("recovered"))
	if unmark == nil || keepRow {
		t.Fatalf("unmark %v keepRow %v: want the marker to go with the row restored", unmark != nil, keepRow)
	}
	unmark()
	if _, ok := r.marker(); ok {
		t.Fatal("the marker is left")
	}
	requireAbortModes(t, r, modePre)
}

// §7 M1b with the source domain's state unreadable: not a cutover (its state
// cannot be read as final) and not a failure on the source; the move parks
// source_state_missing with both copies kept, and the row stays migrating
// (D2-12a review m-2), never error.
//
// Mutation: restore the row after the park; verify or commit — red.
func TestMigrateVM_FirmwareLive_UnreadableSourceStateParksMigrating(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.afterMigrate = func() {
		r.srcFake.FailDomainState = func(name string) error {
			if name == fwlVM {
				return errors.New("libvirt: connection reset")
			}
			return nil
		}
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseMigrating)
	if r.log.has("verify") || r.log.has("commit") {
		t.Fatalf("steps %v", r.log.get())
	}
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating", vm.State)
	}
}

// §7 P1, D2-12a review m-6: a Prepare whose dial failed sent nothing, so the
// move is a clean refusal: no marker (no veto), no abort, row running.
//
// Mutation: keep the run so the undo aborts and parks — red.
func TestMigrateVM_FirmwareLive_PrepareDialFailedRefusesClean(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.dialErr = func() error {
		// The dial of Prepare: the marker is preparing, nothing sent yet.
		if m, ok, _ := fwmig.New(r.src.dataDir).GetMarker(fwlVM); ok && m.Phase == fwmig.PhasePreparing {
			return errors.New("dial dst-host: connection refused")
		}
		return nil
	}
	err := r.migrate()
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("got %v, want the dial failure", err)
	}
	if len(r.aborts()) != 0 {
		t.Errorf("aborts sent: %v", r.aborts())
	}
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v", m)
	}
	if vm := r.row(); vm.State != "running" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s", vm.State, vm.HostName)
	}
}

// §7 V1: Verify MISMATCH after the source stopped as a completed migration
// stops it. Abort DISCARD; then the row stopped on the source,
// firmware_migration_unverified raised, the marker removed; the target's
// copy quarantined, the source's kept.
//
// Mutation: park instead of DISCARD; skip the row — red.
func TestV1_MismatchMigratedDiscardsAndStops(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.dstFake.CorruptLandedPermall = func(string) bool { return true }
	err := r.migrate()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv start") {
		t.Fatalf("got %v, want the V1 refusal naming lv start", err)
	}
	requireAbortModes(t, r, modeDiscard)
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v", m)
	}
	if vm := r.row(); vm.HostName != "src-host" || vm.State != "stopped" {
		t.Errorf("row %s on %s, want stopped on src-host", vm.State, vm.HostName)
	}
	requireFwmigCondition(t, r.src, condFwmigUnverified)
	if _, ok := r.hold(); ok {
		t.Error("the target still holds the attempt")
	}
	if !r.quarantined() {
		t.Error("the target's copy was not quarantined")
	}
	if r.log.has("commit") {
		t.Fatal("committed on a mismatch")
	}
	r.requireSourceIntact("after V1")
}

// §7 V1 with the DISCARD unanswered: discard_pending, raising
// target_unreachable — not "unverified", which says the DISCARD ran
// (D2-12a review m-6, :87).
//
// Mutation: raise unverified for discard_pending — red.
func TestV1_DiscardUnansweredIsPendingNotUnverified(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.dstFake.CorruptLandedPermall = func(string) bool { return true }
	r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseDiscardPending, fwmig.PhaseCutover)
	requireFwmigCondition(t, r.src, condFwmigTargetUnreachable)
	requireNoFwmigCondition(t, r.src, condFwmigUnverified)
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating until the DISCARD answers", vm.State)
	}
}

// §7 V1 with the DISCARD refused: park target_ran.
//
// Mutation: take a refused DISCARD as done — red.
func TestV1_DiscardRefusedParksTargetRan(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.dstFake.CorruptLandedPermall = func(string) bool { return true }
	r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		return &pb.AbortLiveFirmwareTargetResponse{Refused: true, TargetDomain: &pb.TargetDomain{Present: true, State: "running"}}, nil
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetRan, fwmig.PhaseCutover)
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating", vm.State)
	}
}

// verifyAnswers replaces Verify's answer with v and td.
func (r *fwlRig) verifyAnswers(v pb.FirmwareVerdict, td *pb.TargetDomain) {
	r.peerC.verifyAnswer = func(func() (*pb.VerifyLiveFirmwareTargetResponse, error)) (*pb.VerifyLiveFirmwareTargetResponse, error) {
		return &pb.VerifyLiveFirmwareTargetResponse{Verdict: v, TargetDomain: td, Detail: "test answer"}, nil
	}
}

// §7 V4: NOT_HELD and no target domain — the incoming migration never
// landed. Row stopped on the source, state kept, marker removed, no DISCARD.
//
// Mutation: park target_unreachable for NOT_HELD with no domain — red.
func TestV4_NotHeldNoDomainStopsOnSource(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.verifyAnswers(pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_HELD, &pb.TargetDomain{})
	err := r.migrate()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "never landed") {
		t.Fatalf("got %v, want the V4 refusal", err)
	}
	if len(r.aborts()) != 0 {
		t.Errorf("aborts sent: %v", r.aborts())
	}
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left %+v", m)
	}
	if vm := r.row(); vm.HostName != "src-host" || vm.State != "stopped" {
		t.Errorf("row %s on %s, want stopped on src-host", vm.State, vm.HostName)
	}
	r.requireSourceIntact("after V4")
}

// §7 V3: NOT_HELD with a target domain present parks target_unreachable,
// row migrating.
//
// Mutation: take V4 whatever the domain — red.
func TestV3_NotHeldWithDomainParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.verifyAnswers(pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_HELD, &pb.TargetDomain{Present: true, State: "paused"})
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCutover)
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating", vm.State)
	}
}

// §7 V6 from Verify (pre-commit): BAD_REQUEST parks with the hold kept, row
// migrating, no commit.
//
// Mutation: commit or retry as unreachable — red.
func TestV6_VerifyBadRequestParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.verifyAnswers(pb.FirmwareVerdict_FIRMWARE_VERDICT_BAD_REQUEST, &pb.TargetDomain{Present: true, State: "paused"})
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseCutover)
	if r.log.has("commit") {
		t.Fatal("committed on BAD_REQUEST")
	}
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating", vm.State)
	}
}

// D2-10 review I-2: a NOT_RUNNING from RELEASE (H1, held_domain_absent)
// parks and never discards — keyed on the RPC: the target holds the only
// verified copy and the row names it.
//
// Mutation: map Release verdicts through Verify's (V1 DISCARD) — red.
func TestRelease_NotRunningParksNeverDiscards(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return &pb.ReleaseLiveFirmwareTargetResponse{Verdict: pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_RUNNING,
			TargetDomain: &pb.TargetDomain{}, Detail: "held_domain_absent"}, nil
	}
	_ = r.migrate()
	if len(r.aborts()) != 0 {
		t.Fatalf("aborts sent after the commit: %v", r.aborts())
	}
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCommitted)
	if vm := r.row(); vm.HostName != "dst-host" {
		t.Errorf("row on %s, want dst-host (committed)", vm.HostName)
	}
	requireNoFwmigCondition(t, r.src, condFwmigUnverified)
	if _, ok := r.hold(); !ok {
		t.Error("the target's hold is gone")
	}
}

// §7 V6 from Release (post-commit): BAD_REQUEST parks from committed.
//
// Mutation: treat it as unreachable — red.
func TestV6_ReleaseBadRequestParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return &pb.ReleaseLiveFirmwareTargetResponse{Verdict: pb.FirmwareVerdict_FIRMWARE_VERDICT_BAD_REQUEST, Detail: "no src_nvram_sha256"}, nil
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseSourceStateMissing, fwmig.PhaseCommitted)
}

// §7 C1: the commit fails. The marker stays verified (recovery retries), the
// target's guest stays paused under its verified hold, Release is never sent.
//
// Mutation: release after a failed commit — red.
func TestC1_CommitFailsStaysVerified(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.verifyAnswer = func(call func() (*pb.VerifyLiveFirmwareTargetResponse, error)) (*pb.VerifyLiveFirmwareTargetResponse, error) {
		resp, err := call()
		// The row changes under the move: the guarded commit refuses.
		if xerr := r.src.db.Execute(context.Background(), `UPDATE vms SET host_name = 'elsewhere' WHERE name = ?`, fwlVM); xerr != nil {
			t.Error(xerr)
		}
		return resp, err
	}
	if err := r.migrate(); err == nil {
		t.Fatal("the move succeeded with the commit refused")
	}
	if m, ok := r.marker(); !ok || m.Phase != fwmig.PhaseVerified {
		t.Fatalf("marker %+v (present %v), want verified", m, ok)
	}
	if r.log.has("release") {
		t.Fatal("Release was sent without the commit")
	}
	if h, ok := r.hold(); !ok || h.State != fwmig.HoldVerified {
		t.Errorf("hold %+v (present %v), want verified", h, ok)
	}
	if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StatePaused {
		t.Errorf("target domain %q, want paused", st)
	}
}

// §7 R1: Release refused while the commit has not replicated to the target
// is retried, and the move completes.
//
// Mutation: do not retry a refused Release — red.
func TestR1_ReleaseRefusedThenRetried(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	n := 0
	r.peerC.releaseAnswer = func(call func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		if n++; n == 1 {
			return nil, status.Error(codes.FailedPrecondition, "the VM's row does not name this host yet")
		}
		return call()
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	if n < 2 {
		t.Fatalf("Release sent %d times, want a retry", n)
	}
	r.requireCleanedUp("after a retried Release")
}

// §7 R1 then V3: Release refused for as long as the retries last parks
// target_unreachable from committed.
//
// Mutation: drop the park — red.
func TestR1_ReleaseRefusedThroughoutParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.FailedPrecondition, "the VM's row does not name this host yet")
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCommitted)
}

// §7 H1: the held guest is shut off on the target after Verify. The source
// sends nvram_final with Release; the target pushes it, records the VM
// stopped there, removes the hold; the source goes on to released and the
// cleanup. Nothing booted.
//
// Mutation: send Release without nvram_final — red.
func TestH1_HeldShutOffPushesNvramAndReleases(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.src.fwLive.stepHook = func(step string) {
		r.log.add(step)
		if step == "commit" {
			r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown) // the target host crashed
		}
	}
	r.dstFake.OnRunning = func(string) { r.log.add("target-running") }
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v (steps %v)", err, r.log.get())
	}
	if r.log.has("target-running") {
		t.Fatal("the held guest was booted")
	}
	if !r.log.has("cleanup") {
		t.Error("cleanup not called")
	}
	// The source cleanup ran: the source copy is in the retained bundle.
	if m, ok := r.marker(); ok {
		t.Errorf("marker left %+v", m)
	}
	if fwtExists(r.srcPermallPath()) || fwtExists(r.srcStore.NvramPath(fwlVM)) {
		t.Error("the source's firmware state was not wiped")
	}
	requireBundleHoldsSourceState(t, r.retained(r.retainedAttempt()), true)
	if b, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM)); string(b) != string(fwlNvram) {
		t.Errorf("target NVRAM %q, want the source's final", b)
	}
	if vm := r.row(); vm.HostName != "dst-host" || vm.State != "stopped" {
		t.Errorf("row %s on %s, want stopped on dst-host", vm.State, vm.HostName)
	}
	if _, ok := r.hold(); ok {
		t.Error("the hold is left")
	}
}

// D2-10 review m-7: a retry of a parked target_ran or nvram_unconfirmed move
// whose call is refused (the hold is resuming / released_unconfirmed) or
// unanswered must not re-park it as target_unreachable.
//
// Mutation: let target_unreachable replace a parked phase — red.
func TestPark_RetryKeepsTargetRanAndNvramUnconfirmed(t *testing.T) {
	for _, phase := range []fwmig.Phase{fwmig.PhaseTargetRan, fwmig.PhaseNvramUnconfirmed} {
		t.Run(string(phase), func(t *testing.T) {
			r := newFwlRig(t, fwlOpts{})
			m := fwmig.Marker{VM: fwlVM, Binding: fwmig.Binding{UUID: fwLiveUUID, CreatedAt: r.row().CreatedAt, Attempt: newLiveFirmwareAttemptID()},
				Target: "dst-host", Route: fwmig.RouteTunnelled, Phase: fwmig.PhaseCommitted, TPM: true, UEFI: true, Since: time.Now().UTC(),
				SrcNvramSHA256: fwtSHA(fwlNvram), SrcPermallSHA256: fwtSHA(fwlPermall), SrcStopReason: fwmig.StopReasonMigrated}
			parked, err := m.Park(phase)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.src.fwRecords().PutMarker(parked); err != nil {
				t.Fatal(err)
			}
			r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
				return nil, status.Error(codes.FailedPrecondition, "the hold is resuming: it was verified and released")
			}
			run := &liveFirmwareRun{target: corrosion.HostRecord{Name: "dst-host"}, marker: parked}
			if err := r.src.releaseLiveFirmwareMove(context.Background(), run); err == nil {
				t.Fatal("a refused release succeeded")
			}
			requireMarker(t, r, phase, fwmig.PhaseCommitted)
		})
	}
}

// ── Fence resolution and the owed DISCARD (T-32) ──

// fenceTarget proves dst-host off: fenced, with an operator's confirmation.
func (r *fwlRig) fenceTarget() {
	r.t.Helper()
	if err := corrosion.RecordFenceWithState(context.Background(), r.src.db,
		corrosion.FenceLogRecord{ID: "fc-dst", HostName: "dst-host", Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
		r.t.Fatal(err)
	}
}

// parkUnreachableAtVerify runs a move whose Verify is never answered: parked
// target_unreachable from cutover, the source domain shut off.
func (r *fwlRig) parkUnreachableAtVerify() {
	r.t.Helper()
	r.peerC.verifyAnswer = func(func() (*pb.VerifyLiveFirmwareTargetResponse, error)) (*pb.VerifyLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	_ = r.migrate()
	requireMarker(r.t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCutover)
	r.peerC.verifyAnswer = nil
}

// T-32: the target is proved off and the row names the source with this
// incarnation: the owed-discard record is written (with the stubs), the
// marker removed, the row stopped; `lv start`'s libvirt start, refused while
// parked, now works.
//
// Mutations: keep the marker; resolve without re-reading the row; drop
// created_stubs — red.
func TestFenceResolution_RowNamesSource_MarkerRemovedStartWorks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{storage: true})
	r.parkUnreachableAtVerify()
	m, _ := r.marker()
	if err := r.srcFake.StartDomain(fwlVM); err == nil {
		t.Fatal("a start was allowed while the move is parked")
	}
	if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || ok {
		t.Fatalf("resolved %v (%v) with the target not fenced", ok, err)
	}
	r.fenceTarget()
	if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || !ok {
		t.Fatalf("resolve: %v %v", ok, err)
	}
	if _, ok := r.marker(); ok {
		t.Fatal("the marker is left")
	}
	o, ok, err := r.src.fwRecords().GetOwedDiscardFor(fwlVM, m.Binding)
	if err != nil || !ok {
		t.Fatalf("owed-discard record: %v %v", ok, err)
	}
	if len(o.CreatedStubs) == 0 || strings.Join(o.CreatedStubs, ",") != strings.Join(m.CreatedStubs, ",") || o.Target != "dst-host" {
		t.Errorf("owed discard %+v, want the marker's stubs %v and target", o, m.CreatedStubs)
	}
	if vm := r.row(); vm.State != "stopped" || vm.HostName != "src-host" {
		t.Errorf("row %s on %s, want stopped on src-host", vm.State, vm.HostName)
	}
	requireFwmigCondition(t, r.src, condFwmigDiscardOwed)
	if err := r.srcFake.StartDomain(fwlVM); err != nil {
		t.Fatalf("start after the resolution: %v", err)
	}
}

// T-32: a row naming the TARGET leaves the park for an operator.
//
// Mutation: resolve without re-reading the row — red.
func TestFenceResolution_RowNamesTargetParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.peerC.releaseAnswer = func(func() (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCommitted)
	r.fenceTarget()
	if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || ok {
		t.Fatalf("resolved %v (%v) with the row naming the target", ok, err)
	}
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCommitted)
	if owed, _ := r.src.fwRecords().ListOwedDiscards(); len(owed) != 0 {
		t.Errorf("owed discards written: %+v", owed)
	}
}

// resolvedByFence parks at Verify, fences the target and resolves.
func (r *fwlRig) resolvedByFence() fwmig.Marker {
	r.t.Helper()
	r.parkUnreachableAtVerify()
	m, _ := r.marker()
	r.fenceTarget()
	if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || !ok {
		r.t.Fatalf("resolve: %v %v", ok, err)
	}
	return m
}

// T-32: on the target's rejoin the owed DISCARD lands: the target's copy is
// quarantined, its hold gone, and the record removed.
//
// Mutation: skip the DISCARD; keep the record after an answer — red.
func TestFenceResolution_OwedDiscardLandsOnRejoin(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := r.resolvedByFence()
	r.src.RetryOwedFirmwareDiscardsOnce(context.Background())
	requireAbortModes(t, r, modeDiscard)
	if _, ok, _ := r.src.fwRecords().GetOwedDiscardFor(fwlVM, m.Binding); ok {
		t.Fatal("the owed-discard record is left after the DISCARD answered")
	}
	if _, ok := r.hold(); ok {
		t.Error("the target still holds the attempt")
	}
	if !r.quarantined() {
		t.Error("the target's copy was not quarantined")
	}
	requireNoFwmigCondition(t, r.src, condFwmigDiscardOwed)
}

// T-32: an owed DISCARD the target refuses (its domain runs) raises
// firmware_migration_discard_owed as critical, and the record stays.
//
// Mutation: drop the record on a refusal; no condition — red.
func TestFenceResolution_RefusedOwedDiscardRaisesCondition(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := r.resolvedByFence()
	r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		return &pb.AbortLiveFirmwareTargetResponse{Refused: true, TargetDomain: &pb.TargetDomain{Present: true, State: "running"}, Detail: "its domain is running here"}, nil
	}
	r.src.RetryOwedFirmwareDiscardsOnce(context.Background())
	if _, ok, _ := r.src.fwRecords().GetOwedDiscardFor(fwlVM, m.Binding); !ok {
		t.Fatal("the owed-discard record was dropped on a refusal")
	}
	c, found, err := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigDiscardOwed, "vm", fwlVM)
	if err != nil || !found || c.Severity != corrosion.SeverityCritical || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition %+v found=%v err=%v, want discard_owed open and critical", c, found, err)
	}
}

// T-32: removing the target host from the cluster drops the record: nothing
// is left to discard, and nothing is sent.
//
// Mutation: keep the record for a removed host — red.
func TestFenceResolution_OwedDiscardDroppedOnHostRemove(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := r.resolvedByFence()
	if err := corrosion.DeleteHost(context.Background(), r.src.db, "dst-host"); err != nil {
		t.Fatal(err)
	}
	r.src.RetryOwedFirmwareDiscardsOnce(context.Background())
	if _, ok, _ := r.src.fwRecords().GetOwedDiscardFor(fwlVM, m.Binding); ok {
		t.Fatal("the owed-discard record is left after the host was removed")
	}
	if len(r.aborts()) != 0 {
		t.Errorf("a DISCARD was sent to a removed host: %v", r.aborts())
	}
}

// T-23, failure half: an adopted move (the client went away mid-copy) that
// fails with the source still running is M1 too: the abort and the
// automatic DISCARD, the marker removed, the row running.
//
// Mutation: drop the adopter's firmware failure handling — red.
func TestAdoptedFirmwareMigration_FailedOnSourceIsM1(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	proceed := make(chan struct{})
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		cancel()
		<-proceed
		if err := land(name, uri, p); err != nil {
			return err
		}
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		return errors.New("injected confirm-phase failure")
	}
	err := r.src.MigrateVM(&pb.MigrateVMRequest{VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE},
		&mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("got %v, want the adopted move's DeadlineExceeded", err)
	}
	close(proceed)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := r.marker(); !ok && r.row().State == "running" {
			break
		}
		if time.Now().After(deadline) {
			m, ok := r.marker()
			t.Fatalf("the adopted failure was not settled: marker %+v (%v), row %s, aborts %v", m, ok, r.row().State, r.aborts())
		}
		time.Sleep(10 * time.Millisecond)
	}
	requireAbortModes(t, r, modePre, modeDiscard)
	if r.log.has("verify") {
		t.Fatal("Verify called before cutover")
	}
}

// T-23, D2-12a review m-3 on the adopter: an adopted migration that returned
// success with the source domain still active is M1 too, never a cutover.
//
// Mutation: let the adopter take an active source to cutover — red.
func TestAdoptedFirmwareMigration_SourceStillActiveIsM1(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	proceed := make(chan struct{})
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		cancel()
		<-proceed
		return land(name, uri, p)
	}
	r.afterMigrate = func() { r.srcFake.SetState(fwlVM, libvirtfake.StateRunning) }
	err := r.src.MigrateVM(&pb.MigrateVMRequest{VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE},
		&mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("got %v, want the adopted move's DeadlineExceeded", err)
	}
	close(proceed)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := r.marker(); !ok && r.row().State == "running" {
			break
		}
		if time.Now().After(deadline) {
			m, ok := r.marker()
			t.Fatalf("the adopted move was not settled as M1: marker %+v (%v), row %s, steps %v", m, ok, r.row().State, r.log.get())
		}
		time.Sleep(10 * time.Millisecond)
	}
	requireAbortModes(t, r, modePre, modeDiscard)
	if r.log.has("verify") || r.log.has("commit") {
		t.Fatalf("steps %v", r.log.get())
	}
}

// ── Fix round 1 ──

// Review I-1 (spec amendment 2026-10-16): a move whose Verify went
// unanswered after the source stopped with a reason other than migrated (here
// M1b: the migration call failed, the source domain crashed) is not resolved
// by fence: the source's TPM state may be stale (I6), so neither copy is
// declared current and no DISCARD is owed.
//
// Mutation: resolve whatever the stop reason — red.
func TestFenceResolution_SourceStopReasonNotMigratedStaysParked(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	land := r.srcFake.OnMigrateToTarget
	r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.srcFake.SetStateReason(fwlVM, "crashed")
		return errors.New("injected failure; the source domain crashed")
	}
	r.parkUnreachableAtVerify()
	m, _ := r.marker()
	if m.SrcStopReason != "crashed" {
		t.Fatalf("marker stop reason %q, want crashed (the scenario needs it)", m.SrcStopReason)
	}
	r.fenceTarget()
	if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || ok {
		t.Fatalf("resolved %v (%v) after the source stopped with reason crashed", ok, err)
	}
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCutover)
	if owed, _ := r.src.fwRecords().ListOwedDiscards(); len(owed) != 0 {
		t.Errorf("owed discards written: %+v", owed)
	}
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating", vm.State)
	}
}

// Review I-1, the other side: a park from before cutover is resolved by
// fence (the source never stopped, its copy is current).
//
// Mutation: refuse every park without reason migrated — red.
func TestFenceResolution_PreCutoverParkResolves(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.confirmPhaseFailure(libvirtfake.StateRunning)
	r.peerC.abortAnswer = func(req *pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		if req.GetMode() == modeDiscard {
			return nil, status.Error(codes.Unavailable, "connection refused")
		}
		return r.dst.AbortLiveFirmwareTarget(r.peer, req)
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseMigrating)
	r.fenceTarget()
	if ok, err := r.src.ResolveLiveFirmwareMoveByFence(context.Background(), fwlVM); err != nil || !ok {
		t.Fatalf("resolve: %v %v", ok, err)
	}
	if vm := r.row(); vm.State != "running" {
		t.Errorf("row %s, want running (the source guest runs)", vm.State)
	}
}

// Review I-2: M1p's VFs go back into the guest once it is resumed — not
// while it is paused, which leaves them reserved and out of the guest.
//
// Mutation: reattach before the M1p resume — red.
func TestM1p_ResumedGuestGetsItsVFs(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	fs := newPCIUnbindRecordingFS()
	t.Cleanup(vfio.SetFS(fs))
	const vf = "0000:41:10.0"
	if err := corrosion.UpsertPCIDevice(adminCtx(), r.src.db, corrosion.PCIDeviceRecord{
		HostName: "src-host", Address: vf, Type: "net", VendorID: "8086", VMName: fwlVM}); err != nil {
		t.Fatal(err)
	}
	fs.setVF(vf)
	fs.setBound(vf)
	if err := r.srcFake.AttachHostdev(fwlVM, vf); err != nil {
		t.Fatal(err)
	}
	r.srcFake.FailMigrateToTarget = func(string, string) error {
		if guestHasHostdev(t, r.src, fwlVM, vf) {
			t.Error("the VF is still in the guest at the migration")
		}
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		return errors.New("injected failure that left the guest paused")
	}
	if err := r.migrate(); err == nil {
		t.Fatal("the move succeeded; the scenario needs libvirt to fail it")
	}
	if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		t.Fatalf("source domain %q, want resumed", st)
	}
	if !guestHasHostdev(t, r.src, fwlVM, vf) {
		t.Fatal("the resumed guest runs without its VF")
	}
	if _, ok := r.marker(); ok {
		t.Error("marker left")
	}
}

// Review m-1: a parked M1 keeps everything on the target, its stubs included
// (CleanupMigrationArtifacts is not asked).
//
// Mutation: clean the target up after a park — red.
func TestM1_ParkKeepsTargetStubs(t *testing.T) {
	r := newFwlRig(t, fwlOpts{storage: true})
	r.confirmPhaseFailure(libvirtfake.StateRunning)
	r.peerC.abortAnswer = func(req *pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		if req.GetMode() == modeDiscard {
			return &pb.AbortLiveFirmwareTargetResponse{Refused: true, TargetDomain: &pb.TargetDomain{Present: true, State: "running"}}, nil
		}
		return r.dst.AbortLiveFirmwareTarget(r.peer, req)
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseTargetRan, fwmig.PhaseMigrating)
	if r.peerC.cleanups != 0 {
		t.Fatalf("the target was asked to clean up %d times after a park", r.peerC.cleanups)
	}
}

// Review m-2: the source domain is active but its state (running or paused)
// cannot be read: a paused guest must not lose its marker unresumed, so the
// move parks source_paused and the row stays migrating.
//
// Mutation: take the M1 path on an unreadable state — red.
func TestM1_UnreadableActiveStateParks(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.srcFake.FailMigrateToTarget = func(string, string) error {
		r.srcFake.FailDomainStateReason = func(name string) error {
			if name == fwlVM {
				return errors.New("libvirt: connection reset")
			}
			return nil
		}
		return errors.New("injected migration failure")
	}
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseSourcePaused, fwmig.PhaseMigrating)
	if vm := r.row(); vm.State != "migrating" {
		t.Errorf("row %s, want migrating", vm.State)
	}
}

// Review m-3: an owed DISCARD answered with a domain of the VM still defined
// on the target, while the row names the source, keeps its record and raises
// discard_owed as critical.
//
// Mutation: drop the record on any answer that is not a refusal — red.
func TestFenceResolution_OwedDiscardWithDomainLeftKept(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := r.resolvedByFence()
	r.peerC.abortAnswer = func(*pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
		return &pb.AbortLiveFirmwareTargetResponse{TargetDomain: &pb.TargetDomain{Present: true, State: "shutoff"}}, nil
	}
	r.src.RetryOwedFirmwareDiscardsOnce(context.Background())
	if _, ok, _ := r.src.fwRecords().GetOwedDiscardFor(fwlVM, m.Binding); !ok {
		t.Fatal("the owed-discard record was dropped with a domain left on the target")
	}
	c, found, err := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigDiscardOwed, "vm", fwlVM)
	if err != nil || !found || c.Severity != corrosion.SeverityCritical {
		t.Fatalf("condition %+v found=%v err=%v, want discard_owed critical", c, found, err)
	}
}
