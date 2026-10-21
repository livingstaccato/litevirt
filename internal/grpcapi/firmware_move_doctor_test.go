package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// T-33: `lv doctor firmware-move` (spec §17 D-5), one sub-test per row of the
// action table, on the fwlRig: crashAt builds the state a move leaves in a
// phase, a park puts the marker where the move parked it, and the doctor is
// asked as an operator asks it, through the node that takes the request.
// Each action is allowed only with its preconditions (and acknowledgement);
// each refusal leaves both records and both copies as they were.

// The doctor's RPCs, as the source's peer reaches the target.
func (p *fwlPeer) FirmwareMoveDoctor(_ context.Context, req *pb.FirmwareMoveDoctorRequest, opts ...grpc.CallOption) (*pb.FirmwareMoveDoctorResponse, error) {
	if err := p.refuse("FirmwareMoveDoctor"); err != nil {
		return nil, err
	}
	p.mu.Lock()
	aerr := p.actionErr
	p.mu.Unlock()
	if aerr != nil && req.GetAction() != pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED {
		return nil, aerr
	}
	p.mu.Lock()
	ra := p.readAnswer
	p.mu.Unlock()
	resp, err := withPeerTrailer(p.r.peer, opts, func(ctx context.Context) (*pb.FirmwareMoveDoctorResponse, error) {
		return p.r.dst.FirmwareMoveDoctor(ctx, req)
	})
	if ra != nil && err == nil && req.GetAction() == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED {
		resp = ra(resp)
	}
	return resp, err
}

// fwTrailerStream records the trailer a handler sets, as a gRPC transport
// would carry it to the caller.
type fwTrailerStream struct{ md metadata.MD }

func (*fwTrailerStream) Method() string               { return "" }
func (*fwTrailerStream) SetHeader(metadata.MD) error  { return nil }
func (*fwTrailerStream) SendHeader(metadata.MD) error { return nil }
func (t *fwTrailerStream) SetTrailer(md metadata.MD) error {
	t.md = metadata.Join(t.md, md)
	return nil
}

// withPeerTrailer runs an in-process handler and hands its trailer to a
// grpc.Trailer call option, as the real peer call does.
func withPeerTrailer(ctx context.Context, opts []grpc.CallOption, fn func(context.Context) (*pb.FirmwareMoveDoctorResponse, error)) (*pb.FirmwareMoveDoctorResponse, error) {
	st := &fwTrailerStream{}
	resp, err := fn(grpc.NewContextWithServerTransportStream(ctx, st))
	for _, o := range opts {
		if t, ok := o.(grpc.TrailerCallOption); ok {
			*t.TrailerAddr = st.md
		}
	}
	return resp, err
}

func (p *fwlPeer) FirmwareMoveDoctorTarget(_ context.Context, req *pb.FirmwareMoveDoctorTargetRequest, _ ...grpc.CallOption) (*pb.FirmwareMoveDoctorTargetResponse, error) {
	p.r.log.add("doctor-target:" + strings.TrimPrefix(req.GetOp().String(), "FIRMWARE_MOVE_DOCTOR_TARGET_OP_"))
	if err := p.refuse("FirmwareMoveDoctorTarget"); err != nil {
		return nil, err
	}
	return p.r.dst.FirmwareMoveDoctorTarget(p.r.peer, req)
}

// fwdSrcPeer is the source as the target's peer client reaches it.
type fwdSrcPeer struct {
	pb.LiteVirtClient
	r *fwlRig
}

func (p *fwdSrcPeer) FirmwareMoveDoctor(_ context.Context, req *pb.FirmwareMoveDoctorRequest, opts ...grpc.CallOption) (*pb.FirmwareMoveDoctorResponse, error) {
	ctx := context.WithValue(context.WithValue(mtlsCtx("dst-host"), ctxKeyUsername, "admin"), ctxKeyRole, "admin")
	return withPeerTrailer(ctx, opts, func(ctx context.Context) (*pb.FirmwareMoveDoctorResponse, error) {
		return p.r.src.FirmwareMoveDoctor(ctx, req)
	})
}

// newFwdRig is the fwlRig with the target's peer reaching the source, and
// the doctor's waits short.
func newFwdRig(t *testing.T, o fwlOpts) *fwlRig {
	t.Helper()
	r := newFwlRig(t, o)
	r.dst.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &fwdSrcPeer{r: r}, func() {}, nil
	}
	ow, op := fwDoctorStopWait, fwDoctorStopPoll
	fwDoctorStopWait, fwDoctorStopPoll = 2*time.Second, 5*time.Millisecond
	t.Cleanup(func() { fwDoctorStopWait, fwDoctorStopPoll = ow, op })
	return r
}

// doctor asks the source node for an action.
func (r *fwlRig) doctor(a pb.FirmwareMoveDoctorAction, mod ...func(*pb.FirmwareMoveDoctorRequest)) (*pb.FirmwareMoveDoctorResponse, error) {
	req := &pb.FirmwareMoveDoctorRequest{VmName: fwlVM, Action: a}
	for _, f := range mod {
		f(req)
	}
	return r.src.FirmwareMoveDoctor(adminCtx(), req)
}

func withAck(req *pb.FirmwareMoveDoctorRequest)  { req.AcknowledgeRollback = true }
func withStop(req *pb.FirmwareMoveDoctorRequest) { req.StopTarget = true }
func withHash(h string) func(*pb.FirmwareMoveDoctorRequest) {
	return func(req *pb.FirmwareMoveDoctorRequest) { req.AcceptNvramHash = h }
}

const (
	actAcceptTarget = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_TARGET
	actAcceptSource = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE
	actAdopt        = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY
	actDiscard      = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET
	actConfirm      = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM
	actPush         = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM
	actReverify     = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_REVERIFY
	actResolve      = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_RESOLVE_CONDITION
)

// park parks run's marker in p from its phase now.
func (r *fwlRig) park(run *liveFirmwareRun, p fwmig.Phase, detail string) fwmig.Marker {
	r.t.Helper()
	m, err := run.marker.Park(p)
	if err != nil {
		r.t.Fatal(err)
	}
	m.Detail = detail
	if err := r.src.fwRecords().PutMarker(m); err != nil {
		r.t.Fatal(err)
	}
	run.marker = m
	return m
}

// snapshot is everything a refusal must leave as it was.
type fwdSnap struct {
	marker   fwmig.Marker
	markerOK bool
	hold     fwmig.Hold
	holdOK   bool
	row      corrosion.VMRecord
	srcDom   libvirtfake.State
	dstDom   libvirtfake.State
	srcNvram []byte
	dstNvram []byte
}

func (r *fwlRig) snap() fwdSnap {
	var s fwdSnap
	s.marker, s.markerOK = r.marker()
	s.hold, s.holdOK = r.hold()
	s.row = *r.row()
	s.srcDom, _ = r.srcFake.RawState(fwlVM)
	s.dstDom, _ = r.dstFake.RawState(fwlVM)
	s.srcNvram, _ = os.ReadFile(r.srcStore.NvramPath(fwlVM))
	s.dstNvram, _ = os.ReadFile(r.dstStore.NvramPath(fwlVM))
	return s
}

// refused: the action failed with FailedPrecondition naming want, and
// nothing changed.
func (r *fwlRig) refused(err error, want string, before fwdSnap) {
	r.t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		r.t.Fatalf("err = %v, want FailedPrecondition naming %q", err, want)
	}
	after := r.snap()
	if after.markerOK != before.markerOK || after.marker.Phase != before.marker.Phase || after.marker.Attempt != before.marker.Attempt {
		r.t.Errorf("marker %+v (%v) after a refusal, was %+v (%v)", after.marker.Phase, after.markerOK, before.marker.Phase, before.markerOK)
	}
	if after.holdOK != before.holdOK || after.hold.State != before.hold.State {
		r.t.Errorf("hold %s (%v) after a refusal, was %s (%v)", after.hold.State, after.holdOK, before.hold.State, before.holdOK)
	}
	if after.row.HostName != before.row.HostName || after.row.State != before.row.State {
		r.t.Errorf("row %s on %s after a refusal, was %s on %s", after.row.State, after.row.HostName, before.row.State, before.row.HostName)
	}
	if after.srcDom != before.srcDom || after.dstDom != before.dstDom {
		r.t.Errorf("domains src %s dst %s after a refusal, were %s %s", after.srcDom, after.dstDom, before.srcDom, before.dstDom)
	}
	if !bytes.Equal(after.srcNvram, before.srcNvram) || !bytes.Equal(after.dstNvram, before.dstNvram) {
		r.t.Error("an NVRAM changed after a refusal")
	}
}

// resolved: the marker is gone and the row is state on host.
func (r *fwlRig) resolved(err error, host, state string) {
	r.t.Helper()
	if err != nil {
		r.t.Fatalf("action: %v (steps %v)", err, r.log.get())
	}
	if m, ok := r.marker(); ok {
		r.t.Fatalf("marker left: %s (from %s): %s", m.Phase, m.ParkedFrom, m.Detail)
	}
	if vm := r.row(); vm.HostName != host || vm.State != state {
		r.t.Errorf("row %s on %s, want %s on %s", vm.State, vm.HostName, state, host)
	}
}

// discardedOnTarget: the target's domain and hold are gone, its state
// quarantined.
func (r *fwlRig) discardedOnTarget(why string) {
	r.t.Helper()
	if st, ok := r.dstFake.RawState(fwlVM); ok {
		r.t.Errorf("%s: the target domain is still there (%s)", why, st)
	}
	if _, ok := r.hold(); ok {
		r.t.Errorf("%s: the target's hold is left", why)
	}
	ents, _ := os.ReadDir(filepath.Join(r.dst.dataDir, fwmig.QuarantineDir))
	if len(ents) == 0 {
		r.t.Errorf("%s: nothing was quarantined on the target", why)
	}
}

func TestDoctorFirmwareMove(t *testing.T) {
	// ── verified, the commit failing (C1): --accept-target ──
	t.Run("verified/accept_target", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseVerified)
		_, err := r.doctor(actAcceptTarget)
		r.resolved(err, "dst-host", "running")
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("target domain %s, want running", st)
		}
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left after the release")
		}
	})
	// Mutation: drop the hold/paused check — red (the commit lands on a
	// target whose guest is gone).
	t.Run("verified/accept_target_refuses_target_not_paused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseVerified)
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		before := r.snap()
		_, err := r.doctor(actAcceptTarget)
		r.refused(err, "verified with its guest paused", before)
	})
	// --accept-target refuses every parked marker before verified.
	t.Run("source_state_suspect/accept_target_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		r.park(run, fwmig.PhaseSourceStateSuspect, "test")
		before := r.snap()
		_, err := r.doctor(actAcceptTarget)
		r.refused(err, "never a move parked before verified", before)
	})

	// ── V6 after the commit: --accept-target recomputes and resends ──
	// Mutation: resend Release without recomputing the hash — red (BAD_REQUEST
	// parks it again).
	t.Run("source_state_missing_from_committed/accept_target", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		run.marker.SrcNvramSHA256 = ""
		r.park(run, fwmig.PhaseSourceStateMissing, "Release answered BAD_REQUEST")
		_, err := r.doctor(actAcceptTarget)
		r.resolved(err, "dst-host", "running")
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("target domain %s, want running", st)
		}
	})
	t.Run("source_state_missing_from_committed/accept_target_refuses_changed_source", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.park(run, fwmig.PhaseSourceStateMissing, "Release answered BAD_REQUEST")
		r.write(r.srcStore.NvramPath(fwlVM), []byte("changed since cutover"))
		before := r.snap()
		_, err := r.doctor(actAcceptTarget)
		r.refused(err, "recorded at cutover", before)
	})

	// ── released, the row on a third host (D2-13 m-3 c): --accept-target ──
	t.Run("released_row_elsewhere/accept_target", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "the row names a third host")
		if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "third-host", "running"); err != nil {
			t.Fatal(err)
		}
		_, err := r.doctor(actAcceptTarget)
		r.resolved(err, "third-host", "running")
		if _, err := os.Stat(r.srcStore.NvramPath(fwlVM)); !os.IsNotExist(err) {
			t.Errorf("source NVRAM still there (%v)", err)
		}
		ents, _ := os.ReadDir(filepath.Join(r.src.dataDir, fwmig.RetainedDir))
		if len(ents) != 1 {
			t.Errorf("retained bundles %v, want the attempt's", ents)
		}
	})
	t.Run("released_row_here/accept_target_refused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "test")
		if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "src-host", "stopped"); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actAcceptTarget)
		r.refused(err, "names src-host", before)
	})

	// ── cleaning, the source state changed after cutover (D2-12c m-6) ──
	// Mutation: wipe instead of quarantine — red.
	t.Run("cleaning_state_changed/accept_target", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		changed := []byte("written after the cutover")
		r.write(r.srcStore.NvramPath(fwlVM), changed)
		if err := r.src.fwmigCleanupSource(context.Background(), run.marker); err == nil {
			t.Fatal("the rig's cleanup went through a changed source state")
		}
		requireMarker(t, r, fwmig.PhaseCleaning, "")
		_, err := r.doctor(actAcceptTarget)
		r.resolved(err, "dst-host", "running")
		dir, _ := r.src.fwRecords().QuarantinePath(fwlVM, run.marker.Attempt)
		if b, _ := os.ReadFile(filepath.Join(dir, "nvram")); !bytes.Equal(b, changed) {
			t.Errorf("quarantined NVRAM %q, want the changed source state", b)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "swtpm", "tpm2", "tpm2-00.permall")); !bytes.Equal(b, fwlPermall) {
			t.Errorf("quarantined permall %q, want the source's", b)
		}
		requireNoFwmigCondition(t, r.src, condFwmigCleanupFailed)
	})

	// ── source_paused (M1p with a target domain): --accept-source ──
	sourcePaused := func(t *testing.T, srcState, dstState libvirtfake.State) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, srcState)
		if dstState != "" {
			r.dstFake.SetState(fwlVM, dstState)
		}
		r.park(run, fwmig.PhaseSourcePaused, "the migration failed and left the source paused")
		return r
	}
	t.Run("source_paused/accept_source", func(t *testing.T) {
		r := sourcePaused(t, libvirtfake.StatePaused, "")
		_, err := r.doctor(actAcceptSource)
		r.resolved(err, "src-host", "running")
		r.discardedOnTarget("source_paused")
		if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("source domain %s, want running", st)
		}
		r.requireSourceIntact("after --accept-source")
	})
	// D2-12b re-review m-B: a source guest already running is left running.
	t.Run("source_paused/accept_source_source_already_running", func(t *testing.T) {
		r := sourcePaused(t, libvirtfake.StateRunning, "")
		_, err := r.doctor(actAcceptSource)
		r.resolved(err, "src-host", "running")
		r.discardedOnTarget("source_paused, source running")
	})
	// A target guest that runs ran after the source paused: its copy is the
	// newer one, and the source guest stays paused.
	// Mutation: resume before the check — red.
	t.Run("source_paused/accept_source_refuses_running_target", func(t *testing.T) {
		r := sourcePaused(t, libvirtfake.StatePaused, libvirtfake.StateRunning)
		before := r.snap()
		_, err := r.doctor(actAcceptSource)
		r.refused(err, "it ran after the source paused", before)
	})

	// D2-13 re-review 3 m-A: a source_paused park whose target holds nothing
	// of the move (the resume failed) has the same exit.
	t.Run("source_paused_target_holds_no_domain/accept_source", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		r.park(run, fwmig.PhaseSourcePaused, "the target holds nothing of it, but the resume failed")
		_, err := r.doctor(actAcceptSource)
		r.resolved(err, "src-host", "running")
		if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("source domain %s, want running", st)
		}
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left")
		}
	})

	// D2-13 m-3 b: a park before cutover whose reachable target keeps
	// refusing the abort (a domain under the hold) takes --discard-target.
	t.Run("target_unreachable_pre_cutover/discard_target", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseTargetUnreachable, "the abort before cutover was refused: a domain of the VM is defined here")
		_, err := r.doctor(actDiscard)
		r.resolved(err, "src-host", "running")
		r.discardedOnTarget("target_unreachable before cutover")
	})

	// ── M1, target_ran before cutover: --discard-target --stop-target ──
	m1 := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseTargetRan, "the target holds a domain the abort could not account for")
		return r
	}
	// Mutation: drop the running-domain refusal (no --stop-target) — red.
	t.Run("target_ran_pre_cutover/discard_target_needs_stop_target", func(t *testing.T) {
		r := m1(t)
		before := r.snap()
		_, err := r.doctor(actDiscard)
		r.refused(err, "add --stop-target", before)
	})
	t.Run("target_ran_pre_cutover/discard_target_stop_target", func(t *testing.T) {
		r := m1(t)
		_, err := r.doctor(actDiscard, withStop)
		r.resolved(err, "src-host", "running")
		r.discardedOnTarget("--discard-target --stop-target")
		if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("source domain %s, want running", st)
		}
	})
	// D2-12b m-4: target_ran parked from prepared takes the same row.
	t.Run("target_ran_from_prepared/discard_target", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhasePrepared)
		r.park(run, fwmig.PhaseTargetRan, "the abort before cutover was refused")
		_, err := r.doctor(actDiscard)
		r.resolved(err, "src-host", "running")
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left")
		}
	})
	t.Run("target_ran_pre_cutover/adopt_refused", func(t *testing.T) {
		r := m1(t)
		before := r.snap()
		_, err := r.doctor(actAdopt)
		r.refused(err, "--discard-target --stop-target", before)
	})
	t.Run("target_ran_pre_cutover/accept_source_refused", func(t *testing.T) {
		r := m1(t)
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "--discard-target", before)
	})

	// ── source_state_suspect before the commit (V1b) ──
	suspect := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		r.park(run, fwmig.PhaseSourceStateSuspect, "Verify answered MISMATCH after the source stopped with reason unknown")
		return r
	}
	// Mutation: drop the acknowledgement check — red.
	t.Run("source_state_suspect/accept_source_needs_ack", func(t *testing.T) {
		r := suspect(t)
		before := r.snap()
		_, err := r.doctor(actAcceptSource)
		r.refused(err, "--acknowledge-rollback", before)
	})
	t.Run("source_state_suspect/accept_source", func(t *testing.T) {
		r := suspect(t)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		r.discardedOnTarget("suspect --accept-source")
		r.requireSourceIntact("after --accept-source")
	})
	t.Run("source_state_suspect/adopt", func(t *testing.T) {
		r := suspect(t)
		_, err := r.doctor(actAdopt)
		r.resolved(err, "dst-host", "running")
		if !r.log.has("doctor-target:ADOPT") {
			t.Errorf("no adopt op sent (steps %v)", r.log.get())
		}
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("target domain %s, want running", st)
		}
	})
	// Mutation: drop the source-inactive check — red.
	t.Run("source_state_suspect/adopt_refuses_active_source", func(t *testing.T) {
		r := suspect(t)
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		before := r.snap()
		_, err := r.doctor(actAdopt)
		r.refused(err, "source domain on src-host is active", before)
	})

	// ── source_state_missing (V2): --adopt-target-copy ──
	t.Run("source_state_missing/adopt", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		r.land()
		r.park(run, fwmig.PhaseSourceStateMissing, "the source's final TPM state cannot be read")
		if err := os.Remove(filepath.Join(r.srcStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")); err != nil {
			t.Fatal(err)
		}
		_, err := r.doctor(actAdopt)
		r.resolved(err, "dst-host", "running")
		// What is left of the source's state could not be retained against
		// the cutover's hashes: it is quarantined, not wiped.
		dir, _ := r.src.fwRecords().QuarantinePath(fwlVM, run.marker.Attempt)
		if b, _ := os.ReadFile(filepath.Join(dir, "nvram")); !bytes.Equal(b, fwlNvram) {
			t.Errorf("quarantined NVRAM %q, want the source's", b)
		}
	})
	// V6 before the commit, its source state present (D2-12b m-5): no adopt;
	// --reverify takes it.
	// Mutation: offer adopt for it — red.
	v6pre := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		r.park(run, fwmig.PhaseSourceStateMissing, "Verify answered BAD_REQUEST")
		return r
	}
	t.Run("source_state_missing_from_cutover/adopt_refused", func(t *testing.T) {
		r := v6pre(t)
		before := r.snap()
		_, err := r.doctor(actAdopt)
		r.refused(err, "--reverify", before)
	})
	t.Run("source_state_missing_from_cutover/reverify", func(t *testing.T) {
		r := v6pre(t)
		_, err := r.doctor(actReverify)
		r.resolved(err, "dst-host", "running")
	})

	// ── target_ran after cutover (V5) ──
	v5 := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCutover)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseTargetRan, "TARGET_RAN")
		return r
	}
	// The hold goes to resuming, so Release's retry completes the hand-over.
	t.Run("target_ran_post_cutover/adopt", func(t *testing.T) {
		r := v5(t)
		_, err := r.doctor(actAdopt)
		r.resolved(err, "dst-host", "running")
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left")
		}
	})
	t.Run("target_ran_post_cutover/accept_source_needs_stop_target", func(t *testing.T) {
		r := v5(t)
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "add --stop-target", before)
	})
	t.Run("target_ran_post_cutover/accept_source_stop_target", func(t *testing.T) {
		r := v5(t)
		_, err := r.doctor(actAcceptSource, withAck, withStop)
		r.resolved(err, "src-host", "stopped")
		r.discardedOnTarget("V5 --accept-source --stop-target")
	})

	// ── committed, the target fenced: --accept-source returns the VM ──
	committedFenced := func(t *testing.T, o fwlOpts) *fwlRig {
		r := newFwdRig(t, o)
		run := r.crashAt(fwmig.PhaseCommitted)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		return r
	}
	// Mutations: move the VM row only (no disk rows) — red in the corrosion
	// test; skip the return writer — red here.
	t.Run("committed_target_fenced/accept_source", func(t *testing.T) {
		r := committedFenced(t, fwlOpts{})
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		disks, _ := corrosion.GetVMDisks(context.Background(), r.src.db, fwlVM)
		for _, d := range disks {
			if d.HostName != "src-host" {
				t.Errorf("disk %s on %s, want src-host", d.DiskName, d.HostName)
			}
		}
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		if len(owed) != 1 || owed[0].Target != "dst-host" {
			t.Errorf("owed discards %+v, want one to dst-host", owed)
		}
		r.requireSourceIntact("after the return")
	})
	t.Run("committed_target_fenced/accept_source_needs_ack", func(t *testing.T) {
		r := committedFenced(t, fwlOpts{})
		before := r.snap()
		_, err := r.doctor(actAcceptSource)
		r.refused(err, "--acknowledge-rollback", before)
	})
	// Mutation: allow a storage-copy route — red.
	t.Run("committed_target_fenced/accept_source_refuses_storage_copy", func(t *testing.T) {
		r := committedFenced(t, fwlOpts{storage: true})
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "the VM's disks are on dst-host", before)
	})
	// Mutation: drop the re-hash check — red.
	t.Run("committed_target_fenced/accept_source_refuses_changed_source", func(t *testing.T) {
		r := committedFenced(t, fwlOpts{})
		r.write(r.srcStore.NvramPath(fwlVM), []byte("changed since cutover"))
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "recorded at cutover", before)
	})

	// D2-13 m-3 a: source_state_suspect parked from committed, the source's
	// guest running again: --accept-source keeps it (the return writer, the
	// target's paused copy discarded), and --adopt-target-copy needs the
	// source shut off first.
	suspectCommitted := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseSourceStateSuspect, "the source domain is active again although the move cut over")
		return r
	}
	t.Run("source_state_suspect_from_committed/accept_source", func(t *testing.T) {
		r := suspectCommitted(t)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "running")
		r.discardedOnTarget("suspect after the commit")
		disks, _ := corrosion.GetVMDisks(context.Background(), r.src.db, fwlVM)
		for _, d := range disks {
			if d.HostName != "src-host" {
				t.Errorf("disk %s on %s, want src-host", d.DiskName, d.HostName)
			}
		}
	})
	t.Run("source_state_suspect_from_committed/adopt_needs_source_off", func(t *testing.T) {
		r := suspectCommitted(t)
		before := r.snap()
		_, err := r.doctor(actAdopt)
		r.refused(err, "is active", before)
	})

	// ── held_domain_absent (H1 after the commit) ──
	heldAbsent := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.dstFake.VanishDomain(fwlVM)
		if err := r.src.releaseLiveFirmwareMove(context.Background(), run); err == nil {
			t.Fatal("Release of a vanished held domain succeeded")
		}
		requireMarker(t, r, fwmig.PhaseTargetUnreachable, fwmig.PhaseCommitted)
		return r
	}
	// D2-6 m-10: through H1's own entry point, with H1's checks.
	t.Run("held_domain_absent/push_source_nvram", func(t *testing.T) {
		r := heldAbsent(t)
		_, err := r.doctor(actPush)
		r.resolved(err, "dst-host", "stopped")
		if vm := r.row(); vm.StateDetail != h1StoppedDetail("dst-host") {
			t.Errorf("row detail %q, want H1's", vm.StateDetail)
		}
		if b, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM)); !bytes.Equal(b, fwlNvram) {
			t.Errorf("target NVRAM %q, want the source's final", b)
		}
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left")
		}
	})
	t.Run("held_domain_absent/accept_source", func(t *testing.T) {
		r := heldAbsent(t)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left")
		}
	})

	// ── N1: --confirm-target-nvram, --push-source-nvram ──
	n1 := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		other := []byte("os1's vars as the source last wrote them")
		r.write(r.srcStore.NvramPath(fwlVM), other)
		run.marker.SrcNvramSHA256 = fwtSHA(other)
		if err := r.src.fwRecords().PutMarker(run.marker); err != nil {
			t.Fatal(err)
		}
		op, oe := releaseNvramPollFor, releaseNvramPollEvery
		releaseNvramPollFor, releaseNvramPollEvery = 20*time.Millisecond, 5*time.Millisecond
		t.Cleanup(func() { releaseNvramPollFor, releaseNvramPollEvery = op, oe })
		if err := r.src.releaseLiveFirmwareMove(context.Background(), run); err == nil {
			t.Fatal("the rig's release confirmed the NVRAM")
		}
		requireMarker(t, r, fwmig.PhaseNvramUnconfirmed, fwmig.PhaseCommitted)
		return r
	}
	// Mutation: skip the hash check on the target — red.
	t.Run("nvram_unconfirmed/confirm_refuses_other_hash", func(t *testing.T) {
		r := n1(t)
		before := r.snap()
		_, err := r.doctor(actConfirm, withHash(fwtSHA([]byte("not it"))))
		r.refused(err, "confirm the hash it has now", before)
	})
	t.Run("nvram_unconfirmed/confirm", func(t *testing.T) {
		r := n1(t)
		_, err := r.doctor(actConfirm, withHash(fwtSHA(fwlNvram)))
		r.resolved(err, "dst-host", "running")
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left")
		}
		requireNoFwmigCondition(t, r.src, condFwmigNvramUnconfirmed)
	})
	// D2-10: it works with no hold left on the target.
	t.Run("nvram_unconfirmed/confirm_no_hold_left", func(t *testing.T) {
		r := n1(t)
		if err := r.dst.fwRecords().RemoveHold(fwlVM); err != nil {
			t.Fatal(err)
		}
		_, err := r.doctor(actConfirm, withHash(fwtSHA(fwlNvram)))
		r.resolved(err, "dst-host", "running")
	})
	t.Run("nvram_unconfirmed/push_needs_ack", func(t *testing.T) {
		r := n1(t)
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		before := r.snap()
		_, err := r.doctor(actPush)
		r.refused(err, "--acknowledge-rollback", before)
	})
	// D2-6 m-10: the push checks the guest is not running, under the lock.
	// Mutation: drop that check — red.
	t.Run("nvram_unconfirmed/push_refuses_running_guest", func(t *testing.T) {
		r := n1(t)
		before := r.snap()
		_, err := r.doctor(actPush, withAck)
		r.refused(err, "add --stop-target", before)
	})
	t.Run("nvram_unconfirmed/push_stop_target", func(t *testing.T) {
		r := n1(t)
		_, err := r.doctor(actPush, withAck, withStop)
		r.resolved(err, "dst-host", "running")
		if b, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM)); !bytes.Equal(b, []byte("os1's vars as the source last wrote them")) {
			t.Errorf("target NVRAM %q, want the source's final", b)
		}
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateShutdown {
			t.Errorf("target domain %s, want shut off", st)
		}
	})

	// ── a target hold, no source marker (the source host lost) ──
	lost := func(t *testing.T, fence bool) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		r.crashAt(fwmig.PhaseCutover)
		if err := r.src.fwRecords().RemoveMarker(fwlVM); err != nil {
			t.Fatal(err)
		}
		if fence {
			if err := corrosion.RecordFenceWithState(context.Background(), r.src.db,
				corrosion.FenceLogRecord{ID: "fc-src", HostName: "src-host", Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	t.Run("hold_no_marker/adopt", func(t *testing.T) {
		r := lost(t, true)
		_, err := r.doctor(actAdopt)
		if err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if vm := r.row(); vm.HostName != "dst-host" || vm.State != "running" {
			t.Errorf("row %s on %s, want running on dst-host", vm.State, vm.HostName)
		}
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
			t.Errorf("target domain %s, want running", st)
		}
		if _, ok := r.hold(); ok {
			t.Error("the target's hold is left")
		}
	})
	// Mutation: drop the fence requirement — red.
	t.Run("hold_no_marker/adopt_refuses_unfenced_source", func(t *testing.T) {
		r := lost(t, false)
		before := r.snap()
		_, err := r.doctor(actAdopt)
		r.refused(err, "fence-confirm src-host", before)
	})
	t.Run("hold_no_marker/discard", func(t *testing.T) {
		r := lost(t, false)
		_, err := r.doctor(actDiscard)
		if err != nil {
			t.Fatalf("discard: %v", err)
		}
		r.discardedOnTarget("hold, no marker")
		if vm := r.row(); vm.HostName != "src-host" {
			t.Errorf("row on %s, want src-host", vm.HostName)
		}
	})
	// Mutation: drop the row check — red.
	t.Run("hold_no_marker/discard_refuses_row_on_target", func(t *testing.T) {
		r := lost(t, false)
		if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "dst-host", "running"); err != nil {
			t.Fatal(err)
		}
		before := r.snap()
		_, err := r.doctor(actDiscard)
		r.refused(err, "the VM's own copy", before)
	})

	// ── conditions no move closes: --resolve ──
	for _, c := range []struct{ name, code string }{{"unverified", condFwmigUnverified}, {"quarantine", condFwmigQuarantine}} {
		t.Run("condition_"+c.name+"/resolve", func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			if _, err := r.doctor(actResolve, func(q *pb.FirmwareMoveDoctorRequest) { q.ResolveCondition = c.name }); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("resolve with none open: %v, want FailedPrecondition", err)
			}
			if err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{Code: c.code, VM: fwlVM, Attempt: "a"}); err != nil {
				t.Fatal(err)
			}
			if _, err := r.doctor(actResolve, func(q *pb.FirmwareMoveDoctorRequest) { q.ResolveCondition = c.name }); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			requireNoFwmigCondition(t, r.src, c.code)
		})
	}
}

// Every action and every refusal is audited as vm.firmware-move, under the
// operator's name, with the --acknowledge-rollback it carried.
//
// Mutation: drop the audit of a refusal — red.
func TestDoctorFirmwareMove_Audited(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCutover)
	r.park(run, fwmig.PhaseSourceStateSuspect, "test")
	if _, err := r.doctor(actAcceptSource); err == nil {
		t.Fatal("accept-source without the acknowledgement went through")
	}
	if _, err := r.doctor(actAcceptSource, withAck); err != nil {
		t.Fatalf("accept-source: %v", err)
	}
	rows, err := r.src.db.Query(context.Background(),
		`SELECT username, target, detail, result FROM audit_log WHERE action = ?`, fwDoctorVerb)
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	for _, a := range rows {
		if a.String("target") == fwlVM && a.String("username") == "admin" {
			results = append(results, a.String("result"))
			if a.String("result") == "ok" && !strings.Contains(a.String("detail"), "--acknowledge-rollback") {
				t.Errorf("audit detail %q does not name the acknowledgement", a.String("detail"))
			}
		}
	}
	if !strings.Contains(strings.Join(results, ","), "error") || !strings.Contains(strings.Join(results, ","), "ok") {
		t.Errorf("audit results %v, want the refusal and the action", results)
	}
}

// Without an action the doctor shows both records and every hash, from both
// hosts.
func TestDoctorFirmwareMove_ShowsBothRecords(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	r.crashAt(fwmig.PhaseCutover)
	resp, err := r.doctor(pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED)
	if err != nil {
		t.Fatal(err)
	}
	var src, dst *pb.FirmwareMoveHostRecords
	for _, h := range resp.GetHosts() {
		switch h.GetHost() {
		case "src-host":
			src = h
		case "dst-host":
			dst = h
		}
	}
	if src == nil || dst == nil {
		t.Fatalf("hosts %v, want src-host and dst-host", resp.GetHosts())
	}
	if !strings.Contains(src.GetMarkerJson(), `"phase":"cutover"`) || !strings.Contains(src.GetMarkerJson(), fwtSHA(fwlPermall)) {
		t.Errorf("source marker %s", src.GetMarkerJson())
	}
	if !strings.Contains(dst.GetHoldJson(), `"state":"prepared"`) || dst.GetDomain().GetState() != "paused" {
		t.Errorf("target hold %s, domain %v", dst.GetHoldJson(), dst.GetDomain())
	}
	if dst.GetHashes()["permall_now"] != fwtSHA(fwlPermall) || dst.GetHashes()["nvram_now"] == "" {
		t.Errorf("target hashes %v", dst.GetHashes())
	}
}

// The adopt hold transition (spec §17 D-5, m-7): prepared or mismatch with a
// paused guest → verified, the permall verified as it is now; a running
// guest → resuming; the operator, the reason and the hashes recorded; a
// shut-off guest refused; only the hold's source may ask.
//
// Mutations: allow a shut-off guest; skip the caller check — red.
func TestFirmwareMoveDoctorTarget_AdoptTransition(t *testing.T) {
	for _, c := range []struct {
		name  string
		hold  fwmig.HoldState
		dom   libvirtfake.State
		want  fwmig.HoldState
		error bool
	}{
		{"prepared_paused", fwmig.HoldPrepared, libvirtfake.StatePaused, fwmig.HoldVerified, false},
		{"mismatch_paused", fwmig.HoldMismatch, libvirtfake.StatePaused, fwmig.HoldVerified, false},
		{"prepared_running", fwmig.HoldPrepared, libvirtfake.StateRunning, fwmig.HoldResuming, false},
		{"verified_shutoff", fwmig.HoldVerified, libvirtfake.StateShutdown, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			run := r.crashAt(fwmig.PhaseCutover)
			h, _ := r.hold()
			h.State = c.hold
			if err := r.dst.fwRecords().PutHold(h); err != nil {
				t.Fatal(err)
			}
			r.dstFake.SetState(fwlVM, c.dom)
			m := run.marker
			req := &pb.FirmwareMoveDoctorTargetRequest{VmName: fwlVM, Uuid: m.UUID, CreatedAt: m.CreatedAt, AttemptId: m.Attempt,
				Op: pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_ADOPT, Operator: "alice", Reason: "test"}
			resp, err := r.dst.FirmwareMoveDoctorTarget(r.peer, req)
			got, _ := r.hold()
			if c.error {
				if status.Code(err) != codes.FailedPrecondition || got.State != c.hold || got.Adoption != nil {
					t.Fatalf("err %v, hold %s %+v; want refused, hold unchanged", err, got.State, got.Adoption)
				}
				return
			}
			if err != nil || resp.GetHoldState() != string(c.want) || got.State != c.want {
				t.Fatalf("err %v, hold %s (answered %s), want %s", err, got.State, resp.GetHoldState(), c.want)
			}
			a := got.Adoption
			if a == nil || a.By != "alice" || a.From != c.hold || a.Reason != "test" || a.PermallSHA256 != fwtSHA(fwlPermall) {
				t.Errorf("adoption %+v", a)
			}
			if c.want == fwmig.HoldVerified && got.VerifiedPermallSHA256 != fwtSHA(fwlPermall) {
				t.Errorf("verified permall %s, want the target's now", got.VerifiedPermallSHA256)
			}
			other := context.WithValue(context.WithValue(peerCtxFor(t, r.dst, "other-host"), ctxKeyUsername, "admin"), ctxKeyRole, "admin")
			if _, err := r.dst.FirmwareMoveDoctorTarget(other, req); status.Code(err) != codes.PermissionDenied {
				t.Errorf("another host's adopt: %v, want PermissionDenied", err)
			}
		})
	}
}

// The post-commit --accept-source returns the VM with the return writer,
// never with RepointMigratedVM, which needs `migrating` on the source and
// moves the VM row alone (spec §17 D-5). Only the commits' own fallbacks
// (a migration's and a drain's live move) call it, and failover's settle of
// a non-firmware VM whose failed source left it running on the target.
//
// Mutation: call RepointMigratedVM from the doctor — red.
func TestDoctorFirmwareMove_NeverRepoints(t *testing.T) {
	n := 0
	for _, c := range fwCallSites(t, map[string]bool{"RepointMigratedVM": true, "ReturnMigratedVM": true}) {
		switch {
		case c.sel == "RepointMigratedVM" && c.caller != "internal/grpcapi.Server.finalizeMigrationOwnership" &&
			// A drain's live move commits with its own fresh-read transfer, and
			// re-points as the same fallback after a cut-over (host.go).
			c.caller != "internal/grpcapi.Server.drainOneVM" &&
			// Failover re-points a migrating row whose failed source left the
			// guest running on the target; never a firmware VM's.
			c.caller != "internal/grpcapi.Server.settleFailedSourceMigration":
			t.Errorf("RepointMigratedVM called from %s at %s", c.caller, c.pos)
		case c.sel == "ReturnMigratedVM":
			n++
			if c.caller != "internal/grpcapi.Server.doctorAcceptSourceAfterCommit" {
				t.Errorf("ReturnMigratedVM called from %s at %s", c.caller, c.pos)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d calls of ReturnMigratedVM, want the doctor's one", n)
	}
}
