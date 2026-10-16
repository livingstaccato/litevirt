package grpcapi

// The source half of a live firmware (Secure Boot / vTPM) migration (spec
// §6.1): stage A, the marker, Prepare and stage B before any target setup;
// stage C once EnsureDisks has answered; the marker through migrating,
// cutover and Verify before the commit; and Release in place of the NIC
// hand-over after it. migrateOwnedVM drives it under the VM's lock.
//
// One copy of the VM at every moment: the target's guest arrives paused and
// only Release lets it run, after Verify matched and the commit landed. This
// side never resumes a guest whose target may have run. Every outcome other
// than the happy flow keeps both copies: the move is undone before cutover
// only once the target has answered for its hold, and is parked (marker kept,
// condition raised) otherwise.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
)

// liveFirmwareRun is one live firmware move on its source, from the marker on.
type liveFirmwareRun struct {
	target corrosion.HostRecord
	elig   *liveFirmwareEligible
	// marker is the source marker as last written.
	marker fwmig.Marker
	// prepared is when Prepare answered: the target's hold is as old.
	prepared time.Time
}

// fwLiveSourceState is the Server's test seams for the source half.
type fwLiveSourceState struct {
	// stepHook, when set, is called with each source step as it is reached
	// ("commit", "cleanup"). Test-only.
	stepHook func(step string)
}

func (s *Server) fwLiveStep(step string) {
	if h := s.fwLive.stepHook; h != nil {
		h(step)
	}
}

// liveFirmwareSourceCleanup is the source cleanup (spec §6.7, marker
// released → cleaning → removed). nil leaves the marker released, its start
// veto in force, until restart recovery runs the cleanup.
var liveFirmwareSourceCleanup func(s *Server, ctx context.Context, m fwmig.Marker) error

// Timing of the source half; vars so tests can shorten them.
var (
	// liveFirmwareStep4Limit bounds §6.1 step 4 (the target setup between
	// Prepare and the migration). The target's hold sweep may quarantine a
	// hold with no domain once it is heldStaleAfter old and the row is not
	// migrating, so a move whose setup took longer is undone instead of
	// started (D2-9 M-4).
	liveFirmwareStep4Limit = 30 * time.Minute
	// fwLiveCallTimeout bounds one Verify, Release or Abort call; Release
	// polls the NVRAM for up to releaseNvramPollFor on the target.
	fwLiveCallTimeout = time.Minute
	// fwLiveRetryBackoff and fwLiveRetryFor: a Verify or Release that does
	// not answer is retried with backoff for fwLiveRetryFor (§7 V3, R1).
	fwLiveRetryBackoff = time.Second
	fwLiveRetryFor     = 2 * time.Minute
)

// newLiveFirmwareAttemptID is a fresh attempt id (a UUID, spec §4).
func newLiveFirmwareAttemptID() string { return uuid.NewString() }

// fwmigConditionFor is the condition a parked phase raises (spec §14).
var fwmigConditionFor = map[fwmig.Phase]string{
	fwmig.PhaseTargetUnreachable:  condFwmigTargetUnreachable,
	fwmig.PhaseSourceStateMissing: condFwmigSourceStateMissing,
	fwmig.PhaseSourceStateSuspect: condFwmigSourceStateSuspect,
	fwmig.PhaseTargetRan:          condFwmigTargetRan,
	fwmig.PhaseNvramUnconfirmed:   condFwmigNvramUnconfirmed,
	fwmig.PhaseDiscardPending:     condFwmigUnverified,
	fwmig.PhaseSourcePaused:       condFwmigSourcePaused,
}

// putLiveFirmwareMarker writes r's marker in phase p.
func (s *Server) putLiveFirmwareMarker(r *liveFirmwareRun, p fwmig.Phase) error {
	m := r.marker
	m.Phase = p
	if err := s.fwRecords().PutMarker(m); err != nil {
		return status.Errorf(codes.Internal, "VM %q: record live firmware migration %s as %s: %v", m.VM, m.Attempt, p, err)
	}
	r.marker = m
	return nil
}

// parkLiveFirmwareMove parks r's move in phase p: the marker kept (with the
// phase it left), its condition raised, nothing deleted anywhere. The error
// is what the caller returns.
func (s *Server) parkLiveFirmwareMove(ctx context.Context, r *liveFirmwareRun, p fwmig.Phase, detail string) error {
	ctx = context.WithoutCancel(ctx)
	m, err := r.marker.Park(p)
	if err != nil {
		// A park this marker cannot take keeps it as it is: it still vetoes.
		slog.Error("live firmware move: cannot park the marker; it is kept as it is", "vm", r.marker.VM, "phase", p, "error", err)
		m = r.marker
	} else {
		m.Detail = detail
		if perr := s.fwRecords().PutMarker(m); perr != nil {
			slog.Error("live firmware move: cannot record the park; the marker on disk is kept", "vm", m.VM, "phase", p, "error", perr)
		} else {
			r.marker = m
		}
	}
	if code, ok := fwmigConditionFor[p]; ok {
		if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
			Code: code, VM: m.VM, Attempt: m.Attempt, Source: s.hostName, Target: m.Target,
			Hashes: map[string]string{"src_permall_sha256": m.SrcPermallSHA256, "src_nvram_sha256": m.SrcNvramSHA256},
			Paths:  []string{s.fw().SwtpmDir(m.UUID), s.fw().NvramPath(m.VM)},
			Detail: detail,
			Action: "both copies of the firmware state are kept, and nothing is deleted until the move is resolved",
		}); cerr != nil {
			slog.Warn("live firmware move: raise the condition", "vm", m.VM, "code", code, "error", cerr)
		}
	}
	slog.Error("live firmware move parked", "vm", m.VM, "attempt", m.Attempt, "target", m.Target, "phase", p, "detail", detail)
	s.recordVMEvent(ctx, m.VM, "vm.migrate.firmware", "error", fmt.Sprintf("live firmware migration %s to %s parked as %s: %s", m.Attempt, m.Target, p, detail))
	return status.Errorf(codes.FailedPrecondition,
		"VM %q: live firmware migration %s to %s is parked as %s: %s; both copies of its firmware state are kept",
		m.VM, m.Attempt, m.Target, p, detail)
}

// liveFirmwarePeer dials the move's target.
func (s *Server) liveFirmwarePeer(ctx context.Context, target string) (pb.LiteVirtClient, func(), error) {
	return s.dialPeer(ctx, target)
}

// sourceDomainActive reports whether this host's domain of vm is active; an
// unreadable answer is false (so a target disposes of its state by rule Q,
// never rule D).
func (s *Server) sourceDomainActive(vm string) bool {
	if s.virt == nil {
		return false
	}
	active, err := s.virt.DomainIsActive(vm)
	return err == nil && active
}

// ── Steps 2 and 3: the marker, Prepare, stage B ──

// beginLiveFirmwareMove writes the marker (preparing), asks the target to
// hold the move (Prepare) and judges its answer (stage B); the marker is then
// prepared. It returns a run whenever the target may hold the attempt, also
// with an error: the caller's undo then aborts it before cutover (§7 P2). A
// target whose build lacks the RPC wrote nothing, and gets no run.
func (s *Server) beginLiveFirmwareMove(ctx context.Context, vm *corrosion.VMRecord, target *corrosion.HostRecord, elig *liveFirmwareEligible) (*liveFirmwareRun, error) {
	route := fwmig.RouteTunnelled
	if elig.storage {
		route = fwmig.RouteStorageCopy
	}
	r := &liveFirmwareRun{target: *target, elig: elig, marker: fwmig.Marker{
		VM: vm.Name, Binding: fwmig.Binding{UUID: elig.uuid, CreatedAt: vm.CreatedAt, Attempt: newLiveFirmwareAttemptID()},
		Target: target.Name, Route: route, Phase: fwmig.PhasePreparing,
		TPM: elig.applicability.GetTpm(), UEFI: elig.applicability.GetUefi(), Since: time.Now().UTC(),
	}}
	var nvram []byte
	if r.marker.UEFI {
		b, err := os.ReadFile(s.fw().NvramPath(vm.Name))
		if err != nil {
			return nil, liveFirmwareRefusal(vm.Name, target.Name, "its NVRAM on %s cannot be read: %v", s.hostName, err)
		}
		nvram = b
	}
	if err := s.putLiveFirmwareMarker(r, fwmig.PhasePreparing); err != nil {
		return nil, err
	}
	client, closer, err := s.liveFirmwarePeer(ctx, target.Name)
	var resp *pb.PrepareLiveFirmwareTargetResponse
	if err == nil {
		cctx, cancel := context.WithTimeout(ctx, fwLiveCallTimeout)
		resp, err = client.PrepareLiveFirmwareTarget(cctx, &pb.PrepareLiveFirmwareTargetRequest{
			VmName: vm.Name, Uuid: elig.uuid, CreatedAt: vm.CreatedAt, AttemptId: r.marker.Attempt,
			ProtocolVersion: liveFirmwareProtocolVersion, SrcRuntime: elig.runtime, SrcApplicability: elig.applicability,
			SourceDomainActive: s.sourceDomainActive(vm.Name), Nvram: nvram,
		})
		cancel()
		closer()
	}
	if status.Code(err) == codes.Unimplemented {
		// An older target: nothing was written there (§7 P1).
		if rerr := s.fwRecords().RemoveMarker(vm.Name); rerr != nil {
			return r, status.Errorf(codes.Internal, "VM %q: remove the marker of a refused live firmware migration: %v", vm.Name, rerr)
		}
		return nil, liveFirmwareStageB(vm.Name, target.Name, elig, nil, err)
	}
	r.prepared = time.Now()
	if err := liveFirmwareStageB(vm.Name, target.Name, elig, resp, err); err != nil {
		// The target may hold the attempt (a Prepare that failed after its
		// hold write, or a refused answer): the undo aborts it (§7 P2).
		return r, err
	}
	if err := s.putLiveFirmwareMarker(r, fwmig.PhasePrepared); err != nil {
		return r, err
	}
	slog.Info("live firmware move: target holds the attempt", "vm", vm.Name, "attempt", r.marker.Attempt, "target", target.Name)
	return r, nil
}

// recordLiveFirmwareRoute is §6.1 step 4's record: the route stage C
// allowed and the stubs EnsureDisks reported creating, in the prepared
// marker.
func (s *Server) recordLiveFirmwareRoute(r *liveFirmwareRun, route fwmig.Route, stubs []string) error {
	r.marker.Route = route
	r.marker.CreatedStubs = append([]string(nil), stubs...)
	return s.putLiveFirmwareMarker(r, r.marker.Phase)
}

// startLiveFirmwareMigration is §6.1 step 5: the marker migrating, unless the
// target setup took so long that the target's hold sweep may have disposed
// of its hold.
func (s *Server) startLiveFirmwareMigration(r *liveFirmwareRun) error {
	if took := time.Since(r.prepared); took > liveFirmwareStep4Limit {
		return liveFirmwareRefusal(r.marker.VM, r.target.Name,
			"setting up the target took %s since it began holding the move (limit %s); try again", took.Round(time.Second), liveFirmwareStep4Limit)
	}
	return s.putLiveFirmwareMarker(r, fwmig.PhaseMigrating)
}

// ── Before cutover: abort (§7 P2) ──

// abortLiveFirmwareBeforeCutover sends Abort PRE_CUTOVER for r's attempt. It
// reports whether the target answered that it holds nothing of the attempt
// and has no domain of the VM (D2-9 M-6: an OK answer with a domain present
// is not "nothing held"), with the reason when not.
func (s *Server) abortLiveFirmwareBeforeCutover(ctx context.Context, r *liveFirmwareRun) (bool, string) {
	ctx = context.WithoutCancel(ctx)
	m := r.marker
	client, closer, err := s.liveFirmwarePeer(ctx, r.target.Name)
	if err != nil {
		return false, fmt.Sprintf("the abort could not reach %s: %v", r.target.Name, err)
	}
	defer closer()
	cctx, cancel := context.WithTimeout(ctx, fwLiveCallTimeout)
	defer cancel()
	resp, err := client.AbortLiveFirmwareTarget(cctx, &pb.AbortLiveFirmwareTargetRequest{
		VmName: m.VM, Uuid: m.UUID, CreatedAt: m.CreatedAt, AttemptId: m.Attempt,
		Mode: pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER, SourceDomainActive: s.sourceDomainActive(m.VM),
		CreatedStubs: m.CreatedStubs,
	})
	switch {
	case err != nil:
		return false, fmt.Sprintf("the abort before cutover was not answered by %s: %v", r.target.Name, err)
	case resp.GetRefused():
		return false, fmt.Sprintf("%s refused the abort before cutover (hold %s, domain %s): %s",
			r.target.Name, resp.GetHoldState(), domainWord(resp.GetTargetDomain()), resp.GetDetail())
	case resp.GetTargetDomain().GetPresent():
		return false, fmt.Sprintf("%s answered the abort, but a domain of the VM is defined there (%s)",
			r.target.Name, resp.GetTargetDomain().GetState())
	}
	return true, ""
}

// settleLiveFirmwareAbort ends r's move after an abort before cutover: the
// marker removed once the target answered for its hold, parked
// target_unreachable otherwise (restart recovery retries the abort).
func (s *Server) settleLiveFirmwareAbort(ctx context.Context, r *liveFirmwareRun, answered bool, why string) {
	if !answered {
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, why)
		return
	}
	if err := s.fwRecords().RemoveMarker(r.marker.VM); err != nil {
		slog.Error("live firmware move: the target dropped its hold, but the marker cannot be removed; restart recovery removes it",
			"vm", r.marker.VM, "attempt", r.marker.Attempt, "error", err)
		return
	}
	slog.Info("live firmware move: undone before cutover", "vm", r.marker.VM, "attempt", r.marker.Attempt, "target", r.target.Name)
}

// ── After the migration call ──

// liveFirmwareSourceInactive reports whether this host's domain of vm is
// defined and inactive (shut off): the guest left it, so the move continues
// to cutover (§7 M1b). An unreadable state is not inactive.
func (s *Server) liveFirmwareSourceInactive(vm string) bool {
	if s.virt == nil {
		return false
	}
	active, err := s.virt.DomainIsActive(vm)
	return err == nil && !active
}

// liveFirmwareMigrateFailed is the source's answer to a migration call that
// failed with its domain not inactive: before cutover, the guest is still
// here. A running guest's move is aborted before cutover and its marker
// removed once the target answered for its hold; anything else is parked
// with both copies kept. The caller then restores the row as for any failed
// migration.
func (s *Server) liveFirmwareMigrateFailed(ctx context.Context, r *liveFirmwareRun, migrateErr error) {
	ctx = context.WithoutCancel(ctx)
	st, err := s.virt.DomainStateReason(r.marker.VM)
	switch {
	case err != nil:
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("the migration failed (%v) and the state of the source domain cannot be read: %v", migrateErr, err))
	case st.State == "running":
		answered, why := s.abortLiveFirmwareBeforeCutover(ctx, r)
		s.settleLiveFirmwareAbort(ctx, r, answered, fmt.Sprintf("the migration failed (%v); %s", migrateErr, why))
	case st.Reason == "paused":
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourcePaused,
			fmt.Sprintf("the migration failed (%v) and left the source guest paused", migrateErr))
	default:
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("the migration failed (%v) and the source domain is %s (%s)", migrateErr, st.State, st.Reason))
	}
}

// ── Step 7 and 8: cutover and Verify ──

// liveFirmwareCutover is §6.1 steps 7 and 8: the source domain confirmed
// inactive, its stop reason and final state read, the marker cutover; then
// Verify, and on MATCH the marker verified. Any other outcome parks the move
// and returns its error; the commit must not follow.
func (s *Server) liveFirmwareCutover(ctx context.Context, r *liveFirmwareRun) error {
	ctx = context.WithoutCancel(ctx)
	vm := r.marker.VM
	active, err := s.virt.DomainIsActive(vm)
	if err != nil {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("the migration returned, and whether the source domain is still active cannot be read: %v", err))
	}
	if active {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateSuspect,
			"the migration returned, and the source domain is still active")
	}
	reason := "unknown"
	if st, err := s.virt.DomainStateReason(vm); err == nil && st.Reason != "" {
		reason = st.Reason
	}
	fw := s.fw()
	var permall, nvram string
	if r.marker.TPM {
		if permall, err = fw.PermallSHA256(r.marker.UUID); err != nil {
			return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
				fmt.Sprintf("the source's final TPM state cannot be read: %v", err))
		}
	}
	if r.marker.UEFI {
		if nvram, err = fw.NvramSHA256(vm); err != nil {
			return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
				fmt.Sprintf("the source's final NVRAM cannot be read: %v", err))
		}
	}
	r.marker.SrcPermallSHA256, r.marker.SrcNvramSHA256, r.marker.SrcStopReason = permall, nvram, reason
	if err := s.putLiveFirmwareMarker(r, fwmig.PhaseCutover); err != nil {
		return err
	}
	return s.verifyLiveFirmwareMove(ctx, r)
}

// verifyLiveFirmwareMove sends Verify (retried while unanswered) and judges
// the verdict. MATCH sets the marker verified. Before the commit, every other
// verdict parks the move with both copies kept.
func (s *Server) verifyLiveFirmwareMove(ctx context.Context, r *liveFirmwareRun) error {
	m := r.marker
	var resp *pb.VerifyLiveFirmwareTargetResponse
	err := s.retryLiveFirmwareCall(ctx, r, "verify", func(cctx context.Context, c pb.LiteVirtClient) (err error) {
		resp, err = c.VerifyLiveFirmwareTarget(cctx, &pb.VerifyLiveFirmwareTargetRequest{
			VmName: m.VM, Uuid: m.UUID, AttemptId: m.Attempt, SrcPermallSha256: m.SrcPermallSHA256})
		return err
	})
	if err != nil {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf("Verify was not answered by %s: %v", r.target.Name, err))
	}
	td := resp.GetTargetDomain()
	switch resp.GetVerdict() {
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_MATCH:
		if err := s.putLiveFirmwareMarker(r, fwmig.PhaseVerified); err != nil {
			return err
		}
		slog.Info("live firmware move: target verified", "vm", m.VM, "attempt", m.Attempt, "target", r.target.Name)
		return nil
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_TARGET_RAN:
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetRan, resp.GetDetail())
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_MISMATCH, pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_RUNNING:
		if m.SrcStopReason != fwmig.StopReasonMigrated {
			// The source domain did not stop as a completed migration stops
			// it: its state may be stale (I6). Both copies are kept.
			return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateSuspect,
				fmt.Sprintf("Verify answered %s after the source stopped with reason %q: %s", resp.GetVerdict(), m.SrcStopReason, resp.GetDetail()))
		}
		// The target's copy is not the source's final state: it is to be
		// discarded; until that is done both copies are kept.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseDiscardPending,
			fmt.Sprintf("Verify answered %s: %s", resp.GetVerdict(), resp.GetDetail()))
	default:
		// NOT_HELD, BAD_REQUEST or a verdict this build does not know: the
		// target's answer decides nothing here.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("Verify answered %s (domain %s): %s", resp.GetVerdict(), domainWord(td), resp.GetDetail()))
	}
}

// retryLiveFirmwareCall makes call against r's target until it answers, with
// backoff, for fwLiveRetryFor. A target without the RPC, or one that denies
// this host, is not retried.
func (s *Server) retryLiveFirmwareCall(ctx context.Context, r *liveFirmwareRun, what string, call func(context.Context, pb.LiteVirtClient) error) error {
	deadline := time.Now().Add(fwLiveRetryFor)
	wait := fwLiveRetryBackoff
	for {
		client, closer, err := s.liveFirmwarePeer(ctx, r.target.Name)
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, fwLiveCallTimeout)
			err = call(cctx, client)
			cancel()
			closer()
		}
		if err == nil {
			return nil
		}
		switch status.Code(err) {
		case codes.Unimplemented, codes.PermissionDenied, codes.InvalidArgument:
			return err
		}
		if time.Now().Add(wait).After(deadline) {
			return err
		}
		slog.Warn("live firmware move: retrying", "vm", r.marker.VM, "call", what, "target", r.target.Name, "error", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		if wait *= 2; wait > 15*time.Second {
			wait = 15 * time.Second
		}
	}
}

// ── Steps 9 to 12: commit, Release, NVRAM, cleanup ──

// liveFirmwareCommitted is §6.1 step 9's record: the commit landed.
func (s *Server) liveFirmwareCommitted(r *liveFirmwareRun) error {
	s.fwLiveStep("commit")
	return s.putLiveFirmwareMarker(r, fwmig.PhaseCommitted)
}

// releaseLiveFirmwareMove is §6.1 steps 10 to 12, in place of the NIC
// hand-over (armedMigration.finish): Release (the target puts the NIC
// firewall in force and resumes its guest), the NVRAM confirmation, and the
// source cleanup. An error means the guest is held or parked as it says.
func (s *Server) releaseLiveFirmwareMove(ctx context.Context, r *liveFirmwareRun) error {
	ctx = context.WithoutCancel(ctx)
	m := r.marker
	var nvramFinal []byte
	if m.UEFI {
		// The source domain is inactive, so this is its final NVRAM; Release
		// uses it only for a held guest the target lost (§7 H1), and only
		// with the hash Verify's cutover recorded.
		if b, err := os.ReadFile(s.fw().NvramPath(m.VM)); err == nil && fwBytesSHA256(b) == m.SrcNvramSHA256 {
			nvramFinal = b
		} else {
			slog.Warn("live firmware move: the source's final NVRAM is not as recorded at cutover; Release carries none",
				"vm", m.VM, "attempt", m.Attempt, "error", err)
		}
	}
	var resp *pb.ReleaseLiveFirmwareTargetResponse
	err := s.retryLiveFirmwareCall(ctx, r, "release", func(cctx context.Context, c pb.LiteVirtClient) (err error) {
		resp, err = c.ReleaseLiveFirmwareTarget(cctx, &pb.ReleaseLiveFirmwareTargetRequest{
			VmName: m.VM, Uuid: m.UUID, AttemptId: m.Attempt, CreatedAt: m.CreatedAt,
			SrcNvramSha256: m.SrcNvramSHA256, NvramFinal: nvramFinal})
		return err
	})
	if err != nil {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf("Release was not answered by %s: %v", r.target.Name, err))
	}
	// Release's refusals are judged here, by the RPC that gave them: after
	// the commit the target holds the only verified copy, so every one parks
	// and none discards it.
	switch v := resp.GetVerdict(); v {
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED:
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_TARGET_RAN:
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetRan, resp.GetDetail())
	default:
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("Release answered %s (domain %s): %s", v, domainWord(resp.GetTargetDomain()), resp.GetDetail()))
	}
	if !resp.GetNvramConfirmed() {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseNvramUnconfirmed, resp.GetDetail())
	}
	if err := s.putLiveFirmwareMarker(r, fwmig.PhaseReleased); err != nil {
		return err
	}
	slog.Info("live firmware move: released on the target", "vm", m.VM, "attempt", m.Attempt, "target", r.target.Name, "nvram", resp.GetNvramSha256())
	s.fwLiveStep("cleanup")
	if liveFirmwareSourceCleanup == nil {
		slog.Info("live firmware move: the source state stays until the source cleanup runs", "vm", m.VM, "attempt", m.Attempt)
		return nil
	}
	return liveFirmwareSourceCleanup(s, ctx, r.marker)
}
