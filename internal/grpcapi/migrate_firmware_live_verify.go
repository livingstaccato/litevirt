package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/safename"
)

// The target's half of a live firmware move after cutover (spec §6.5, §6.6,
// §7 H1): Verify compares the paused guest's TPM state with the source's
// final state and records the verdict in the hold; Release is the one path
// that lets a held guest run (I5), and H1 the one that writes its NVRAM after
// a target host lost the paused guest. Both run under firmwareTargets.op, as
// Prepare and Abort do.

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	verdictBadRequest = pb.FirmwareVerdict_FIRMWARE_VERDICT_BAD_REQUEST
	verdictNotHeld    = pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_HELD
	verdictNotRunning = pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_RUNNING
	verdictTargetRan  = pb.FirmwareVerdict_FIRMWARE_VERDICT_TARGET_RAN
	verdictMatch      = pb.FirmwareVerdict_FIRMWARE_VERDICT_MATCH
	verdictMismatch   = pb.FirmwareVerdict_FIRMWARE_VERDICT_MISMATCH
)

// ── Verify (spec §6.5) ──

// VerifyLiveFirmwareTarget answers whether the held guest of one attempt is
// the source's final state: paused, the domain of the hold's uuid, and (TPM)
// its permall equal to src_permall_sha256. It reads the guest's state and
// writes only the hold's verdict (verified, or mismatch). It never compares
// the NVRAM: a paused guest's NVRAM is still T0 (§6.4).
func (s *Server) VerifyLiveFirmwareTarget(ctx context.Context, req *pb.VerifyLiveFirmwareTargetRequest) (*pb.VerifyLiveFirmwareTargetResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := safename.ValidateVMName(req.VmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()

	td, err := s.targetDomain(req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: %v", req.VmName, err)
	}
	resp := &pb.VerifyLiveFirmwareTargetResponse{TargetDomain: td}
	h, ok, err := s.fwRecords().GetHold(req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: its firmware move hold on %s cannot be read: %v", req.VmName, s.hostName, err)
	}
	if !ok || req.AttemptId == "" || h.Attempt != req.AttemptId || !strings.EqualFold(h.UUID, req.Uuid) {
		resp.Verdict = verdictNotHeld
		resp.Detail = fmt.Sprintf("VM %s: %s holds no live firmware move of attempt %s (uuid %s)", req.VmName, s.hostName, req.AttemptId, req.Uuid)
		return resp, nil
	}
	if caller := callerMTLSCommonName(ctx); caller != h.Source {
		return nil, status.Errorf(codes.PermissionDenied,
			"VM %q: the hold of attempt %s is %s's; %s may not verify it", h.VM, h.Attempt, h.Source, caller)
	}
	answer := func(v pb.FirmwareVerdict, why string) (*pb.VerifyLiveFirmwareTargetResponse, error) {
		resp.Verdict = v
		resp.Detail = fmt.Sprintf("VM %s: attempt %s from %s on %s (hold %s): %s", h.VM, h.Attempt, h.Source, s.hostName, h.State, why)
		if v != verdictMatch {
			slog.Warn("live firmware move: verify", "vm", h.VM, "attempt", h.Attempt, "verdict", v, "detail", resp.Detail)
		}
		return resp, nil
	}
	// The source's hash is what a TPM hold is compared with: an empty one is a
	// source that did not read it, never "nothing to compare".
	if h.TPM && req.SrcPermallSha256 == "" {
		return answer(verdictBadRequest, "the VM has a vTPM and the request carries no src_permall_sha256")
	}
	if req.SrcPermallSha256 != "" && !sha256HexRe.MatchString(req.SrcPermallSha256) {
		return answer(verdictBadRequest, fmt.Sprintf("src_permall_sha256 %q is not a sha256", req.SrcPermallSha256))
	}
	switch h.State {
	case fwmig.HoldPrepared, fwmig.HoldVerified, fwmig.HoldMismatch:
	default:
		// resuming, released_unconfirmed: verified and handed over already.
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the hold of attempt %s is %s: it was verified and released; Verify does not judge it again", h.VM, h.Attempt, h.State)
	}
	// A guest that ran is TARGET_RAN whatever else is wrong with its hold:
	// that is the guard failing, and the source must hear it as such.
	switch {
	case td.State == "running":
		return answer(verdictTargetRan, "its domain is running here: the guest ran before its state was verified")
	case td.Present && td.State != "shutoff" && td.State != "paused":
		// Active, neither running nor paused (pm-suspended, crashed): only a
		// guest that ran gets there.
		return answer(verdictTargetRan, fmt.Sprintf("its domain is %s here, which only a guest that ran reaches", td.State))
	}
	if h.UEFI && h.NvramMaterialised != fwmig.NvramDone {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the hold of attempt %s never finished materialising the NVRAM (%s); its Prepare did not complete", h.VM, h.Attempt, h.NvramMaterialised)
	}
	if !td.Present || td.State == "shutoff" {
		return answer(verdictNotRunning, fmt.Sprintf("its domain is %s here", domainWord(td)))
	}
	if !strings.EqualFold(td.Uuid, h.UUID) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the paused domain here has uuid %q, not the hold's %s; nothing is judged", h.VM, td.Uuid, h.UUID)
	}
	if h.TPM {
		dst, err := s.fw().PermallSHA256(h.UUID)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if h.State != fwmig.HoldMismatch {
				if err := s.putHoldState(h, fwmig.HoldMismatch, ""); err != nil {
					return nil, err
				}
			}
			return answer(verdictMismatch, "the VM has a vTPM and its permall is missing here")
		case err != nil:
			return nil, status.Errorf(codes.Unavailable, "VM %q: hash its permall: %v", h.VM, err)
		}
		resp.DstPermallSha256 = dst
		if dst != req.SrcPermallSha256 {
			if h.State != fwmig.HoldMismatch {
				if err := s.putHoldState(h, fwmig.HoldMismatch, ""); err != nil {
					return nil, err
				}
			}
			return answer(verdictMismatch, fmt.Sprintf("its permall is %s, the source's final permall is %s", dst, req.SrcPermallSha256))
		}
	}
	switch h.State {
	case fwmig.HoldMismatch:
		// A mismatch stays one: the source decides from it (V1, V1b), and a
		// later equal answer would hide that the state once differed.
		return answer(verdictMismatch, "the hold already recorded a mismatch for this attempt")
	case fwmig.HoldVerified:
		if h.VerifiedPermallSHA256 != resp.DstPermallSha256 {
			if err := s.putHoldState(h, fwmig.HoldMismatch, ""); err != nil {
				return nil, err
			}
			return answer(verdictMismatch, fmt.Sprintf("its permall is %s, and it was verified as %s", resp.DstPermallSha256, h.VerifiedPermallSHA256))
		}
	default:
		if err := s.putHoldState(h, fwmig.HoldVerified, resp.DstPermallSha256); err != nil {
			return nil, err
		}
	}
	slog.Info("live firmware move: target verified", "vm", h.VM, "attempt", h.Attempt, "source", h.Source, "permall", resp.DstPermallSha256)
	return answer(verdictMatch, "verified")
}

// putHoldState writes h in state st (verified records the permall hash it
// verified).
func (s *Server) putHoldState(h fwmig.Hold, st fwmig.HoldState, verifiedPermall string) error {
	h.State = st
	if st == fwmig.HoldVerified {
		h.VerifiedPermallSHA256 = verifiedPermall
	}
	if err := s.fwRecords().PutHold(h); err != nil {
		return status.Errorf(codes.Internal, "VM %q: record the hold of attempt %s as %s: %v", h.VM, h.Attempt, st, err)
	}
	return nil
}

// domainWord names a target domain for operator text.
func domainWord(td *pb.TargetDomain) string {
	if td == nil || !td.Present {
		return "absent"
	}
	return td.State
}

// ── Release (spec §6.6) ──

// The NVRAM confirmation (§6.6 step 6): read at once, then every
// releaseNvramPollEvery until releaseNvramPollFor has passed.
var (
	releaseNvramPollEvery = 250 * time.Millisecond
	releaseNvramPollFor   = 10 * time.Second
)

// ReleaseLiveFirmwareTarget hands a verified, committed guest over: its NIC
// firewall in force, the hold set to resuming (fsynced), the guest resumed
// through the move's own exempt entry point, and (UEFI) its NVRAM confirmed
// against the source's final NVRAM. It is the only path that resumes a held
// guest. A held guest this host lost (shut off or gone after Verify) is
// handled by row H1 (§7): the source's final NVRAM is pushed only when every
// check proves the guest never ran, and the VM is left stopped here.
//
// A refusal that parks the move on the source is an answer (verdict, detail,
// TargetDomain); an error writes nothing and is retried.
func (s *Server) ReleaseLiveFirmwareTarget(ctx context.Context, req *pb.ReleaseLiveFirmwareTargetRequest) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := safename.ValidateVMName(req.VmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()

	td, err := s.targetDomain(req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: %v", req.VmName, err)
	}
	resp := &pb.ReleaseLiveFirmwareTargetResponse{TargetDomain: td}
	h, held, err := s.fwRecords().GetHold(req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: its firmware move hold on %s cannot be read: %v", req.VmName, s.hostName, err)
	}
	reqBinding := fwmig.Binding{UUID: strings.ToLower(req.Uuid), CreatedAt: req.CreatedAt, Attempt: req.AttemptId}
	if held && !h.Binding.Matches(reqBinding) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: %s holds it for live firmware migration %s from %s (state %s), not for attempt %s",
			req.VmName, s.hostName, h.Attempt, h.Source, h.State, req.AttemptId)
	}
	if held {
		if caller := callerMTLSCommonName(ctx); caller != h.Source {
			return nil, status.Errorf(codes.PermissionDenied,
				"VM %q: the hold of attempt %s is %s's; %s may not release it", h.VM, h.Attempt, h.Source, caller)
		}
	}
	row, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", req.VmName, err)
	}
	// The row names this host for the incarnation: the commit landed.
	rowHere := func(b fwmig.Binding) bool {
		return row != nil && row.HostName == s.hostName &&
			b.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt})
	}
	uefi := held && h.UEFI
	if !held && row != nil {
		uefi = liveFirmwareApplicability(parseFirmwareSpec(row.Spec)).Uefi
	}
	answer := func(v pb.FirmwareVerdict, why string) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		resp.Verdict = v
		resp.Detail = fmt.Sprintf("VM %s: release of attempt %s on %s: %s", req.VmName, req.AttemptId, s.hostName, why)
		slog.Warn("live firmware move: release refused", "vm", req.VmName, "attempt", req.AttemptId, "verdict", v, "detail", resp.Detail)
		return resp, nil
	}

	// 1. The source's final NVRAM hash is what a UEFI guest is confirmed
	// against: empty is a source bug, never "nothing to confirm".
	if uefi && req.SrcNvramSha256 == "" {
		return answer(verdictBadRequest, "the VM keeps a UEFI NVRAM and the request carries no src_nvram_sha256")
	}
	if req.SrcNvramSha256 != "" && !sha256HexRe.MatchString(req.SrcNvramSha256) {
		return answer(verdictBadRequest, fmt.Sprintf("src_nvram_sha256 %q is not a sha256", req.SrcNvramSha256))
	}

	running := td.Present && td.State == "running"
	off := !td.Present || td.State == "shutoff"
	paused := td.Present && td.State == "paused"

	// 2. An idempotent retry of a release that resumed the guest: no hold
	// left, or one left in resuming (a crash between the resume and the next
	// hold write) or released_unconfirmed, with the guest running under the
	// request's uuid and the row naming this host for the request's
	// incarnation.
	if (!held || h.State == fwmig.HoldResuming || h.State == fwmig.HoldReleasedUnconfirmed) && running {
		if !strings.EqualFold(td.Uuid, req.Uuid) || !rowHere(reqBinding) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"VM %q: a guest runs here (uuid %q), and the request's uuid %s and incarnation %s are not both it and the row's (row on %s)",
				req.VmName, td.Uuid, req.Uuid, req.CreatedAt, rowHost(row))
		}
		var hp *fwmig.Hold
		if held {
			hp = &h
		}
		// An adopted copy whose guest runs here (target_ran) is the VM's as
		// it is now: a variable it wrote since the adopt is its own (review
		// m5).
		return s.confirmNvramAs(ctx, resp, req.VmName, hp, uefi, req.SrcNvramSha256, held && h.Adoption != nil)
	}
	if !held {
		resp.Verdict = verdictNotHeld
		resp.Detail = fmt.Sprintf("VM %s: %s holds no live firmware move of attempt %s, and no guest of it runs here (domain %s)",
			req.VmName, s.hostName, req.AttemptId, domainWord(td))
		return resp, nil
	}
	switch h.State {
	case fwmig.HoldReleasedUnconfirmed:
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: it was released here with its NVRAM unconfirmed, and its guest is %s; only an operator action resolves it",
			h.VM, domainWord(td))
	case fwmig.HoldResuming:
		switch {
		case paused:
			// 2a. The resume failed, or did not happen: retry steps 5 and 6.
			if !strings.EqualFold(td.Uuid, h.UUID) || !rowHere(h.Binding) {
				return nil, status.Errorf(codes.FailedPrecondition,
					"VM %q: the paused domain (uuid %q) or the row (on %s) is not the hold's incarnation; it is not resumed",
					h.VM, td.Uuid, rowHost(row))
			}
			return s.resumeReleased(ctx, resp, h, uefi, req.SrcNvramSha256)
		case off:
			// 2b. Lost after the resume began: it may have run. H1 decides.
			return s.releaseH1(ctx, resp, h, row, req, answer)
		default:
			return answer(verdictTargetRan, fmt.Sprintf("its domain is %s here, which only a guest that ran reaches", td.State))
		}
	case fwmig.HoldPrepared, fwmig.HoldVerified:
		if running {
			// 4. Running with the hold not yet resuming: the guard failed.
			return answer(verdictTargetRan, fmt.Sprintf("its domain is running here and the hold is still %s: the guest ran before its release", h.State))
		}
	}
	// 3. Verified, and the commit landed.
	if h.State != fwmig.HoldVerified {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the hold of attempt %s is %s, not verified; it is not released", h.VM, h.Attempt, h.State)
	}
	if !rowHere(h.Binding) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: its row names %s, not %s for this incarnation: the move has not committed, so the guest is not released",
			h.VM, rowHost(row), s.hostName)
	}
	// 4. Paused, the hold's domain.
	switch {
	case off:
		return s.releaseH1(ctx, resp, h, row, req, answer)
	case !paused:
		return answer(verdictTargetRan, fmt.Sprintf("its domain is %s here, which only a guest that ran reaches", td.State))
	case !strings.EqualFold(td.Uuid, h.UUID):
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the paused domain here has uuid %q, not the hold's %s; it is not resumed", h.VM, td.Uuid, h.UUID)
	}
	return s.resumeReleased(ctx, resp, h, uefi, req.SrcNvramSha256)
}

// rowHost is the host a row names, for operator text.
func rowHost(row *corrosion.VMRecord) string {
	if row == nil {
		return "no host (the row is gone)"
	}
	return row.HostName
}

// resumeReleased is §6.6 step 5 then step 6: the NIC firewall in force, the
// hold set to resuming and fsynced BEFORE the resume (so a crash after it is
// recognised as the hand-over it was), the guest resumed through the one
// exempt entry point, and any NIC hand-over record dropped.
func (s *Server) resumeReleased(ctx context.Context, resp *pb.ReleaseLiveFirmwareTargetResponse, h fwmig.Hold, uefi bool, srcNvram string) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
	actx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := s.ArmNICsFor(actx, h.VM)
	cancel()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: its NIC firewall is not in force here, so it is not resumed: %v", h.VM, err)
	}
	if h.State != fwmig.HoldResuming {
		if err := s.putHoldState(h, fwmig.HoldResuming, ""); err != nil {
			return nil, err
		}
		h.State = fwmig.HoldResuming
	}
	if s.virt == nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: no libvirt connection", h.VM)
	}
	// Its NICs' VLANs live on the taps libvirt made here, not in the domain
	// XML: put them on while the guest is still paused.
	s.reapplyVLANTapsOf(ctx, h.VM)
	if err := s.virt.ResumeFirmwareMoveTarget(h.VM, h.UUID, h.Attempt); err != nil {
		return nil, status.Errorf(codes.Internal, "VM %q: resume the held guest (the hold stays resuming, and a retry resumes it): %v", h.VM, err)
	}
	s.endHeld(h.VM, "its live firmware move released it")
	slog.Info("live firmware move: target guest released", "vm", h.VM, "attempt", h.Attempt, "source", h.Source)
	// Once it runs, not while it was held paused: the guest reads the
	// gratuitous ARPs now, so its cached gateway moves to this host's bridge.
	go s.announceGatewaysOf(context.WithoutCancel(ctx), h.VM)
	if td, err := s.targetDomain(h.VM); err == nil {
		resp.TargetDomain = td
	}
	return s.confirmNvram(ctx, resp, h.VM, &h, uefi, srcNvram)
}

// confirmNvram is §6.6 step 6. UEFI: the NVRAM is hashed at once and every
// releaseNvramPollEvery up to releaseNvramPollFor until it equals the
// source's final NVRAM, or the one an operator adopted with the hold. Equal, or not UEFI, removes the hold (h, nil when a
// retry found none). Never equal sets it released_unconfirmed: the guest keeps
// running, and the hold keeps refusing a start and a stop of it until an
// operator resolves it. A caller gone mid-poll writes nothing: the hold stays
// resuming, and a retry (step 2) confirms again.
func (s *Server) confirmNvram(ctx context.Context, resp *pb.ReleaseLiveFirmwareTargetResponse, vm string, h *fwmig.Hold, uefi bool, srcNvram string) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
	return s.confirmNvramAs(ctx, resp, vm, h, uefi, srcNvram, false)
}

// confirmNvramAs is confirmNvram; adoptedLive confirms whatever NVRAM the
// running guest of an adopted hold has now.
func (s *Server) confirmNvramAs(ctx context.Context, resp *pb.ReleaseLiveFirmwareTargetResponse, vm string, h *fwmig.Hold, uefi bool, srcNvram string, adoptedLive bool) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
	confirmed := !uefi
	if uefi {
		deadline := time.Now().Add(releaseNvramPollFor)
		for {
			sum, err := s.fw().NvramSHA256(vm)
			if err == nil {
				resp.NvramSha256 = sum
				if sum == srcNvram || adoptedNvram(h, sum) || adoptedLive {
					confirmed = true
					break
				}
			}
			if !time.Now().Before(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return nil, status.Errorf(codes.Unavailable,
					"VM %q: the release was cancelled while its NVRAM was being confirmed; the guest runs, and a retry confirms it: %v", vm, ctx.Err())
			case <-time.After(releaseNvramPollEvery):
			}
		}
	}
	resp.NvramConfirmed = confirmed
	if confirmed {
		if h != nil {
			if err := s.fwRecords().RemoveHold(vm); err != nil {
				return nil, status.Errorf(codes.Internal, "VM %q: remove the hold of attempt %s after its release: %v", vm, h.Attempt, err)
			}
		}
		slog.Info("live firmware move: target released and confirmed", "vm", vm, "uefi", uefi, "nvram", resp.NvramSha256)
		return resp, nil
	}
	if h != nil && h.State != fwmig.HoldReleasedUnconfirmed {
		if err := s.putHoldState(*h, fwmig.HoldReleasedUnconfirmed, ""); err != nil {
			return nil, err
		}
	}
	resp.Detail = fmt.Sprintf("VM %s: released on %s; its NVRAM is %s, the source's final NVRAM is %s, and they did not become equal within %s. "+
		"The guest keeps running; its hold stays, refusing a start or a stop of it, until an operator confirms or replaces the NVRAM",
		vm, s.hostName, orAbsent(resp.NvramSha256), srcNvram, releaseNvramPollFor)
	slog.Warn("live firmware move: target NVRAM unconfirmed", "vm", vm, "detail", resp.Detail)
	return resp, nil
}

// adoptedNvram: sum is the NVRAM an operator adopted with the hold (`lv
// doctor firmware-move --adopt-target-copy`): the target's copy, which a
// guest that ran there changed since the source's final NVRAM, is then the
// VM's, and is what its release is confirmed against (lab2-D2-proof F4).
func adoptedNvram(h *fwmig.Hold, sum string) bool {
	return h != nil && h.Adoption != nil && h.Adoption.NvramSHA256 != "" && sum == h.Adoption.NvramSHA256
}

func orAbsent(sum string) string {
	if sum == "" {
		return "unreadable"
	}
	return sum
}

// releaseH1 is §7 row H1 (and §6.6 step 2b): the held guest is shut off or
// gone here after Verify. ALL must hold, or the move parks with nothing
// written:
//   - the domain is defined (absent: NOT_RUNNING, held_domain_absent) and is
//     the hold's uuid;
//   - the row names this host for the hold's incarnation;
//   - UEFI: sha256(nvram_final) is src_nvram_sha256;
//   - TPM: the permall re-hash is the verified permall;
//   - UEFI: the target NVRAM is still T0 — never written by a run, the only
//     run detector for a Secure Boot VM without a vTPM.
//
// Then the row is set stopped (the hold still refusing a start), the NVRAM
// pushed through its exempt entry point, and the hold removed (DECISION
// D-10: the VM is left for `lv start`). A crash part-way leaves the hold, and
// a retry redoes the checks: before the push it finds the NVRAM at T0; after
// it, the source's final NVRAM beside the row this H1 wrote.
func (s *Server) releaseH1(ctx context.Context, resp *pb.ReleaseLiveFirmwareTargetResponse, h fwmig.Hold, row *corrosion.VMRecord,
	req *pb.ReleaseLiveFirmwareTargetRequest, answer func(pb.FirmwareVerdict, string) (*pb.ReleaseLiveFirmwareTargetResponse, error)) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
	td := resp.TargetDomain
	if !td.Present {
		return answer(verdictNotRunning, fmt.Sprintf("held_domain_absent: the held domain of attempt %s (hold %s) is gone here; its firmware state and hold are kept", h.Attempt, h.State))
	}
	ran := func(why string) (*pb.ReleaseLiveFirmwareTargetResponse, error) {
		return answer(verdictTargetRan, fmt.Sprintf("the held guest is shut off here (hold %s), and %s; nothing was written, and the hold is kept", h.State, why))
	}
	if !strings.EqualFold(td.Uuid, h.UUID) {
		return ran(fmt.Sprintf("the shut-off domain has uuid %q, not the hold's %s", td.Uuid, h.UUID))
	}
	if row == nil || row.HostName != s.hostName ||
		!h.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		return ran(fmt.Sprintf("the VM's row names %s, not %s for this incarnation", rowHost(row), s.hostName))
	}
	if h.UEFI {
		if len(req.NvramFinal) == 0 {
			return ran("the request carries no nvram_final")
		}
		if got := fwBytesSHA256(req.NvramFinal); got != req.SrcNvramSha256 {
			return ran(fmt.Sprintf("nvram_final hashes to %s, not src_nvram_sha256 %s", got, req.SrcNvramSha256))
		}
	}
	fw := s.fw()
	if h.TPM {
		got, err := fw.PermallSHA256(h.UUID)
		if err != nil {
			return ran(fmt.Sprintf("its permall cannot be hashed: %v", err))
		}
		if h.VerifiedPermallSHA256 == "" || got != h.VerifiedPermallSHA256 {
			return ran(fmt.Sprintf("its permall is %s, not the verified %s: the guest's TPM was written after Verify", got, orAbsent(h.VerifiedPermallSHA256)))
		}
	}
	if h.UEFI {
		got, err := fw.NvramSHA256(h.VM)
		if err != nil {
			return ran(fmt.Sprintf("its NVRAM cannot be hashed: %v", err))
		}
		switch {
		case h.NvramT0SHA256 != "" && got == h.NvramT0SHA256:
		case got == req.SrcNvramSha256 && row.State == "stopped" && row.StateDetail == h1StoppedDetail(s.hostName):
			// An earlier H1 of this hold recorded the VM stopped here, pushed
			// this NVRAM, and stopped before removing the hold. It wrote the
			// row only after these checks passed with the NVRAM at T0, and
			// since then the hold refused every start, so the guest has not
			// run. (Without that row, the source's final NVRAM is what a
			// resume writes: a run.)
		default:
			return ran(fmt.Sprintf("its NVRAM is %s, not the %s Prepare materialised: the guest wrote it, so it ran", got, orAbsent(h.NvramT0SHA256)))
		}
	}
	if err := corrosion.UpdateVMStateAtEpoch(ctx, s.db, h.VM, "stopped", h1StoppedDetail(s.hostName), row.OwnerEpoch); err != nil {
		return nil, status.Errorf(codes.Internal, "VM %q: record it stopped here: %v", h.VM, err)
	}
	if h.UEFI {
		if err := fw.PushFirmwareMoveNvram(h.VM, h.UUID, h.Attempt, req.NvramFinal); err != nil {
			return nil, status.Errorf(codes.Internal, "VM %q: push the source's final NVRAM: %v", h.VM, err)
		}
		resp.NvramSha256 = req.SrcNvramSha256
	}
	if err := s.fwRecords().RemoveHold(h.VM); err != nil {
		return nil, status.Errorf(codes.Internal, "VM %q: remove the hold of attempt %s: %v", h.VM, h.Attempt, err)
	}
	resp.NvramConfirmed = true
	resp.Detail = fmt.Sprintf("VM %s: the held guest of attempt %s was shut off on %s before its release and never ran; "+
		"its verified TPM state is kept, the source's final NVRAM was written, and the VM is stopped here for `lv start`", h.VM, h.Attempt, s.hostName)
	slog.Warn("live firmware move: held guest found shut off; firmware handed over, VM left stopped", "vm", h.VM, "attempt", h.Attempt, "source", h.Source)
	return resp, nil
}

// h1StoppedDetail is the row detail H1 records for a VM it left stopped on
// host (DECISION D-10).
func h1StoppedDetail(host string) string {
	return fmt.Sprintf("stopped on %s before release; firmware verified; `lv start`", host)
}

func fwBytesSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
