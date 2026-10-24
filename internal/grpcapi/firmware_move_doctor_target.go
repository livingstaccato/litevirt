package grpcapi

// The target's part of `lv doctor firmware-move` (spec §17 D-5): the ops its
// source asks for (FirmwareMoveDoctorTarget, the hold's source only, as
// Abort), and the actions an operator takes on the target itself once the
// source holds no marker of the move (its host lost, or only an owed DISCARD
// left there). Every op runs under firmwareTargets.op, as the move's own
// target steps do.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/safename"
)

// FirmwareMoveDoctorTarget is a target op of the doctor, from the move's
// source. It binds to the hold (uuid, created_at, attempt), and only the
// hold's source may ask; CONFIRM_NVRAM also answers with no hold left, from
// the row and the domain (D2-10: the hold may be gone).
func (s *Server) FirmwareMoveDoctorTarget(ctx context.Context, req *pb.FirmwareMoveDoctorTargetRequest) (*pb.FirmwareMoveDoctorTargetResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := safename.ValidateVMName(req.GetVmName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()

	b := fwmig.Binding{UUID: strings.ToLower(req.GetUuid()), CreatedAt: req.GetCreatedAt(), Attempt: req.GetAttemptId()}
	h, held, err := s.fwRecords().GetHold(req.GetVmName())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: its firmware move hold on %s cannot be read: %v", req.GetVmName(), s.hostName, err)
	}
	if held && !h.Binding.Matches(b) {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: %s holds it for live firmware migration %s from %s (state %s), not for attempt %s",
			req.GetVmName(), s.hostName, h.Attempt, h.Source, h.State, req.GetAttemptId())
	}
	if held {
		if caller := callerMTLSCommonName(ctx); caller != h.Source {
			return nil, status.Errorf(codes.PermissionDenied, "VM %q: the hold of attempt %s is %s's; %s may not act on it", h.VM, h.Attempt, h.Source, caller)
		}
	}
	var hp *fwmig.Hold
	if held {
		hp = &h
	}
	switch req.GetOp() {
	case pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_CONFIRM_NVRAM:
		if err := s.confirmTargetNvramForOperator(ctx, req.GetVmName(), hp, b, req.GetAcceptNvramHash()); err != nil {
			return nil, err
		}
	case pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_STOP,
		pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_ADOPT,
		pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_PUSH_NVRAM:
		if !held {
			return nil, status.Errorf(codes.FailedPrecondition, "VM %q: %s holds no live firmware move of attempt %s; a domain or state not under the move's hold is not touched",
				req.GetVmName(), s.hostName, req.GetAttemptId())
		}
		switch req.GetOp() {
		case pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_STOP:
			err = s.stopHeldGuestForOperator(h)
		case pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_ADOPT:
			_, err = s.adoptHold(h, req.GetOperator(), req.GetReason())
		default:
			err = s.pushSourceNvramForOperator(ctx, h, req.GetNvram(), req.GetSrcNvramSha256(), req.GetAcknowledgeRollback())
		}
		if err != nil {
			return nil, err
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "firmware-move target op %v is not one this host acts on", req.GetOp())
	}
	resp := &pb.FirmwareMoveDoctorTargetResponse{}
	if td, err := s.targetDomain(req.GetVmName()); err == nil {
		resp.TargetDomain = td
	}
	if cur, ok, err := s.fwRecords().GetHold(req.GetVmName()); err == nil && ok {
		resp.HoldState, resp.NvramT0Sha256 = string(cur.State), cur.NvramT0SHA256
	}
	fw := s.fw()
	if sum, err := fw.PermallSHA256(b.UUID); err == nil {
		resp.PermallSha256 = sum
	}
	if sum, err := fw.NvramSHA256(req.GetVmName()); err == nil {
		resp.NvramSha256 = sum
	}
	slog.Warn("firmware-move doctor: target op", "vm", req.GetVmName(), "attempt", req.GetAttemptId(), "op", req.GetOp(), "hold", resp.HoldState)
	return resp, nil
}

// stopHeldGuestForOperator is --stop-target: the held guest stopped through
// its own entry point (destroyed when paused, which no ACPI shutdown reaches;
// shut down otherwise), and waited for until it is shut off. The caller holds
// firmwareTargets.op.
func (s *Server) stopHeldGuestForOperator(h fwmig.Hold) error {
	td, err := s.targetDomain(h.VM)
	if err != nil {
		return status.Errorf(codes.Unavailable, "VM %q: %v", h.VM, err)
	}
	if !td.Present || td.State == "shutoff" {
		return nil
	}
	if s.virt == nil {
		return status.Errorf(codes.Unavailable, "VM %q: no libvirt connection", h.VM)
	}
	if err := s.virt.StopFirmwareMoveTargetForOperator(h.VM, h.UUID, h.Attempt, td.State == "paused"); err != nil {
		return status.Errorf(codes.FailedPrecondition, "VM %q: stop the held guest on %s: %v", h.VM, s.hostName, err)
	}
	deadline := time.Now().Add(fwDoctorStopWait)
	for {
		active, err := s.virt.DomainIsActive(h.VM)
		if lv.IsNoDomain(err) || (err == nil && !active) {
			slog.Warn("firmware-move doctor: held guest stopped", "vm", h.VM, "attempt", h.Attempt, "was", td.State)
			return nil
		}
		if !time.Now().Before(deadline) {
			return status.Errorf(codes.FailedPrecondition, "VM %q: the held guest on %s did not shut off within %s; its hold stays; run the action again",
				h.VM, s.hostName, fwDoctorStopWait)
		}
		time.Sleep(fwDoctorStopPoll)
	}
}

// adoptHold is the hold transition of --adopt-target-copy (spec §17 D-5): a
// paused guest's hold goes to verified, its verified permall the one here now;
// a running guest's (target_ran) to resuming, so Release's retry completes the
// hand-over. The operator, the reason and the hashes are recorded in the
// hold. The caller holds firmwareTargets.op.
func (s *Server) adoptHold(h fwmig.Hold, operator, reason string) (fwmig.Hold, error) {
	td, err := s.targetDomain(h.VM)
	if err != nil {
		return h, status.Errorf(codes.Unavailable, "VM %q: %v", h.VM, err)
	}
	refuse := func(why string) (fwmig.Hold, error) {
		return h, status.Errorf(codes.FailedPrecondition, "VM %q: the target's copy of attempt %s (hold %s, domain %s) is not adopted: %s",
			h.VM, h.Attempt, h.State, domainWord(td), why)
	}
	if td.Present && !strings.EqualFold(td.Uuid, h.UUID) {
		return refuse(fmt.Sprintf("the domain here has uuid %q, not the hold's %s", td.Uuid, h.UUID))
	}
	var next fwmig.HoldState
	switch {
	case td.State == "paused" && (h.State == fwmig.HoldPrepared || h.State == fwmig.HoldMismatch || h.State == fwmig.HoldVerified):
		next = fwmig.HoldVerified
	case td.State == "running" && (h.State == fwmig.HoldPrepared || h.State == fwmig.HoldMismatch || h.State == fwmig.HoldVerified || h.State == fwmig.HoldResuming):
		next = fwmig.HoldResuming
	default:
		return refuse("an adopted copy must be a guest paused or running here under a hold that has not been released")
	}
	if h.UEFI && h.NvramMaterialised != fwmig.NvramDone {
		return refuse("its Prepare never finished materialising the NVRAM")
	}
	fw := s.fw()
	permall, nvram := "", ""
	if h.TPM {
		if permall, err = fw.PermallSHA256(h.UUID); err != nil {
			return refuse(fmt.Sprintf("its TPM state cannot be read: %v", err))
		}
	}
	if h.UEFI {
		if nvram, err = fw.NvramSHA256(h.VM); err != nil {
			return refuse(fmt.Sprintf("its NVRAM cannot be read: %v", err))
		}
	}
	if operator == "" {
		operator = "unknown"
	}
	a := &fwmig.HoldAdoption{By: operator, At: time.Now().UTC(), From: h.State, Reason: reason, PermallSHA256: permall, NvramSHA256: nvram}
	h2 := h
	h2.State, h2.Adoption = next, a
	if next == fwmig.HoldVerified {
		h2.VerifiedPermallSHA256 = permall
	}
	if err := s.fwRecords().PutHold(h2); err != nil {
		return h, status.Errorf(codes.Internal, "VM %q: record the adoption: %v", h.VM, err)
	}
	slog.Warn("firmware-move doctor: the target's copy was adopted", "vm", h.VM, "attempt", h.Attempt, "from", h.State, "to", next, "by", operator)
	return h2, nil
}

// confirmTargetNvramForOperator is --confirm-target-nvram on the target: the
// NVRAM here must hash to hash now; then a released_unconfirmed hold is
// removed. With no hold left (D2-10), the row must name this host for the
// incarnation and the domain here be its uuid: there is nothing to remove,
// and the answer says the NVRAM is the one accepted.
func (s *Server) confirmTargetNvramForOperator(ctx context.Context, vm string, h *fwmig.Hold, b fwmig.Binding, hash string) error {
	if !sha256HexRe.MatchString(hash) {
		return status.Errorf(codes.InvalidArgument, "VM %q: %q is not a sha256 (64 lowercase hex)", vm, hash)
	}
	cur, err := s.fw().NvramSHA256(vm)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "VM %q: its NVRAM on %s cannot be read: %v", vm, s.hostName, err)
	}
	if cur != hash {
		return status.Errorf(codes.FailedPrecondition, "VM %q: its NVRAM on %s is %s now, not %s; confirm the hash it has now", vm, s.hostName, cur, hash)
	}
	if h != nil {
		if h.State != fwmig.HoldReleasedUnconfirmed {
			return status.Errorf(codes.FailedPrecondition, "VM %q: the hold of attempt %s is %s, not released_unconfirmed", vm, h.Attempt, h.State)
		}
		if err := s.fwRecords().RemoveHold(vm); err != nil {
			return status.Errorf(codes.Internal, "VM %q: remove the hold of attempt %s: %v", vm, h.Attempt, err)
		}
		slog.Warn("firmware-move doctor: the target's NVRAM was confirmed; hold removed", "vm", vm, "attempt", h.Attempt, "nvram", hash)
		return nil
	}
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", vm, err)
	}
	if row == nil || row.HostName != s.hostName || !b.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		return status.Errorf(codes.FailedPrecondition, "VM %q: no hold here, and its row (on %s) does not name %s for the move's incarnation", vm, rowHost(row), s.hostName)
	}
	td, err := s.targetDomain(vm)
	if err != nil {
		return status.Errorf(codes.Unavailable, "VM %q: %v", vm, err)
	}
	if !td.Present || !strings.EqualFold(td.Uuid, b.UUID) {
		return status.Errorf(codes.FailedPrecondition, "VM %q: no hold here, and no domain of uuid %s (domain %s)", vm, b.UUID, domainWord(td))
	}
	return nil
}

// pushSourceNvramForOperator is --push-source-nvram on the target:
//   - released_unconfirmed (N1): the guest must not run (checked here, under
//     the lock: the store's entry point cannot), the operator acknowledged
//     it, and the pushed NVRAM is the source's final one; then the hold goes;
//   - verified or resuming with no domain (held_domain_absent, H1 after the
//     commit): H1's checks without "domain defined" — the row names this
//     host for the incarnation, the permall is the verified one, the NVRAM
//     still T0, the pushed NVRAM the source's final one; the row stopped
//     here, the NVRAM pushed through H1's own entry point, the hold removed.
//
// The caller holds firmwareTargets.op.
func (s *Server) pushSourceNvramForOperator(ctx context.Context, h fwmig.Hold, nvram []byte, srcHash string, ack bool) error {
	td, err := s.targetDomain(h.VM)
	if err != nil {
		return status.Errorf(codes.Unavailable, "VM %q: %v", h.VM, err)
	}
	refuse := func(why string) error {
		return status.Errorf(codes.FailedPrecondition, "VM %q: the source's NVRAM is not pushed to %s (hold %s, domain %s): %s",
			h.VM, s.hostName, h.State, domainWord(td), why)
	}
	if h.UEFI && (len(nvram) == 0 || fwBytesSHA256(nvram) != srcHash) {
		return refuse(fmt.Sprintf("the pushed NVRAM hashes to %s, not the source's final %s", fwBytesSHA256(nvram), orNone(srcHash)))
	}
	fw := s.fw()
	switch h.State {
	case fwmig.HoldReleasedUnconfirmed:
		if !ack {
			return refuse("it needs --acknowledge-rollback")
		}
		if td.Present && td.State != "shutoff" {
			return refuse("its guest is not powered off: add --stop-target")
		}
		if h.UEFI {
			if err := fw.PushSourceNvramForOperator(h.VM, h.UUID, h.Attempt, nvram); err != nil {
				return status.Errorf(codes.Internal, "VM %q: push the NVRAM: %v", h.VM, err)
			}
		}
	case fwmig.HoldVerified, fwmig.HoldResuming:
		if td.Present {
			return refuse("its domain is defined here: Release handles a held guest it finds")
		}
		row, err := corrosion.GetVM(ctx, s.db, h.VM)
		if err != nil {
			return status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", h.VM, err)
		}
		if row == nil || row.HostName != s.hostName ||
			!h.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
			return refuse(fmt.Sprintf("the VM's row names %s, not %s for this incarnation", rowHost(row), s.hostName))
		}
		if h.TPM {
			got, err := fw.PermallSHA256(h.UUID)
			if err != nil || h.VerifiedPermallSHA256 == "" || got != h.VerifiedPermallSHA256 {
				return refuse(fmt.Sprintf("its permall is %s (%v), not the verified %s", orAbsent(got), err, orAbsent(h.VerifiedPermallSHA256)))
			}
		}
		if h.UEFI {
			got, err := fw.NvramSHA256(h.VM)
			if err != nil {
				return refuse(fmt.Sprintf("its NVRAM cannot be hashed: %v", err))
			}
			stopped := row.State == "stopped" && row.StateDetail == h1StoppedDetail(s.hostName)
			if !(h.NvramT0SHA256 != "" && got == h.NvramT0SHA256) && !(got == srcHash && stopped) {
				return refuse(fmt.Sprintf("its NVRAM is %s, not the %s Prepare materialised: the guest wrote it", got, orAbsent(h.NvramT0SHA256)))
			}
		}
		if err := corrosion.UpdateVMStateAtEpoch(ctx, s.db, h.VM, "stopped", h1StoppedDetail(s.hostName), row.OwnerEpoch); err != nil {
			return status.Errorf(codes.Internal, "VM %q: record it stopped here: %v", h.VM, err)
		}
		if h.UEFI {
			if err := fw.PushFirmwareMoveNvram(h.VM, h.UUID, h.Attempt, nvram); err != nil {
				return status.Errorf(codes.Internal, "VM %q: push the source's final NVRAM: %v", h.VM, err)
			}
		}
	default:
		return refuse("it takes a hold released_unconfirmed, or verified with its domain gone")
	}
	if err := s.fwRecords().RemoveHold(h.VM); err != nil {
		return status.Errorf(codes.Internal, "VM %q: remove the hold of attempt %s: %v", h.VM, h.Attempt, err)
	}
	slog.Warn("firmware-move doctor: the source's NVRAM was pushed; hold removed", "vm", h.VM, "attempt", h.Attempt, "was", h.State)
	return nil
}

// ── Actions on the target itself ──

// doctorTargetLocalAct is an action on this host's hold when no marker of the
// move is left on the source (spec §17 D-5, "target hold, no source marker"
// and the refused owed DISCARD): --discard-target, --adopt-target-copy (the
// source host proved off) and --confirm-target-nvram.
func (s *Server) doctorTargetLocalAct(ctx context.Context, h fwmig.Hold, req *pb.FirmwareMoveDoctorRequest, actor string) (string, error) {
	a := req.GetAction()
	refuse := func(why string) (string, error) {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: %s holds it for live firmware migration %s from %s (state %s); %s does not resolve it here: %s",
			h.VM, s.hostName, h.Attempt, h.Source, h.State, fwDoctorFlagOf(a), why)
	}
	switch a {
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET,
		pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY,
		pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM:
	default:
		return refuse(fmt.Sprintf("it acts on the move's source, which must answer with the move's marker (%s)", h.Source))
	}
	off, err := corrosion.HostProvedOff(ctx, s.db, h.Source)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: whether %s is proved off cannot be read: %v", h.VM, h.Source, err)
	}
	// sourceOwes: the source answered and holds an owed DISCARD of this
	// attempt, so the VM's current copy is the source's (the refused owed
	// discard row), and only then may --stop-target stop a held guest here.
	sourceOwes := false
	if !off {
		if a == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY {
			return refuse(fmt.Sprintf("the source %s is not proved off: once it is powered off, `lv host fence-confirm %s`", h.Source, h.Source))
		}
		sr, err := s.inspectFirmwareMoveHost(ctx, h.Source, h.VM)
		if err != nil {
			return refuse(fmt.Sprintf("the source %s does not answer (%v) and is not proved off: once it is powered off, `lv host fence-confirm %s`", h.Source, err, h.Source))
		}
		if m := markerOf(sr); m != nil && m.Attempt == h.Attempt {
			return refuse(fmt.Sprintf("the source %s holds the move's marker (%s); the action runs there", h.Source, fwDescribe(*m)))
		}
		sourceOwes = owesDiscard(sr, h.VM, h.Binding)
	}
	switch a {
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET:
		return s.doctorTargetLocalDiscard(ctx, h, req.GetStopTarget(), sourceOwes)
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY:
		return s.doctorTargetLocalAdopt(ctx, h, actor)
	default:
		s.firmwareTargets.op.Lock()
		defer s.firmwareTargets.op.Unlock()
		cur, ok, err := s.fwRecords().GetHoldFor(h.VM, h.Binding)
		if err != nil || !ok {
			return refuse(fmt.Sprintf("the hold changed under the action (%v)", err))
		}
		if err := s.confirmTargetNvramForOperator(ctx, h.VM, &cur, h.Binding, req.GetAcceptNvramHash()); err != nil {
			return "", err
		}
		return fmt.Sprintf("VM %q: the NVRAM on %s was confirmed by an operator and the hold of attempt %s removed", h.VM, s.hostName, h.Attempt), nil
	}
}

// owesDiscard reports whether a host's records carry an owed DISCARD of b's
// attempt of vm.
func owesDiscard(r *pb.FirmwareMoveHostRecords, vm string, b fwmig.Binding) bool {
	for _, j := range r.GetOwedDiscards() {
		var o fwmig.OwedDiscard
		if json.Unmarshal([]byte(j), &o) == nil && o.VM == vm && o.Binding.Matches(b) {
			return true
		}
	}
	return false
}

// doctorTargetLocalDiscard is --discard-target on the target: the VM's row
// does not name this host for the hold's incarnation, so the held copy is
// not the VM's; the domain goes (its state kept) and the state is
// quarantined. Nothing is deleted. A held guest that runs is stopped
// (--stop-target) only in the refused owed DISCARD row, where the source
// answered with the owed record: with the source lost, a guest that runs may
// be the only copy, and is never stopped here.
func (s *Server) doctorTargetLocalDiscard(ctx context.Context, h fwmig.Hold, stop, sourceOwes bool) (string, error) {
	row, err := corrosion.GetVM(ctx, s.db, h.VM)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", h.VM, err)
	}
	if row != nil && row.HostName == s.hostName &&
		h.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		return "", status.Errorf(codes.FailedPrecondition,
			"VM %q: its row names %s for the hold's incarnation: the held guest is the VM's own copy, and --discard-target does not drop it", h.VM, s.hostName)
	}
	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()
	cur, ok, err := s.fwRecords().GetHoldFor(h.VM, h.Binding)
	if err != nil || !ok {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: the hold of attempt %s changed under the action (%v)", h.VM, h.Attempt, err)
	}
	td, err := s.targetDomain(h.VM)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: %v", h.VM, err)
	}
	if td.Present && td.State != "shutoff" && td.State != "paused" {
		if !sourceOwes {
			return "", status.Errorf(codes.FailedPrecondition,
				"VM %q: its held guest is %s on %s, and %s holds no owed DISCARD of attempt %s: that guest may be the only copy of the VM, and it is not stopped",
				h.VM, td.State, s.hostName, h.Source, h.Attempt)
		}
		if !stop {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: its held guest is %s on %s: add --stop-target", h.VM, td.State, s.hostName)
		}
		if err := s.stopHeldGuestForOperator(cur); err != nil {
			return "", err
		}
	}
	if s.virt == nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: no libvirt connection", h.VM)
	}
	if err := s.virt.DiscardFirmwareMoveTarget(cur.VM, cur.UUID, cur.Attempt); err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: discard the held domain: %v", h.VM, err)
	}
	dir, err := s.quarantineHold(ctx, cur, "an operator discarded it (lv doctor firmware-move --discard-target)")
	if err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: %v", h.VM, err)
	}
	_ = s.resolveFirmwareMigrationCondition(ctx, condFwmigHeld, h.VM)
	return fmt.Sprintf("VM %q: the held copy of attempt %s on %s is quarantined in %s; nothing was deleted", h.VM, h.Attempt, s.hostName, dir), nil
}

// doctorTargetLocalAdopt is --adopt-target-copy on the target with the
// source host proved off: the paused guest's hold to verified, the commit
// written here (the row naming the lost source for the hold's incarnation),
// and the guest released through Release's own resume, its NVRAM confirmed
// against itself (the source's final NVRAM is gone with the host).
func (s *Server) doctorTargetLocalAdopt(ctx context.Context, h fwmig.Hold, actor string) (string, error) {
	row, err := corrosion.GetVM(ctx, s.db, h.VM)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", h.VM, err)
	}
	if row == nil || !h.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) ||
		(row.HostName != h.Source && row.HostName != s.hostName) {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: its row (on %s) does not name %s or %s for the hold's incarnation", h.VM, rowHost(row), h.Source, s.hostName)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, h.VM)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: its disks cannot be read: %v", h.VM, err)
	}
	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()
	cur, ok, err := s.fwRecords().GetHoldFor(h.VM, h.Binding)
	if err != nil || !ok {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: the hold of attempt %s changed under the action (%v)", h.VM, h.Attempt, err)
	}
	td, err := s.targetDomain(h.VM)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: %v", h.VM, err)
	}
	// An earlier run's resume landed: the hold resuming (or
	// released_unconfirmed) with its guest running here, and the row on this
	// host. It is taken up from there.
	landed := td.Present && td.State == "running" && strings.EqualFold(td.Uuid, cur.UUID) && row.HostName == s.hostName &&
		(cur.State == fwmig.HoldResuming || cur.State == fwmig.HoldReleasedUnconfirmed)
	if td.State != "paused" && !landed {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: its held domain on %s is %s; an adopted copy without its source must be paused here", h.VM, s.hostName, domainWord(td))
	}
	adopted := cur
	if cur.State != fwmig.HoldResuming && cur.State != fwmig.HoldReleasedUnconfirmed {
		// A resuming hold is an earlier run's adoption whose resume failed
		// or landed.
		if adopted, err = s.adoptHold(cur, actor, fmt.Sprintf("the source %s is proved off and holds no marker", h.Source)); err != nil {
			return "", err
		}
	}
	if row.HostName == h.Source {
		// The row says migrating until the guest runs here; the commit
		// moves it and its disks to this host.
		ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, h.VM, h.Source, s.hostName, "migrating", disks)
		if err != nil || !ok {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: the hold is adopted (verified), and the commit from %s to %s did not land (ok %v, %v); run this again",
				h.VM, h.Source, s.hostName, ok, err)
		}
	}
	did := fmt.Sprintf("an operator adopted the held copy of attempt %s from %s, which is proved off", h.Attempt, h.Source)
	confirmed, err := s.releaseAdoptedHold(ctx, adopted, td.State == "paused", did)
	if err != nil {
		return "", err
	}
	s.recordVMEvent(ctx, h.VM, "vm.migrate.firmware", "ok", did)
	return fmt.Sprintf("VM %q: the held copy of attempt %s was adopted by %s, committed to %s and released (NVRAM confirmed %v)",
		h.VM, h.Attempt, actor, s.hostName, confirmed), nil
}

// fwDoctorAdoptHook, when set, runs at each step of releaseAdoptedHold
// ("resumed", "published"); an error ends the action there, as a crash
// would. Test-only.
var fwDoctorAdoptHook func(step string) error

// releaseAdoptedHold releases an adopted hold on a target whose source is
// lost: the NIC firewall in force, the guest resumed (unless an earlier run
// resumed it), its NVRAM confirmed against the adopted copy's, the row
// published running, the network converged, the missing VFs named, and only
// then the hold removed (or left released_unconfirmed). Each step is taken up
// again by a rerun: the hold stays until the row says running. The caller
// holds firmwareTargets.op.
func (s *Server) releaseAdoptedHold(ctx context.Context, h fwmig.Hold, resume bool, did string) (bool, error) {
	ctx = context.WithoutCancel(ctx)
	if s.virt == nil {
		return false, status.Errorf(codes.Unavailable, "VM %q: no libvirt connection", h.VM)
	}
	want := ""
	if h.Adoption != nil {
		want = h.Adoption.NvramSHA256
	}
	if want == "" {
		want, _ = s.fw().NvramSHA256(h.VM)
	}
	if resume {
		if err := s.readyGuestHere(ctx, h.VM, arrivedHere); err != nil {
			return false, status.Errorf(codes.FailedPrecondition, "VM %q: its NIC firewall or NIC VLANs are not in force here, so it is not resumed: %v", h.VM, err)
		}
		if h.State != fwmig.HoldResuming {
			if err := s.putHoldState(h, fwmig.HoldResuming, ""); err != nil {
				return false, err
			}
			h.State = fwmig.HoldResuming
		}
		if err := s.virt.ResumeFirmwareMoveTarget(h.VM, h.UUID, h.Attempt); err != nil {
			return false, status.Errorf(codes.Internal, "VM %q: resume the adopted guest (the hold stays resuming, and a rerun resumes it): %v", h.VM, err)
		}
		s.endHeld(h.VM, "an operator adopted it")
		if hk := fwDoctorAdoptHook; hk != nil {
			if err := hk("resumed"); err != nil {
				return false, err
			}
		}
	}
	confirmed := h.State == fwmig.HoldReleasedUnconfirmed
	if !confirmed {
		resp, err := s.confirmNvram(ctx, &pb.ReleaseLiveFirmwareTargetResponse{}, h.VM, nil, h.UEFI, want)
		if err != nil {
			return false, err
		}
		confirmed = resp.GetNvramConfirmed()
	}
	if err := s.publishRunning(ctx, h.VM, "running", func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, s.db, h.VM, "running", did)
	}); err != nil {
		s.noteStateWriteFail(corrosion.OpVMState, err)
		return false, status.Errorf(codes.Unavailable, "VM %q: the adopted guest runs on %s, and its row is not yet running (%v); its hold stays; run this again", h.VM, s.hostName, err)
	}
	if hk := fwDoctorAdoptHook; hk != nil {
		if err := hk("published"); err != nil {
			return false, err
		}
	}
	if cur, err := corrosion.GetVM(ctx, s.db, h.VM); err == nil && cur != nil {
		s.convergeMovedGuest(ctx, cur, h.Source, s.hostName, true)
	}
	s.noteAdoptedVFsMissing(ctx, h)
	switch {
	case confirmed && h.State != fwmig.HoldReleasedUnconfirmed:
		if err := s.fwRecords().RemoveHold(h.VM); err != nil {
			return false, status.Errorf(codes.Internal, "VM %q: remove the adopted hold of attempt %s: %v; run this again", h.VM, h.Attempt, err)
		}
	case !confirmed:
		if err := s.putHoldState(h, fwmig.HoldReleasedUnconfirmed, ""); err != nil {
			return false, err
		}
	}
	return confirmed && h.State != fwmig.HoldReleasedUnconfirmed, nil
}

// noteAdoptedVFsMissing raises firmware_migration_vf_missing for the SR-IOV
// VFs the VM's spec asks for: the move detached them on the lost source, and
// nothing allocated equivalents here. It names the source's network-function
// rows the VM held there that are not themselves SR-IOV capable (its VFs).
func (s *Server) noteAdoptedVFsMissing(ctx context.Context, h fwmig.Hold) {
	row, err := corrosion.GetVM(ctx, s.db, h.VM)
	if err != nil || row == nil {
		return
	}
	wanted := 0
	for _, d := range parseVMSpecBlob(row.Spec).GetDevices() {
		if kind, _ := corrosion.ClassifyPCISelector(d); kind == "sriov" {
			n := int(d.GetCount())
			if n == 0 {
				n = 1
			}
			wanted += n
		}
	}
	if wanted == 0 {
		return
	}
	devs, err := corrosion.ListPCIDevices(ctx, s.db, h.Source, "")
	if err != nil {
		slog.Warn("firmware-move doctor: the lost source's devices cannot be listed", "vm", h.VM, "error", err)
	}
	var vfs []string
	for _, d := range devs {
		if d.VMName == h.VM && d.Type == "network" && !d.SRIOVCapable {
			vfs = append(vfs, d.Address)
		}
	}
	on := ""
	if len(vfs) > 0 {
		on = " (" + strings.Join(vfs, ", ") + " on " + h.Source + ")"
	}
	if err := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
		Code: condFwmigVFMissing, VM: h.VM, Attempt: h.Attempt, Source: h.Source, Target: s.hostName,
		RunsOn: s.hostName, VFs: vfs, VFsWanted: wanted,
		Detail: fmt.Sprintf("the adopted guest runs on %s without the %d SR-IOV VF(s) its spec asks for%s", s.hostName, wanted, on),
		Action: fmt.Sprintf("attach %d SR-IOV VF(s) to the guest on %s, or restart it there so its devices are allocated again", wanted, s.hostName),
	}); err != nil {
		slog.Warn("firmware-move doctor: raise the condition", "vm", h.VM, "code", condFwmigVFMissing, "error", err)
	}
}

// doctorDiscardOwedLeftover is --discard-target on a target that holds no
// hold of the VM, while another host owes this one a DISCARD of it (the hold
// went with a release, and the source took the VM back after the commit). The
// owing host answered with the owed record, or, when none owes it any more,
// this host's leftover record stands in for it (a guest that runs is then
// never stopped). The VM's row does not name this host for the owed
// incarnation; the domain here has the owed uuid. Under
// firmwareTargets.op: the leftover record is written first (the guard and the
// reconciler then leave the domain alone), a guest that runs is stopped
// (--stop-target), the swtpm tree and NVRAM go into
// <data_dir>/fwmig-quarantine/<vm>-<attempt>/, the domain is undefined keeping
// its state, and the record goes. Nothing is deleted. A rerun takes up where
// one stopped.
func (s *Server) doctorDiscardOwedLeftover(ctx context.Context, vm, actor string, stop bool) (string, error) {
	report := s.gatherFirmwareMoveRecords(ctx, vm, actor)
	var (
		o     fwmig.OwedDiscard
		owner string
		found bool
	)
	for _, h := range report.GetHosts() {
		if h.GetHost() == s.hostName {
			continue
		}
		for _, j := range h.GetOwedDiscards() {
			var x fwmig.OwedDiscard
			if json.Unmarshal([]byte(j), &x) == nil && x.VM == vm && x.Target == s.hostName {
				o, owner, found = x, h.GetHost(), true
			}
		}
	}
	// localOnly: no host that answered owes the DISCARD any more, and this
	// host's own leftover record is the authority; a running guest is never
	// stopped on it.
	localOnly := false
	if !found {
		l, ok, err := s.fwRecords().GetLeftover(vm)
		if err != nil {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: its leftover record on %s cannot be read: %v", vm, s.hostName, err)
		}
		if !ok {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: no move record names it on %s, and no host that answered owes %s a DISCARD of it", vm, s.hostName, s.hostName)
		}
		o, owner, localOnly = fwmig.OwedDiscard{VM: vm, Binding: l.Binding, Target: s.hostName, Since: l.Since}, l.Source, true
	}
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", vm, err)
	}
	if row != nil && row.HostName == s.hostName && o.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: its row names %s for the owed incarnation: the domain here is the VM's own, and it is not discarded",
			vm, s.hostName)
	}
	if s.virt == nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: no libvirt connection", vm)
	}
	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()
	recs := s.fwRecords()
	if _, ok, err := recs.GetHold(vm); err != nil || ok {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: a hold appeared on %s under the action (%v); run this again", vm, s.hostName, err)
	}
	td, err := s.targetDomain(vm)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: %v", vm, err)
	}
	if td.Present && !strings.EqualFold(td.Uuid, o.UUID) {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: the domain here has uuid %q, not the owed incarnation's %s; it is not touched", vm, td.Uuid, o.UUID)
	}
	if err := s.putOwedLeftover(o, owner); err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: record the leftover of attempt %s: %v", vm, o.Attempt, err)
	}
	if td.Present && td.State != "shutoff" {
		if localOnly {
			return "", status.Errorf(codes.FailedPrecondition,
				"VM %q: its leftover domain on %s is %s, and no host that answered owes a DISCARD of it any more; it is kept under its leftover record, and only a guest that is shut off is discarded on that record alone",
				vm, s.hostName, td.State)
		}
		if !stop {
			return "", status.Errorf(codes.FailedPrecondition,
				"VM %q: its leftover domain on %s is %s, and the VM's row names %s; it is kept under a leftover record: add --stop-target",
				vm, s.hostName, td.State, owner)
		}
		if err := s.virt.StopOwedFirmwareLeftover(vm, o.UUID, o.Attempt, td.State != "running"); err != nil {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: stop the leftover on %s: %v; it stays under its leftover record", vm, s.hostName, err)
		}
		if err := s.waitShutOff(vm, "the leftover"); err != nil {
			return "", err
		}
	}
	dir, err := recs.QuarantinePath(vm, o.Attempt)
	if err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: %v", vm, err)
	}
	if err := s.fw().QuarantineOwedFirmwareLeftover(vm, o.UUID, o.Attempt, dir); err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: quarantine the leftover's state: %v; it stays under its leftover record", vm, err)
	}
	reason := fmt.Sprintf("vm: %s\nuuid: %s\ncreated_at: %s\nattempt: %s\nsource: %s\ntarget: %s\nquarantined_at: %s\n"+
		"reason: an operator discarded the leftover an owed DISCARD names (lv doctor firmware-move --discard-target)\n"+
		"quarantined_permall: %s\nquarantined_nvram: %s\n",
		vm, o.UUID, o.CreatedAt, o.Attempt, owner, s.hostName, time.Now().UTC().Format(time.RFC3339),
		fileSHA256OrAbsent(filepath.Join(dir, "swtpm", "tpm2", "tpm2-00.permall")), fileSHA256OrAbsent(filepath.Join(dir, "nvram")))
	if err := writeFileDurable(filepath.Join(dir, "reason.txt"), []byte(reason)); err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: quarantine reason.txt: %v", vm, err)
	}
	if err := s.raiseQuarantineCondition(ctx, fwmigCondition{
		VM: vm, Attempt: o.Attempt, Source: owner, Target: s.hostName, Paths: []string{dir},
		Detail: fmt.Sprintf("an operator discarded the leftover of attempt %s on %s; its state is quarantined in %s", o.Attempt, s.hostName, dir),
		Action: "inspect it and remove the directory by hand when it is no longer needed; `lv doctor firmware-move <vm> --resolve quarantine` closes this",
	}); err != nil {
		slog.Warn("firmware-move doctor: raise the quarantine condition", "vm", vm, "error", err)
	}
	if h := fwDoctorLeftoverHook; h != nil {
		if err := h(); err != nil {
			return "", err
		}
	}
	if td.Present {
		if err := s.virt.UndefineOwedFirmwareLeftover(vm, o.UUID, o.Attempt); err != nil && !lv.IsNoDomain(err) {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: undefine the leftover keeping its state: %v; its state is quarantined in %s, and the record stays", vm, err, dir)
		}
	}
	s.removeDiscardedCopySeed(ctx, vm, o.UUID)
	if err := recs.RemoveLeftover(vm); err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: remove the leftover record: %v", vm, err)
	}
	return fmt.Sprintf("VM %q: the leftover of attempt %s on %s is undefined, its state quarantined in %s; nothing was deleted", vm, o.Attempt, s.hostName, dir), nil
}

// fwDoctorLeftoverHook, when set, runs after the leftover's state is
// quarantined and before its domain is undefined; an error ends the action
// there, as a crash would. Test-only.
var fwDoctorLeftoverHook func() error

// putOwedLeftover writes the leftover record of o's incarnation unless one is
// there. The caller holds firmwareTargets.op.
func (s *Server) putOwedLeftover(o fwmig.OwedDiscard, owner string) error {
	recs := s.fwRecords()
	if l, ok, err := recs.GetLeftover(o.VM); err != nil {
		return err
	} else if ok && l.Binding.Matches(o.Binding) {
		return nil
	}
	return recs.PutLeftover(fwmig.Leftover{VM: o.VM, Binding: o.Binding, Source: owner, Since: time.Now().UTC()})
}

// doctorAdoptOwnLeftover is --adopt-target-copy on a host that keeps a
// leftover record while the VM's row names this host for the record's own
// incarnation (D2-18 re-review 3, m-3). The source that owed the DISCARD no
// longer owes it (it was lost, or its DISCARD found the row here and dropped
// its record), and a failover or a re-key that kept the incarnation placed the
// VM here: the leftover domain is the VM's own, and its NVRAM and TPM state
// the newest copy that survives. The record still vetoes its define and start,
// and --discard-target refuses a row naming this host. This drops the record
// and keeps the domain and its state; nothing is stopped, moved or deleted.
//
// It never acts on a copy another host may hold as the live one: the row
// names this host for the record's incarnation; no host that answered holds a
// marker, a hold or an owed DISCARD of the VM; the record's source answered,
// is proved off, or is no longer a host. Under firmwareTargets.op: no hold;
// the same leftover record; the domain, when defined, has the record's uuid,
// carries no managed stamp of another incarnation, and is shut off (a guest
// that runs or is paused is refused, never stopped).
//
// The leftover is the state of the attempt as of the record's Since, when the
// source took its own copy as current: whatever the VM wrote afterwards, on
// the source or a later host, is newer (D2-18 re-review 4, I-1). So it takes
// --acknowledge-rollback, and both the refusal and the outcome name the
// leftover's age and every newer copy the answering hosts report (a domain of
// the VM, a reconciler quarantine of it), which `lv host superseded-disks
// <host> --restore <dir>` brings back. A host list that cannot be read
// refuses: no host was asked.
func (s *Server) doctorAdoptOwnLeftover(ctx context.Context, l fwmig.Leftover, actor string, ack bool) (string, error) {
	vm := l.VM
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", vm, err)
	}
	if row == nil || row.HostName != s.hostName || !l.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		return "", status.Errorf(codes.FailedPrecondition,
			"VM %q: its row does not name %s for the incarnation of the leftover of attempt %s; --adopt-target-copy keeps a leftover only as the VM's own: `lv doctor firmware-move %s --discard-target`",
			vm, s.hostName, l.Attempt, vm)
	}
	report, unreachable, listErr := s.gatherFirmwareMoveRecordsChecked(ctx, vm, actor)
	if listErr != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: the host list cannot be read on %s (%v), so no other host was asked about the VM; run this again", vm, s.hostName, listErr)
	}
	var newer []string
	for _, h := range report.GetHosts() {
		for _, q := range h.GetQuarantines() {
			if b := filepath.Base(q); strings.Contains(b, "-reconciled-") || strings.Contains(b, "-reconciling-") || strings.Contains(b, "-restoring-") {
				newer = append(newer, fmt.Sprintf("%s:%s", h.GetHost(), q))
			}
		}
		if h.GetHost() == s.hostName {
			continue
		}
		if d := h.GetDomain(); d.GetPresent() {
			newer = append(newer, fmt.Sprintf("%s: a domain of the VM (%s)", h.GetHost(), d.GetState()))
		}
		if h.GetMarkerJson() != "" || h.GetHoldJson() != "" {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: %s holds a live firmware move record of it; resolve that move first", vm, h.GetHost())
		}
		for _, j := range h.GetOwedDiscards() {
			var x fwmig.OwedDiscard
			if json.Unmarshal([]byte(j), &x) == nil && x.VM == vm {
				return "", status.Errorf(codes.FailedPrecondition,
					"VM %q: %s owes %s a DISCARD of it (attempt %s), so it holds the VM's copy by its record; the leftover on %s is not kept as the VM's own while it does",
					vm, x.Target, h.GetHost(), x.Attempt, s.hostName)
			}
		}
	}
	for _, u := range unreachable {
		if u != l.Source {
			continue
		}
		off, err := corrosion.HostProvedOff(ctx, s.db, l.Source)
		if err != nil || !off {
			return "", status.Errorf(codes.FailedPrecondition,
				"VM %q: the leftover's source %s did not answer and is not proved off (%v); it may still owe a DISCARD of it", vm, l.Source, err)
		}
	}
	age := fmt.Sprintf("the state of attempt %s as of %s (%s ago), when %s took its own copy as current",
		l.Attempt, l.Since.UTC().Format(time.RFC3339), time.Since(l.Since).Round(time.Minute), l.Source)
	where := "no answering host reports one"
	if len(newer) > 0 {
		where = strings.Join(newer, "; ")
	}
	// The sequence that brings another copy back (D2-18 verify, m-D): the
	// restore is refused on this host while the leftover record stands, and
	// on another host until the VM is placed there.
	steps := fmt.Sprintf("to run another copy instead: (1) `lv doctor firmware-move %[1]s --adopt-target-copy --acknowledge-rollback` drops the record (do not start the VM); "+
		"(2) for a directory on another host H, `lv migrate %[1]s H --cold`; (3) `lv host superseded-disks H --restore <dir>`; (4) `lv start %[1]s`", vm)
	if !ack {
		return "", status.Errorf(codes.FailedPrecondition,
			"VM %q: the leftover on %s is %s; whatever the VM wrote since, on %s or a later host, is newer, and keeping the leftover rolls its TPM and NVRAM back to then. "+
				"Other copies, possibly newer (check their dates): %s. To keep the leftover, add --acknowledge-rollback; %s",
			vm, s.hostName, age, l.Source, where, steps)
	}
	if s.virt == nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: no libvirt connection", vm)
	}
	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()
	recs := s.fwRecords()
	if _, ok, err := recs.GetHold(vm); err != nil || ok {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: a hold appeared on %s under the action (%v); run this again", vm, s.hostName, err)
	}
	if cur, ok, err := recs.GetLeftover(vm); err != nil || !ok || !cur.Binding.Matches(l.Binding) {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: its leftover record on %s changed under the action (%v); run this again", vm, s.hostName, err)
	}
	td, err := s.targetDomain(vm)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: %v", vm, err)
	}
	if td.Present {
		if !strings.EqualFold(td.Uuid, l.UUID) {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: the domain here has uuid %q, not the leftover's %s; it is not touched", vm, td.Uuid, l.UUID)
		}
		if st, ok := s.virt.(interface {
			GetDomainManagedIncarnation(string) (string, bool, error)
		}); ok {
			inc, has, err := st.GetDomainManagedIncarnation(vm)
			if err != nil {
				return "", status.Errorf(codes.Unavailable, "VM %q: its managed stamp cannot be read: %v", vm, err)
			}
			if has && inc != l.CreatedAt {
				return "", status.Errorf(codes.FailedPrecondition, "VM %q: the domain here is stamped incarnation %s, not the leftover's %s; it is not touched", vm, inc, l.CreatedAt)
			}
		}
		if td.State != "shutoff" {
			return "", status.Errorf(codes.FailedPrecondition,
				"VM %q: its leftover domain on %s is %s; only a shut-off leftover is kept as the VM's own on this record, and none is stopped by it",
				vm, s.hostName, td.State)
		}
	}
	if err := recs.RemoveLeftover(vm); err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: remove the leftover record: %v", vm, err)
	}
	if err := s.resolveFirmwareMigrationCondition(ctx, condFwmigDiscardOwed, vm); err != nil {
		slog.Warn("firmware-move doctor: resolve discard_owed", "vm", vm, "error", err)
	}
	kept := "its domain (shut off) and its NVRAM and TPM state are kept"
	if !td.Present {
		kept = "no domain of it is defined here; its NVRAM and TPM state, if any, are kept"
	}
	next := fmt.Sprintf("`lv start %s` starts it", vm)
	if len(newer) > 0 {
		next = "do not start the VM until you have chosen between the leftover and the other copies; to run another copy, " + steps[strings.Index(steps, "(2)"):]
	}
	return fmt.Sprintf("VM %q: the leftover record of attempt %s on %s is dropped, and %s as the VM's own (its row names %s for this incarnation); it is %s (rollback acknowledged; other copies, possibly newer: %s); nothing was deleted: %s",
		vm, l.Attempt, s.hostName, kept, s.hostName, age, where, next), nil
}

// waitShutOff waits up to fwDoctorStopWait for vm's domain to shut off.
func (s *Server) waitShutOff(vm, what string) error {
	deadline := time.Now().Add(fwDoctorStopWait)
	for {
		active, err := s.virt.DomainIsActive(vm)
		if lv.IsNoDomain(err) || (err == nil && !active) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return status.Errorf(codes.FailedPrecondition, "VM %q: %s on %s did not shut off within %s; run the action again", vm, what, s.hostName, fwDoctorStopWait)
		}
		time.Sleep(fwDoctorStopPoll)
	}
}
