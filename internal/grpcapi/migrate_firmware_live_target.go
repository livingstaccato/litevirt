package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/safename"
)

// The target half of a live firmware migration (spec §6.2, §6.8): Prepare
// records the target's hold and materialises the NVRAM, Abort disposes of the
// hold, and the hold sweep quarantines a hold whose move was abandoned. The
// hold is what keeps the incoming guest paused (the firmware move guard,
// libvirt/firmware_move_guard.go): while it exists nothing on this host runs,
// stops, redefines or wipes the VM except the move's own entry points.
//
// Every step that reads or writes a hold runs under firmwareTargets.op, the
// lock EnsureFirmwareState and RollbackFirmwareState take, so a hold is never
// read by one step while another rewrites it.

// liveFirmwareProtocolVersion is the Prepare protocol this build speaks.
const liveFirmwareProtocolVersion = 1

// fwTargetState is the Server's live firmware host check.
type fwTargetState struct {
	host atomic.Pointer[liveFirmwareHostBox]
}

// liveFirmwareHostBox holds a LiveFirmwareHost for the atomic pointer.
type liveFirmwareHostBox struct{ LiveFirmwareHost }

// SetLiveFirmwareHost installs this host's live firmware check, which stage A
// (as a move's source) and Prepare (as its target) both read; the daemon
// passes the one it builds from its config and probes. The RPC server may
// already be serving, so it is held in an atomic. nil removes it, and a
// Server without one refuses every live firmware move.
func (s *Server) SetLiveFirmwareHost(h LiveFirmwareHost) {
	if h == nil {
		s.fwTarget.host.Store(nil)
		return
	}
	s.fwTarget.host.Store(&liveFirmwareHostBox{h})
}

// liveFirmwareHost is the installed check, or nil.
func (s *Server) liveFirmwareHost() LiveFirmwareHost {
	if b := s.fwTarget.host.Load(); b != nil {
		return b.LiveFirmwareHost
	}
	return nil
}

// fwRecords is this host's firmware move records, beside its firmware store.
func (s *Server) fwRecords() *fwmig.Records { return fwmig.New(s.fw().DataDir) }

// ── Target domain ──

// errTargetDomainUnknown: libvirt did not say whether a domain of the name is
// defined here (a dropped connection, a failed read). Nothing is decided on
// it: a step that would act on "absent" refuses instead.
var errTargetDomainUnknown = errors.New("target domain unknown")

// targetDomain is what libvirt holds here for name (spec I-7). Only libvirt's
// own "no such domain" is absent; any other failure to read is
// errTargetDomainUnknown.
func (s *Server) targetDomain(name string) (*pb.TargetDomain, error) {
	if s.virt == nil {
		return nil, fmt.Errorf("%w: no libvirt connection", errTargetDomainUnknown)
	}
	active, err := s.virt.DomainIsActive(name)
	if err != nil {
		if lv.IsNoDomain(err) {
			return &pb.TargetDomain{}, nil
		}
		return nil, fmt.Errorf("%w: %s: %v", errTargetDomainUnknown, name, err)
	}
	st, err := s.virt.DomainStateReason(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errTargetDomainUnknown, name, err)
	}
	td := &pb.TargetDomain{Present: true, Reason: st.Reason}
	switch {
	case !active:
		td.State = "shutoff"
	case st.State == "running":
		td.State = "running"
	case st.Reason == "paused":
		td.State = "paused"
	default:
		// Active and neither running nor paused (pm-suspended, shutting
		// down, crashed): name it, and never read it as paused.
		td.State = st.State
		if td.State == "stopped" {
			td.State = st.Reason
		}
	}
	if x, err := s.virt.DumpXML(name); err == nil {
		td.Uuid = lv.UUIDFromXML(x)
	}
	return td, nil
}

// ── Prepare (spec §6.2) ──

// PrepareLiveFirmwareTarget holds this host as the target of a live firmware
// move. Items 1 to 5 write nothing; item 4 may dispose of a leftover hold by
// rule D or rule Q first. Prepare never defines a domain or creates a swtpm
// tree: the incoming migration does both.
func (s *Server) PrepareLiveFirmwareTarget(ctx context.Context, req *pb.PrepareLiveFirmwareTargetRequest) (*pb.PrepareLiveFirmwareTargetResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	vm, err := s.authorizeMigrationTarget(ctx, req.VmName)
	if err != nil {
		return nil, err
	}
	if req.ProtocolVersion != liveFirmwareProtocolVersion {
		return nil, status.Errorf(codes.FailedPrecondition,
			"live firmware migration protocol %d is not spoken by %s (it speaks %d)", req.ProtocolVersion, s.hostName, liveFirmwareProtocolVersion)
	}
	// The row names the source until the commit: only that host prepares a
	// move of the VM here, and the hold records it as the hold's source.
	src := callerMTLSCommonName(ctx)
	if vm.HostName == s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q lives on %s; it is not the target of a move to itself", vm.Name, s.hostName)
	}
	if src != vm.HostName {
		return nil, status.Errorf(codes.PermissionDenied,
			"VM %q is owned by %s; %s may not prepare a move of it", vm.Name, vm.HostName, src)
	}
	fs := parseFirmwareSpec(vm.Spec)
	if !lv.ValidFirmwareUUID(req.Uuid) || !strings.EqualFold(fs.UUID, req.Uuid) {
		return nil, status.Errorf(codes.InvalidArgument, "firmware uuid %q is not the recorded uuid of VM %q", req.Uuid, vm.Name)
	}
	if req.CreatedAt == "" || req.CreatedAt != vm.CreatedAt {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the source names incarnation %q, this host's replica holds %q", vm.Name, req.CreatedAt, vm.CreatedAt)
	}
	app := liveFirmwareApplicability(fs)
	tpm, uefi := app.Tpm, app.Uefi
	planned := fwmig.Hold{
		VM: vm.Name, Binding: fwmig.Binding{UUID: strings.ToLower(req.Uuid), CreatedAt: req.CreatedAt, Attempt: req.AttemptId},
		Source: src, Since: time.Now().UTC(), State: fwmig.HoldPrepared, TPM: tpm, UEFI: uefi,
		NvramMaterialised: fwmig.NvramNo,
	}
	if uefi {
		planned.NvramMaterialised = fwmig.NvramPending
	}
	if err := planned.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "VM %q: %v", vm.Name, err)
	}
	if uefi != (len(req.Nvram) > 0) {
		return nil, status.Errorf(codes.InvalidArgument,
			"VM %q: uefi is %v here and the request carries %d bytes of NVRAM", vm.Name, uefi, len(req.Nvram))
	}

	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()

	// 1. This host, read now, and the source's runtime and applicability,
	// compared as stage B compares them (compareFirmwareRuntimes) with the
	// runtime this host answers.
	host := s.liveFirmwareHost()
	if host == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s cannot check its own live firmware runtime", s.hostName)
	}
	installed, err := host.Check(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s cannot take a live firmware move: %v", s.hostName, err)
	}
	own, err := s.pbFirmwareRuntime(installed.Runtime)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s cannot take a live firmware move: %v", s.hostName, err)
	}
	if req.SrcRuntime == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: the source sent no src_runtime", vm.Name)
	}
	if err := compareFirmwareRuntimes(req.SrcRuntime, own); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the firmware runtimes of %s and %s differ: %v", vm.Name, src, s.hostName, err)
	}
	if a := req.SrcApplicability; a == nil || a.Tpm != tpm || a.Uefi != uefi {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: the source says tpm=%v uefi=%v, this host's row says tpm=%v uefi=%v",
			vm.Name, a.GetTpm(), a.GetUefi(), tpm, uefi)
	}
	// 2. (above: the row names the source.)
	// 3. No domain of the name here. A live snapshot or any guarded
	// operation on the target needs one, so this, with the row naming the
	// source until the commit, keeps them off the held guest.
	td, err := s.targetDomain(vm.Name)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: %v", vm.Name, err)
	}
	if td.Present {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: a domain of that name is defined on %s (%s); a live firmware move does not land on it", vm.Name, s.hostName, td.State)
	}
	// 4. A hold left by an earlier attempt.
	recs := s.fwRecords()
	old, ok, err := recs.GetHold(vm.Name)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: its firmware move hold on %s cannot be read: %v", vm.Name, s.hostName, err)
	}
	if ok {
		if err := s.disposePreparedHold(ctx, old, planned.Binding, src, req.SourceDomainActive); err != nil {
			return nil, err
		}
	}
	// 5. Firmware state here that no hold accounts for.
	fw := s.fw()
	for _, p := range []string{fw.SwtpmDir(planned.UUID), fw.NvramPath(vm.Name)} {
		if _, err := os.Lstat(p); err == nil || !os.IsNotExist(err) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"VM %q: %s exists on %s and no firmware move hold accounts for it; a live firmware move does not land over it", vm.Name, p, s.hostName)
		}
	}
	planned.SwtpmAbsentAtPrepare = true
	// 6. The hold, before anything is written under it.
	if err := recs.PutHold(planned); err != nil {
		return nil, status.Errorf(codes.Internal, "VM %q: write the firmware move hold: %v", vm.Name, err)
	}
	// 7. The NVRAM, through the hold's own exempt entry point.
	if uefi {
		if err := fw.MaterialiseFirmwareMoveNvram(vm.Name, planned.UUID, planned.Attempt, req.Nvram); err != nil {
			return nil, status.Errorf(codes.Internal, "VM %q: materialise the NVRAM: %v", vm.Name, err)
		}
		sum, err := fw.NvramSHA256(vm.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "VM %q: hash the materialised NVRAM: %v", vm.Name, err)
		}
		planned.NvramMaterialised, planned.NvramT0SHA256 = fwmig.NvramDone, sum
		if err := recs.PutHold(planned); err != nil {
			return nil, status.Errorf(codes.Internal, "VM %q: record the materialised NVRAM: %v", vm.Name, err)
		}
	}
	slog.Info("live firmware move: target held", "vm", vm.Name, "attempt", planned.Attempt, "source", src, "tpm", tpm, "uefi", uefi)
	return &pb.PrepareLiveFirmwareTargetResponse{
		DstRuntime:       own,
		DstApplicability: app,
		SwtpmAbsent:      planned.SwtpmAbsentAtPrepare,
		TargetDomain:     td,
	}, nil
}

// disposePreparedHold is Prepare item 4, with no domain of the VM here. A
// hold of this incarnation, prepared, from the caller, which says its domain
// is active (the guest is still the source's), is deleted (rule D). A hold
// of another incarnation, or past prepared, is quarantined (rule Q). Any
// other hold refuses, naming its attempt and source; so does a
// released_unconfirmed one, which stays until an operator resolves it.
func (s *Server) disposePreparedHold(ctx context.Context, h fwmig.Hold, b fwmig.Binding, caller string, sourceActive bool) error {
	refuse := func(why string) error {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q: %s holds it for live firmware migration %s from %s in state %s; %s",
			h.VM, s.hostName, h.Attempt, h.Source, h.State, why)
	}
	if h.State == fwmig.HoldReleasedUnconfirmed {
		return refuse("its NVRAM is unconfirmed, and it stays until an operator resolves it")
	}
	if h.Binding.SameIncarnation(b) && h.State == fwmig.HoldPrepared {
		if h.Source != caller || !sourceActive {
			return refuse("only its source, with the guest still active there, may replace it")
		}
		if err := s.deleteHoldState(h); err != nil {
			return status.Errorf(codes.Internal, "VM %q: %v", h.VM, err)
		}
		return nil
	}
	// Another incarnation's hold (the VM was recreated), or one past
	// prepared: its state may be the only copy of something, so it is kept.
	if _, err := s.quarantineHold(ctx, h, "a later Prepare found it with no domain"); err != nil {
		return status.Errorf(codes.Internal, "VM %q: %v", h.VM, err)
	}
	return nil
}

// ── Rule D and rule Q (spec §6.8) ──

// deleteHoldState is rule D: delete the NVRAM the hold materialised (or was
// materialising) and the swtpm tree if there was none at Prepare, then the
// hold. Only for a prepared hold whose source attested its domain active;
// the store's guard refuses it in any other state.
func (s *Server) deleteHoldState(h fwmig.Hold) error {
	if h.State != fwmig.HoldPrepared {
		return fmt.Errorf("rule D is only for a prepared hold, not %s", h.State)
	}
	if err := s.fw().RemoveFirmwareMoveTargetState(h.VM, h.UUID, h.Attempt,
		h.NvramMaterialised != fwmig.NvramNo, h.SwtpmAbsentAtPrepare); err != nil {
		return fmt.Errorf("delete the firmware state of attempt %s: %w", h.Attempt, err)
	}
	if err := s.fwRecords().RemoveHold(h.VM); err != nil {
		return fmt.Errorf("remove the hold of attempt %s: %w", h.Attempt, err)
	}
	slog.Info("live firmware move: target state deleted (rule D)", "vm", h.VM, "attempt", h.Attempt, "source", h.Source)
	return nil
}

// quarantineHoldRemovedHook, test-only, runs in quarantineHold once the
// hold is removed; an error stops it there, as a crash would.
var quarantineHoldRemovedHook func() error

// quarantineHold is rule Q: move the swtpm tree and the NVRAM into
// fwmig-quarantine/<vm>-<attempt>/, write the hold and a reason.txt naming
// every hash beside them, and only then remove the hold. Nothing is deleted.
// A crash at any step leaves the hold, and a retry finishes the move. It
// returns the quarantine directory.
func (s *Server) quarantineHold(ctx context.Context, h fwmig.Hold, reason string) (string, error) {
	recs := s.fwRecords()
	dir, err := recs.QuarantinePath(h.VM, h.Attempt)
	if err != nil {
		return "", err
	}
	if err := s.fw().QuarantineFirmwareMoveTargetState(h.VM, h.UUID, h.Attempt, dir); err != nil {
		return "", fmt.Errorf("quarantine the firmware state of attempt %s: %w", h.Attempt, err)
	}
	hashes := map[string]string{
		"nvram_t0_sha256":         h.NvramT0SHA256,
		"verified_permall_sha256": h.VerifiedPermallSHA256,
		"quarantined_nvram":       fileSHA256OrAbsent(filepath.Join(dir, "nvram")),
		"quarantined_permall":     fileSHA256OrAbsent(filepath.Join(dir, "swtpm", "tpm2", "tpm2-00.permall")),
	}
	hj, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return "", err
	}
	var why strings.Builder
	fmt.Fprintf(&why, "vm: %s\nuuid: %s\ncreated_at: %s\nattempt: %s\nsource: %s\ntarget: %s\nstate: %s\nquarantined_at: %s\nreason: %s\n",
		h.VM, h.UUID, h.CreatedAt, h.Attempt, h.Source, s.hostName, h.State, time.Now().UTC().Format(time.RFC3339), reason)
	for _, k := range []string{"nvram_t0_sha256", "verified_permall_sha256", "quarantined_nvram", "quarantined_permall"} {
		fmt.Fprintf(&why, "%s: %s\n", k, hashes[k])
	}
	for name, data := range map[string][]byte{"hold.json": hj, "reason.txt": []byte(why.String())} {
		if err := writeFileDurable(filepath.Join(dir, name), data); err != nil {
			return "", fmt.Errorf("quarantine %s of attempt %s: %w", name, h.Attempt, err)
		}
	}
	// The seed goes before the hold: a crash after the hold's removal leaves
	// nothing to retry from, and one before it retries all of this
	// (re-review 3, m-3).
	s.removeDiscardedCopySeed(ctx, h.VM, h.UUID)
	if err := recs.RemoveHold(h.VM); err != nil {
		return "", fmt.Errorf("remove the hold of attempt %s: %w", h.Attempt, err)
	}
	if hk := quarantineHoldRemovedHook; hk != nil {
		if err := hk(); err != nil {
			return "", err
		}
	}
	slog.Warn("live firmware move: target state quarantined (rule Q)", "vm", h.VM, "attempt", h.Attempt,
		"source", h.Source, "state", h.State, "dir", dir, "reason", reason)
	if err := s.raiseQuarantineCondition(ctx, fwmigCondition{
		Code: condFwmigQuarantine, VM: h.VM, Attempt: h.Attempt, Source: h.Source, Target: s.hostName,
		Hashes: hashes, Paths: []string{dir},
		Detail: fmt.Sprintf("the firmware state the hold of attempt %s (state %s) kept on %s is quarantined in %s: %s; nothing was deleted, and nothing removes a quarantine",
			h.Attempt, h.State, s.hostName, dir, reason),
	}); err != nil {
		slog.Warn("live firmware move: raise the quarantine condition", "vm", h.VM, "error", err)
	}
	return dir, nil
}

// removeDiscardedCopySeed removes the cloud-init seed of vm here once this
// host's copy of it was discarded or quarantined: the seed the move wrote
// for the copy (EnsureCloudInit), stamped for the VM's uuid. Never while the
// VM's row names this host, or cannot be read; a seed of another VM of the
// name is not touched (lab-2 D2: seeds left on a lost target).
func (s *Server) removeDiscardedCopySeed(ctx context.Context, vm, uuid string) {
	if s.db == nil || uuid == "" {
		return
	}
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil || (row != nil && row.HostName == s.hostName) {
		return
	}
	iso, err := lv.SafeCloudInitISOPath(s.dataDir, vm)
	if err != nil || !cloudinit.SeedIsFor(iso, uuid) {
		return
	}
	if err := cloudinit.RemoveSeed(iso); err != nil {
		slog.Warn("live firmware move: the discarded copy's seed was not removed", "vm", vm, "seed", iso, "error", err)
		return
	}
	slog.Info("live firmware move: removed the discarded copy's seed", "vm", vm, "seed", iso)
}

// fileSHA256OrAbsent is the hex sha256 of the file at p, "absent" when there
// is none, or the read error.
func fileSHA256OrAbsent(p string) string {
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		return "unreadable: " + err.Error()
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unreadable: " + err.Error()
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeFileDurable writes data to p (0600): temp file, fsync, rename,
// directory fsync.
func writeFileDurable(p string, data []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// answerOwedLeftover is a DISCARD (an owed one: the caller took the VM back
// after the commit) that finds no hold here. A domain of the owed uuid while
// the VM's row does not name this host for the owed incarnation (it names
// the caller, another host, another incarnation, or nothing) is the leftover
// the DISCARD names: it is put under a leftover record, which the guard and the
// reconciler honour, and the DISCARD is refused until an operator's
// --discard-target quarantines it. Once that domain is gone the record goes.
// handled false is the ordinary no-hold answer. The caller holds
// firmwareTargets.op.
func (s *Server) answerOwedLeftover(ctx context.Context, req *pb.AbortLiveFirmwareTargetRequest, td *pb.TargetDomain, resp *pb.AbortLiveFirmwareTargetResponse) (bool, error) {
	b := fwmig.Binding{UUID: req.Uuid, CreatedAt: req.CreatedAt, Attempt: req.AttemptId}
	recs := s.fwRecords()
	l, lok, err := recs.GetLeftover(req.VmName)
	if err != nil {
		return true, status.Errorf(codes.FailedPrecondition, "VM %q: its leftover record on %s cannot be read: %v", req.VmName, s.hostName, err)
	}
	if !td.GetPresent() {
		if lok && l.Binding.Matches(b) {
			if err := recs.RemoveLeftover(req.VmName); err != nil {
				return true, status.Errorf(codes.Internal, "VM %q: remove the leftover record: %v", req.VmName, err)
			}
		}
		return false, nil
	}
	if !strings.EqualFold(td.GetUuid(), req.Uuid) {
		return false, nil
	}
	caller := callerMTLSCommonName(ctx)
	row, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil {
		return true, status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", req.VmName, err)
	}
	if row != nil && row.HostName == s.hostName && b.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		// The row names this host for the owed incarnation: the return may
		// not have landed here yet, and the domain may be the VM's own.
		return false, nil
	}
	if !lok || !l.Binding.Matches(b) {
		if err := recs.PutLeftover(fwmig.Leftover{VM: req.VmName, Binding: b, Source: caller, Since: time.Now().UTC()}); err != nil {
			return true, status.Errorf(codes.Internal, "VM %q: record the leftover of attempt %s: %v", req.VmName, req.AttemptId, err)
		}
		slog.Warn("live firmware move: an owed DISCARD found a leftover with no hold; it is kept under a leftover record",
			"vm", req.VmName, "attempt", req.AttemptId, "source", caller, "domain", td.GetState())
	}
	stop := ""
	if td.GetState() != "shutoff" {
		stop = " --stop-target"
	}
	resp.Refused = true
	resp.Detail = fmt.Sprintf("VM %s: %s holds no hold of attempt %s, and its leftover domain (%s) is kept under a leftover record: `lv doctor firmware-move %s --discard-target%s` quarantines it",
		req.VmName, s.hostName, req.AttemptId, td.GetState(), req.VmName, stop)
	return true, nil
}

// ── Abort (spec §6.8) ──

// AbortLiveFirmwareTarget disposes of the hold of one attempt. It binds to
// the HOLD — the request's uuid, created_at and attempt must be the hold's —
// not to the current row, so an owed DISCARD still lands after the VM was
// deleted and recreated on the source. With no hold of that attempt it
// answers OK and touches nothing: it never acts on a domain or files found
// only by name. A refusal is an answer (refused, with the target's domain and
// the hold's state), from which the source decides (§7 M1); an error is a
// failure to act, and the hold is kept.
func (s *Server) AbortLiveFirmwareTarget(ctx context.Context, req *pb.AbortLiveFirmwareTargetRequest) (*pb.AbortLiveFirmwareTargetResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := safename.ValidateVMName(req.VmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	mode := req.Mode
	if mode != pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER && mode != pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED {
		return nil, status.Errorf(codes.InvalidArgument, "abort mode %v is not one this host acts on", mode)
	}

	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()

	td, err := s.targetDomain(req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: %v", req.VmName, err)
	}
	resp := &pb.AbortLiveFirmwareTargetResponse{TargetDomain: td}
	h, ok, err := s.fwRecords().GetHold(req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q: its firmware move hold on %s cannot be read: %v", req.VmName, s.hostName, err)
	}
	if !ok || !h.Binding.Matches(fwmig.Binding{UUID: req.Uuid, CreatedAt: req.CreatedAt, Attempt: req.AttemptId}) {
		if !ok && mode == pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED {
			if handled, err := s.answerOwedLeftover(ctx, req, td, resp); err != nil || handled {
				return resp, err
			}
		}
		slog.Info("live firmware move: abort of an attempt this host holds nothing of", "vm", req.VmName, "attempt", req.AttemptId)
		return resp, nil
	}
	if caller := callerMTLSCommonName(ctx); caller != h.Source {
		return nil, status.Errorf(codes.PermissionDenied,
			"VM %q: the hold of attempt %s is %s's; %s may not abort it", h.VM, h.Attempt, h.Source, caller)
	}
	refuse := func(why string) (*pb.AbortLiveFirmwareTargetResponse, error) {
		resp.Refused, resp.HoldState = true, string(h.State)
		resp.Detail = fmt.Sprintf("VM %s: %s keeps the hold of attempt %s (state %s): %s", h.VM, s.hostName, h.Attempt, h.State, why)
		slog.Warn("live firmware move: abort refused", "vm", h.VM, "attempt", h.Attempt, "mode", mode, "detail", resp.Detail)
		return resp, nil
	}
	if h.State == fwmig.HoldReleasedUnconfirmed {
		return refuse("the guest was released here and its NVRAM is unconfirmed; only an operator resolves it")
	}
	switch mode {
	case pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER:
		if td.Present {
			return refuse(fmt.Sprintf("a domain of the VM is defined here (%s)", td.State))
		}
		// Rule D only for a prepared hold whose source attests its domain
		// is active; every other disposal keeps the state (rule Q).
		if h.State == fwmig.HoldPrepared && req.SourceDomainActive {
			err = s.deleteHoldState(h)
		} else {
			_, err = s.quarantineHold(ctx, h, "aborted before cutover")
		}
	case pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED:
		if td.Present && td.State != "paused" && td.State != "shutoff" {
			return refuse(fmt.Sprintf("its domain is %s here; a discard never stops a guest that may run", td.State))
		}
		// A commit that landed made the held guest the owner: the row names
		// this host for the hold's incarnation. The source sends a DISCARD
		// only before the commit, or with the row naming it, so one that
		// finds this is stray. A row that cannot be read decides nothing.
		row, rerr := corrosion.GetVM(ctx, s.db, h.VM)
		if rerr != nil {
			return nil, status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", h.VM, rerr)
		}
		if row != nil && row.HostName == s.hostName &&
			h.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
			return refuse(fmt.Sprintf("the VM's row names %s for this incarnation: the move committed, and the held guest is its owner", s.hostName))
		}
		// The domain goes first (destroy if paused, undefine keeping its
		// state), so the state is never moved from under a defined domain.
		if s.virt == nil {
			return nil, status.Errorf(codes.Unavailable, "VM %q: no libvirt connection", h.VM)
		}
		if err := s.virt.DiscardFirmwareMoveTarget(h.VM, h.UUID, h.Attempt); err != nil {
			if lv.IsFirmwareMoveRefusal(err) {
				return refuse(err.Error())
			}
			return nil, status.Errorf(codes.Internal, "VM %q: discard the held domain: %v", h.VM, err)
		}
		if _, err = s.quarantineHold(ctx, h, "the source discarded the unverified copy"); err == nil {
			s.removeDiscardedStubs(ctx, h.VM, req.CreatedStubs)
		}
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VM %q: %v", h.VM, err)
	}
	if td, err := s.targetDomain(req.VmName); err == nil {
		resp.TargetDomain = td
	}
	return resp, nil
}

// removeDiscardedStubs removes the disk stubs a discarded attempt created
// here, by CleanupMigrationArtifacts' rules: only in a disk-artifact root,
// only one this host's ledger records making for the VM, and never for a VM
// whose row names this host. After a restart the ledger is empty, so the
// stubs are left and logged: a safe leak.
func (s *Server) removeDiscardedStubs(ctx context.Context, vmName string, stubs []string) {
	if len(stubs) == 0 {
		return
	}
	if vm, err := corrosion.GetVM(ctx, s.db, vmName); err != nil || (vm != nil && vm.HostName == s.hostName) {
		slog.Warn("live firmware move: discard leaves the disk stubs; the VM's row names this host or cannot be read",
			"vm", vmName, "stubs", stubs, "error", err)
		return
	}
	for _, p := range stubs {
		if p == "" || !s.withinDiskArtifactRoot(p) || !s.madeHere(ctx, &s.migrationStubs, vmName, p) {
			slog.Warn("live firmware move: discard leaves a disk file this host did not record making as a stub",
				"vm", vmName, "path", p)
			continue
		}
		if err := s.removeDiskFileBeneath(p, true); err != nil {
			slog.Warn("live firmware move: discard could not remove a disk stub", "vm", vmName, "path", p, "error", err)
			continue
		}
		s.migrationStubs.forget(p)
	}
}

// ── Hold sweep (spec §6.8) ──

const (
	// firmwareHoldSweepInterval is how often the hold sweep looks.
	firmwareHoldSweepInterval = 10 * time.Second
	// firmwareHeldConditionAfter is how long a hold with a domain is held
	// before firmware_migration_held names it.
	firmwareHeldConditionAfter = 5 * time.Minute
)

// RunFirmwareHoldSweep looks at this host's holds now and every
// firmwareHoldSweepInterval (FirmwareHoldSweepOnce). It is its own loop: the
// NIC held-guest sweep visits only nic-guard-held/.
func (s *Server) RunFirmwareHoldSweep(ctx context.Context) {
	t := time.NewTicker(firmwareHoldSweepInterval)
	defer t.Stop()
	for {
		s.FirmwareHoldSweepOnce(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// FirmwareHoldSweepOnce is one look of the hold sweep at now:
//   - a hold with NO domain, older than heldStaleAfter, whose row is gone,
//     recreated, or not migrating and names another host, is quarantined
//     (rule Q, never D);
//   - a hold WITH a domain is never disposed of here; after
//     firmwareHeldConditionAfter it raises firmware_migration_held;
//   - a released_unconfirmed hold stays until an operator resolves it.
//
// It resolves firmware_migration_held for a VM this host no longer holds.
func (s *Server) FirmwareHoldSweepOnce(ctx context.Context, now time.Time) {
	holds, err := s.fwRecords().ListHolds()
	if err != nil {
		// firmware_migration_record_unreadable names the file.
		slog.Warn("firmware hold sweep: the holds cannot be read", "error", err)
		return
	}
	held := map[string]bool{}
	for _, h := range holds {
		if s.sweepFirmwareHold(ctx, h.VM, now) {
			held[h.VM] = true
		}
	}
	s.resolveFirmwareHeld(ctx, held)
}

// sweepFirmwareHold judges vm's hold under the target lock; it reports
// whether the hold is held with a domain (and keeps firmware_migration_held).
func (s *Server) sweepFirmwareHold(ctx context.Context, vmName string, now time.Time) bool {
	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()
	h, ok, err := s.fwRecords().GetHold(vmName)
	switch {
	case err != nil:
		return true // unknown: keep whatever it raised
	case !ok || h.State == fwmig.HoldReleasedUnconfirmed:
		return false
	}
	td, err := s.targetDomain(h.VM)
	if err != nil {
		slog.Debug("firmware hold sweep: domain unknown; leaving the hold", "vm", h.VM, "error", err)
		return true
	}
	if td.Present {
		if now.Sub(h.Since) >= firmwareHeldConditionAfter {
			if err := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
				Code: condFwmigHeld, VM: h.VM, Attempt: h.Attempt, Source: h.Source, Target: s.hostName,
				Hashes: map[string]string{"nvram_t0_sha256": h.NvramT0SHA256, "verified_permall_sha256": h.VerifiedPermallSHA256},
				Paths:  []string{filepath.Join(s.fw().DataDir, fwmig.HoldDir, h.VM+".json")},
				Detail: fmt.Sprintf("held for firmware verification of attempt %s from %s since %s (hold %s, domain %s)",
					h.Attempt, h.Source, h.Since.UTC().Format(time.RFC3339), h.State, td.State),
			}); err != nil {
				slog.Warn("firmware hold sweep: raise firmware_migration_held", "vm", h.VM, "error", err)
			}
		}
		return true
	}
	if now.Sub(h.Since) < heldStaleAfter {
		return false
	}
	// The row is judged only from a replica that has caught up with a peer,
	// as DeletedVMMarkerSweepTick does: after an outage longer than
	// heldStaleAfter every hold is stale on the first pass, while the replica
	// is at its stalest. A later pass decides.
	if ok, _ := s.db.ReplicaCaughtUp(); !ok {
		return false
	}
	row, err := corrosion.GetVM(ctx, s.db, h.VM)
	if err != nil {
		return false
	}
	var why string
	switch {
	case row == nil:
		why = "its VM's row is gone"
	case !h.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}):
		why = "its VM was recreated"
	case row.State != "migrating" && row.HostName != s.hostName:
		why = fmt.Sprintf("its VM is %s on %s", row.State, row.HostName)
	default:
		return false
	}
	if _, err := s.quarantineHold(ctx, h, fmt.Sprintf("the hold sweep found it with no domain after %s: %s", heldStaleAfter, why)); err != nil {
		slog.Warn("firmware hold sweep: quarantine", "vm", h.VM, "attempt", h.Attempt, "error", err)
	}
	return false
}

// resolveFirmwareHeld resolves firmware_migration_held, as this host raised
// it, for each VM not in held.
func (s *Server) resolveFirmwareHeld(ctx context.Context, held map[string]bool) {
	if s.db == nil {
		return
	}
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, s.db, firmwareMigrationEvaluator, condFwmigHeld)
	if err != nil {
		return
	}
	for _, c := range open {
		if held[c.SubjectID] || c.Reporter != s.hostName {
			continue
		}
		if err := s.resolveFirmwareMigrationCondition(ctx, condFwmigHeld, c.SubjectID); err != nil {
			slog.Warn("firmware hold sweep: resolve firmware_migration_held", "vm", c.SubjectID, "error", err)
		}
	}
}

// ── Record refusals at the entry of other target operations (spec §6.9) ──

// firmwareMoveRecordRefusal is a FailedPrecondition naming the live firmware
// move whose record (a source marker or a target hold) names the VM here, or
// nil when none does. A record that cannot be read refuses too.
func (s *Server) firmwareMoveRecordRefusal(op, name, uuid string) error {
	recs, err := s.fwRecords().Lookup(name, uuid)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "%s of VM %q refused on %s: %v", op, name, s.hostName, err)
	}
	for _, r := range recs {
		dir, what := "to", "phase"
		if r.Kind == lv.FirmwareHold {
			dir, what = "from", "state"
		}
		return status.Errorf(codes.FailedPrecondition,
			"%s of VM %q refused on %s: live firmware migration %s %s %s is in %s %s",
			op, name, s.hostName, r.Attempt, dir, r.Peer, what, r.State)
	}
	return nil
}
