package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
)

// Attempt progression and supersede (docs/design/recovery-claims.md §3.12):
// the voter's check of supersede evidence, the destination's signed
// abandonment, the operator's `lv host rm --dead` plan, and the
// ha.claim.stranded condition that points at it.

func supersedeToPB(ev *corrosion.SupersedeEvidence) (*pb.RecoveryClaimSupersede, error) {
	if ev == nil {
		return nil, nil
	}
	value, err := valueToPB(ev.PriorValue)
	if err != nil {
		return nil, err
	}
	return &pb.RecoveryClaimSupersede{PriorCertificate: ev.PriorCertificate, PriorValue: value, Abandonment: ev.Abandonment}, nil
}

func supersedeFromPB(p *pb.RecoveryClaimSupersede) *corrosion.SupersedeEvidence {
	if p == nil {
		return nil
	}
	return &corrosion.SupersedeEvidence{PriorCertificate: p.GetPriorCertificate(), PriorValue: valueFromPB(p.GetPriorValue()),
		Abandonment: p.GetAbandonment()}
}

// checkSupersede is a voter's check, before it promises at key.Attempt > 0,
// that the value decided at the previous attempt will never execute (§3.12):
//
//  1. ev's certificate decided the previous attempt of this key, for the value
//     ev carries, and verifies against the voter generation it names;
//  2. that value's destination either signed an abandonment of its proof that
//     verifies, or is — in THIS voter's own replica — fenced proof-grade, no
//     longer a member, and revoked.
//
// It returns a refusal reason and detail, or "" when the evidence holds.
// Refusing writes nothing, so replica lag here delays a supersede and never
// admits one.
func (s *Server) checkSupersede(ctx context.Context, key corrosion.ClaimKey, ev *corrosion.SupersedeEvidence) (string, string) {
	refuse := func(format string, a ...any) (string, string) {
		return corrosion.RefusalSupersedeUnproven, fmt.Sprintf("%s refuses %s: ", s.hostName, key) + fmt.Sprintf(format, a...)
	}
	if ev == nil || ev.PriorValue == nil || ev.PriorValue.Proof == nil {
		return refuse("attempt %d needs evidence that attempt %d's decided value will never execute", key.Attempt, key.Attempt-1)
	}
	prior, err := corrosion.DecodeClaimCertificate(ev.PriorCertificate)
	if err != nil {
		return refuse("the prior certificate: %v", err)
	}
	want := key
	want.Attempt--
	if prior.Key != want {
		return refuse("the prior certificate decides %s, not %s", prior.Key, want)
	}
	digest, err := ev.PriorValue.Digest()
	if err != nil || digest != prior.ValueDigest {
		return refuse("the prior value does not match the prior certificate's digest")
	}
	p := ev.PriorValue.Proof
	if p.TargetKind != key.TargetKind || p.TargetName != key.TargetName || p.OwnerEpoch != fmt.Sprint(key.OwnerEpoch) {
		return refuse("the prior value binds %s/%s@%s", p.TargetKind, p.TargetName, p.OwnerEpoch)
	}
	// The same generation rule a destination applies (VerifyClaimCertificate):
	// a certificate at a generation this voter has not adopted, or one a
	// forced reconfiguration replaced, certifies nothing here — so it cannot
	// prove what the previous attempt decided either. The coordinator
	// re-decides that attempt under the current generation first, which
	// certifies the same value again, and supersedes with that.
	adopted, err := corrosion.AdoptedVoterGeneration(ctx, s.db)
	if err != nil {
		return refuse("read the adopted voter generation: %v", err)
	}
	if prior.ConfigGeneration < 1 || prior.ConfigGeneration > adopted {
		return refuse("the prior certificate is at voter generation %d, which this voter has not adopted (adopted %d)",
			prior.ConfigGeneration, adopted)
	}
	if forced, err := corrosion.ReplacedByForcedGeneration(ctx, s.db, prior.ConfigGeneration); err != nil {
		return refuse("%v", err)
	} else if forced > 0 {
		return refuse("the prior certificate is at voter generation %d, which forced generation %d replaced; "+
			"re-decide attempt %d under the current generation", prior.ConfigGeneration, forced, want.Attempt)
	}
	cfg, err := corrosion.GetVoterConfig(ctx, s.db, prior.ConfigGeneration)
	if err != nil || !cfg.Explicit() {
		return refuse("voter generation %d, which the prior certificate names, is not a member generation here", prior.ConfigGeneration)
	}
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return refuse("no verifier: %v", err)
	}
	if err := verifier.Verify(prior, corrosion.CertExpectation{Key: prior.Key, ValueDigest: digest,
		ConfigGeneration: prior.ConfigGeneration, Electorate: cfg.Members, Quorum: corrosion.MajorityOf(len(cfg.Members))}); err != nil {
		return refuse("the prior certificate does not verify: %v", err)
	}
	dest := p.DestHost
	if ev.Abandonment != "" {
		ab, err := corrosion.DecodeClaimAbandonment(ev.Abandonment)
		if err != nil {
			return refuse("%v", err)
		}
		if err := verifier.VerifyAbandonment(ab, dest, p.ID, prior.Key); err != nil {
			return refuse("%s's abandonment of proof %s does not verify: %v", dest, p.ID, err)
		}
		return "", ""
	}
	if err := corrosion.RemovedHostEvidence(ctx, s.db, s.pkiDir, dest); err != nil {
		return refuse("%s decided %s for %s, which has not been removed for good: %v", prior.Key, p.ID, dest, err)
	}
	return "", ""
}

// AbandonRecoveryProof is a recovery destination's signed promise that it has
// not executed, and will never execute, the proof a decided claim named
// (§3.12). Peer-only: only a coordinator asks. It refuses — FailedPrecondition
// — when this node may already have executed the proof.
func (s *Server) AbandonRecoveryProof(ctx context.Context, req *pb.AbandonRecoveryProofRequest) (*pb.AbandonRecoveryProofResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	ab, err := s.abandonRecoveryProof(ctx, keyFromPB(req.GetKey()), req.GetProofId(), req.GetReason(), req.GetForeignOnly(),
		req.GetOperatorRelease())
	if err != nil {
		return nil, err
	}
	enc, err := ab.Encode()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode abandonment: %v", err)
	}
	return &pb.AbandonRecoveryProofResponse{Abandonment: enc}, nil
}

// abandonRecoveryProof is the destination's abandonment. operatorRelease
// (with foreignOnly only) is `lv cluster claim-release`: the destination first
// confirms, under the workload's own locks, that nothing here runs the proof
// (holdWorkloadIdle), and only then may a proof it claimed and left in
// progress be abandoned (corrosion.AbandonForeignProofInFlight). The holds
// are kept until the abandonment is recorded, after which no claim of the
// proof succeeds here.
func (s *Server) abandonRecoveryProof(ctx context.Context, key corrosion.ClaimKey, proofID, reason string, foreignOnly, operatorRelease bool) (corrosion.ClaimAbandonment, error) {
	if !key.IsWorkload() || proofID == "" {
		return corrosion.ClaimAbandonment{}, status.Error(codes.InvalidArgument, "an abandonment names a workload claim key and a proof")
	}
	if operatorRelease && !foreignOnly {
		return corrosion.ClaimAbandonment{}, status.Error(codes.InvalidArgument, "an operator release is a foreign abandonment")
	}
	signer, _, err := s.claimIdentity()
	if err != nil {
		return corrosion.ClaimAbandonment{}, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	// One decision with an operator promotion's start fence on this host
	// (fenceOperatorStart): a value it has started is never abandoned, and
	// one abandoned is never started (review I2).
	s.operatorClaimMu.Lock()
	defer s.operatorClaimMu.Unlock()
	if s.operatorStartRecorded(proofID) {
		return corrosion.ClaimAbandonment{}, status.Errorf(codes.FailedPrecondition,
			"%v: proof %s is an operator's promotion that %s has started", corrosion.ErrProofExecuted, proofID, s.hostName)
	}
	// Belt and braces (review I-1, m1): nothing is abandoned here while a
	// domain of the workload is active on this host, or libvirt cannot say it
	// is not — whatever the records say, it may be running the proof.
	if !foreignOnly && key.TargetKind == "vm" && s.virt != nil && !s.domainPositivelyInactive(key.TargetName) {
		return corrosion.ClaimAbandonment{}, status.Errorf(codes.FailedPrecondition,
			"%v: a domain of %s is active on %s, or libvirt cannot say it is not", corrosion.ErrProofExecuted, key.TargetName, s.hostName)
	}
	abandon := s.db.AbandonProof
	if foreignOnly {
		abandon = s.db.AbandonForeignProof
	}
	if operatorRelease {
		release, err := s.holdWorkloadIdle(ctx, key.TargetKind, key.TargetName)
		if err != nil {
			return corrosion.ClaimAbandonment{}, status.Errorf(codes.FailedPrecondition,
				"%s cannot confirm nothing runs proof %s: %v", s.hostName, proofID, err)
		}
		defer release()
		abandon = s.db.AbandonForeignProofInFlight
	}
	if err := abandon(ctx, proofID, key, reason); err != nil {
		if errors.Is(err, corrosion.ErrProofExecuted) || errors.Is(err, corrosion.ErrProofNotForeign) {
			return corrosion.ClaimAbandonment{}, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return corrosion.ClaimAbandonment{}, status.Errorf(codes.Unavailable, "record abandonment: %v", err)
	}
	slog.Warn("recovery claims: abandoned a decided recovery this host will never execute",
		"claim", key.String(), "proof", proofID, "reason", reason)
	s.audit(ctx, "recovery_claim.abandon", key.TargetKind+"/"+key.TargetName,
		fmt.Sprintf("proof %s at %s: %s", proofID, key, reason), "ok")
	return signer.SignAbandonment(proofID, key, reason)
}

// RequestAbandonment asks host — this node, or a peer over the claim RPC — to
// abandon proofID at key, and returns the encoded signed abandonment. The
// failover coordinator calls it when a promote it decided failed before
// StartDomain and it falls back to a reschedule (§3.12).
func (s *Server) RequestAbandonment(ctx context.Context, host string, key corrosion.ClaimKey, proofID, reason string) (string, error) {
	return s.requestAbandonment(ctx, host, key, proofID, reason, false)
}

// RequestForeignAbandonment asks host to sign that proofID is not the
// decision of the incarnation key names and will never run
// (corrosion.AbandonForeignProof). The coordinator moves a scoped claim past
// a spent decided proof on it (§10 item 37).
func (s *Server) RequestForeignAbandonment(ctx context.Context, host string, key corrosion.ClaimKey, proofID, reason string) (string, error) {
	return s.requestAbandonment(ctx, host, key, proofID, reason, true)
}

// requestAbandonment is RequestAbandonment, with foreignOnly asking for the
// legacy-key bridge's exclusion (corrosion.AbandonForeignProof) instead.
func (s *Server) requestAbandonment(ctx context.Context, host string, key corrosion.ClaimKey, proofID, reason string, foreignOnly bool) (string, error) {
	if host == s.hostName {
		ab, err := s.abandonRecoveryProof(ctx, key, proofID, reason, foreignOnly, false)
		if err != nil {
			return "", err
		}
		return ab.Encode()
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cl, closer, err := s.dialPeer(cctx, host)
	if err != nil {
		return "", err
	}
	defer closer()
	resp, err := cl.AbandonRecoveryProof(cctx, &pb.AbandonRecoveryProofRequest{Key: keyToPB(key), ProofId: proofID, Reason: reason,
		ForeignOnly: foreignOnly})
	if err != nil {
		return "", err
	}
	return resp.GetAbandonment(), nil
}

// ── `lv host rm --dead` (§3.12) ────────────────────────────────────────────

// strandedOn lists the recoveries a host holds up: every workload still
// recorded on it. One pending under a certified proof was decided FOR it and
// retries at the next attempt once it is removed; any other was left on it
// when it failed and is recovered at the attempt its claim is at.
func (s *Server) strandedOn(ctx context.Context, host string) ([]*pb.StrandedRecovery, error) {
	var out []*pb.StrandedRecovery
	vms, err := corrosion.ListVMs(ctx, s.db, "", host)
	if err != nil {
		return nil, err
	}
	for _, vm := range vms {
		full, err := corrosion.GetVM(ctx, s.db, vm.Name)
		if err != nil || full == nil {
			continue
		}
		if full.State == "stopped" {
			disks, derr := corrosion.GetVMDisks(ctx, s.db, full.Name)
			if derr != nil {
				return nil, derr
			}
			local := corrosion.VMHasHostLocalDisk(disks)
			switch {
			case corrosion.VMStoppedForFailover(*full) && !local:
				out = append(out, &pb.StrandedRecovery{Kind: "vm", Name: full.Name, Detail: fmt.Sprintf(
					"vm/%s is stopped, on shared storage: once this removal and the CRL have replicated, failover may "+
						"move it, still stopped, to a live host (it needs a failure policy or auto-promote, no firmware "+
						"state and no ownership dispute); start it there with `lv start %s`. Otherwise it stays recorded "+
						"on %s and comes back with %s when the machine is added again under that name",
					full.Name, full.Name, host, host)})
				continue
			case corrosion.VMStoppedForFailover(*full) || local:
				out = append(out, &pb.StrandedRecovery{Kind: "vm", Name: full.Name, Detail: stoppedOnDeadHostDetail("vm", full.Name, host)})
				continue
			}
		}
		// Failover never recovers a Secure Boot / vTPM VM: its firmware state
		// was host-local and died with the host (failover.recoverWorkloads).
		if corrosion.VMUsesFirmwareState(*full) {
			detail := firmwareOnDeadHostDetail(full.Name, host)
			if v := s.firmwareMoveSourceCopy(ctx, full.Name, host); v.kind != fwCopyNone {
				detail = firmwareSourceCopyDetail(full.Name, host, v)
			}
			out = append(out, &pb.StrandedRecovery{Kind: "vm", Name: full.Name, Detail: detail})
			continue
		}
		out = append(out, s.strandedFor(ctx, "vm", full.Name, host, full.PendingActionID))
	}
	cts, err := corrosion.ListContainers(ctx, s.db, host)
	if err != nil {
		return nil, err
	}
	for _, ct := range cts {
		if corrosion.ContainerStoppedForFailover(ct) {
			out = append(out, &pb.StrandedRecovery{Kind: "container", Name: ct.Name, Detail: stoppedOnDeadHostDetail("container", ct.Name, host)})
			continue
		}
		id := ""
		if ct.RelocateToken != "" {
			if pr, ok, _ := corrosion.GetActionProofByToken(ctx, s.db, ct.RelocateToken); ok {
				id = pr.ID
			}
		}
		out = append(out, s.strandedFor(ctx, "container", ct.Name, host, id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Name < out[j].Kind+out[j].Name })
	return out, nil
}

// stoppedOnDeadHostDetail is what `lv host rm --dead` says about a stopped
// workload failover leaves on the host it removes: one stopped by intent that
// it could not move still stopped, or one with a host-local disk
// (failover.recoverWorkloads). Removing the host does not move it either: it
// stays recorded there, its data with the machine, and comes back with the
// machine if it is added again under the same name (AdmitHost admits a name
// whose only recorded workloads are stopped). It carries no next attempt, so
// it is not counted as a recovery that will retry.
func stoppedOnDeadHostDetail(kind, name, host string) string {
	if kind == "container" {
		return fmt.Sprintf("container/%s is stopped: failover never recreates or starts a stopped container, so it stays "+
			"recorded on %s with its rootfs and is not moved by this removal. To keep its data, bring %s back: it "+
			"returns with %s when the machine is added again under that name (`lv host add`). If the data is lost "+
			"for good, remove it with `lv ct rm %s --host %s`",
			name, host, host, host, name, host)
	}
	return fmt.Sprintf("vm/%s is stopped: failover does not start it or rebuild its disks elsewhere, so it stays "+
		"recorded on %s with its disks and is not moved by this removal. To keep its data, bring %s back: it "+
		"returns with %s when the machine is added again under that name (`lv host add`). Or promote a replica "+
		"onto a live host (`lv replication promote %s`). If the data is lost for good, remove it with `lv rm %s` "+
		"and create it again",
		name, host, host, host, name, name)
}

// fwSourceCopyKind sorts what `lv host rm --dead` can say about a Secure
// Boot / vTPM VM whose live firmware move had the removed host as target.
type fwSourceCopyKind int

const (
	fwCopyNone       fwSourceCopyKind = iota // no open move names the host: the state was on the host
	fwCopyUnchecked                          // a surviving copy could not be ruled out or confirmed
	fwCopyReturnable                         // post-commit, the source kept its state: --accept-source returns it
	fwCopyNvram                              // nvram_unconfirmed: the guest ran on the target after the release
	fwCopyPaused                             // source_paused: its exit needs the target to answer
)

// fwSourceCopy is firmwareMoveSourceCopy's verdict.
type fwSourceCopy struct {
	kind         fwSourceCopyKind
	source, code string
	why          string   // fwCopyUnchecked: what could not be checked
	silent       []string // hosts that did not answer the marker sweep
	tpm          bool     // the move's VM keeps a vTPM state
	settles      bool     // fwCopyNone found by a marker the fence resolution settles
}

// firmwareMoveSourceCopy finds an open live firmware move of vm whose target
// is host. First the replicated firmware_migration conditions: one counts
// only while open, raised by the move's source (evidence host == source),
// naming host as target, and for the attempt the source's own marker still
// records (read from the source). With no condition, every other host's
// records are read for a marker naming host as target: a committed move
// whose cleanup has not stopped raises no condition. Anything that cannot be
// read or does not match is fwCopyUnchecked, never fwCopyNone: only clean
// reads with no open move say the state went with the host.
func (s *Server) firmwareMoveSourceCopy(ctx context.Context, vm, host string) fwSourceCopy {
	codeList := make([]string, 0, len(firmwareMigrationConditionSeverity))
	for c := range firmwareMigrationConditionSeverity {
		codeList = append(codeList, c)
	}
	sort.Strings(codeList)
	var other fwSourceCopy
	for _, code := range codeList {
		if code == condFwmigDiscardOwed {
			// The move ended with the VM on its source; the DISCARD owed
			// the target is cleanup of the target's copy, not a live move.
			continue
		}
		row, found, err := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, code, "vm", vm)
		if err != nil {
			return fwSourceCopy{kind: fwCopyUnchecked, why: "its firmware_migration conditions cannot be read: " + err.Error()}
		}
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			continue
		}
		var ev struct {
			Attempt string `json:"attempt"`
			Source  string `json:"source"`
			Target  string `json:"target"`
			Host    string `json:"host"`
		}
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			return fwSourceCopy{kind: fwCopyUnchecked, code: code, why: fmt.Sprintf("its open %s cannot be read: %v", code, err)}
		}
		if ev.Target != host || ev.Source == "" || ev.Source == host || ev.Host != ev.Source {
			if other.kind == fwCopyNone {
				other = fwSourceCopy{kind: fwCopyUnchecked, code: code, why: fmt.Sprintf(
					"an open %s (raised by %s, source %s, target %s) does not match a move from a live source to %s", code, orNone(ev.Host), orNone(ev.Source), orNone(ev.Target), host)}
			}
			continue
		}
		v := s.classifySourceCopy(ctx, vm, code, ev.Source, ev.Attempt)
		if v.kind != fwCopyUnchecked {
			return v
		}
		if other.kind == fwCopyNone {
			other = v
		}
	}
	if other.kind != fwCopyNone {
		return other
	}
	return s.firmwareMoveMarkerSweep(ctx, vm, host)
}

// firmwareMoveMarkerSweep reads vm's records on every host but host and
// classifies a marker that names host as the move's target. A host that does
// not answer leaves the answer unchecked.
func (s *Server) firmwareMoveMarkerSweep(ctx context.Context, vm, host string) fwSourceCopy {
	rctx, cancel := context.WithTimeout(ctx, fwCleanupAliveReadTimeout)
	defer cancel()
	resp, unreachable, err := s.gatherFirmwareMoveRecordsChecked(rctx, vm, s.hostName)
	if err != nil {
		return fwSourceCopy{kind: fwCopyUnchecked, why: "the host list cannot be read: " + err.Error()}
	}
	for _, rec := range resp.GetHosts() {
		if rec.GetHost() == host {
			continue
		}
		if m := markerOf(rec); m != nil && m.VM == vm && m.Target == host {
			row, _ := corrosion.GetVM(ctx, s.db, vm)
			v := classifyFwMoveMarker(*m, "", row, rec.GetHost())
			v.source = rec.GetHost()
			if v.kind == fwCopyUnchecked && v.why == "" {
				v.why = fmt.Sprintf("%s holds a marker of a move to %s that is %s", rec.GetHost(), host, fwDescribe(*m))
			}
			return v
		}
	}
	var silent []string
	for _, h := range unreachable {
		if h != host {
			silent = append(silent, h)
		}
	}
	if len(silent) > 0 {
		return fwSourceCopy{kind: fwCopyUnchecked, silent: silent,
			why: strings.Join(silent, ", ") + " did not answer for its records of the VM"}
	}
	return fwSourceCopy{}
}

// classifySourceCopy asks source for vm's marker and sorts code by what the
// doctor's --accept-source does with that marker (doctorAcceptSource).
func (s *Server) classifySourceCopy(ctx context.Context, vm, code, source, attempt string) fwSourceCopy {
	unchecked := func(why string) fwSourceCopy {
		return fwSourceCopy{kind: fwCopyUnchecked, source: source, code: code, why: why}
	}
	rctx, cancel := context.WithTimeout(ctx, fwCleanupAliveReadTimeout)
	defer cancel()
	rec, err := s.inspectFirmwareMoveHost(rctx, source, vm)
	if err != nil {
		return unchecked(fmt.Sprintf("%s raised %s, and its records cannot be read: %v", source, code, err))
	}
	m := markerOf(rec)
	if m == nil || attempt == "" || m.Attempt != attempt {
		return unchecked(fmt.Sprintf("%s raised %s for attempt %s, and holds no marker of that attempt", source, code, orNone(attempt)))
	}
	row, _ := corrosion.GetVM(ctx, s.db, vm)
	v := classifyFwMoveMarker(*m, code, row, source)
	v.source = source
	if v.kind == fwCopyUnchecked {
		v.why = fmt.Sprintf("%s raised %s, and its marker is %s", source, code, fwDescribe(*m))
	}
	return v
}

// classifyFwMoveMarker sorts a source marker m on source (and the condition
// code it was found by, "" for none; row is the VM's row) by what the
// doctor's --accept-source, or the fence resolution, does with it.
func classifyFwMoveMarker(m fwmig.Marker, code string, row *corrosion.VMRecord, source string) fwSourceCopy {
	v := fwSourceCopy{code: code, kind: fwCopyUnchecked, tpm: m.TPM}
	post := fwPostCommit(fwProgress(m))
	switch {
	case (code == "" || code == condFwmigTargetUnreachable) && fenceResolves(m, row, source):
		// The fence resolution returns the VM to its source once the target
		// is proved off, removed or not (ResolveLiveFirmwareMoveByFence),
		// by the same predicate.
		v.kind, v.settles = fwCopyNone, true
	case (code == "" || code == condFwmigCleanupFailed) && post && !m.Phase.Parked():
		v.kind = fwCopyReturnable
	case (code == "" || code == condFwmigTargetUnreachable) && m.Phase == fwmig.PhaseTargetUnreachable && post,
		(code == "" || code == condFwmigTargetRan) && m.Phase == fwmig.PhaseTargetRan && post:
		v.kind = fwCopyReturnable
	case (code == "" || code == condFwmigNvramUnconfirmed) && m.Phase == fwmig.PhaseNvramUnconfirmed:
		v.kind = fwCopyNvram
	case (code == "" || code == condFwmigSourcePaused) && m.Phase == fwmig.PhaseSourcePaused:
		v.kind = fwCopyPaused
	}
	return v
}

// firmwareSourceCopyDetail is what `lv host rm --dead` says about a Secure
// Boot / vTPM VM whose live firmware move to host is still open (v).
func firmwareSourceCopyDetail(name, host string, v fwSourceCopy) string {
	return firmwareMoveDetail(name, host, host, v)
}

// firmwareMoveDetail is firmwareSourceCopyDetail for a VM whose row is on
// rowHost.
func firmwareMoveDetail(name, rowHost, host string, v fwSourceCopy) string {
	head := fmt.Sprintf("vm/%s uses Secure Boot / vTPM: failover never recovers it. ", name)
	if rowHost != host {
		head = fmt.Sprintf("vm/%s, recorded on %s, has a live firmware move to %s. ", name, rowHost, host)
	}
	open := fmt.Sprintf("Its live firmware move from %s to %s is still open (its marker on %s", v.source, host, v.source)
	if v.code != "" {
		open += ", " + v.code
	}
	open += "). "
	switch v.kind {
	case fwCopyReturnable:
		return head + open + fmt.Sprintf("%s kept its own firmware state of the move. Settle it before removing %s: "+
			"`lv doctor firmware-move %s --accept-source --acknowledge-rollback` returns the VM to %s, stopped, from that state. "+
			"It discards %s's copy, which may be newer: the guest ran there after the commit. "+
			"The doctor refuses when that state changed since the cutover, or the cleanup already undefined its domain. "+
			"Then run `lv start %s`. "+
			"To keep %s's copy instead, bring %s back up rather than removing it; `lv doctor firmware-move %s` then names its exits",
			v.source, host, name, v.source, host, name, host, host, name)
	case fwCopyNvram:
		return head + open + fmt.Sprintf("The guest ran on %s after the release, so its newest firmware state is there. "+
			"If %s can come back, bring it back up rather than removing it, then run "+
			"`lv doctor firmware-move %s --confirm-target-nvram --accept-nvram-hash=<sha256>`, or "+
			"`lv doctor firmware-move %s --push-source-nvram --acknowledge-rollback` once its guest is powered off. "+
			"If it cannot, settle it before removing %s: `lv doctor firmware-move %s --accept-source --acknowledge-rollback` "+
			"returns the VM to %s, stopped, from %s's older state, and gives up the newer %s on %s",
			host, host, name, name, host, name, v.source, v.source, map[bool]string{true: "NVRAM and TPM state", false: "NVRAM"}[v.tpm], host)
	case fwCopyPaused:
		return head + open + fmt.Sprintf("The guest is paused on %s with its state. "+
			"`lv doctor firmware-move %s --accept-source` needs %s to answer: bring %s back up rather than removing it, then run it. "+
			"Until then %s keeps the paused guest and its state",
			v.source, name, host, host, v.source)
	}
	return head + fmt.Sprintf("Whether another host still holds its firmware state could not be confirmed (%s). "+
		"Do not delete it. Before removing %s, run `lv doctor firmware-move %s`: it lists every host's records of a live "+
		"firmware move and the exit each allows. `lv health` shows the open firmware_migration conditions",
		v.why, host, name)
}

// deadRemovalFirmwareRefusal is `lv host rm --dead`'s refusal while a Secure
// Boot / vTPM VM recorded on host has a live firmware move to it that is not
// settled, or whose state could not be checked (lab-2 D2 re-review I-3).
// The doctor's exits all work while host is a fenced member; once removed,
// a re-add is refused while the VM's row is there. --force removes it
// anyway: each such VM stays recorded on host, and a source's copy stays
// for `lv doctor firmware-move`.
func (s *Server) deadRemovalFirmwareRefusal(ctx context.Context, host string) error {
	cands, err := s.firmwareMoveCandidates(ctx, host)
	if err != nil {
		return status.Errorf(codes.Unavailable, "list the firmware VMs that may be moving to %s: %v", host, err)
	}
	var open []string
	silent := map[string]bool{}
	for _, vm := range cands {
		v := s.firmwareMoveSourceCopy(ctx, vm.Name, host)
		if v.kind == fwCopyNone {
			continue
		}
		open = append(open, firmwareMoveDetail(vm.Name, vm.HostName, host, v))
		for _, h := range v.silent {
			silent[h] = true
		}
	}
	if len(open) == 0 {
		return nil
	}
	note := ""
	if len(silent) > 0 {
		hs := slices.Sorted(maps.Keys(silent))
		note = fmt.Sprintf(" %s did not answer: one host that does not answer leaves every firmware VM checked through it "+
			"unconfirmed, and each such VM waits up to %s for its own check. If %s is itself gone for good, --force is the way out.",
			strings.Join(hs, ", "), fwCleanupAliveReadTimeout, strings.Join(hs, ", "))
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s is the target of %d live firmware move(s) that are not settled, and removing it would leave no way to bring it back for them:\n  %s\n"+
			"Settle each first. Or run `lv host rm --dead --force %s` to remove it anyway: each such VM stays where it is recorded, "+
			"and a source's copy stays for `lv doctor firmware-move <vm>`.%s",
		host, len(open), strings.Join(open, "\n  "), host, note)
}

// migratingToward is the target host a migrating row's detail names
// (migratingDetail), "" when it names none.
func migratingToward(detail string) string {
	h, ok := strings.CutPrefix(detail, migratingDetailPrefix)
	if !ok {
		return ""
	}
	return strings.TrimSpace(h)
}

// firmwareMoveCandidates are the Secure Boot / vTPM VMs that may have a live
// firmware move to host, wherever their row is: those recorded on host,
// those an open firmware_migration condition names with host as target, and
// those migrating toward it (row state migrating, detail naming host).
func (s *Server) firmwareMoveCandidates(ctx context.Context, host string) ([]corrosion.VMRecord, error) {
	names := map[string]bool{}
	vms, err := corrosion.ListVMs(ctx, s.db, "", host)
	if err != nil {
		return nil, err
	}
	for _, vm := range vms {
		names[vm.Name] = true
	}
	for code := range firmwareMigrationConditionSeverity {
		conds, err := corrosion.ListOpenHealthConditionsByCode(ctx, s.db, firmwareMigrationEvaluator, code)
		if err != nil {
			return nil, err
		}
		for _, c := range conds {
			var ev struct {
				Target string `json:"target"`
			}
			if json.Unmarshal([]byte(c.Evidence), &ev) != nil || ev.Target == host {
				names[c.SubjectID] = true
			}
		}
	}
	all, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, err
	}
	for _, vm := range all {
		if vm.State == "migrating" && migratingToward(vm.StateDetail) == host {
			names[vm.Name] = true
		}
	}
	var out []corrosion.VMRecord
	for _, n := range slices.Sorted(maps.Keys(names)) {
		full, err := corrosion.GetVM(ctx, s.db, n)
		if err != nil {
			return nil, err
		}
		if full != nil && corrosion.VMUsesFirmwareState(*full) {
			out = append(out, *full)
		}
	}
	return out, nil
}

// firmwareOnDeadHostDetail is what `lv host rm --dead` says about a Secure
// Boot / vTPM VM on the host it removes. It carries no next attempt.
func firmwareOnDeadHostDetail(name, host string) string {
	return fmt.Sprintf("vm/%s uses Secure Boot / vTPM: failover never recovers it, because its firmware state "+
		"(UEFI NVRAM, TPM) was kept on %s and is lost with it, and this removal does not change that. Restore it, "+
		"firmware included, from a backup that carried it: `lv backup restore-live --repo <repo> --vm %s --disk "+
		"<disk> --timestamp <ts> --auto-start --blockpull --name <new>` (--blockpull localizes the disk: keep the "+
		"command running until it prints [LOCALIZED], since stopping it earlier takes the disk's source away "+
		"from the running guest; --name while this record still holds %s). If %s's "+
		"disks survive, it returns with %s when the machine is added again under that name (`lv host add`). "+
		"Otherwise remove it with `lv rm %s` and create it again",
		name, host, name, name, host, host, name)
}

func (s *Server) strandedFor(ctx context.Context, kind, name, host, proofID string) *pb.StrandedRecovery {
	st := &pb.StrandedRecovery{Kind: kind, Name: name,
		Detail: fmt.Sprintf("%s/%s is recorded on %s; recovered at its current claim attempt", kind, name, host)}
	if proofID == "" {
		return st
	}
	pr, ok, err := corrosion.GetActionProof(ctx, s.db, proofID)
	if err != nil || !ok || pr.ClaimCertificate == "" {
		return st
	}
	cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
	if err != nil {
		return st
	}
	st.NextAttempt = cert.Key.Attempt + 1
	st.Detail = fmt.Sprintf("%s/%s was decided for %s at attempt %d (proof %s); it retries at attempt %d",
		kind, name, host, cert.Key.Attempt, pr.ID, cert.Key.Attempt+1)
	return st
}

// PlanDeadHostRemoval reports what `lv host rm --dead` would do (and is its
// --dry-run): the fence it rests on, whether the host is a voter to remove
// first, and the recoveries its removal unblocks.
func (s *Server) PlanDeadHostRemoval(ctx context.Context, req *pb.PlanDeadHostRemovalRequest) (*pb.PlanDeadHostRemovalResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	h, err := corrosion.GetHost(ctx, s.db, name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", name)
	}
	resp := &pb.PlanDeadHostRemovalResponse{Host: name, HostState: h.State,
		FenceCommand: "lv host fence-confirm " + name}
	if fr, ok, err := corrosion.HostProofGradeFence(ctx, s.db, name); err != nil {
		return nil, status.Errorf(codes.Unavailable, "read fencing_log: %v", err)
	} else if ok {
		resp.Fenced = true
		resp.FenceDetail = fmt.Sprintf("%s %s at %s (fencing_log %s)", fr.Method, fr.Result, fr.Timestamp, fr.ID)
	} else {
		resp.FenceDetail = s.fenceLifeNote(ctx, name)
	}
	if h.State == "active" {
		// A host the cluster believes is up is not dead, whatever an old fence
		// row says.
		resp.Fenced = false
		resp.FenceDetail = name + " is active"
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the voter set: %v", err)
	}
	if _, member := cfg.Member(name); member {
		resp.Voter, resp.VoterGeneration = true, cfg.Generation
	}
	if resp.Stranded, err = s.strandedOn(ctx, name); err != nil {
		return nil, status.Errorf(codes.Unavailable, "list %s's workloads: %v", name, err)
	}
	return resp, nil
}

// deadRemovalRefusal is RemoveHost's own check for `--dead`: the host is
// fenced proof-grade and not active. The CLI checks first and names the fix;
// this is the boundary a caller cannot skip.
func (s *Server) deadRemovalRefusal(ctx context.Context, h *corrosion.HostRecord) error {
	if h.State == "active" {
		return status.Errorf(codes.FailedPrecondition, "%s is active; --dead removes a host that is fenced and gone for good", h.Name)
	}
	if _, ok, err := corrosion.HostProofGradeFence(ctx, s.db, h.Name); err != nil {
		return status.Errorf(codes.Unavailable, "read fencing_log: %v", err)
	} else if !ok {
		note := ""
		if n := s.fenceLifeNote(ctx, h.Name); n != "" {
			note = "; " + n
		}
		return status.Errorf(codes.FailedPrecondition,
			"%s has no proof-grade fence (an IPMI or Redfish power-off, or `lv host fence-confirm %s` once it is powered off)%s; "+
				"--dead removes only a host proven off", h.Name, h.Name, note)
	}
	return nil
}

// fenceLifeNote says why a proof-grade fence on record does not count for
// host: it is older than the host's current life (corrosion.HostFenceLife).
// "" when there is no such fence.
func (s *Server) fenceLifeNote(ctx context.Context, host string) string {
	since, state, ok, err := corrosion.HostFenceLife(ctx, s.db, host)
	if err != nil || !ok {
		return ""
	}
	rows, err := s.db.Query(ctx, `SELECT method, result FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if corrosion.FenceProofGrade(r.String("method"), r.String("result")) {
			return fmt.Sprintf("its fence on record predates its current life (recorded %s since about %s), so it is about "+
				"an earlier life of %s, such as a machine removed under its name, and does not count",
				state, since.Format(time.RFC3339), host)
		}
	}
	return ""
}

// ── ha.claim.stranded (§3.12, §5.4) ────────────────────────────────────────

const (
	claimEvaluator    = "recovery_claim"
	condClaimStranded = "ha.claim.stranded"
	// condClaimUncertified names each pending recovery minted without a
	// certificate before recovery claims were enforced, which its destination
	// refuses until the lease holder has claimed it (certifyUncertified).
	condClaimUncertified = "ha.claim.uncertified"
	// condClaimLegacyHeld names each workload whose incarnation-scoped claim
	// re-proposed a decision made at the legacy key before
	// claim_incarnation_v1 latched, which its destination could not show to be
	// another incarnation's (Server.legacyValueExcluded,
	// docs/design/recovery-claims.md §10 item 37).
	condClaimLegacyHeld  = "ha.claim.legacy_held"
	claimConditionSubjct = "claims"
)

// strandedClaims finds every workload whose recovery was DECIDED for a
// destination that cannot run it: pending on a host that is fenced, offline or
// otherwise not voting-eligible, under a certified proof. No abandonment can be
// obtained from a dead destination, and it might come back and execute its
// valid certificate, so the workload stays — deliberately — until the
// destination is removed for good. Each line names the command.
func (s *Server) strandedClaims(ctx context.Context) (map[string]string, error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, err
	}
	down := map[string]string{}
	for _, h := range hosts {
		if !health.VotingEligible(h.State) {
			down[h.Name] = h.State
		}
	}
	out := map[string]string{}
	for host, state := range down {
		recs, err := s.strandedOn(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if r.GetNextAttempt() == 0 {
				continue // left on the host, not decided for it: ordinary recovery
			}
			fence := ""
			if _, ok, _ := corrosion.HostProofGradeFence(ctx, s.db, host); !ok {
				fence = fmt.Sprintf("`lv host fence-confirm %s` once it is powered off, then ", host)
			}
			out[host] = strings.TrimSpace(out[host] + fmt.Sprintf(" %s/%s is decided for %s, which is %s and cannot run it; "+
				"if %s is gone for good, %s`lv host rm --dead %s` (try --dry-run first) lets it retry at attempt %d.",
				r.GetKind(), r.GetName(), host, state, host, fence, host, r.GetNextAttempt()))
		}
	}
	return out, nil
}

// uncertifiedClaims is ha.claim.uncertified's evidence, one line per
// destination: each pending proof minted without a certificate before
// recovery claims were enforced. Its destination refuses it
// (recovery_claim_unproven) until the lease holder has claimed it for its own
// value; one that binds no proof-grade fence of its old owner names no owner
// for the voters to probe, so it cannot be claimed and will not run while
// recovery claims are enforced.
func (s *Server) uncertifiedClaims(ctx context.Context) (map[string]string, error) {
	pending, err := corrosion.UncertifiedPendingProofs(ctx, s.db)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, pr := range pending {
		var line string
		if src, ok := corrosion.UncertifiedProofSource(pr.ActionProof); ok {
			line = fmt.Sprintf("%s/%s's %s to %s (proof %s) has no recovery-claim certificate; the lease holder "+
				"claims it for its old owner %s on its next tick (a refusal shows in `lv cluster claim %s/%s`).",
				pr.TargetKind, pr.TargetName, pr.Action, pr.DestHost, pr.ID, src, pr.TargetKind, pr.TargetName)
		} else {
			line = fmt.Sprintf("%s/%s's %s to %s (proof %s) has no recovery-claim certificate and binds no "+
				"proof-grade fence of its old owner, so no claim can name the owner for the voters to probe; it will "+
				"not run while recovery claims are enforced. Set enforcement.recovery_claim false on every host "+
				"until it has run, then turn it back on.",
				pr.TargetKind, pr.TargetName, pr.Action, pr.DestHost, pr.ID)
		}
		out[pr.DestHost] = strings.TrimSpace(out[pr.DestHost] + " " + line)
	}
	return out, nil
}

// RecoveryClaimHealthTick is the lease holder's pass over the recovery-claim
// health conditions, run each tick it holds the failover lease (like
// VoterGenesisTick): ha.claim.stranded names every workload decided for a
// destination that cannot run it, with the command that unblocks it. It
// also evaluates host.address_shared, which is the lease holder's to write
// too.
func (s *Server) RecoveryClaimHealthTick(ctx context.Context) {
	if s.db == nil {
		return
	}
	s.applyHostAddressShared(ctx)
	s.applyVoterConditions(ctx)
	s.applyVoterUnavailable(ctx)
	if !s.RecoveryClaimEnforced(ctx) {
		s.applyClusterCondition(ctx, claimEvaluator, condClaimStranded, claimConditionSubjct, nil, nil, "")
		s.applyClusterCondition(ctx, claimEvaluator, condClaimUncertified, claimConditionSubjct, nil, nil, "")
		s.resolveLegacyHeld(ctx, true)
		return
	}
	s.resolveLegacyHeld(ctx, false)
	if waiting, err := s.uncertifiedClaims(ctx); err != nil {
		slog.Warn("recovery claims: evaluate uncertified proofs", "error", err)
	} else {
		var dests []string
		for h := range waiting {
			dests = append(dests, h)
		}
		s.applyClusterCondition(ctx, claimEvaluator, condClaimUncertified, claimConditionSubjct, waiting, dests,
			"recoveries minted before recovery claims were enforced, refused by their destinations until claimed: ")
	}
	stranded, err := s.strandedClaims(ctx)
	if err != nil {
		slog.Warn("recovery claims: evaluate stranded claims", "error", err)
		return
	}
	var hosts []string
	for h := range stranded {
		hosts = append(hosts, h)
	}
	s.applyClusterCondition(ctx, claimEvaluator, condClaimStranded, claimConditionSubjct, stranded, hosts,
		"recoveries decided for a destination that cannot run them: ")
}

// applyClusterCondition raises a cluster-scoped condition with one line per
// host in lines, or resolves it when lines is empty — the genesis-pending
// shape, shared by the recovery-claim conditions. The lease holder is the only
// writer.
func (s *Server) applyClusterCondition(ctx context.Context, evaluator, code, subject string, lines map[string]string, hostList []string, prefix string) {
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, evaluator, code, "cluster", subject)
	if err != nil {
		slog.Warn("health condition: read", "code", code, "error", err)
		return
	}
	if len(lines) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("health condition: resolve", "code", code, "error", err)
		}
		return
	}
	var text []string
	for _, why := range lines {
		text = append(text, why)
	}
	hosts := dedupSorted(hostList)
	sort.Strings(text)
	detail := prefix + strings.Join(text, " ")
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: evaluator, Code: code, SubjectKind: "cluster", SubjectID: subject,
			Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = hosts
	row.Evidence = encodeEvidence(detail, hosts)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("health condition: persist", "code", code, "error", err)
	}
}
