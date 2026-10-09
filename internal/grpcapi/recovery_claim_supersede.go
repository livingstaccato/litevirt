package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Attempt progression and supersede (docs/design/recovery-claims.md §3.12):
// the voter's check of supersede evidence, the destination's signed
// abandonment, the operator's `lv host rm --dead` plan, and the
// ha.claim.stranded condition that points at it.

func supersedeToPB(ev *corrosion.SupersedeEvidence) *pb.RecoveryClaimSupersede {
	if ev == nil {
		return nil
	}
	return &pb.RecoveryClaimSupersede{PriorCertificate: ev.PriorCertificate, PriorValue: valueToPB(ev.PriorValue),
		Abandonment: ev.Abandonment}
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
		if corrosion.VMStoppedForFailover(*full) {
			out = append(out, &pb.StrandedRecovery{Kind: "vm", Name: full.Name, Detail: stoppedOnDeadHostDetail("vm", full.Name, host)})
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
// workload on the host it removes. Failover never starts or moves a stopped
// workload (corrosion.VMRecoverableOnHostFailure), so removing the host does
// not move it either: it stays recorded there, its data with the machine, and
// what happens to that data is the operator's choice, made before the
// removal. It carries no next attempt, so it is not counted as a recovery that
// will retry.
func stoppedOnDeadHostDetail(kind, name, host string) string {
	if kind == "container" {
		return fmt.Sprintf("container/%s is stopped: failover never recreates or starts a stopped container, so it stays "+
			"recorded on %s with its rootfs and is not moved by this removal. To keep its data, bring %s back instead "+
			"of removing it; if the data is lost for good, remove it with `lv ct rm %s --host %s`",
			name, host, host, name, host)
	}
	return fmt.Sprintf("vm/%s is stopped: failover never starts or moves a stopped VM, so it stays recorded on %s "+
		"with its disks and is not moved by this removal. To keep its data, bring %s back instead of removing it, "+
		"or promote a replica onto a live host (`lv replication promote %s`); if the data is lost for good, "+
		"remove it with `lv rm %s` and create it again",
		name, host, host, name, name)
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
			"%s has no proof-grade fence (an IPMI power-off, or `lv host fence-confirm %s` once it is powered off)%s; "+
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
// destination that cannot run it, with the command that unblocks it.
func (s *Server) RecoveryClaimHealthTick(ctx context.Context) {
	if s.db == nil {
		return
	}
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
