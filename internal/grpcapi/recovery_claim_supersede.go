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
	ab, err := s.abandonRecoveryProof(ctx, keyFromPB(req.GetKey()), req.GetProofId(), req.GetReason())
	if err != nil {
		return nil, err
	}
	enc, err := ab.Encode()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode abandonment: %v", err)
	}
	return &pb.AbandonRecoveryProofResponse{Abandonment: enc}, nil
}

func (s *Server) abandonRecoveryProof(ctx context.Context, key corrosion.ClaimKey, proofID, reason string) (corrosion.ClaimAbandonment, error) {
	if !key.IsWorkload() || proofID == "" {
		return corrosion.ClaimAbandonment{}, status.Error(codes.InvalidArgument, "an abandonment names a workload claim key and a proof")
	}
	signer, _, err := s.claimIdentity()
	if err != nil {
		return corrosion.ClaimAbandonment{}, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if err := s.db.AbandonProof(ctx, proofID, key, reason); err != nil {
		if errors.Is(err, corrosion.ErrProofExecuted) {
			return corrosion.ClaimAbandonment{}, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return corrosion.ClaimAbandonment{}, status.Errorf(codes.Unavailable, "record abandonment: %v", err)
	}
	slog.Warn("recovery claims: abandoned a decided recovery this host will never execute",
		"key", key.String(), "proof", proofID, "reason", reason)
	s.audit(ctx, "recovery_claim.abandon", key.TargetKind+"/"+key.TargetName,
		fmt.Sprintf("proof %s at %s: %s", proofID, key, reason), "ok")
	return signer.SignAbandonment(proofID, key, reason)
}

// RequestAbandonment asks host — this node, or a peer over the claim RPC — to
// abandon proofID at key, and returns the encoded signed abandonment. The
// failover coordinator calls it when a promote it decided failed before
// StartDomain and it falls back to a reschedule (§3.12).
func (s *Server) RequestAbandonment(ctx context.Context, host string, key corrosion.ClaimKey, proofID, reason string) (string, error) {
	if host == s.hostName {
		ab, err := s.abandonRecoveryProof(ctx, key, proofID, reason)
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
	resp, err := cl.AbandonRecoveryProof(cctx, &pb.AbandonRecoveryProofRequest{Key: keyToPB(key), ProofId: proofID, Reason: reason})
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
		out = append(out, s.strandedFor(ctx, "vm", full.Name, host, full.PendingActionID))
	}
	cts, err := corrosion.ListContainers(ctx, s.db, host)
	if err != nil {
		return nil, err
	}
	for _, ct := range cts {
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
		return status.Errorf(codes.FailedPrecondition,
			"%s has no proof-grade fence (an IPMI power-off, or `lv host fence-confirm %s` once it is powered off); "+
				"--dead removes only a host proven off", h.Name, h.Name)
	}
	return nil
}

// ── ha.claim.stranded (§3.12, §5.4) ────────────────────────────────────────

const (
	claimEvaluator       = "recovery_claim"
	condClaimStranded    = "ha.claim.stranded"
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

// RecoveryClaimHealthTick is the lease holder's pass over the recovery-claim
// health conditions, run each tick it holds the failover lease (like
// VoterGenesisTick): ha.claim.stranded names every workload decided for a
// destination that cannot run it, with the command that unblocks it.
func (s *Server) RecoveryClaimHealthTick(ctx context.Context) {
	if s.db == nil {
		return
	}
	if !s.RecoveryClaimEnforced(ctx) {
		s.applyClusterCondition(ctx, claimEvaluator, condClaimStranded, claimConditionSubjct, nil, nil, "")
		return
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
