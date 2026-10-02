package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// `lv cluster claim-release <kind>/<name>` (docs/design/recovery-claims.md
// §10 item 37): the scoped escape for one workload held by ha.claim.legacy_held
// behind a legacy decision whose proof is stuck in flight on a live
// destination. Before it, the only escape was the cluster-wide stand-down
// (enforcement.recovery_claim: false on every host).
//
// The release is the destination's, not the operator's. The operator's
// command asks the destination for the same signed foreign abandonment the
// bridge asks for, and may override exactly one of its refusals — a proof the
// destination claimed and left in progress — and only once the destination
// has confirmed, from its own state and under the workload's own locks, that
// nothing runs it (holdWorkloadIdle). The abandonment is recorded in the
// destination's node-local table, which every claim of the proof reads in its
// own transaction, so no runner can take the proof afterwards: not another
// host, and not the destination resuming its own claim. A destination that
// does not answer cannot confirm anything, and the command refuses and points
// at `lv host rm --dead`.

// claimReleaseLockHolder is the per-VM start-lease identity the release takes
// while it confirms a VM idle, distinct from every start path's
// (health.reconcilerLockHolder and the rest) so neither can re-take or free
// the other's lease.
func claimReleaseLockHolder(hostName string) string { return hostName + "/claim-release" }

// holdWorkloadIdle is a destination's confirmation that nothing on this node
// runs a proof for kind/name. It takes every local hold a runner of such a
// proof takes, and returns their release:
//
//   - a VM: the in-process operation lock (lockVM) and the per-VM start lease
//     (health.TryVMStartLease), which the reconciler holds for a whole
//     reschedule start; a promote holds neither, but records its start
//     checkpoint through AppendProofStepUnlessAbandoned, so the abandonment
//     refuses it there, and a promote past that checkpoint is never
//     released (corrosion.AbandonForeignProofInFlight);
//   - a container: the container operation lock (TryLockContainer), which the
//     container sweep holds through a relocation's recreate.
//
// Under those holds there must be no live runtime of the name here: no
// active domain, no running container. Anything it cannot confirm — a hold
// taken by someone else, no backend wired, a runtime read error — is a
// refusal.
func (s *Server) holdWorkloadIdle(ctx context.Context, kind, name string) (func(), error) {
	switch kind {
	case corrosion.ClaimKindVM:
		mu := s.vmMutex(name)
		if !mu.TryLock() {
			return nil, fmt.Errorf("an operation on vm/%s is in progress on %s", name, s.hostName)
		}
		holder := claimReleaseLockHolder(s.hostName)
		heldBy, err := health.TryVMStartLease(ctx, s.db, holder, name, time.Now())
		if err != nil || heldBy != holder {
			mu.Unlock()
			if err != nil {
				return nil, fmt.Errorf("take vm/%s's start lease on %s: %v", name, s.hostName, err)
			}
			return nil, fmt.Errorf("a start of vm/%s is in progress on %s (its start lease is held by %s)", name, s.hostName, heldBy)
		}
		release := func() {
			health.ReleaseVMStartLease(context.WithoutCancel(ctx), s.db, holder, name)
			mu.Unlock()
		}
		if s.virt == nil {
			release()
			return nil, fmt.Errorf("%s has no libvirt backend to confirm vm/%s is not running", s.hostName, name)
		}
		if s.virt.DomainExists(name) {
			active, err := s.virt.DomainIsActive(name)
			if err != nil || active {
				release()
				if err != nil {
					return nil, fmt.Errorf("read vm/%s's domain on %s: %v", name, s.hostName, err)
				}
				return nil, fmt.Errorf("a domain of vm/%s is active on %s", name, s.hostName)
			}
		}
		return release, nil
	case corrosion.ClaimKindContainer:
		unlock, ok := s.TryLockContainer(name)
		if !ok {
			return nil, fmt.Errorf("an operation on container/%s is in progress on %s", name, s.hostName)
		}
		if s.containerRuntime == nil {
			unlock()
			return nil, fmt.Errorf("%s has no container runtime to confirm container/%s is not running", s.hostName, name)
		}
		exists, err := s.containerRuntime.ContainerExists(ctx, name)
		if err != nil {
			unlock()
			return nil, fmt.Errorf("read container/%s on %s: %v", name, s.hostName, err)
		}
		if exists {
			st, err := s.containerRuntime.StateContainer(ctx, name)
			if err != nil || !strings.EqualFold(st, "stopped") {
				unlock()
				if err != nil {
					return nil, fmt.Errorf("read container/%s's state on %s: %v", name, s.hostName, err)
				}
				return nil, fmt.Errorf("container/%s is %s on %s", name, strings.ToLower(st), s.hostName)
			}
		}
		return unlock, nil
	}
	return nil, fmt.Errorf("unknown workload kind %q", kind)
}

// ReleaseLegacyHeldClaim is `lv cluster claim-release <kind>/<name>`
// (admin). Every call writes an audit row, refused or not.
func (s *Server) ReleaseLegacyHeldClaim(ctx context.Context, req *pb.ReleaseLegacyHeldClaimRequest) (*pb.ReleaseLegacyHeldClaimResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	kind, name := strings.TrimSpace(req.GetKind()), strings.TrimSpace(req.GetName())
	if kind != corrosion.ClaimKindVM && kind != corrosion.ClaimKindContainer {
		return nil, status.Errorf(codes.InvalidArgument, "a claim is for a vm or a container, not %q", kind)
	}
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name the workload: <kind>/<name>")
	}
	resp, err := s.releaseLegacyHeld(ctx, kind, name)
	if err != nil {
		s.audit(ctx, "recovery_claim.release", kind+"/"+name, status.Convert(err).Message(), "refused")
		return nil, err
	}
	s.audit(ctx, "recovery_claim.release", kind+"/"+name,
		fmt.Sprintf("%s abandoned proof %s at %s", resp.GetDestHost(), resp.GetProofId(), resp.GetKey()), "ok")
	return resp, nil
}

func (s *Server) releaseLegacyHeld(ctx context.Context, kind, name string) (*pb.ReleaseLegacyHeldClaimResponse, error) {
	if !s.RecoveryClaimEnforced(ctx) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"recovery claims are not enforced on %s, so no claim holds %s/%s", s.hostName, kind, name)
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, claimEvaluator, condClaimLegacyHeld, kind, name)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read %s for %s/%s: %v", condClaimLegacyHeld, kind, name, err)
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		return nil, status.Errorf(codes.NotFound,
			"no open %s names %s/%s; a release is only for a workload that condition holds", condClaimLegacyHeld, kind, name)
	}
	var ev legacyHeldEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.Proof == "" || len(ev.Hosts) != 1 ||
		ev.Key.TargetKind != kind || ev.Key.TargetName != name || ev.Key.Incarnation == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "%s for %s/%s carries no decision this release can name", condClaimLegacyHeld, kind, name)
	}
	dest := ev.Hosts[0]
	if !s.legacyHeldStill(ctx, ev) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s/%s has moved on from proof %s; the lease holder resolves %s on its next tick", kind, name, ev.Proof, condClaimLegacyHeld)
	}
	if err := corrosion.RemovedHostEvidence(ctx, s.db, s.pkiDir, dest); err == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s has been removed for good, so the next tick excludes proof %s without a release", dest, ev.Proof)
	}
	reason := fmt.Sprintf("operator release of a legacy-held claim (lv cluster claim-release %s/%s) by %s",
		kind, name, callerUsername(ctx))
	enc, err := s.requestRelease(ctx, dest, ev.Key, ev.Proof, reason)
	if err != nil {
		return nil, releaseRefusal(dest, ev.Proof, err)
	}
	ab, err := corrosion.DecodeClaimAbandonment(enc)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s's abandonment of proof %s: %v", dest, ev.Proof, err)
	}
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if err := verifier.VerifyAbandonment(ab, dest, ev.Proof, ev.Key); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s's abandonment of proof %s does not verify: %v", dest, ev.Proof, err)
	}
	return &pb.ReleaseLegacyHeldClaimResponse{DestHost: dest, ProofId: ev.Proof, Key: ev.Key.String(),
		Detail: fmt.Sprintf("%s confirmed nothing runs proof %s and signed that it never will; the next recovery tick "+
			"decides %s/%s afresh, and %s resolves once it has moved on", dest, ev.Proof, kind, name, condClaimLegacyHeld)}, nil
}

// requestRelease asks dest — this node, or a peer — for the operator release
// of proofID at key.
func (s *Server) requestRelease(ctx context.Context, dest string, key corrosion.ClaimKey, proofID, reason string) (string, error) {
	if dest == s.hostName {
		ab, err := s.abandonRecoveryProof(ctx, key, proofID, reason, true, true)
		if err != nil {
			return "", err
		}
		return ab.Encode()
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cl, closer, err := s.dialPeer(cctx, dest)
	if err != nil {
		return "", err
	}
	defer closer()
	resp, err := cl.AbandonRecoveryProof(cctx, &pb.AbandonRecoveryProofRequest{Key: keyToPB(key), ProofId: proofID,
		Reason: reason, ForeignOnly: true, OperatorRelease: true})
	if err != nil {
		return "", err
	}
	return resp.GetAbandonment(), nil
}

// releaseRefusal names why a release did not happen. A destination that
// answered and refused says why; one that did not answer cannot confirm that
// nothing runs the proof, and the way out for a destination that is gone is
// its removal.
func releaseRefusal(dest, proofID string, err error) error {
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.FailedPrecondition, codes.InvalidArgument:
			return status.Errorf(codes.FailedPrecondition, "%s refused to release proof %s: %s", dest, proofID, st.Message())
		case codes.Unimplemented:
			return status.Errorf(codes.FailedPrecondition,
				"%s cannot release proof %s (an older build); upgrade it and run the release again", dest, proofID)
		}
	}
	if errors.Is(err, context.Canceled) {
		return status.FromContextError(err).Err()
	}
	return status.Errorf(codes.Unavailable,
		"%s did not answer (%v): only the destination can confirm that nothing runs proof %s, so nothing was released. "+
			"If %s is gone for good, `lv host fence-confirm %s` once it is powered off, then `lv host rm --dead %s` "+
			"releases the decision.", dest, err, proofID, dest, dest, dest)
}
