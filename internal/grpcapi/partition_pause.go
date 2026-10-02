package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// partitionResumeRPCTimeout bounds each voter's answer to the resume check.
const partitionResumeRPCTimeout = 3 * time.Second

// ConfirmPartitionResume is the majority check a self-paused workload must pass
// before it resumes (docs/design/partition-pause.md §3.5 step 3), wired as the
// PartitionPauser's ResumeConfirmer.
//
// It asks every OTHER voter of this node's voter set, directly and not through
// this node's replica, which a healed partition leaves stale:
//
//   - its replica's state of this host (ListHosts). Every recovery is preceded
//     by a fence that writes this host fenced or offline, which the majority
//     side holds for at least the pause wait before anything starts;
//   - while a voter generation is adopted, whether it has accepted any
//     recovery-claim value for the workload at the recorded epoch and
//     incarnation, attempt 0, under the incarnation-scoped key or the legacy
//     one (GetRecoveryClaim). A decided claim needs a majority of accepts, and
//     this host never accepts its own eviction.
//
// A workload is confirmed only with clean answers from enough voters that,
// with this host, they are a majority — any two majorities of one set
// intersect — and no answer objecting (health.DecideResume). An unreachable
// voter, or one on an older build, is not an answer.
func (s *Server) ConfirmPartitionResume(ctx context.Context, recs []health.PauseRecord) map[string]health.ResumeVerdict {
	out := make(map[string]health.ResumeVerdict, len(recs))
	voters, err := corrosion.VoterSet(ctx, s.db)
	if err != nil {
		for _, r := range recs {
			out[r.Key()] = health.ResumeVerdict{Reason: "voter set unreadable: " + err.Error()}
		}
		return out
	}
	need := len(voters)/2 + 1
	if voters[s.hostName] {
		need--
	}
	adopted, _ := corrosion.AdoptedVoterGeneration(ctx, s.db)
	names := make([]string, 0, len(voters))
	for v := range voters {
		if v != s.hostName {
			names = append(names, v)
		}
	}
	sort.Strings(names)
	answers := make([]health.VoterAnswer, len(names))
	var wg sync.WaitGroup
	for i, v := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i] = s.askPartitionResume(ctx, v, recs, adopted > 0)
		}()
	}
	wg.Wait()
	for _, r := range recs {
		out[r.Key()] = health.DecideResume(r, answers, need)
	}
	return out
}

// askPartitionResume collects one voter's answer for every record.
func (s *Server) askPartitionResume(ctx context.Context, voter string, recs []health.PauseRecord, claims bool) health.VoterAnswer {
	a := health.VoterAnswer{Voter: voter, Accepted: map[string]string{}}
	cctx, cancel := context.WithTimeout(ctx, partitionResumeRPCTimeout)
	defer cancel()
	client, conn, err := s.peerClient(cctx, voter)
	if err != nil {
		a.Err = err
		return a
	}
	defer conn.Close()
	hosts, err := client.ListHosts(cctx, &pb.ListHostsRequest{})
	if err != nil {
		a.Err = fmt.Errorf("list hosts: %w", err)
		return a
	}
	found := false
	for _, h := range hosts.GetHosts() {
		if h.GetName() != s.hostName {
			continue
		}
		found = true
		a.HostState = h.GetState().String()
		a.HostDown = h.GetState() == pb.HostState_HOST_OFFLINE
	}
	if !found {
		a.HostDown, a.HostState = true, "absent"
	}
	if !claims {
		return a
	}
	for _, r := range recs {
		kind := corrosion.ClaimKindVM
		if r.Kind == health.PauseKindContainer {
			kind = corrosion.ClaimKindContainer
		}
		key := corrosion.ClaimKey{TargetKind: kind, TargetName: r.Name, OwnerEpoch: r.OwnerEpoch, Incarnation: r.Incarnation}
		for _, k := range []corrosion.ClaimKey{key, key.Legacy()} {
			resp, err := client.GetRecoveryClaim(cctx, &pb.GetRecoveryClaimRequest{Key: keyToPB(k)})
			if err != nil {
				a.Err = fmt.Errorf("recovery claim %s: %w", k, err)
				return a
			}
			if v := resp.GetState().GetAcceptedValue(); v != nil && v.GetDestHost() != "" {
				a.Accepted[r.Key()] = v.GetDestHost()
			}
		}
	}
	return a
}

// VerifySettleProof verifies the recovery-claim certificate on p against this
// node's adopted voter generation and the cluster CA
// (corrosion.VerifyClaimCertificate) — the positive proof Layer 3 of
// partition pause needs before it stops a local copy whose row moved
// (docs/design/partition-pause.md §6). Injected into the reconciler, which
// cannot import this package. It checks the certificate whether or not this
// node enforces recovery claims: it is evidence about what a majority decided,
// not a gate on this node's own recoveries.
func (s *Server) VerifySettleProof(ctx context.Context, p corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return corrosion.ClaimCertificate{}, fmt.Errorf("no claim verifier on this node: %w", err)
	}
	return corrosion.VerifyClaimCertificate(ctx, s.db, verifier, p)
}
