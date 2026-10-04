package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// partitionResumeRPCTimeout bounds each voter's answer to the resume check.
const partitionResumeRPCTimeout = 3 * time.Second

// CheckPartitionResume is the majority check a self-paused workload must pass
// before it resumes (docs/design/partition-pause.md §3.5 step 3), wired as the
// PartitionPauser's ResumeConfirmer.
//
// It asks every OTHER voter of this node's voter set, directly and not through
// this node's replica — a healed partition leaves that stale, and an
// anti-entropy exchange with another host of the same minority does not
// freshen it — for the voter's own view (ConfirmPartitionResume):
//
//   - this host's state: every recovery is preceded by a fence that writes
//     this host fenced or offline;
//   - each workload's ROW: its host, owner epoch and incarnation must be what
//     the pause recorded. This is what holds a resume when recovery claims are
//     off, or after `lv host undrain` cleared the fenced state while the
//     replacement still runs, and when the majority moved the workload to an
//     epoch the minority never saw;
//   - any recovery-claim value the voter accepted for the workload at the
//     recorded epoch and incarnation.
//
// A workload is confirmed only with clean answers from enough voters that,
// with this host, they are a majority — any two majorities of one set
// intersect — and no answer objecting (health.DecideResume). An unreachable
// voter, or one on a build without the RPC, is not an answer.
func (s *Server) CheckPartitionResume(ctx context.Context, recs []health.PauseRecord) map[string]health.ResumeVerdict {
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
	names := make([]string, 0, len(voters))
	for v := range voters {
		if v != s.hostName {
			names = append(names, v)
		}
	}
	sort.Strings(names)
	req := &pb.ConfirmPartitionResumeRequest{}
	for _, r := range recs {
		req.Workloads = append(req.Workloads, &pb.PausedWorkload{Kind: claimKindOf(r.Kind), Name: r.Name,
			OwnerEpoch: r.OwnerEpoch, Incarnation: r.Incarnation})
	}
	answers := make([]health.VoterAnswer, len(names))
	var wg sync.WaitGroup
	for i, v := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i] = s.askPartitionResume(ctx, v, req, recs)
		}()
	}
	wg.Wait()
	for _, r := range recs {
		out[r.Key()] = health.DecideResume(r, answers, need)
	}
	return out
}

func claimKindOf(pauseKind string) string {
	if pauseKind == health.PauseKindContainer {
		return corrosion.ClaimKindContainer
	}
	return corrosion.ClaimKindVM
}

// askPartitionResume collects one voter's answer for every record.
func (s *Server) askPartitionResume(ctx context.Context, voter string, req *pb.ConfirmPartitionResumeRequest, recs []health.PauseRecord) health.VoterAnswer {
	a := health.VoterAnswer{Voter: voter, Accepted: map[string]string{}, Rows: map[string]health.RowView{}}
	cctx, cancel := context.WithTimeout(ctx, partitionResumeRPCTimeout)
	defer cancel()
	client, conn, err := s.peerClient(cctx, voter)
	if err != nil {
		a.Err = err
		return a
	}
	defer conn.Close()
	resp, err := client.ConfirmPartitionResume(cctx, req)
	if err != nil {
		a.Err = err
		return a
	}
	a.HostState = resp.GetCallerState()
	a.HostDown = a.HostState == "fenced" || a.HostState == "offline" || a.HostState == "absent"
	views := map[string]*pb.PausedWorkloadView{}
	for _, v := range resp.GetViews() {
		views[v.GetKind()+"/"+v.GetName()] = v
	}
	for _, r := range recs {
		v := views[claimKindOf(r.Kind)+"/"+r.Name]
		if v == nil {
			a.Err = fmt.Errorf("no view of %s", r.Key())
			return a
		}
		a.Rows[r.Key()] = health.RowView{Live: v.GetLive(), Host: v.GetHostName(), OwnerEpoch: v.GetOwnerEpoch(),
			Incarnation: v.GetIncarnation()}
		if d := v.GetAcceptedDest(); d != "" {
			a.Accepted[r.Key()] = d
		}
	}
	return a
}

// ConfirmPartitionResume answers a paused host's resume check from THIS
// voter's own replica and claim tables. Peer-only and read-only.
func (s *Server) ConfirmPartitionResume(ctx context.Context, req *pb.ConfirmPartitionResumeRequest) (*pb.ConfirmPartitionResumeResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	caller := callerMTLSCommonName(ctx)
	if caller == "" {
		return nil, status.Error(codes.PermissionDenied, "partition resume check: no caller identity")
	}
	resp := &pb.ConfirmPartitionResumeResponse{Voter: s.hostName, CallerState: "absent"}
	h, err := corrosion.GetHost(ctx, s.db, caller)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read host %s: %v", caller, err)
	}
	if h != nil {
		resp.CallerState = h.State
	}
	for _, w := range req.GetWorkloads() {
		v := &pb.PausedWorkloadView{Kind: w.GetKind(), Name: w.GetName()}
		switch w.GetKind() {
		case corrosion.ClaimKindVM:
			vm, err := corrosion.GetVM(ctx, s.db, w.GetName())
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "read vm %s: %v", w.GetName(), err)
			}
			if vm != nil {
				v.Live, v.HostName, v.OwnerEpoch, v.Incarnation = true, vm.HostName, vm.OwnerEpoch, corrosion.IncarnationOf(vm.CreatedAt)
			}
		case corrosion.ClaimKindContainer:
			// Container rows are keyed by (host, name): the caller's own row is
			// the one it paused, and a relocation tombstones it.
			ct, err := corrosion.GetContainer(ctx, s.db, caller, w.GetName())
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "read container %s: %v", w.GetName(), err)
			}
			if ct != nil {
				v.Live, v.HostName, v.OwnerEpoch, v.Incarnation = true, ct.HostName, ct.OwnerEpoch, corrosion.IncarnationOf(ct.CreatedAt)
			}
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unknown workload kind %q", w.GetKind())
		}
		key := corrosion.ClaimKey{TargetKind: w.GetKind(), TargetName: w.GetName(), OwnerEpoch: w.GetOwnerEpoch(),
			Incarnation: w.GetIncarnation()}
		for _, k := range []corrosion.ClaimKey{key, key.Legacy()} {
			st, _, err := s.db.ClaimState(ctx, k)
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "read claim state %s: %v", k, err)
			}
			if st.Value != nil && st.Value.Proof != nil && st.Value.Proof.DestHost != "" {
				v.AcceptedDest = st.Value.Proof.DestHost
			}
		}
		resp.Views = append(resp.Views, v)
	}
	return resp, nil
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
