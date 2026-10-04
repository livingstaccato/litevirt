package grpcapi

// Failover-scope RPCs: `lv cluster failover-scope` (colonelpanik/litevirt#265,
// docs/design/region-scoped-failover.md).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetFailoverScope reports the failover_scope policy as this host's replica
// holds it, with every region's voting strength.
func (s *Server) GetFailoverScope(ctx context.Context, _ *emptypb.Empty) (*pb.FailoverScopeStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	return s.failoverScopeStatus(ctx)
}

// SetFailoverScope changes the failover_scope policy.
//
// Two preconditions, and each is the answer to a way the change could do harm:
//
//   - failover_scope_v1 must be DURABLY latched here. The latch proves every
//     replication recipient decodes cluster_policies and honours the policy;
//     without it a previous-release peer's stream would stall on the write, and
//     an old coordinator holding the lease would ignore it.
//   - every voter must be reachable from this host. Each node acts on the value
//     in its own replica, so a change made while a partition hides some voters
//     reaches only one side. `region` -> `cluster` is the dangerous direction: a
//     minority that never hears it keeps executing on its region's quorum while
//     the majority, which did, may fence it. A change is therefore made on a
//     whole cluster, and reaches every node before a partition can hide it.
func (s *Server) SetFailoverScope(ctx context.Context, req *pb.SetFailoverScopeRequest) (*pb.FailoverScopeStatus, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	scope := req.GetScope()
	if !corrosion.ValidFailoverScope(scope) {
		return nil, status.Errorf(codes.InvalidArgument, "unknown failover scope %q (valid: %s, %s)",
			scope, corrosion.FailoverScopeCluster, corrosion.FailoverScopeRegion)
	}
	if !s.failoverScopeSettable() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"the failover scope cannot be changed until %s has latched on every host: "+
				"finish rolling every host (and every host in maintenance) to this release first",
			capabilities.FailoverScopeV1)
	}
	if missing, err := s.unreachableVoters(ctx); err != nil {
		return nil, status.Errorf(codes.Unavailable, "check voters are reachable: %v", err)
	} else if len(missing) > 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"the failover scope can only be changed while every voter is reachable, and %s cannot reach %s. "+
				"A change made from one side of a partition reaches only that side. Bring the hosts back, "+
				"or fence and remove the dead ones, then retry",
			s.hostName, strings.Join(missing, ", "))
	}
	if err := corrosion.SetFailoverScope(ctx, s.db, scope, callerUsername(ctx)); err != nil {
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "set failover scope: %v", err)
	}
	s.audit(ctx, "cluster.failover_scope", "failover_scope", "failover scope set to "+scope, "ok")
	s.publish("cluster.failover_scope", scope, "set by "+callerUsername(ctx))
	return s.failoverScopeStatus(ctx)
}

// failoverScopeSettable reports whether this host may write the policy:
// failover_scope_v1 durably latched, as the corrosion gate requires too.
func (s *Server) failoverScopeSettable() bool {
	return s.gate != nil && s.gate.DurablyLatched(capabilities.FailoverScopeV1)
}

// unreachableVoters lists the voters this host cannot currently reach: not
// itself and not among the peers it probed healthy. Without a gate nothing can
// be shown reachable, so every other voter is listed.
func (s *Server) unreachableVoters(ctx context.Context) ([]string, error) {
	voters, err := corrosion.VoterSet(ctx, s.db)
	if err != nil {
		return nil, err
	}
	reach := map[string]bool{s.hostName: true}
	if s.gate != nil {
		for _, p := range s.gate.HealthyPeers(ctx) {
			reach[p] = true
		}
	}
	var missing []string
	for v := range voters {
		if !reach[v] {
			missing = append(missing, v)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func (s *Server) failoverScopeStatus(ctx context.Context) (*pb.FailoverScopeStatus, error) {
	p, err := corrosion.GetFailoverScope(ctx, s.db)
	if err != nil && !errors.Is(err, corrosion.ErrUnknownFailoverScope) {
		return nil, status.Errorf(codes.Internal, "read failover scope: %v", err)
	}
	report, rerr := corrosion.RegionQuorumReport(ctx, s.db)
	if rerr != nil {
		return nil, status.Errorf(codes.Internal, "region quorum report: %v", rerr)
	}
	out := &pb.FailoverScopeStatus{
		Scope: p.Value, SetBy: p.SetBy, UpdatedAt: p.UpdatedAt,
		Settable: s.failoverScopeSettable(),
	}
	if err != nil {
		// Show what is stored, and say it is not understood: every coordinator
		// on this build is deciding nothing until it is replaced.
		out.Scope = fmt.Sprintf("%s (unknown to this build: failover decides nothing until it is set again)", p.Value)
	}
	for _, r := range report {
		out.Regions = append(out.Regions, &pb.FailoverScopeRegion{
			Name: r.Region, Hosts: int32(r.Hosts), Workers: int32(r.Workers),
			Voters: int32(r.Voters), VotingWitnesses: int32(r.VotingWitnesses),
			Quorum: int32(r.Quorum), CanFenceOwn: r.CanFenceOwn(),
		})
	}
	return out, nil
}
