package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// nonWorkloadTargetError is why host cannot take a migrated workload, as a
// FailedPrecondition naming the host and the role or state that rules it out;
// nil when it can. A witness is a tiebreaker: it is `active` and answers
// every request, but the execution gate (health.localWorkerIn) refuses any
// start or move on it, so a workload landed there can neither start nor leave
// by the ordinary route. A host that is not active (draining, maintenance,
// fenced, offline...) takes on no new work either. Placement applies the same
// rules to a chosen host (placement.restrictToPinnedHost); an explicit
// migrate target never went through placement.
//
// "is not active" is the wording failback matches on: keep it. The witness
// refusal deliberately lacks it: failback retries because a host that is
// returning to service becomes active in a moment, and a role is replicated
// configuration that does not change under a retry, so retrying a witness
// would only wait out the budget for the same answer.
func nonWorkloadTargetError(h *corrosion.HostRecord) error {
	if h.IsWitness() {
		return status.Errorf(codes.FailedPrecondition,
			"target host %q is a witness (role: %s) and runs no workloads: a workload moved there could not start or be moved off by the ordinary route; choose a worker host",
			h.Name, h.Role)
	}
	if h.State != "active" {
		return status.Errorf(codes.FailedPrecondition,
			"target host %q is not active (state: %s)", h.Name, h.State)
	}
	return nil
}

// refuseSelfWitnessTarget is the target-side half of the same rule: a helper
// RPC that stages a migration on THIS host refuses when this host is a
// witness. The source's own check cannot protect a target against an older
// source that never makes it (a mixed-version rollout), so the target decides
// for itself. Only the role is judged here, never the state: a host that
// began draining after the source's check must still be able to finish and
// roll back what is already in flight, and a witness's role is replicated
// configuration that does not change under a move. A host with no row of its
// own decides nothing; a read that fails refuses, since nothing has been
// staged yet. Cleanup and rollback RPCs do not call it: they must still
// work on whatever a refused or older move left behind.
func (s *Server) refuseSelfWitnessTarget(ctx context.Context, what string) error {
	h, err := corrosion.GetHost(ctx, s.db, s.hostName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read this host's record to check it runs workloads: %v", err)
	}
	if h == nil || !h.IsWitness() {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s refused: host %q is a witness (role: %s) and runs no workloads; choose a worker host",
		what, s.hostName, h.Role)
}

// witnessLocalHint is the extra a gate refusal carries when this host is a
// witness: the bare local_not_active_worker names neither the role nor the
// way out. The way out is a migration to a worker, which a witness admits
// (health.localHostIsEvacuatingWorker).
func (s *Server) witnessLocalHint(ctx context.Context) (string, bool) {
	h, err := corrosion.GetHost(ctx, s.db, s.hostName)
	if err != nil || h == nil || !h.IsWitness() {
		return "", false
	}
	return fmt.Sprintf("host %s is a witness (role: %s) and runs no workloads; "+
		"move a VM stranded on it to a worker host with `lv migrate <vm> <worker-host> --cold`",
		s.hostName, h.Role), true
}
