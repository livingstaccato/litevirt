package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ResolveHealthCondition marks one open dual-run condition resolved on an
// admin's word (`lv health resolve`).
//
// The detector resolves its own conditions only on proof: two complete clean
// scans under a valid gate. A condition that proof can never reach — one its
// evaluator can no longer see, or one stranded by a fault in the evaluator —
// would otherwise refuse admission to the hosts it names for good, with no way
// out. This is that way out, and it proves nothing: it records who resolved
// what and why, in the audit log and as an ha.condition.resolved event.
//
// It is limited to the dual-run detector's conditions. Those are the only ones
// that gate admission, and the detector re-derives every finding from scratch
// each pass, so a condition that still holds is raised again — observed, and
// gating admission again — on its next pass. Other evaluators write on their
// own transitions and could leave a still-true condition resolved.
//
// Admin only (cluster.health.resolve), and never a peer: a peer certificate
// authorizes as admin, and a node must not be able to clear evidence that
// names it.
func (s *Server) ResolveHealthCondition(ctx context.Context, req *pb.ResolveHealthConditionRequest) (*pb.ResolveHealthConditionResponse, error) {
	if callerPrincipalKind(ctx) == principalKindPeer {
		return nil, status.Error(codes.PermissionDenied,
			"resolving a health condition is an operator's decision and not peer-callable")
	}
	if err := s.RequirePerm(ctx, "/", "cluster.health.resolve", "admin"); err != nil {
		return nil, err
	}
	code, kind, id := req.GetCode(), req.GetSubjectKind(), req.GetSubjectId()
	if code == "" || kind == "" || id == "" {
		return nil, status.Error(codes.InvalidArgument, "code, subject kind and subject id are all required")
	}
	open, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read health conditions: %v", err)
	}
	var matches []corrosion.HealthCondition
	for _, h := range open {
		if h.Code != code || h.SubjectKind != kind || h.SubjectID != id {
			continue
		}
		if ev := req.GetEvaluator(); ev != "" && h.Evaluator != ev {
			continue
		}
		matches = append(matches, h)
	}
	switch {
	case len(matches) == 0:
		return nil, status.Errorf(codes.NotFound,
			"no open condition %s on %s/%s; `lv health` lists the open ones", code, kind, id)
	case len(matches) > 1:
		evs := make([]string, 0, len(matches))
		for _, h := range matches {
			evs = append(evs, h.Evaluator)
		}
		return nil, status.Errorf(codes.InvalidArgument,
			"%d evaluators hold an open %s on %s/%s (%s); name one with --evaluator",
			len(matches), code, kind, id, strings.Join(evs, ", "))
	}
	row := matches[0]
	if row.Evaluator != dualRunEvaluator {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s on %s/%s is evaluator %q's: only the dual-run detector's conditions can be resolved by hand, "+
				"since it re-raises one that still holds on its next pass; remove the cause and %s resolves it",
			code, kind, id, row.Evaluator, row.Evaluator)
	}

	prior := row.Lifecycle
	now := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt = corrosion.ConditionResolved, now
	row.ObserveCount, row.CleanCount = 0, 0
	row.Reporter = s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.Unavailable, "record the resolution: %v", err)
	}

	target := strings.Join([]string{row.Evaluator, code, kind, id}, "/")
	detail := fmt.Sprintf("resolved by hand on %s (was %s, hosts %s)", s.hostName, prior, strings.Join(row.Hosts, ","))
	if r := strings.TrimSpace(req.GetReason()); r != "" {
		detail += ": " + r
	}
	s.audit(ctx, "health.condition.resolve", target, detail, "ok")
	s.publish("ha.condition.resolved", code+":"+kind+"/"+id, detail)
	return &pb.ResolveHealthConditionResponse{Condition: healthConditionToPB(row)}, nil
}
