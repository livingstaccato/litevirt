package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetClusterHealth is THE health read. It aggregates the durable condition
// set, evaluator coverage, and the observer→target connectivity mesh into one
// response with one overall state. There is no per-signal health RPC and no
// operator force-clear: the rows say what the evaluators proved, and only the
// evaluators change them.
func (s *Server) GetClusterHealth(ctx context.Context, req *pb.GetClusterHealthRequest) (*pb.ClusterHealth, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}

	// These three queries are deliberately unsynchronized — no shared snapshot
	// or transaction ties them together. A detector pass landing between them
	// can produce a response that mixes pre- and post-transition state (e.g. a
	// condition already resolved but an evaluator row not yet updated to match).
	// That's an acceptable tradeoff here: this is a read-only advisory endpoint,
	// not a consistency-sensitive decision point, the window is one detector
	// cycle wide, and the response self-heals within ~60s on the next scan —
	// nothing this handler does relies on the three views agreeing exactly.
	conditions, err := corrosion.ListHealthConditions(ctx, s.db, req.GetIncludeResolved())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list health conditions: %v", err)
	}
	evaluators, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list evaluator status: %v", err)
	}
	edges, err := s.db.Query(ctx,
		`SELECT observer, target, status, consecutive_failures, last_seen
		 FROM host_health WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query connectivity: %v", err)
	}

	// Parse the mesh once: the same edges feed both the response body and the
	// roll-up (which counts failing/suspect links as coverage gaps).
	mesh := make([]connectivityEdge, 0, len(edges))
	for _, r := range edges {
		mesh = append(mesh, connectivityEdge{
			Observer: r.String("observer"), Target: r.String("target"),
			Status:              r.String("status"),
			ConsecutiveFailures: r.Int("consecutive_failures"),
			LastSeen:            r.String("last_seen"),
		})
	}

	resp := &pb.ClusterHealth{
		Overall:     overallHealth(conditions, evaluators, mesh, time.Now().UTC()),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, h := range conditions {
		resp.Conditions = append(resp.Conditions, &pb.HealthCondition{
			Evaluator: h.Evaluator, Code: h.Code,
			SubjectKind: h.SubjectKind, SubjectId: h.SubjectID,
			Lifecycle: h.Lifecycle, Severity: h.Severity,
			Hosts: h.Hosts, Evidence: h.Evidence,
			ObserveCount: int32(h.ObserveCount), CleanCount: int32(h.CleanCount),
			FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
			ConfirmedAt: h.ConfirmedAt, ResolvedAt: h.ResolvedAt,
			Reporter: h.Reporter,
		})
	}
	for _, e := range evaluators {
		resp.Evaluators = append(resp.Evaluators, &pb.HealthEvaluatorStatus{
			Evaluator: e.Evaluator, LastScan: e.LastScan,
			Coverage: e.Coverage, Reporter: e.Reporter, Detail: e.Detail,
		})
	}
	for _, e := range mesh {
		resp.Connectivity = append(resp.Connectivity, &pb.ConnectivityEdge{
			Observer: e.Observer, Target: e.Target,
			Status:              e.Status,
			ConsecutiveFailures: int32(e.ConsecutiveFailures),
			LastSeen:            parseTimestamp(e.LastSeen),
		})
	}
	return resp, nil
}

// connectivityEdge is one observer→target peer-probe result from host_health,
// as both the response body and the roll-up read it. It is the typed shape of
// the row, not a new storage concept: internal/health's checker owns the column.
type connectivityEdge struct {
	Observer            string
	Target              string
	Status              string // healthy | suspect | failing
	ConsecutiveFailures int
	LastSeen            string
}

// Connectivity statuses that mean a peer link is not proven good. The checker
// (internal/health) writes "healthy" and "suspect" today; "failing" is accepted
// as the same class so a future terminal state degrades rather than reading as
// silently fine — an unrecognized status is NOT treated as a problem, since
// guessing would turn any new value into a cluster-wide DEGRADED.
func connectivityDegrades(status string) bool {
	return status == "failing" || status == "suspect"
}

// Overall cluster-health states.
const (
	HealthHealthy  = "HEALTHY"
	HealthDegraded = "DEGRADED"
	HealthCritical = "CRITICAL"
	HealthUnknown  = "UNKNOWN"
)

// evaluatorScanTTL is how old an evaluator's last scan may be before its
// evaluation is STALE. The detector runs every 60s and its leader lease fails
// over within ~2 intervals, so five intervals of silence is a wedged or
// fleet-wide-stopped detector, not scheduling jitter. Without this bound, the
// last row ever written keeps saying coverage=complete forever and a stopped
// detector leaves the cluster green-and-blind indefinitely.
const evaluatorScanTTL = 5 * time.Minute

// overallHealth rolls the pieces into one state:
//
//	CRITICAL — any ACTIVE critical condition (an observed one included: the
//	           operator should be looking before the confirm lands);
//	DEGRADED — active warning conditions, an evaluator without complete
//	           coverage, a STALE evaluator (last scan past evaluatorScanTTL),
//	           or a connectivity edge that is not proven good (failing or
//	           suspect). A broken peer link is the same kind of gap as missing
//	           coverage — the mesh is part of what "the cluster is healthy"
//	           claims, so a fully partitioned mesh can no longer read HEALTHY;
//	UNKNOWN  — no evaluator has ever completed a scan, or every evaluator's
//	           last scan is stale;
//	HEALTHY  — none of the above.
//
// Deliberately, staleness does NOT gate admission — this roll-up is a read,
// not an enforcement point. Coupling admission to a single detector's
// liveness would make that detector a cluster-wide availability SPOF.
func overallHealth(
	conditions []corrosion.HealthCondition,
	evaluators []corrosion.HealthEvaluatorStatus,
	mesh []connectivityEdge,
	now time.Time,
) string {
	if len(evaluators) == 0 {
		return HealthUnknown
	}
	degraded := false
	for _, h := range conditions {
		if h.Lifecycle == corrosion.ConditionResolved {
			continue
		}
		if h.Severity == corrosion.SeverityCritical {
			return HealthCritical
		}
		if h.Severity == corrosion.SeverityWarning {
			degraded = true
		}
	}
	allStale := true
	for _, e := range evaluators {
		stale := true
		if at, err := time.Parse(time.RFC3339, e.LastScan); err == nil {
			// A future-dated LastScan (clock skew) yields a negative Sub, which
			// would otherwise read as "fresh" and mask a wedged detector — so
			// require the delta be non-negative as well as within the TTL.
			d := now.Sub(at)
			if d >= 0 && d <= evaluatorScanTTL {
				stale = false
				allStale = false
			}
		}
		if stale || e.Coverage != corrosion.CoverageComplete {
			degraded = true
		}
	}
	// A failing or suspect peer link degrades, and does not escalate past it:
	// a broken edge is a coverage/observability gap, not proof of corruption,
	// so it belongs in the same tier as an incomplete scan.
	for _, e := range mesh {
		if connectivityDegrades(e.Status) {
			degraded = true
			break
		}
	}
	if allStale {
		return HealthUnknown
	}
	if degraded {
		return HealthDegraded
	}
	return HealthHealthy
}
