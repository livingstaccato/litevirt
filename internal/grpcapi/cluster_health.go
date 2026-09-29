package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// GetClusterHealth is THE health read. It aggregates the durable condition
// set, evaluator coverage, the observer→target connectivity mesh, and per-host
// capacity assessments into one response with one overall state — the single
// surface the CLI, REST, MCP, UI, and dashboard all consume. There is no
// per-signal health RPC and no operator force-clear: the rows say what the
// evaluators proved, and only the evaluators change them.
func (s *Server) GetClusterHealth(ctx context.Context, req *pb.GetClusterHealthRequest) (*pb.ClusterHealth, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}

	conditions, err := corrosion.ListHealthConditions(ctx, s.db, req.GetIncludeResolved())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list health conditions: %v", err)
	}
	evaluators, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list evaluator status: %v", err)
	}
	capacity, err := corrosion.ListHostCapacityObservations(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list capacity observations: %v", err)
	}
	edges, err := s.db.Query(ctx,
		`SELECT observer, target, status, consecutive_failures, last_seen
		 FROM host_health WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query connectivity: %v", err)
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}
	// internal/health's checker does not probe a target in maintenance, so that
	// target's edges are frozen at whatever they last said. Mark them here, at
	// the one place that knows both tables, so the roll-up can tell "this link
	// is bad" from "nobody is looking at this link any more".
	maintenance := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h.State == "maintenance" {
			maintenance[h.Name] = true
		}
	}
	// The same holds for an edge outside its observer's probe plan: a non-voter
	// probes only a sample of the other non-voters (health.ObserverPlan), so an
	// edge it dropped from that sample is frozen too. An unreadable voter set
	// excludes nothing — every edge keeps its vote, as before the plan.
	var plans map[string]map[string]bool
	if voters, verr := corrosion.VoterSet(ctx, s.db); verr == nil {
		plans = make(map[string]map[string]bool, len(hosts))
		for _, h := range hosts {
			plans[h.Name] = health.ObserverPlan(h.Name, hosts, voters)
		}
	}
	notProbed := func(observer, target string) bool {
		plan, known := plans[observer]
		return known && !plan[target]
	}

	// Parse the mesh once: the same edges feed both the response body and the
	// roll-up, which counts a link that is not proven good as a coverage gap.
	mesh := make([]connectivityEdge, 0, len(edges))
	for _, r := range edges {
		target := r.String("target")
		mesh = append(mesh, connectivityEdge{
			Observer:            r.String("observer"),
			Target:              target,
			Status:              r.String("status"),
			ConsecutiveFailures: r.Int("consecutive_failures"),
			LastSeen:            r.String("last_seen"),
			TargetInMaintenance: maintenance[target],
			NotProbed:           notProbed(r.String("observer"), target),
		})
	}

	resp := &pb.ClusterHealth{
		Overall:     overallHealth(conditions, evaluators, capacity, mesh, time.Now().UTC()),
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
			LastSeen:            e.LastSeen,
		})
	}
	if len(capacity) > 0 {
		db, err := s.dbCapacityByHost(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "database capacity: %v", err)
		}
		for _, c := range capacity {
			d := db[c.HostName]
			resp.Capacity = append(resp.Capacity, &pb.HostCapacityAssessment{
				HostName: c.HostName,
				DbCpu:    int32(d.cpu), DbMemMib: int32(d.mem), DbCtMemMib: int32(d.ctMem),
				ExtraCpu: int32(c.ExtraCPU), ExtraMemMib: int32(c.ExtraMemMiB),
				EffectiveCpu: int32(d.cpu + c.ExtraCPU), EffectiveMemMib: int32(d.mem + c.ExtraMemMiB),
				Complete: c.Complete, Detail: c.Detail, SampledAt: c.SampledAt,
			})
		}
	}
	return resp, nil
}

// hostDBCapacity is what the database says one host holds: cpu and memory
// over running VMs and containers, with the containers' memory share apart.
type hostDBCapacity struct{ cpu, mem, ctMem int }

// dbCapacityByHost reads the capacity section's DB column from the database
// as it is NOW, by the rules placement charges by (dbVMCharge,
// dbContainerCharge) — not from the sampler's last copy of it, which is up to
// a minute old and would show a container deployed since as not there while
// placement already counts it. EXTRA (runtime beyond the database) is the
// sampler's finding, and EFFECTIVE is DB + EXTRA, which is what placement
// admits against.
func (s *Server) dbCapacityByHost(ctx context.Context) (map[string]hostDBCapacity, error) {
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, err
	}
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return nil, err
	}
	out := map[string]hostDBCapacity{}
	for _, vm := range vms {
		if cpu, mem, ok := dbVMCharge(vm); ok {
			d := out[vm.HostName]
			d.cpu += cpu
			d.mem += mem
			out[vm.HostName] = d
		}
	}
	for _, ct := range cts {
		if mem, ok := dbContainerCharge(ct); ok {
			d := out[ct.HostName]
			d.mem += mem
			d.ctMem += mem
			out[ct.HostName] = d
		}
	}
	return out, nil
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
	// TargetInMaintenance marks an edge whose target the checker has stopped
	// probing. Reported in the body unchanged; excluded from the roll-up.
	TargetInMaintenance bool
	// NotProbed marks an edge outside its observer's probe plan
	// (health.ObserverPlan). Reported unchanged; excluded from the roll-up.
	NotProbed bool
}

// connectivityDegrades reports whether an edge's status means the link is not
// proven good. The checker (internal/health) writes "healthy" and "suspect"
// today; "failing" is accepted as the same class so a future terminal state
// degrades rather than reading as silently fine.
//
// An UNRECOGNISED status is deliberately NOT treated as a problem: guessing
// would turn any new status value the checker starts writing into an immediate
// cluster-wide DEGRADED on every node that has not been upgraded yet.
func connectivityDegrades(status string) bool {
	// unready is the peer's own answer that it cannot serve: it degrades the
	// cluster as much as a suspect edge, though it licenses no fence.
	return status == "failing" || status == "suspect" || status == health.StatusUnready
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
// fleet-wide-stopped detector, not scheduling jitter. The evaluator status row
// is LWW state with no expiry — without this bound, the last row ever written
// keeps saying coverage=complete forever and a stopped detector leaves the
// cluster green-and-blind indefinitely. (Compare localInventoryTTL: the OTHER
// input admission trusts is already freshness-bounded; this closes the same
// hole for the roll-up.)
const evaluatorScanTTL = 5 * time.Minute

// overallHealth rolls the pieces into one state:
//
//	CRITICAL — any ACTIVE critical condition (an observed one included: the
//	           operator should be looking before the confirm lands);
//	DEGRADED — active warning conditions, an evaluator without complete
//	           coverage, a STALE evaluator (last scan past evaluatorScanTTL, or
//	           dated in the FUTURE), an incomplete capacity observation, or a
//	           connectivity edge that is not proven good and whose target is
//	           still being probed. Active INFO conditions
//	           do NOT degrade: they are advisories, not faults (see the severity
//	           branch below);
//	UNKNOWN  — no evaluator has ever completed a scan, or every evaluator's
//	           last scan is stale (nothing is watching NOW, which is not the
//	           same as nothing being wrong);
//	HEALTHY  — none of the above.
//
// Deliberately, staleness does NOT gate admission. The ownership admission
// gate acts on durable condition rows plus a freshly-probed LOCAL inventory,
// both of which stay sound when the detector stops — what is lost is the
// discovery of NEW cross-host conditions, which this roll-up now surfaces
// instead of hiding. Coupling every admission to a single detector's liveness
// would make that detector a cluster-wide availability SPOF, which is a worse
// trade than a loudly-degraded health state; an operator who wants a hard stop
// on a blind cluster has the DEGRADED/UNKNOWN exit codes to wire it from.
func overallHealth(conditions []corrosion.HealthCondition, evaluators []corrosion.HealthEvaluatorStatus, capacity []corrosion.HostCapacityObservation, mesh []connectivityEdge, now time.Time) string {
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
		if h.Severity == corrosion.SeverityInfo {
			// AN INFO CONDITION IS AN ADVISORY, NOT A FAULT, and the severity
			// column is the only place that distinction can live. The three
			// severities are a contract with the evaluators: critical means a
			// workload is in danger now, warning means something is wrong and
			// wants attention, and info means a state worth SEEING for as long
			// as it lasts. An advisory can legitimately stand for months — it
			// often describes something an operator chose — so degrading the
			// roll-up for its whole life would make `lv health` exit non-zero
			// indefinitely and train an operator to ignore the exit code, which
			// costs the warnings and criticals their only channel.
			//
			// This is a POLICY, deliberately independent of who writes info
			// rows: today nothing does, and the branch still has to be right, so
			// that an evaluator can raise a standing advisory without silently
			// making every cluster that has one look broken.
			//
			// It does NOT resolve anything. A stale row that nothing owns any
			// more keeps standing at whatever severity it was written with, and a
			// WARNING or CRITICAL one keeps degrading the roll-up — correctly, it
			// is unresolved state. This branch changes the reading of severity,
			// not the lifecycle: conditions that mean something is wrong are
			// warning or critical, and both still degrade below.
			continue
		}
		degraded = true
	}
	allStale := true
	for _, e := range evaluators {
		stale := true
		// A scan dated in the FUTURE is not fresh — it is a clock-skewed or
		// forged row, and now.Sub(at) <= TTL is trivially true for any negative
		// age, so an unbounded check reads the most suspect row in the table as
		// the most current one. Requiring d >= 0 makes a future timestamp stale,
		// which is the honest reading: nothing has been proven scanned by now.
		if at, err := time.Parse(time.RFC3339, e.LastScan); err == nil {
			if d := now.Sub(at); d >= 0 && d <= evaluatorScanTTL {
				stale = false
				allStale = false
			}
		}
		if stale || e.Coverage != corrosion.CoverageComplete {
			degraded = true
		}
	}
	if allStale {
		return HealthUnknown
	}
	for _, c := range capacity {
		if !c.Complete {
			degraded = true
		}
	}
	// A peer-probe mesh full of failing links used to roll up as HEALTHY: the
	// edges were reported in the response body but never read by the state.
	// Connectivity is exactly the kind of cross-host fact this endpoint is the
	// single surface for, so a link the checker cannot prove good degrades.
	for _, e := range mesh {
		// A target taken out of service is not probed any more (checkAllPeers
		// skips it), so its last recorded status never changes again. Counting
		// it would latch the cluster DEGRADED for as long as the host stays in
		// maintenance — a light stuck on, with no link left to fix. The edge is
		// still reported in the body; it just stops voting.
		if e.TargetInMaintenance || e.NotProbed {
			continue
		}
		if connectivityDegrades(e.Status) {
			degraded = true
		}
	}
	if degraded {
		return HealthDegraded
	}
	return HealthHealthy
}
