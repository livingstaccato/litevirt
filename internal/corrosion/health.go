package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Durable cluster-health storage (v48).
//
// These are STORAGE primitives: full-row writes and typed reads. The lifecycle
// POLICY — what counts as an observation, when a condition confirms, who may
// resolve it and under what coverage — lives in the health evaluator
// (internal/grpcapi/dualrun_lifecycle.go), which is the only writer. Keeping
// policy out of the storage layer means the rules are in one place and the
// rows can never encode a transition the evaluator did not decide.
//
// Merge is default LWW. Condition rows are keyed per evaluator and written by
// one evaluator instance at a time (the detector lease holder), so last-
// writer-wins converges every replica to the newest scan.

// Condition lifecycle states.
const (
	ConditionObserved  = "observed"
	ConditionConfirmed = "confirmed"
	ConditionResolved  = "resolved"
)

// Condition severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Evaluator coverage states. Absence of a condition is only meaningful under
// CoverageComplete: a partial or unreachable scan cannot prove anything is gone.
const (
	CoverageComplete    = "complete"
	CoveragePartial     = "partial"
	CoverageUnreachable = "unreachable"
	CoverageUnsupported = "unsupported"
)

// HealthCondition is one detected condition's current state. Identity is
// (evaluator, code, subject_kind, subject_id); everything else is the latest
// scan's view of it.
type HealthCondition struct {
	Evaluator   string
	Code        string
	SubjectKind string // vm | container | vip | host | cluster
	SubjectID   string

	Lifecycle string // ConditionObserved | ConditionConfirmed | ConditionResolved
	Severity  string // SeverityInfo | SeverityWarning | SeverityCritical
	Hosts     []string
	Evidence  string // canonical structured evidence (JSON)

	ObserveCount int // consecutive positive scans
	CleanCount   int // consecutive complete clean scans

	FirstSeen   string // RFC3339
	LastSeen    string
	ConfirmedAt string // "" until confirmed
	ResolvedAt  string // "" until resolved
	Reporter    string // host that wrote the latest transition
}

// UpsertHealthCondition writes a condition's full current state. The caller (the
// evaluator) has already decided the lifecycle transition; this persists it.
func UpsertHealthCondition(ctx context.Context, c *Client, h HealthCondition) error {
	if h.Evaluator == "" || h.Code == "" || h.SubjectKind == "" {
		return fmt.Errorf("corrosion: health condition requires evaluator, code and subject_kind (got %q/%q/%q)",
			h.Evaluator, h.Code, h.SubjectKind)
	}
	hosts := ""
	if len(h.Hosts) > 0 {
		b, err := json.Marshal(h.Hosts)
		if err != nil {
			return err
		}
		hosts = string(b)
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO health_conditions (evaluator, code, subject_kind, subject_id,
		   lifecycle, severity, hosts, evidence, observe_count, clean_count,
		   first_seen, last_seen, confirmed_at, resolved_at, reporter,
		   created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(evaluator, code, subject_kind, subject_id) DO UPDATE SET
		   lifecycle = excluded.lifecycle,
		   severity = excluded.severity,
		   hosts = excluded.hosts,
		   evidence = excluded.evidence,
		   observe_count = excluded.observe_count,
		   clean_count = excluded.clean_count,
		   first_seen = excluded.first_seen,
		   last_seen = excluded.last_seen,
		   confirmed_at = excluded.confirmed_at,
		   resolved_at = excluded.resolved_at,
		   reporter = excluded.reporter,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		h.Evaluator, h.Code, h.SubjectKind, h.SubjectID,
		h.Lifecycle, h.Severity, hosts, h.Evidence, h.ObserveCount, h.CleanCount,
		h.FirstSeen, h.LastSeen, nullIfEmpty(h.ConfirmedAt), nullIfEmpty(h.ResolvedAt), h.Reporter,
		nowRFC3339(), now)
}

// GetHealthCondition reads one condition by identity; ok=false when absent.
func GetHealthCondition(ctx context.Context, c *Client, evaluator, code, subjectKind, subjectID string) (HealthCondition, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT evaluator, code, subject_kind, subject_id, lifecycle, severity, hosts,
		        evidence, observe_count, clean_count, first_seen, last_seen,
		        confirmed_at, resolved_at, reporter
		 FROM health_conditions
		 WHERE evaluator = ? AND code = ? AND subject_kind = ? AND subject_id = ?
		   AND deleted_at IS NULL`,
		evaluator, code, subjectKind, subjectID)
	if err != nil || len(rows) == 0 {
		return HealthCondition{}, false, err
	}
	return scanHealthCondition(rows[0]), true, nil
}

// ListHealthConditions returns every live condition. includeResolved=false
// filters to observed+confirmed — the "active conditions" GetClusterHealth reads.
func ListHealthConditions(ctx context.Context, c *Client, includeResolved bool) ([]HealthCondition, error) {
	q := `SELECT evaluator, code, subject_kind, subject_id, lifecycle, severity, hosts,
	             evidence, observe_count, clean_count, first_seen, last_seen,
	             confirmed_at, resolved_at, reporter
	      FROM health_conditions WHERE deleted_at IS NULL`
	if !includeResolved {
		q += ` AND lifecycle != 'resolved'`
	}
	q += ` ORDER BY evaluator, code, subject_kind, subject_id`
	rows, err := c.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]HealthCondition, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanHealthCondition(r))
	}
	return out, nil
}

func scanHealthCondition(r Row) HealthCondition {
	h := HealthCondition{
		Evaluator:    r.String("evaluator"),
		Code:         r.String("code"),
		SubjectKind:  r.String("subject_kind"),
		SubjectID:    r.String("subject_id"),
		Lifecycle:    r.String("lifecycle"),
		Severity:     r.String("severity"),
		Evidence:     r.String("evidence"),
		ObserveCount: r.Int("observe_count"),
		CleanCount:   r.Int("clean_count"),
		FirstSeen:    r.String("first_seen"),
		LastSeen:     r.String("last_seen"),
		ConfirmedAt:  r.String("confirmed_at"),
		ResolvedAt:   r.String("resolved_at"),
		Reporter:     r.String("reporter"),
	}
	if hosts := r.String("hosts"); hosts != "" {
		_ = json.Unmarshal([]byte(hosts), &h.Hosts)
	}
	return h
}

// ResolvedConditionRetention is how long a RESOLVED condition stays readable
// before GC tombstones it. Long enough that an operator investigating "what
// happened last week" still finds the record; bounded so the table cannot grow
// without limit.
const ResolvedConditionRetention = 30 * 24 * time.Hour

// TombstoneResolvedHealthConditions soft-deletes conditions resolved more than
// ResolvedConditionRetention ago, returning how many it removed. Convergence-
// safe the same way every retention delete here is: it tombstones (deleted_at)
// rather than hard-deleting, so replicas that have not yet seen the resolution
// converge to the tombstone instead of resurrecting the row.
func TombstoneResolvedHealthConditions(ctx context.Context, c *Client, now time.Time) (int, error) {
	cutoff := now.Add(-ResolvedConditionRetention).UTC().Format(time.RFC3339)
	n, err := c.ExecuteRows(ctx,
		`UPDATE health_conditions SET deleted_at = ?, updated_at = ?
		 WHERE lifecycle = 'resolved' AND deleted_at IS NULL
		   AND resolved_at IS NOT NULL AND resolved_at < ?`,
		nowRFC3339(), c.NowTS(), cutoff)
	return int(n), err
}

// HealthEvaluatorStatus is one evaluator's latest scan: when, with what
// coverage, run by whom.
type HealthEvaluatorStatus struct {
	Evaluator string
	LastScan  string // RFC3339
	Coverage  string // CoverageComplete | CoveragePartial | CoverageUnreachable | CoverageUnsupported
	Reporter  string
	Detail    string
}

// UpsertHealthEvaluatorStatus records an evaluator's completed scan.
func UpsertHealthEvaluatorStatus(ctx context.Context, c *Client, st HealthEvaluatorStatus) error {
	if st.Evaluator == "" {
		return fmt.Errorf("corrosion: evaluator status requires an evaluator name")
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO health_evaluator_status (evaluator, last_scan, coverage, reporter, detail,
		   created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(evaluator) DO UPDATE SET
		   last_scan = excluded.last_scan,
		   coverage = excluded.coverage,
		   reporter = excluded.reporter,
		   detail = excluded.detail,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		st.Evaluator, st.LastScan, st.Coverage, st.Reporter, st.Detail,
		nowRFC3339(), now)
}

// ListHealthEvaluatorStatus returns every evaluator's latest scan record.
func ListHealthEvaluatorStatus(ctx context.Context, c *Client) ([]HealthEvaluatorStatus, error) {
	rows, err := c.Query(ctx,
		`SELECT evaluator, last_scan, coverage, reporter, detail
		 FROM health_evaluator_status WHERE deleted_at IS NULL ORDER BY evaluator`)
	if err != nil {
		return nil, err
	}
	out := make([]HealthEvaluatorStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, HealthEvaluatorStatus{
			Evaluator: r.String("evaluator"),
			LastScan:  r.String("last_scan"),
			Coverage:  r.String("coverage"),
			Reporter:  r.String("reporter"),
			Detail:    r.String("detail"),
		})
	}
	return out, nil
}
