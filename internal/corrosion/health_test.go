package corrosion

import (
	"context"
	"testing"
	"time"
)

func TestHealthCondition_UpsertObserveConfirmResolve(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	h := HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: ConditionObserved, Severity: SeverityWarning,
		Hosts: []string{"host-a", "host-b"}, Evidence: `{"detail":"first pass"}`,
		ObserveCount: 1, FirstSeen: "2026-09-06T00:00:00Z", LastSeen: "2026-09-06T00:00:00Z",
		Reporter: "host-a",
	}
	if err := UpsertHealthCondition(ctx, c, h); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, ok, err := GetHealthCondition(ctx, c, "dual_run", "vm_dual_run", "vm", "vm1")
	if err != nil || !ok {
		t.Fatalf("get after insert: ok=%v err=%v", ok, err)
	}
	if got.Lifecycle != ConditionObserved || got.ObserveCount != 1 || len(got.Hosts) != 2 {
		t.Fatalf("got = %#v, want observed/1/2-hosts", got)
	}

	// Second pass confirms it.
	h.Lifecycle = ConditionConfirmed
	h.Severity = SeverityCritical
	h.ObserveCount = 2
	h.ConfirmedAt = "2026-09-06T00:01:00Z"
	h.LastSeen = "2026-09-06T00:01:00Z"
	if err := UpsertHealthCondition(ctx, c, h); err != nil {
		t.Fatalf("confirm upsert: %v", err)
	}
	got, ok, err = GetHealthCondition(ctx, c, "dual_run", "vm_dual_run", "vm", "vm1")
	if err != nil || !ok || got.Lifecycle != ConditionConfirmed || got.ConfirmedAt == "" {
		t.Fatalf("got after confirm = %#v (ok=%v err=%v), want confirmed with ConfirmedAt set", got, ok, err)
	}

	// Resolve.
	h.Lifecycle = ConditionResolved
	h.ResolvedAt = "2026-09-06T00:02:00Z"
	if err := UpsertHealthCondition(ctx, c, h); err != nil {
		t.Fatalf("resolve upsert: %v", err)
	}
	all, err := ListHealthConditions(ctx, c, false)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	for _, cond := range all {
		if cond.SubjectID == "vm1" {
			t.Fatalf("resolved condition still returned by ListHealthConditions(includeResolved=false): %#v", cond)
		}
	}
	allIncl, err := ListHealthConditions(ctx, c, true)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	found := false
	for _, cond := range allIncl {
		if cond.SubjectID == "vm1" && cond.Lifecycle == ConditionResolved {
			found = true
		}
	}
	if !found {
		t.Fatal("resolved condition missing from ListHealthConditions(includeResolved=true)")
	}
}

func TestTombstoneResolvedHealthConditions_RetentionCutoff(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	old := HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "old-vm",
		Lifecycle: ConditionResolved, Severity: SeverityWarning,
		FirstSeen: "2026-08-01T00:00:00Z", LastSeen: "2026-08-01T00:00:00Z",
		ResolvedAt: now.Add(-31 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Reporter:   "host-a",
	}
	recent := old
	recent.SubjectID = "recent-vm"
	recent.ResolvedAt = now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	if err := UpsertHealthCondition(ctx, c, old); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if err := UpsertHealthCondition(ctx, c, recent); err != nil {
		t.Fatalf("insert recent: %v", err)
	}

	n, err := TombstoneResolvedHealthConditions(ctx, c, now)
	if err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if n != 1 {
		t.Fatalf("tombstoned %d rows, want exactly 1 (the 31-day-old one)", n)
	}
	all, err := ListHealthConditions(ctx, c, true)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, cond := range all {
		if cond.SubjectID == "old-vm" {
			t.Fatal("31-day-old resolved condition still returned after tombstoning — deleted_at not filtered or not set")
		}
	}
	foundRecent := false
	for _, cond := range all {
		if cond.SubjectID == "recent-vm" {
			foundRecent = true
		}
	}
	if !foundRecent {
		t.Fatal("1-hour-old resolved condition was tombstoned — retention cutoff is wrong")
	}
}

func TestHealthEvaluatorStatus_UpsertAndList(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertHealthEvaluatorStatus(ctx, c, HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: "2026-09-06T00:00:00Z", Coverage: CoverageComplete, Reporter: "host-a",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := UpsertHealthEvaluatorStatus(ctx, c, HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: "2026-09-06T00:01:00Z", Coverage: CoveragePartial, Reporter: "host-b", Detail: "host-c unreachable",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	all, err := ListHealthEvaluatorStatus(ctx, c)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("got %d evaluator rows, want 1 (upsert must replace, not duplicate)", len(all))
	}
	if all[0].Coverage != CoveragePartial || all[0].Reporter != "host-b" {
		t.Fatalf("got %#v, want the SECOND upsert's values (latest scan wins)", all[0])
	}
}
