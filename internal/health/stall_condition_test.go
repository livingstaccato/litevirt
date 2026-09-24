package health

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A stall that withholds this node's fence votes must be visible in `lv health`,
// not only in its journal: the operator's question is "why did failover wait
// 20s for a dead host?", and the node that was paused is the one nobody is
// reading. So the heartbeat records an observer_stalled condition about ITSELF
// when a stall opens the grace window, and resolves it when the window closes.

func stallCondition(t *testing.T, db *corrosion.Client, host string) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), db,
		stallEvaluator, CondObserverStalled, "host", host)
	if err != nil {
		t.Fatalf("GetHealthCondition: %v", err)
	}
	return row, ok
}

func TestStall_ObserverStalledConditionOpensAndResolves(t *testing.T) {
	ctx := context.Background()
	db := testCheckerDB(t)
	c := NewChecker("host-a", t.TempDir(), db)
	now := time.Now()
	c.clock = func() time.Time { return now }
	tick := func(d time.Duration) {
		now = now.Add(d)
		c.stallTick(ctx)
	}

	tick(0)
	for i := 0; i < 8; i++ {
		tick(stallBeat)
	}
	if _, ok := stallCondition(t, db, "host-a"); ok {
		t.Fatal("a node that never stalled wrote an observer_stalled row; a healthy fleet must write nothing")
	}

	tick(34 * time.Second) // the process was not running for 34s
	row, ok := stallCondition(t, db, "host-a")
	if !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("a 34s stall did not open an observer_stalled condition: ok=%v row=%+v", ok, row)
	}
	if row.Severity != corrosion.SeverityWarning || row.Reporter != "host-a" ||
		len(row.Hosts) != 1 || row.Hosts[0] != "host-a" {
		t.Fatalf("condition fields: %+v", row)
	}
	var ev struct {
		GapSeconds float64 `json:"gap_seconds"`
		GraceUntil string  `json:"grace_until"`
		Detail     string  `json:"detail"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("evidence %q: %v", row.Evidence, err)
	}
	if ev.GapSeconds < 33 || ev.GapSeconds > 35 {
		t.Fatalf("evidence gap_seconds=%v, want ~34", ev.GapSeconds)
	}
	until, err := time.Parse(time.RFC3339, ev.GraceUntil)
	if err != nil || until.Before(now.Add(StallGrace-2*time.Second)) || until.After(now.Add(StallGrace+2*time.Second)) {
		t.Fatalf("evidence grace_until=%q, want ~now+%v", ev.GraceUntil, StallGrace)
	}
	if !strings.Contains(ev.Detail, "fence") {
		t.Fatalf("evidence detail should say what the stall withholds: %q", ev.Detail)
	}

	for moved := time.Duration(0); moved < StallGrace-time.Second; moved += stallBeat {
		tick(stallBeat)
	}
	if row, _ := stallCondition(t, db, "host-a"); row.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("the condition resolved while the grace window was still open")
	}
	for moved := time.Duration(0); moved < 2*time.Second; moved += stallBeat {
		tick(stallBeat)
	}
	if row, _ := stallCondition(t, db, "host-a"); row.Lifecycle != corrosion.ConditionResolved || row.ResolvedAt == "" {
		t.Fatalf("the condition did not resolve when the grace window closed: %+v", row)
	}
}

// A row a previous PROCESS left open — the daemon was killed inside a grace
// window — must not stay open forever: the new process has no stall of its own
// to resolve it with.
func TestStall_AnObserverStalledRowFromAnEarlierProcessResolves(t *testing.T) {
	ctx := context.Background()
	db := testCheckerDB(t)
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
		Evaluator: stallEvaluator, Code: CondObserverStalled, SubjectKind: "host", SubjectID: "host-a",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning, Hosts: []string{"host-a"},
		ObserveCount: 1, FirstSeen: old, LastSeen: old, ConfirmedAt: old, Reporter: "host-a",
	}); err != nil {
		t.Fatal(err)
	}
	c := NewChecker("host-a", t.TempDir(), db)
	c.stallTick(ctx)
	if row, _ := stallCondition(t, db, "host-a"); row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a stale open row from an earlier process was not resolved: %+v", row)
	}
}

// StallGrace is derived from the probe cadence and the fence's failure count,
// never a tuned constant that drifts from them. Pin the relationship so a
// change to either moves the window with it.
func TestStallGrace_IsTheTimeAFenceVerdictTakes(t *testing.T) {
	if want := time.Duration(FailuresToFence) * checkInterval; StallGrace != want {
		t.Fatalf("StallGrace = %v, want FailuresToFence × checkInterval = %v", StallGrace, want)
	}
	if stallThreshold != checkInterval {
		t.Fatalf("stallThreshold = %v, want one missed probe tick (%v)", stallThreshold, checkInterval)
	}
}
