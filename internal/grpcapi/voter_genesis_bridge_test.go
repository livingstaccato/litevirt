package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ha.voter.genesis_pending is critical, and says a split can stall failover,
// while a host that can bridge a split of the derived voter set exists: a
// witness, or a host in maintenance. Its identity does not change.
//
// Mutations: keep the severity at warning — the critical checks go red; drop
// the maintenance case from genesisBridges — the maintenance arm goes red.
func TestGenesisPending_LouderWhileAHostCanBridgeASplit(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.db.SetVoterConfigGate(func() bool { return true })
	for _, h := range []corrosion.HostRecord{
		{Name: "test-host", Address: "10.0.0.1", State: "active"},
		{Name: "a", Address: "10.0.0.2", State: "active"},
		{Name: "down", Address: "10.0.0.3", State: "offline"},
		{Name: "w", Address: "10.0.0.4", State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	read := func() corrosion.HealthCondition {
		t.Helper()
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, voterEvaluator, condVoterGenesisPending, "cluster", voterConditionSubject)
		if err != nil || !ok {
			t.Fatalf("%s not found (%v)", condVoterGenesisPending, err)
		}
		return row
	}
	const stall = "can reach both halves of a split of the voters"

	// No host can bridge: as before.
	s.VoterGenesisTick(ctx, 0)
	if row := read(); row.Severity != corrosion.SeverityWarning || strings.Contains(row.Evidence, stall) {
		t.Fatalf("without a bridging host: severity %s, evidence %s; want warning and no stall line", row.Severity, row.Evidence)
	}

	// A witness can.
	if err := corrosion.UpdateHostRole(ctx, s.db, "w", "witness"); err != nil {
		t.Fatal(err)
	}
	s.VoterGenesisTick(ctx, 0)
	row := read()
	if row.Severity != corrosion.SeverityCritical || !strings.Contains(row.Evidence, "w (witness) "+stall) {
		t.Fatalf("with a witness: severity %s, evidence %s; want critical naming w", row.Severity, row.Evidence)
	}
	if row.Lifecycle == corrosion.ConditionResolved || !strings.Contains(row.Evidence, "down is offline") {
		t.Fatalf("the blocker line or the lifecycle changed: %+v", row)
	}

	// The witness is a worker again, and another host is in maintenance.
	if err := corrosion.UpdateHostRole(ctx, s.db, "w", "worker"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, s.db, "a", "maintenance"); err != nil {
		t.Fatal(err)
	}
	s.VoterGenesisTick(ctx, 0)
	if row := read(); row.Severity != corrosion.SeverityCritical || !strings.Contains(row.Evidence, "a (in maintenance) "+stall) {
		t.Fatalf("with a host in maintenance: severity %s, evidence %s; want critical naming a", row.Severity, row.Evidence)
	}

	// Neither: warning again.
	if err := corrosion.UpdateHostState(ctx, s.db, "a", "active"); err != nil {
		t.Fatal(err)
	}
	s.VoterGenesisTick(ctx, 0)
	if row := read(); row.Severity != corrosion.SeverityWarning || strings.Contains(row.Evidence, stall) {
		t.Fatalf("with the bridges gone: severity %s, evidence %s; want warning and no stall line", row.Severity, row.Evidence)
	}

	// Genesis no longer pending: resolved.
	s.applyGenesisPending(ctx, nil)
	if row := read(); row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("lifecycle %s after genesis stopped waiting, want resolved", row.Lifecycle)
	}
}
