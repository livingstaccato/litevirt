package corrosion

import (
	"context"
	"reflect"
	"testing"
)

// Incoming69 is shipped and must keep its ALTER ID and default independently
// of the ten relocated, still-private automation migrations.
func TestAutomationIntegration69MigrationAndDescriptor(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if CurrentSchemaVersion != 79 || automationCutSourceSchema != 79 {
		t.Fatalf("current SQL/source descriptor = %d/%d, want79/79", CurrentSchemaVersion, automationCutSourceSchema)
	}
	units := 0
	for _, m := range schemaMigrationLedger {
		if m.Version == 69 {
			units++
			if m.Target != "hosts.incarnation" || m.Kind != kindAddColumn {
				t.Fatalf("published69 changed: %+v", m)
			}
		}
	}
	if units != 1 {
		t.Fatalf("schema69 units=%d", units)
	}
}

// Archived metadata and roots retain their old descriptor meanings even
// though the live schema includes the incoming host-incarnation column.
func TestAutomationIntegration69Archived78Reopen(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err := a.c.SealVoterGeneration(ctx, 1, "archive"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.db.Exec(`UPDATE schema_state SET version=78 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, records := cutFixtureRead(t, a.c, id)
	if before.SourceSchema != 78 {
		t.Fatal("archive descriptor changed", before.SourceSchema)
	}
	if err = InitSchema(ctx, a.c); err != nil {
		t.Fatal(err)
	}
	again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || again != id {
		t.Fatal("archive refused after migration", err)
	}
	after, later := cutFixtureRead(t, a.c, id)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
		t.Fatal("migration reinterpreted archived78")
	}
}
