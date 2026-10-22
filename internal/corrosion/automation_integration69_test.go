package corrosion

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Incoming69 is shipped and must keep its ALTER ID and default independently
// of the relocated, still-private automation migrations.
func TestAutomationIntegration69MigrationAndDescriptor(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if CurrentSchemaVersion != 86 || automationCutSourceSchema != 86 {
		t.Fatalf("current SQL/source descriptor = %d/%d, want86/86", CurrentSchemaVersion, automationCutSourceSchema)
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
	sgUnits := 0
	for _, m := range schemaMigrationLedger {
		if m.Version == 70 {
			sgUnits++
			if m.ID != "a091_security_groups_project" || m.Target != "security_groups.project" || m.Kind != kindAddColumn || m.SQL != "ALTER TABLE security_groups ADD COLUMN project TEXT NOT NULL DEFAULT ''" {
				t.Fatalf("published70 changed: %+v", m)
			}
		}
	}
	if sgUnits != 1 {
		t.Fatalf("schema70 units=%d", sgUnits)
	}
	projectUnits := 0
	for _, m := range schemaMigrationLedger {
		if m.Version == 71 {
			projectUnits++
			if m.ID != "a092_projects_incarnation" || m.Target != "projects.incarnation" || m.Kind != kindAddColumn || m.SQL != "ALTER TABLE projects ADD COLUMN incarnation TEXT NOT NULL DEFAULT ''" {
				t.Fatalf("published71 changed: %+v", m)
			}
		}
	}
	if projectUnits != 1 || !supportedAutomationCutDescriptor(82, 1) || !supportedAutomationCutDescriptor(83, 1) || !supportedAutomationCutDescriptor(84, 1) || !supportedAutomationCutDescriptor(85, 1) || !supportedAutomationCutDescriptor(86, 1) || supportedAutomationCutDescriptor(87, 1) {
		t.Fatalf("project71 or archived82/83/84/current86 descriptor boundary changed: units=%d", projectUnits)
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

// Live local proof cannot reuse an older schema row. A retained original may
// carry either accepted pre-metadata namespace without rewriting its frames.
func TestAutomationIntegration80LocalSchemaProvenance(t *testing.T) {
	for _, layout := range []struct {
		name, digest string
		retained     bool
	}{
		{"live", "", false},
		{"retained31", retainedLocalLayout83Digest(), true},
		{"retained33", retainedLocalLayoutDigestFor(automationExecutionArchived85PrivateLayoutForTest()), true},
		{"retained37", retainedLocalLayoutDigest(), true},
	} {
		for _, version := range []int64{77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87} {
			t.Run(fmt.Sprintf("%s_schema%d", layout.name, version), func(t *testing.T) {
				observation := aggregateLocalObservation{retained: layout.retained, layoutDigest: layout.digest}
				row := Row{Columns: []string{"id", "version"}, Values: []interface{}{int64(1), version}}
				err := observation.observe(&aggregateLocalAudit{}, 15, 1, row)
				want := (layout.name == "live" && version == 86) ||
					(layout.name == "retained31" && version >= 78 && version <= 83) ||
					(layout.name == "retained33" && (version == 84 || version == 85)) ||
					(layout.name == "retained37" && version == 86)
				if (err == nil) != want {
					t.Fatalf("schema=%d layout=%s retained=%t: %v", version, layout.name, layout.retained, err)
				}
			})
		}
	}
}

// SQL85 binds local token authentication to the account incarnation. It adds
// neither a certified section nor a transferable credential observation.
func TestAutomationIntegration85TokenStampInventory(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, c) != 86 || len(schemaMigrationLedger) != 206 {
		t.Fatal("SQL85 migration boundary")
	}
	units := 0
	for _, m := range schemaMigrationLedger {
		if m.Version == 85 {
			units++
			if m.ID != "a094_tokens_user_created_at" || m.Target != "tokens.user_created_at" || m.Kind != kindAddColumn || m.SQL != "ALTER TABLE tokens ADD COLUMN user_created_at TEXT NOT NULL DEFAULT ''" {
				t.Fatal("SQL85 migration changed", m)
			}
		}
	}
	if units != 1 {
		t.Fatal("SQL85 unit count", units)
	}
	columns, err := c.Query(ctx, `PRAGMA table_info(tokens)`)
	if err != nil {
		t.Fatal(err)
	}
	stamp := 0
	for _, col := range columns {
		if col.String("name") == "user_created_at" {
			stamp++
			if col.Int64("cid") != 10 || col.String("type") != "TEXT" || col.Int64("notnull") != 1 || col.String("dflt_value") != "''" || col.Int64("pk") != 0 {
				t.Fatal("token stamp column shape", col)
			}
		}
	}
	if stamp != 1 {
		t.Fatal("token stamp missing or repeated", stamp)
	}

	// These invalidate-only triggers stay local: any UPDATE OF the stamp, even
	// an equal-value assignment, must retire issuance. Existing delivered
	// TestTokenIncarnation_AStampRewriteInvalidatesAutomationIssuance exercises
	// actual tamper/refusal; its upgrade companion covers installation.
	for _, trigger := range []struct{ name, sql string }{
		{"automation_issuance_tokens_update", `CREATE TRIGGER automation_issuance_tokens_update
 AFTER UPDATE OF id,username,name,token_hash,expires_at,scope_paths,created_at,deleted_at ON tokens BEGIN
 UPDATE local_automation_credential_issuance SET valid=0 WHERE kind='token' AND credential_id=OLD.id;
 END`},
		{"automation_issuance_tokens_stamp_update", `CREATE TRIGGER automation_issuance_tokens_stamp_update
 AFTER UPDATE OF user_created_at ON tokens BEGIN
 UPDATE local_automation_credential_issuance SET valid=0 WHERE kind='token' AND credential_id=OLD.id;
 END`},
	} {
		rows, err := c.Query(ctx, `SELECT tbl_name,sql FROM sqlite_master WHERE type='trigger' AND name=?`, trigger.name)
		if err != nil || len(rows) != 1 || rows[0].String("tbl_name") != "tokens" || rows[0].String("sql") != trigger.sql {
			t.Fatal("SQL85 local issuance trigger inventory differs", trigger.name, err)
		}
	}
	for schema := 69; schema <= 86; schema++ {
		if !supportedAutomationCutDescriptor(schema, 1) {
			t.Fatal("retained descriptor refused", schema)
		}
		for _, codec := range []int{-1, 0, 2} {
			if supportedAutomationCutDescriptor(schema, codec) {
				t.Fatal("unsupported codec accepted", schema, codec)
			}
		}
	}
	if supportedAutomationCutDescriptor(68, 1) || supportedAutomationCutDescriptor(87, 1) {
		t.Fatal("unsupported source accepted")
	}
	wantSections := []string{"claims", "incarnation_claims", "history", "anchors", "requests", "authority", "adoptions", "seals", "membership"}
	var sections []string
	for _, d := range automationCutSections {
		sections = append(sections, d.name)
		if d.table == "tokens" || d.table == "token_credentials" || strings.Contains(d.columns, "user_created_at") || strings.Contains(d.columns, "credential_digest") {
			t.Fatal("credential entered public inventory", d)
		}
	}
	if !reflect.DeepEqual(sections, wantSections) {
		t.Fatal("certified sections changed", sections)
	}
	for _, layout := range []struct {
		tables []aggregateLocalTable
		count  int
	}{{aggregateLocalTables83(), 31}, {automationExecutionArchived85PrivateLayoutForTest(), 33}, {aggregateLocalTables(), 37}} {
		if len(layout.tables) != layout.count {
			t.Fatal("private layout count changed", len(layout.tables))
		}
		for _, d := range layout.tables {
			if d.table == "tokens" || d.table == "token_credentials" || strings.Contains(d.columns, "user_created_at") || strings.Contains(d.columns, "credential_digest") {
				t.Fatal("credential entered private row inventory", d)
			}
		}
	}
}
