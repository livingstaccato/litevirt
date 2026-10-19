package corrosion

import (
	"context"
	"strings"
	"testing"
)

// Catch a collision that marks the retirement ALTER applied without executing
// it, or omits/misclassifies an automation table when moving SQL versions.
func TestAutomationPrimary636Upgrade67Through82(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	for _, ddl := range schemaDDL {
		if strings.Contains(ddl, "local_automation_") {
			continue
		}
		ddl = strings.Replace(ddl, ",\n\t\tincarnation  INTEGER NOT NULL DEFAULT 0", "", 1)
		ddl = strings.Replace(ddl, "deleted_at TEXT,\n\t\tafter_retirement TEXT NOT NULL DEFAULT ''", "deleted_at TEXT", 1)
		if strings.Contains(ddl, "CREATE TABLE IF NOT EXISTS security_groups (") {
			ddl = strings.Replace(ddl, ",\n\t\t-- project (v70) is LAST, for the v53 digest reason; '' = global.\n\t\tproject     TEXT NOT NULL DEFAULT ''", "", 1)
		}
		if err := c.execLocal(ctx, ddl); err != nil {
			t.Fatal("schema67 DDL", err)
		}
	}
	if err := c.execLocal(ctx, appliedMigrationsDDL); err != nil {
		t.Fatal(err)
	}
	for _, m := range schemaMigrationLedger {
		if m.Version > 67 {
			continue
		}
		if strings.HasPrefix(m.Target, "local_automation_") {
			t.Fatalf("automation table collides with shipped version: %+v", m)
		}
		present, err := m.present(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if !present {
			if m.SQL == "" {
				t.Fatalf("schema67 missing %s", m.ID)
			}
			if err := c.execLocal(ctx, m.SQL); err != nil {
				t.Fatal("schema67 baseline migration", m.ID, err)
			}
		}
		if err := c.execLocal(ctx, `INSERT INTO applied_migrations VALUES (?, 'fixture67', ?)`, m.ID, sha256hex(m.SQL)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.execLocal(ctx, `INSERT INTO schema_state VALUES (1,67,'fixture67')`); err != nil {
		t.Fatal(err)
	}
	if exists, err := columnExists(ctx, c.db, "host_fence_credentials", "after_retirement"); err != nil || exists {
		t.Fatal("fixture already has retirement ALTER", exists, err)
	}
	retirementUnits := 0
	for _, m := range schemaMigrationLedger {
		if m.Version != 68 {
			continue
		}
		retirementUnits++
		if m.Target != "host_fence_credentials.after_retirement" || m.Kind != kindAddColumn {
			t.Fatalf("integration68 meaning changed: %+v", m)
		}
		if err := c.execBatchLocal(ctx, []Statement{
			{SQL: m.SQL},
			{SQL: `INSERT INTO applied_migrations VALUES (?, 'fixture68', ?)`, Params: []interface{}{m.ID, sha256hex(m.SQL)}},
		}); err != nil {
			t.Fatal("actual67->68 ALTER", err)
		}
	}
	if retirementUnits != 1 {
		t.Fatalf("schema68 contains %d units", retirementUnits)
	}
	if err := reconcileSchemaVersion(ctx, c); err != nil || storedVersion(t, c) != 68 {
		t.Fatal("ledger did not reach68", err)
	}
	if err := c.execLocal(ctx, `INSERT INTO host_fence_credentials(host_name,ipmi_pass,updated_at) VALUES('retained','private','before68')`); err != nil {
		t.Fatal(err)
	}
	// Apply the published host-incarnation and SG migrations before our relocated units.
	if err := c.execLocal(ctx, `INSERT INTO hosts(name,address,ssh_user,cert_serial,created_at,updated_at) VALUES('legacy','127.0.0.1','root','legacy-cert','before69','before69')`); err != nil {
		t.Fatal(err)
	}
	incarnationUnits := 0
	for _, m := range schemaMigrationLedger {
		if m.Version != 69 {
			continue
		}
		incarnationUnits++
		if m.Target != "hosts.incarnation" || m.Kind != kindAddColumn {
			t.Fatalf("integration69 meaning changed: %+v", m)
		}
		if err := c.execBatchLocal(ctx, []Statement{{SQL: m.SQL}, {SQL: `INSERT INTO applied_migrations VALUES (?, 'fixture69', ?)`, Params: []interface{}{m.ID, sha256hex(m.SQL)}}}); err != nil {
			t.Fatal("actual68->69 ALTER", err)
		}
	}
	if incarnationUnits != 1 {
		t.Fatal("schema69 unit count", incarnationUnits)
	}
	if err := reconcileSchemaVersion(ctx, c); err != nil || storedVersion(t, c) != 69 {
		t.Fatal("ledger did not reach69", err)
	}
	rows69, err69 := c.Query(ctx, `SELECT incarnation FROM hosts WHERE name='legacy'`)
	if err69 != nil || len(rows69) != 1 || rows69[0].Int64("incarnation") != 0 {
		t.Fatal("published69 default lost", rows69, err69)
	}
	if exists, err := columnExists(ctx, c.db, "security_groups", "project"); err != nil || exists {
		t.Fatal("fixture already has published SG70 ALTER", exists, err)
	}
	if err := c.execLocal(ctx, `INSERT INTO security_groups(id,name,created_at,updated_at) VALUES('legacy-sg','legacy-sg','before70','before70')`); err != nil {
		t.Fatal(err)
	}
	sgUnits := 0
	for _, m := range schemaMigrationLedger {
		if m.Version != 70 {
			continue
		}
		sgUnits++
		if m.ID != "a091_security_groups_project" || m.Target != "security_groups.project" || m.Kind != kindAddColumn || m.SQL != "ALTER TABLE security_groups ADD COLUMN project TEXT NOT NULL DEFAULT ''" {
			t.Fatalf("published SG70 meaning changed: %+v", m)
		}
		if err := c.execBatchLocal(ctx, []Statement{{SQL: m.SQL}, {SQL: `INSERT INTO applied_migrations VALUES (?, 'fixture70', ?)`, Params: []interface{}{m.ID, sha256hex(m.SQL)}}}); err != nil {
			t.Fatal("actual69->70 ALTER", err)
		}
	}
	if sgUnits != 1 {
		t.Fatal("schema70 unit count", sgUnits)
	}
	if err := reconcileSchemaVersion(ctx, c); err != nil || storedVersion(t, c) != 70 {
		t.Fatal("ledger did not reach70", err)
	}
	rows70, err70 := c.Query(ctx, `SELECT project FROM security_groups WHERE id='legacy-sg'`)
	if err70 != nil || len(rows70) != 1 || rows70[0].String("project") != "" {
		t.Fatal("published70 global default lost", rows70, err70)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal("actual70->current upgrade", err)
	}
	if storedVersion(t, c) != CurrentSchemaVersion || appliedCount(t, c) != len(schemaMigrationLedger) {
		t.Fatal("upgrade omitted current schema or ledger units")
	}
	want := map[int]int{71: 7, 72: 2, 73: 2, 74: 7, 75: 3, 76: 8, 77: 2, 78: 7, 79: 3, 80: 2, 81: 3, 82: 1}
	for _, m := range schemaMigrationLedger {
		if m.Version < 71 {
			continue
		}
		custody82 := m.Version == 82 && m.Kind == kindRebuildAutomationCustody && m.ID == automationCustodyMigrationID && m.Target == "local_automation_key_recipients" && m.SQL == automationCustodyRebuildSQL
		if m.Version == 82 && !custody82 {
			t.Fatalf("unexpected custody82 migration %+v", m)
		}
		if !strings.HasPrefix(m.Target, "local_automation_") || (m.Kind != kindCreateTable && !(m.Version == 80 && m.Kind == kindAddColumn && m.Target == "local_automation_receiver_current.established_inventory") && !custody82) {
			t.Fatalf("unexpected relocated migration %+v", m)
		}
		want[m.Version]--
		if present, err := m.present(ctx, c); err != nil || !present {
			t.Fatalf("upgrade omitted actual %s: %v", m.Target, err)
		}
		table := strings.Split(m.Target, ".")[0]
		if !IsNodeLocalClaimTable(table) || IsReplicatedTable(table) {
			t.Fatal("private local table entered replication", m.Target)
		}
	}
	for version, missing := range want {
		if missing != 0 {
			t.Fatalf("schema%d table inventory differs by %d", version, missing)
		}
	}
	rows, err := c.Query(ctx, `SELECT ipmi_pass,after_retirement FROM host_fence_credentials WHERE host_name='retained'`)
	if err != nil || len(rows) != 1 || rows[0].String("ipmi_pass") != "private" || rows[0].String("after_retirement") != "" {
		t.Fatal("upgrade changed existing credential/default", rows, err)
	}
	if err := InitSchema(ctx, c); err != nil || appliedCount(t, c) != len(schemaMigrationLedger) {
		t.Fatal("upgrade is not idempotent", err)
	}
}
