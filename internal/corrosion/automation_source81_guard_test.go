package corrosion

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestAutomationSource82NewCutRequiresSemanticSchema(t *testing.T) {
	for _, tc := range []struct {
		name, mutation, wantGuardError string
	}{
		{"clean_new_cut", "", ""},
		{"generated_semantic_column", `ALTER TABLE local_automation_resources ADD COLUMN unexpected_schema81 TEXT GENERATED ALWAYS AS (uid) VIRTUAL`, "unsupported automation semantic schema: local_automation_resources"},
		{"missing_semantic_index", `DROP INDEX automation_key_id`, "key projection index inventory differs"},
		{"generated_execution_column", `ALTER TABLE local_automation_executors ADD COLUMN unexpected_execution TEXT GENERATED ALWAYS AS (operation_id) VIRTUAL`, "unsupported automation semantic schema: local_automation_executors"},
		{"missing_execution_artifact_index", `DROP INDEX automation_execution_artifact_object`, "execution projection index inventory differs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, a, _, _ := threeVoters(t)
			if storedVersion(t, a.c) != 87 {
				t.Fatal("SETUP actual schema86 required")
			}
			if err := a.c.SealVoterGeneration(ctx, 1, "new82-shape-regression"); err != nil {
				t.Fatal("SETUP seal genuine old generation", err)
			}
			rows, err := a.c.Query(ctx, `SELECT id FROM local_automation_cuts`)
			if err != nil || len(rows) != 0 {
				t.Fatal("SETUP must have NO archived cut to reuse", err)
			}
			if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) }); err != nil {
				t.Fatal("SETUP clean semantic schema invalid", err)
			}
			if tc.mutation != "" {
				if err := a.c.execLocal(ctx, tc.mutation); err != nil {
					t.Fatal("SETUP malformed semantic fixture", err)
				}
				// Prove the existing guard recognizes this defect before testing
				// whether new82 cut creation actually invokes that real owner.
				err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) })
				if err == nil || !strings.Contains(err.Error(), tc.wantGuardError) {
					t.Fatal("SETUP actual semantic guard did not recognize defect", err)
				}
			}
			before := sharedActiveRows(t, a.c)
			id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
			if tc.mutation == "" {
				if err != nil || id == "" {
					t.Fatal("SETUP clean NEW82 cut creation failed", err)
				}
				metadata, _ := cutFixtureRead(t, a.c, id)
				if metadata.SourceSchema != 87 || len(metadata.Inventory) != 9 {
					t.Fatal("SETUP clean NEW82 cut has wrong provenance/inventory")
				}
				return
			}
			if err == nil {
				if id == "" {
					t.Fatal("SETUP cut returned empty ID without refusal")
				}
				metadata, _ := cutFixtureRead(t, a.c, id)
				if metadata.SourceSchema != 87 || len(metadata.Inventory) != 9 {
					t.Fatal("SETUP accepted cut is not actual NEW82 provenance")
				}
				t.Fatalf("RED_NEW82_MALFORMED_CUT_ACCEPTED: mode=%s cut=%s", tc.name, id)
			}
			if !strings.Contains(err.Error(), tc.wantGuardError) {
				t.Fatal("wrong new82 semantic refusal", err)
			}
			rows, queryErr := a.c.Query(ctx, `SELECT id FROM local_automation_cuts UNION ALL SELECT cut_id FROM local_automation_cut_records`)
			if queryErr != nil || len(rows) != 0 || !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
				t.Fatal("new82 refusal persisted a cut or changed active history", queryErr)
			}
		})
	}
}
