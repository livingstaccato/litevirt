package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// Every mutation changes real verifier input after the consumer has obtained its
// exact snapshot. Prefix/head stay unchanged; the final FULL guard must refuse
// and roll back. This includes empty-set presence, losing copies, and prior rows.
func TestReceiverCurrentEveryDependencyClass(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, Continuing: true, LocalHead: 3, BeforeFreeze: currentNativeClaim})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	cases := []struct{ name, query string }{
		{"claim-timestamp", `UPDATE local_recovery_claims SET updated_at='changed'`},
		{"incarnation-claim-presence", `INSERT INTO local_incarnation_claims(target_kind,target_name,incarnation,owner_epoch,attempt,config_generation,updated_at) VALUES('lease','dependency_presence','incarnation',1,1,1,'changed')`},
		{"history", `UPDATE local_automation_history SET receipt_json='changed' WHERE sequence=1`},
		{"anchor", `UPDATE local_automation_anchors SET certificate='changed' WHERE sequence=1`},
		{"request", `UPDATE local_automation_requests SET receipt_json='changed'`},
		{"authority", `UPDATE local_automation_authority SET provenance='changed'`},
		{"adoption", `UPDATE local_voter_adoption SET adopted_at='changed'`},
		{"seal-presence", `INSERT INTO local_voter_seals(generation,reason,sealed_at) VALUES(999,'changed','changed')`},
		{"membership-timestamp", `UPDATE voter_configs SET updated_at='changed'`},
		{"incarnation-timestamp", `UPDATE local_voter_incarnation SET created_at='changed'`},
		{"pending-recovery", `INSERT INTO local_automation_recovery(id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate) VALUES(1,1,'changed',2,'changed',0,'changed',1,'changed','changed')`},
		{"pending-staging", `INSERT INTO local_automation_staging(sequence,digest,value_json,certificate) VALUES(999,'changed','changed','changed')`},
		{"reseed-marker", `INSERT INTO reseed_in_progress(id,started_at,source) VALUES(1,'changed','changed')`},
		{"reseed-generation", `INSERT INTO reseed_generation(id,generation) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET generation=generation+1`},
		{"owned-cut-root", `UPDATE local_automation_cuts SET root='changed'`},
		{"owned-cut-original", `UPDATE local_automation_cut_records SET record=x'00' WHERE section=0`},
		{"private-lifetime-observation", `INSERT INTO local_automation_lifetimes VALUES('principal','changed','changed','birth',0,1)`},
		{"private-issuance-observation", `INSERT INTO local_automation_credential_issuance VALUES('token','changed','changed','changed','changed','changed','secret-not-authority',1)`},
		{"schema-state", `UPDATE schema_state SET updated_at='changed'`},
		{"job-evidence", `UPDATE local_automation_receiver_jobs SET evidence=x'00'`},
		{"validation", `UPDATE local_automation_receiver_validations SET evidence=x'00'`},
		{"established-original", `UPDATE local_automation_receiver_established SET artifact=x'00'`},
		{"source-root-manifest", `UPDATE local_automation_receiver_sources SET metadata=x'00'`},
		{"source-terminal", `UPDATE local_automation_receiver_components SET terminal=0 WHERE component=11`},
		{"source-original-frame", `UPDATE local_automation_receiver_records SET record=x'00' WHERE component=11`},
		{"source-page-progress", `UPDATE local_automation_receiver_pages SET progress=x'00'`},
		{"source-audit-coverage", `UPDATE local_automation_receiver_audits SET coverage='changed'`},
		{"source-original-reference", `UPDATE local_automation_receiver_refs SET accepted_nonce=x'00'`},
		{"source-request-origin", `UPDATE local_automation_receiver_requests SET receipt=x'00'`},
		{"local-audit-origin", `UPDATE local_automation_local_audits SET origin=x'00'`},
		{"local-original-frame", `UPDATE local_automation_local_rows SET record=x'00' WHERE section=0`},
		{"aggregate-roster", `UPDATE local_automation_aggregates SET roster=x'00'`},
		{"aggregate-source-root", `UPDATE local_automation_aggregate_sources SET root='changed'`},
		{"aggregate-losing-copy", `UPDATE local_automation_aggregate_copies SET origin_ref=x'00' WHERE accepted_round=(SELECT MIN(accepted_round) FROM local_automation_aggregate_copies WHERE accepted_round>0)`},
		{"aggregate-independent-maxima", `UPDATE local_automation_aggregate_maxima SET promise_ref=x'00'`},
		{"aggregate-ballot-inventory", `UPDATE local_automation_aggregate_conflicts SET first_ref=x'00'`},
	}
	// Explicit corruptions cover every actual C semantic descriptor. The list is
	// checked against the production inventory only for coverage: queries and
	// expected refusal remain independent of the digest implementation. Each
	// baseline below must pass genuine C before this final-seam corruption runs.
	semanticMutations := map[string]string{
		"local_automation_target_operations":   `INSERT INTO local_automation_target_operations VALUES('','changed','changed','admit_legacy_rebuild','','changed','changed','','changed',1,'changed','{}','{}')`,
		"local_automation_target_reservations": `INSERT INTO local_automation_target_reservations VALUES('','changed','changed','changed',1)`,
		"local_automation_admissions":          `INSERT INTO local_automation_admissions VALUES('','changed','changed','changed','changed','changed','changed','changed','changed','changed','changed',1,1,1,'changed')`,
		"local_automation_aliases":             `INSERT INTO local_automation_aliases VALUES('','changed','','principal','changed','changed',1)`,
		"local_automation_bindings":            `INSERT INTO local_automation_bindings VALUES('','changed','changed','changed','changed',1,'changed','changed','changed',0)`,
		"local_automation_identities":          `INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES('','changed','changed','','principal','changed','changed',1,0)`,
		"local_automation_key_epochs":          `INSERT INTO local_automation_key_epochs VALUES('','changed','changed',1,'changed','changed',0,1)`,
		"local_automation_key_recipients":      `INSERT INTO local_automation_key_recipients VALUES('','changed','changed',1,'changed','changed',1,'changed','changed','changed','changed','changed','changed','changed','changed',1)`,
		"local_automation_names":               `INSERT INTO local_automation_names VALUES('','changed','changed','changed',1,'live','')`,
		"local_automation_owners":              `INSERT INTO local_automation_owners VALUES('','changed','changed','changed','changed','changed','changed',0)`,
		"local_automation_payload_wrappings":   `INSERT INTO local_automation_payload_wrappings VALUES('','changed','changed','changed',1,2,'changed','changed',1,'changed')`,
		"local_automation_resources":           `INSERT INTO local_automation_resources VALUES('','changed','changed','changed','changed','changed','changed','changed','changed',1,'changed',0,'changed','changed',1)`,
		"local_automation_semantic_heads":      `INSERT INTO local_automation_semantic_heads VALUES('','changed',1,'changed') ON CONFLICT(stage) DO UPDATE SET digest='changed'`,
	}
	for _, descriptor := range automationSemanticTables {
		query, ok := semanticMutations[descriptor.table]
		if !ok {
			t.Fatalf("missing final-FULL semantic mutation: %s", descriptor.table)
		}
		cases = append(cases, struct{ name, query string }{descriptor.table, query})
		delete(semanticMutations, descriptor.table)
	}
	if len(semanticMutations) != 0 {
		t.Fatalf("semantic mutations no longer name actual C descriptors: %v", semanticMutations)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			prefix, err := f.local.c.Query(ctx, `SELECT sequence,digest FROM local_automation_prefix WHERE id=1`)
			if err != nil || len(prefix) != 1 {
				t.Fatal(prefix, err)
			}
			reached := false
			var setupErr error
			f.receiver.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
				reached = true
				result, e := tx.ExecContext(ctx, tc.query)
				if e != nil {
					setupErr = fmt.Errorf("mutation setup: %w", e)
					return setupErr
				}
				n, e := result.RowsAffected()
				if e != nil || n == 0 {
					setupErr = fmt.Errorf("mutation did not reach actual dependency: %d %v", n, e)
					return setupErr
				}
				var sequence int64
				var digest string
				if e = tx.QueryRowContext(ctx, `SELECT sequence,digest FROM local_automation_prefix WHERE id=1`).Scan(&sequence, &digest); e != nil {
					setupErr = fmt.Errorf("prefix setup check: %w", e)
					return setupErr
				}
				if sequence != prefix[0].Int64("sequence") || digest != prefix[0].String("digest") {
					setupErr = fmt.Errorf("mutation changed prefix")
					return setupErr
				}
				return nil
			}}
			err = f.receiver.consumeCurrent(ctx, p)
			f.receiver.seams = nil
			if setupErr != nil {
				t.Fatal(setupErr)
			}
			if !reached || err == nil {
				t.Fatalf("dependency accepted: reached=%v err=%v", reached, err)
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("refusal changed ACTIVE/spool")
			}
			// The old proof is consumed even though SQL rolls back. A fresh complete
			// verification in the following case cannot revive that registry entry.
			if err = f.receiver.consumeCurrent(ctx, p); err == nil {
				t.Fatal("rolled-back proof revived")
			}
		})
	}
}
