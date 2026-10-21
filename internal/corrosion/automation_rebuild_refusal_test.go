package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Test-only compile-ready contract. Missing production behavior is an explicit
// assertion after genuine schema/fixture setup, never a fake implementation.
type retainedRebuildChecker interface {
	CheckRetainedManagedRebuildRefusal(context.Context, string) error
}
type retainedRebuildCommitChecker interface {
	checkRetainedManagedRebuildRefusal(context.Context, string, *localCommitSeams) error
}

func requireRetainedRebuildChecker(t *testing.T, c *Client) retainedRebuildChecker {
	t.Helper()
	check, ok := any(c).(retainedRebuildChecker)
	if !ok {
		t.Fatal("RETAINED_REBUILD_CAPABILITY: real Client lacks refusal-only helper")
	}
	return check
}
func requireRetainedRebuildUnavailable(t *testing.T, err error) {
	t.Helper()
	if contract.Code(err) != contract.CodeUnavailable {
		t.Fatalf("uncertain retained state did not remain unavailable: %v", err)
	}
}
func TestRetainedRebuildPristineAndCertified(t *testing.T) {
	t.Run("pristine", func(t *testing.T) {
		c := testClient(t)
		before := sharedActiveRows(t, c)
		check := requireRetainedRebuildChecker(t, c)
		if err := check.CheckRetainedManagedRebuildRefusal(context.Background(), "native-vm"); err != nil {
			t.Fatal("pristine local state unexpectedly refused", err)
		}
		if !reflect.DeepEqual(before, sharedActiveRows(t, c)) {
			t.Fatal("negative guard initialized or wrote automation history")
		}
	})
	t.Run("retained-managed-and-unrelated-absence", func(t *testing.T) {
		c := observeStorageFixture(t, false)
		requireNameStorage(t, c, "legacy-machine", AutomationNamePresent)
		requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
		before, typed := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
		check := requireRetainedRebuildChecker(t, c)
		if err := check.CheckRetainedManagedRebuildRefusal(context.Background(), "legacy-machine"); !errors.Is(err, ErrRetainedManagedRebuild) {
			t.Fatalf("complete retained ownership did not yield definite refusal: %v", err)
		}
		if err := check.CheckRetainedManagedRebuildRefusal(context.Background(), "never-enrolled"); err != nil {
			t.Fatal("unrelated graph became blanket refusal", err)
		}
		if !reflect.DeepEqual(before, sharedActiveRows(t, c)) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, c)) {
			t.Fatal("refusal check mutated certified state")
		}
	})
}

func TestRetainedRebuildPendingAndResidueClasses(t *testing.T) {
	// Fixed composed schema84 inventory. No payload validity is needed to prove surviving
	// residue is not pristine. Prefix itself uses an invalid zero frontier;
	// all other cases have no prefix row. Each row satisfies its table DDL.
	for _, tc := range []struct {
		name, sql string
		staged    bool
	}{
		{"prefix", `INSERT INTO local_automation_prefix(id,cluster_uid,sequence,digest) VALUES(1,'cluster',0,'')`, false},
		{"history", `INSERT INTO local_automation_history(sequence,digest,value_json,certificate,receipt_json,anchor_sequence) VALUES(1,'d','{}','{}','{}',1)`, false},
		{"anchors", `INSERT INTO local_automation_anchors(sequence,digest,generation,members_hash,certificate) VALUES(1,'d',1,'h','{}')`, false},
		{"requests", `INSERT INTO local_automation_requests(scope,request_id,identity,receipt_json,operation_id) VALUES('s','r',x'00','{}','o')`, false},
		{"authority", `INSERT INTO local_automation_authority(id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance) VALUES(1,1,'h','i','p','r','partial')`, false},
		{"recovery", `INSERT INTO local_automation_recovery(id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate) VALUES(1,0,'',1,'d',0,'',1,'h','{}')`, false},
		{"staging", `INSERT INTO local_automation_staging(sequence,digest,value_json,certificate) VALUES(1,'d','{}','{}')`, false},
		{"semantic_heads", `INSERT INTO local_automation_semantic_heads(stage,cluster_uid,sequence,digest) VALUES(?,'c',0,'')`, true},
		{"identities", `INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES(?,'u','c','p','vm','alias','w',1,0)`, true},
		{"aliases", `INSERT INTO local_automation_aliases(stage,cluster_uid,project_scope,kind,alias,uid,generation) VALUES(?,'c','p','vm','alias','u',1)`, true},
		{"owners", `INSERT INTO local_automation_owners(stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation) VALUES(?,'c','p','o','f','s','sp',1)`, true},
		{"resources", `INSERT INTO local_automation_resources(stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence) VALUES(?,'u','c','p','vm','d','i','o','k',1,'r',0,'op','op',1)`, true},
		{"names", `INSERT INTO local_automation_names(stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id) VALUES(?,'c','vm','u',1,'live','')`, true},
		{"bindings", `INSERT INTO local_automation_bindings(stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired) VALUES(?,'c','p','o','k',1,'u','op','r',0)`, true},
		{"admissions", `INSERT INTO local_automation_admissions(stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json) VALUES(?,'op','c','p','o','k','u','r','pr','create','pl',1,1,1,'{}')`, true},
		{"key_epochs", `INSERT INTO local_automation_key_epochs(stage,cluster_uid,recipient_epoch,membership_generation,config_digest,equality_epoch,predecessor_activation_sequence,activation_sequence) VALUES(?,'c','re',1,'d','ee',0,1)`, true},
		{"key_recipients", `INSERT INTO local_automation_key_recipients(stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence) VALUES(?,'c','re',1,'d','host',0,'time','serial','vi','ki','r','er','ra','ea',1)`, true},
		{"payload_wrappings", `INSERT INTO local_automation_payload_wrappings(stage,cluster_uid,operation_id,payload_id,admission_sequence,wrapping_sequence,wrapping_digest,recipient_epoch,membership_generation,config_digest) VALUES(?,'c','op','pl',1,2,'d','re',1,'cd')`, true},
		{"retained_deliveries", `INSERT INTO local_automation_retained_deliveries(id,attempt,envelope) VALUES('d','a',x'00')`, false},
		{"retained_objects", `INSERT INTO local_automation_retained_objects(delivery,ordinal,namespace,descriptor) VALUES('d',1,'n',x'00')`, false},
		{"retained_completions", `INSERT INTO local_automation_retained_completions(delivery,evidence_digest,candidate_ref,coverage_digest) VALUES('d','e',x'00','c')`, false},
		{"aggregates", `INSERT INTO local_automation_aggregates(id,attempt,local_id,head,coverage,roster) VALUES('i','a','l',x'00','c',x'00')`, false},
		{"aggregate_sources", `INSERT INTO local_automation_aggregate_sources(bundle,source,incarnation,audit,publication,root,cut_id) VALUES('b','s','i','a','p','r','c')`, false},
		{"aggregate_copies", `INSERT INTO local_automation_aggregate_copies(bundle,origin_kind,origin_id,component,ordinal,claim_key,promised_round,promised_coord,promised_nonce,accepted_round,accepted_coord,accepted_nonce,origin_ref) VALUES('b','k','i',1,1,x'00',1,'c',x'00',1,'c',x'00',x'00')`, false},
		{"aggregate_maxima", `INSERT INTO local_automation_aggregate_maxima(bundle,claim_key,promise_ref,accepted_ref) VALUES('b',x'00',x'00',x'00')`, false},
		{"aggregate_conflicts", `INSERT INTO local_automation_aggregate_conflicts(bundle,claim_key,round,coord,nonce,first_ref) VALUES('b',x'00',1,'c',x'00',x'00')`, false},
		{"receiver_audits", `INSERT INTO local_automation_receiver_audits(id,attempt,source,publication,root,head,lineage,coverage,records,payloads,requests) VALUES('i','a','s','p','r',x'00','l','c',1,1,1)`, false},
		{"receiver_refs", `INSERT INTO local_automation_receiver_refs(audit,component,ordinal,sequence,semantic_key,scope,request_id,operation_id,claim_key,generation,accepted_round,accepted_coord,accepted_nonce) VALUES('a',1,1,1,x'00','s','r','o',x'00',1,1,'c',x'00')`, false},
		{"receiver_requests", `INSERT INTO local_automation_receiver_requests(audit,scope,request_id,identity,receipt,operation_id,origin) VALUES('a','s','r',x'00',x'00','o',1)`, false},
		{"receiver_jobs", `INSERT INTO local_automation_receiver_jobs(id,job,revision,binding,evidence) VALUES('i','j',1,x'00',x'00')`, false},
		{"receiver_current", `INSERT INTO local_automation_receiver_current(id,attempt,established_inventory) VALUES(1,'a',x'00')`, false},
		{"receiver_established", `INSERT INTO local_automation_receiver_established(attempt,digest,artifact) VALUES('a','d',x'00')`, false},
		{"receiver_validations", `INSERT INTO local_automation_receiver_validations(attempt,digest,evidence) VALUES('a','d',x'00')`, false},
		{"receiver_sources", `INSERT INTO local_automation_receiver_sources(attempt,source,publication,authenticated,metadata) VALUES('a','s','p',0,x'00')`, false},
		{"receiver_components", `INSERT INTO local_automation_receiver_components(attempt,source,component,state,cursor,terminal) VALUES('a','s',1,x'00','',0)`, false},
		{"receiver_records", `INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) VALUES('a','s',1,1,x'00')`, false},
		{"receiver_pages", `INSERT INTO local_automation_receiver_pages(attempt,source,component,position,request,digest,progress) VALUES('a','s',1,1,'r','d',x'00')`, false},
		{"target_operations", `INSERT INTO local_automation_target_operations(stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json) VALUES(?,'c','op','admit_legacy_rebuild','p','pr','r','u','vm',1,'d','{}','{}')`, true},
		{"target_reservations", `INSERT INTO local_automation_target_reservations(stage,cluster_uid,target_key,operation_id,sequence) VALUES(?,'c','key','op',1)`, true},
	} {
		stages := []string{""}
		if tc.staged {
			stages = append(stages, "pending")
		}
		for _, stage := range stages {
			label := tc.name
			if tc.staged {
				if stage == "" {
					label += "/active"
				} else {
					label += "/nonactive"
				}
			}
			t.Run(label, func(t *testing.T) {
				c := testClient(t)
				var args []any
				if tc.staged {
					args = []any{stage}
				}
				if _, err := c.db.ExecContext(context.Background(), tc.sql, args...); err != nil {
					t.Fatal("SETUP real residue row", err)
				}
				check := requireRetainedRebuildChecker(t, c)
				requireRetainedRebuildUnavailable(t, check.CheckRetainedManagedRebuildRefusal(context.Background(), "native-vm"))
			})
		}
	}
}

func TestRetainedRebuildPendingWithCertifiedHead(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"recovery", `INSERT INTO local_automation_recovery(id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate) VALUES(1,12,'pending',13,'next',12,'base',1,'hash','{}')`},
		{"staging", `INSERT INTO local_automation_staging(sequence,digest,value_json,certificate) VALUES(13,'pending','{}','{}')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := observeStorageFixture(t, false)
			requireNameStorage(t, c, "legacy-machine", AutomationNamePresent)
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
			head, err := c.Query(context.Background(), "SELECT * FROM local_automation_prefix")
			if err != nil || len(head) != 1 || head[0].Int64("sequence") != 12 {
				t.Fatal("SETUP certified head", head, err)
			}
			if _, err := c.db.ExecContext(context.Background(), tc.sql); err != nil {
				t.Fatal("SETUP pending evidence", err)
			}
			retained, typed := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
			check := requireRetainedRebuildChecker(t, c)
			for _, name := range []string{"legacy-machine", "never-enrolled"} {
				t.Run(name, func(t *testing.T) {
					requireRetainedRebuildUnavailable(t, check.CheckRetainedManagedRebuildRefusal(context.Background(), name))
				})
			}
			after, err := c.Query(context.Background(), "SELECT * FROM local_automation_prefix")
			if err != nil || !reflect.DeepEqual(head, after) || !reflect.DeepEqual(retained, sharedActiveRows(t, c)) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, c)) {
				t.Fatal("pending check changed certified state", err)
			}
		})
	}
}

func TestRetainedRebuildCertifiedUnownedPresent(t *testing.T) {
	ca, a, b, c := threeVoters(t)
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "retained-unowned-verifier"))
	if err != nil {
		t.Fatal("SETUP verifier", err)
	}
	automationTypedHistoryFixtureThroughDecision(t, a, b, c, verifier, nil, 11)
	got, err := a.c.AutomationObserveName(context.Background(), "established-cluster", "legacy-machine", 11)
	if err != nil || got.State != AutomationNamePresent || got.Prefix.Sequence != 11 || got.Record == nil {
		t.Fatal("SETUP signed unowned Present", got, err)
	}
	if got.Record.Owner != nil || got.Record.Binding != nil || got.Record.Resource.OwnerID != "" {
		t.Fatal("SETUP enrollment is already owned", got.Record)
	}
	retained, typed := sharedActiveRows(t, a.c), automationTypedSnapshot(t, a.c)
	check := requireRetainedRebuildChecker(t, a.c)
	if err := check.CheckRetainedManagedRebuildRefusal(context.Background(), "legacy-machine"); err != nil {
		t.Fatal("genuine unowned Present refused", err)
	}
	if !reflect.DeepEqual(retained, sharedActiveRows(t, a.c)) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, a.c)) {
		t.Fatal("unowned check changed certified state")
	}
}

func TestRetainedRebuildSharedClaimDiscriminator(t *testing.T) {
	for _, table := range []string{"local_recovery_claims", "local_incarnation_claims"} {
		for _, tc := range []struct {
			name   string
			kind   any
			stored string
			refuse bool
		}{
			{"native-text", "vm", "text", false},
			{"automation-text", "automation", "text", true},
			{"automation-blob", []byte("automation"), "blob", true},
		} {
			t.Run(table+"/"+tc.name, func(t *testing.T) {
				_, voter, _, _ := threeVoters(t)
				c := voter.c
				key := workloadKey()
				if table == "local_incarnation_claims" {
					key = scopedKey("inc-1")
				}
				promised, err := c.ClaimPrepare(context.Background(), key, testBallot(1, "native"), 1)
				if err != nil || !promised.Promised {
					t.Fatal("SETUP genuine native promise", promised, err)
				}
				// Native TEXT control is the actual promise above; only negative cases
				// tamper its discriminator, never fabricate a valid native claim.
				if tc.refuse {
					if _, err := c.db.ExecContext(context.Background(), "UPDATE "+table+" SET target_kind=? WHERE target_kind=? AND target_name=?", tc.kind, key.TargetKind, key.TargetName); err != nil {
						t.Fatal("SETUP discriminator tamper", err)
					}
				}
				rows, err := c.Query(context.Background(), "SELECT typeof(target_kind) AS storage_type FROM "+table+" WHERE target_name=?", key.TargetName)
				if err != nil || len(rows) != 1 || rows[0].String("storage_type") != tc.stored {
					t.Fatal("SETUP discriminator storage type", rows, err)
				}
				check := requireRetainedRebuildChecker(t, c)
				err = check.CheckRetainedManagedRebuildRefusal(context.Background(), "native-vm")
				if tc.refuse {
					requireRetainedRebuildUnavailable(t, err)
				} else if err != nil {
					t.Fatal("ordinary TEXT native claim became automation refusal", err)
				}
			})
		}
	}
}

func TestRetainedRebuildReaderFailuresStayUnavailable(t *testing.T) {
	// Representative adapter routes only. Existing name-reader suite owns its
	// full scalar/history/binding tamper matrix; do not clone that suite here.
	for _, tc := range []struct{ name, sql string }{
		{"head-removed", `DELETE FROM local_automation_prefix`},
		{"semantic-head-removed", `DELETE FROM local_automation_semantic_heads`},
		{"owner-removed", `DELETE FROM local_automation_owners`},
		{"name-removed", `DELETE FROM local_automation_names WHERE name='legacy-machine'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := observeStorageFixture(t, false)
			requireNameStorage(t, c, "legacy-machine", AutomationNamePresent)
			if _, err := c.db.ExecContext(context.Background(), tc.sql); err != nil {
				t.Fatal("SETUP damaged graph", err)
			}
			check := requireRetainedRebuildChecker(t, c)
			requireRetainedRebuildUnavailable(t, check.CheckRetainedManagedRebuildRefusal(context.Background(), "legacy-machine"))
		})
	}
}

func TestRetainedRebuildTransactionFailure(t *testing.T) {
	c := testClient(t)
	check := requireRetainedRebuildChecker(t, c)
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := check.CheckRetainedManagedRebuildRefusal(ctx, "native-vm"); !errors.Is(err, context.Canceled) {
			t.Fatalf("lost canceled context: %v", err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
		defer cancel()
		if err := check.CheckRetainedManagedRebuildRefusal(ctx, "native-vm"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lost deadline: %v", err)
		}
	})
	t.Run("commit-after-no-refusal", func(t *testing.T) {
		hooked, ok := any(c).(retainedRebuildCommitChecker)
		if !ok {
			t.Fatal("RETAINED_REBUILD_COMMIT_CAPABILITY: missing private existing-owner commit seam")
		}
		reached := false
		injected := errors.New("retained refusal commit rejected")
		err := hooked.checkRetainedManagedRebuildRefusal(context.Background(), "native-vm", &localCommitSeams{beforeCommit: func(*sql.Tx) error { reached = true; return injected }})
		if !reached {
			t.Fatal("precommit seam was not reached")
		}
		requireRetainedRebuildUnavailable(t, err)
	})
}

func TestRetainedRebuildCommitAndQueryErrors(t *testing.T) {
	t.Run("actual-commit-error", func(t *testing.T) {
		c := observeStorageFixture(t, false)
		requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
		retained, typed := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
		hooked, ok := any(c).(retainedRebuildCommitChecker)
		if !ok {
			t.Fatal("RETAINED_REBUILD_COMMIT_CAPABILITY: missing private existing-owner commit seam")
		}
		reached := false
		var rollbackErr error
		err := hooked.checkRetainedManagedRebuildRefusal(context.Background(), "never-enrolled", &localCommitSeams{beforeCommit: func(tx *sql.Tx) error { reached = true; rollbackErr = tx.Rollback(); return nil }})
		if !reached || rollbackErr != nil {
			t.Fatal("SETUP actual commit failure", reached, rollbackErr)
		}
		requireRetainedRebuildUnavailable(t, err)
		if !reflect.DeepEqual(retained, sharedActiveRows(t, c)) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, c)) {
			t.Fatal("failed commit changed retained rows")
		}
	})
	t.Run("missing-inventory-table", func(t *testing.T) {
		c := testClient(t)
		if _, err := c.db.ExecContext(context.Background(), "ALTER TABLE local_automation_receiver_pages RENAME TO missing_rebuild_receiver_pages"); err != nil {
			t.Fatal("SETUP missing required table", err)
		}
		check := requireRetainedRebuildChecker(t, c)
		requireRetainedRebuildUnavailable(t, check.CheckRetainedManagedRebuildRefusal(context.Background(), "native-vm"))
	})
}
