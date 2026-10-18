package corrosion

import (
	"context"
	"errors"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"reflect"
	"strings"
	"testing"
)

func TestAutomationSourceTypedAuditPreservesActive(t *testing.T) {
	ca, a, b, c := threeVoters(t)
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "typed-audit"))
	if err != nil {
		t.Fatal(err)
	}
	automationTypedHistoryFixture(t, a, b, c, verifier)
	ctx := context.Background()
	before := automationTypedSnapshot(t, a.c)
	permanent := sharedActiveRows(t, a.c)
	err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, err := auditAutomationCutTx(ctx, tx, contract.Reduce); return err })
	if err != nil {
		t.Fatal("typed audit", err)
	}
	if !reflect.DeepEqual(before, automationTypedSnapshot(t, a.c)) || !reflect.DeepEqual(permanent, sharedActiveRows(t, a.c)) {
		t.Fatal("source audit changed active state")
	}

	injected := errors.New("audit callback refusal")
	err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := auditAutomationCutTx(ctx, tx, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
			if d.Sequence == 10 {
				return AutomationReduction{}, injected
			}
			return contract.Reduce(p, d)
		})
		return err
	})
	if !errors.Is(err, injected) {
		t.Fatal("did not reach injected audit failure", err)
	}
	if !reflect.DeepEqual(before, automationTypedSnapshot(t, a.c)) || !reflect.DeepEqual(permanent, sharedActiveRows(t, a.c)) {
		t.Fatal("failed source audit changed active or isolated state")
	}
	if _, err := a.c.db.Exec(`UPDATE local_automation_resources SET revision='corrupt-active' WHERE stage='' AND uid='resource-uid'`); err != nil {
		t.Fatal(err)
	}
	altered := automationTypedSnapshot(t, a.c)
	err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, err := auditAutomationCutTx(ctx, tx, contract.Reduce); return err })
	if err == nil || !strings.Contains(err.Error(), "active automation projection differs") {
		t.Fatal("active corruption not detected", err)
	}
	if !reflect.DeepEqual(altered, automationTypedSnapshot(t, a.c)) || !reflect.DeepEqual(permanent, sharedActiveRows(t, a.c)) {
		t.Fatal("audit repaired corrupt active state")
	}
}

func TestAutomationFreshBusinessRequiresClassAuthority(t *testing.T) {
	ca, a, b, c := threeVoters(t)
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "fresh-class"))
	if err != nil {
		t.Fatal(err)
	}
	automationTypedHistoryFixture(t, a, b, c, verifier)
	ctx := context.Background()
	key, _ := AutomationClaimKey(1)
	installAutomationEvidence(t, a.c, key, "", 1)
	historical, found, err := a.c.AutomationRecord(ctx, 2)
	if err != nil || !found {
		t.Fatal(err)
	}
	d, err := automationDecision(historical.Value)
	if err != nil {
		t.Fatal(err)
	}
	head, err := a.c.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d.Sequence = head.Sequence + 1
	d.ParentDigest = head.Digest
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	if err = contract.ValidateSupportedDecision(d); err != nil {
		t.Fatal("recognized business fixture", err)
	}
	freshKey, _ := AutomationClaimKey(d.Sequence)
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}}
	before := sharedActiveRows(t, a.c)
	typed := automationTypedSnapshot(t, a.c)
	result, err := a.c.ClaimAccept(ctx, freshKey, testBallot(3, "a"), value, 1, a.signer, nil)
	if err != nil || result.Accepted || result.Accept != nil || result.Refusal != RefusalAutomationUnavailable {
		t.Errorf("fresh business without provider persisted: %+v %v", result, err)
	}
	if _, found, err := a.c.ClaimState(ctx, freshKey); err != nil || found {
		t.Errorf("refusal mutated durable claim: %v %v", found, err)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, a.c)) {
		t.Fatal("fresh refusal changed history/projection")
	}
	promised, err := a.c.ClaimPrepare(ctx, freshKey, testBallot(8, "a"), 1)
	if err != nil || !promised.Promised {
		t.Fatal("promise-only Prepare incorrectly required business class", promised, err)
	}
	promisedBefore, found, err := a.c.ClaimState(ctx, freshKey)
	if err != nil || !found {
		t.Fatal(err)
	}
	result, err = a.c.ClaimAccept(ctx, freshKey, testBallot(9, "a"), value, 1, a.signer, nil)
	if err != nil || result.Accepted || result.Refusal != RefusalAutomationUnavailable {
		t.Fatal("business class bypass after promise", result, err)
	}
	promisedAfter, found, err := a.c.ClaimState(ctx, freshKey)
	if err != nil || !found || !reflect.DeepEqual(promisedBefore, promisedAfter) {
		t.Fatal("refusal advanced existing promise", err)
	}
	if _, err := a.c.db.Exec(`DELETE FROM local_automation_semantic_heads WHERE stage=''`); err != nil {
		t.Fatal(err)
	}
	if err := a.c.AutomationReplay(ctx, contract.Reduce, 2); err == nil {
		t.Fatal("partial replay unexpectedly complete")
	}
	historicalKey, _ := AutomationClaimKey(2)
	recertified, err := a.c.ClaimAccept(ctx, historicalKey, testBallot(4, "a"), historical.Value, 1, a.signer, nil)
	if err != nil || !recertified.Accepted || recertified.Accept == nil {
		t.Fatal("historical business recertification", recertified, err)
	}

	create, found, err := a.c.AutomationRecord(ctx, 7)
	if err != nil || !found {
		t.Fatal(err)
	}
	createKey, _ := AutomationClaimKey(7)
	result, err = a.c.ClaimAccept(ctx, createKey, testBallot(5, "a"), create.Value, 1, a.signer, nil)
	if err != nil || !result.Accepted {
		t.Fatal("historical create recertification", result, err)
	}
	stateBefore, found, err := a.c.ClaimState(ctx, createKey)
	if err != nil || !found {
		t.Fatal(err)
	}
	changed, err := automationDecision(create.Value)
	if err != nil {
		t.Fatal(err)
	}
	changed.Command.Ciphertext = []byte("changed-ciphertext")
	encoded, err := contract.EncodeDecision(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := contract.ValidateSupportedDecision(changed); err != nil {
		t.Fatal("changed ciphertext structurally invalid", err)
	}
	result, err = a.c.ClaimAccept(ctx, createKey, testBallot(6, "a"), ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}, 1, a.signer, nil)
	if err != nil || result.Accepted || result.Accept != nil || result.Refusal != RefusalAutomationUnavailable {
		t.Fatal("changed historical ciphertext admitted", result, err)
	}
	stateAfter, found, err := a.c.ClaimState(ctx, createKey)
	if err != nil || !found || !reflect.DeepEqual(stateBefore, stateAfter) {
		t.Fatal("altered historical slot mutated", err)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
		t.Fatal("historical recertification changed permanent history")
	}
}

func TestAutomationReceiverTypedHistoryIsolated(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 0, func(a *claimTestVoter, voters []*claimTestVoter) {
		verifier, err := LoadClaimVerifier(a.pki)
		if err != nil {
			t.Fatal(err)
		}
		automationTypedHistoryFixture(t, a, voters[1], voters[2], verifier)
		key, _ := AutomationClaimKey(1)
		installAutomationEvidence(t, a.c, key, "", 1)
		if _, err := a.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); err != nil {
			t.Fatal(err)
		}
	})
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	before := receiverActive(t, r.client)
	for _, attempt := range []int{1, 2} {
		if err := r.AuditSource(ctx, a, "a"); err != nil {
			t.Fatalf("typed receiver audit %d: %v", attempt, err)
		}
		if receiverActive(t, r.client) != before {
			t.Fatal("isolated audit changed active authority")
		}
	}
	rows, err := r.client.Query(ctx, `SELECT stage,uid,owner_id,revision FROM local_automation_resources ORDER BY uid`)
	if err != nil || len(rows) != 2 {
		t.Fatal("receiver typed resource reconstruction absent", rows, err)
	}
	for _, row := range rows {
		if row.String("stage") == "" || row.String("owner_id") != "target-owner" {
			t.Fatal("receiver used active projection", row)
		}
	}
}

func TestAutomationSchema73UpgradeAndSourceColumns(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	for _, descriptor := range automationSemanticTables {
		if _, err := a.c.db.Exec("DROP TABLE " + descriptor.table); err != nil {
			t.Fatal(err)
		}
	}
	for _, migration := range schemaMigrationLedger {
		if migration.Version == 73 {
			if _, err := a.c.db.Exec(`DELETE FROM applied_migrations WHERE id=?`, migration.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := a.c.db.Exec(`UPDATE schema_state SET version=72 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(ctx, a.c); err != nil {
		t.Fatal("schema72->73", err)
	}
	if storedVersion(t, a.c) != 73 {
		t.Fatal("upgrade did not reach73")
	}
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) }); err != nil {
		t.Fatal(err)
	}
	if err := a.c.SealVoterGeneration(ctx, 1, "columns"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.db.Exec(`ALTER TABLE local_automation_resources ADD COLUMN unknown_provenance TEXT`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.FreezeAutomationCut(ctx, 1, nil); err == nil || !strings.Contains(err.Error(), "unsupported automation semantic schema") {
		t.Fatal("unknown source column accepted", err)
	}
}

// The production cut must require every original permanent receipt; its audit
// may reconstruct projections but must neither repair evidence nor publish it
// incompletely. Include isolated state in the no-mutation snapshot.
func TestAutomationSourceOriginalRequestRequired(t *testing.T) {
	for _, mode := range []string{"intact", "initialize", "read_barrier"} {
		t.Run(mode, func(t *testing.T) {
			_, a, b, _ := threeVoters(t)
			ctx := context.Background()
			first := sharedAutomationRecord(t, 1, "", "initialize", "initialize-op", a, b)
			second := sharedAutomationRecord(t, 2, first.Value.MustDigest(), "barrier", "barrier-op", a, b)
			for _, record := range []AutomationRecord{first, second} {
				if _, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.c.db.Exec(`INSERT INTO local_automation_semantic_heads(stage,cluster_uid,sequence,digest) VALUES('unrelated-stage','unrelated',99,'unrelated-digest')`); err != nil {
				t.Fatal(err)
			}
			if err := a.c.SealVoterGeneration(ctx, 1, "original request audit"); err != nil {
				t.Fatal(err)
			}
			if mode != "intact" {
				request := "initialize"
				if mode == "read_barrier" {
					request = "barrier"
				}
				result, err := a.c.db.Exec(`DELETE FROM local_automation_requests WHERE request_id=?`, request)
				if err != nil {
					t.Fatal(err)
				}
				count, err := result.RowsAffected()
				if err != nil || count != 1 {
					t.Fatal("fixture did not remove exactly one original", count, err)
				}
			}
			snapshot := func() map[string][]Row {
				out := automationTypedSnapshot(t, a.c)
				for _, table := range []string{"local_automation_prefix", "local_automation_history", "local_automation_anchors", "local_automation_requests", "local_automation_cuts", "local_automation_cut_records"} {
					rows, err := a.c.Query(ctx, "SELECT * FROM "+table+" ORDER BY 1,2")
					if err != nil {
						t.Fatal(err)
					}
					out[table] = rows
				}
				return out
			}
			before := snapshot()
			id, err := a.c.FreezeAutomationCut(ctx, 1, contract.Reduce)
			if mode == "intact" {
				if err != nil || id == "" {
					t.Fatal("complete control originals refused", id, err)
				}
				after := snapshot()
				delete(before, "local_automation_cuts")
				delete(before, "local_automation_cut_records")
				delete(after, "local_automation_cuts")
				delete(after, "local_automation_cut_records")
				if !reflect.DeepEqual(before, after) {
					t.Fatal("positive cut mutated active/permanent/isolated evidence")
				}
			} else {
				if err == nil || id != "" {
					t.Error("published source with missing original request", id, err)
				}
				if !reflect.DeepEqual(before, snapshot()) {
					t.Error("refused source changed active/permanent/isolated state or published cut records")
				}
			}
		})
	}
}

func TestAutomationSourceSchemaShapeRequired(t *testing.T) {
	for _, mode := range []string{"generated", "type", "nullable", "primary-key"} {
		t.Run(mode, func(t *testing.T) {
			_, a, _, _ := threeVoters(t)
			ctx := context.Background()
			if mode == "generated" {
				if _, err := a.c.db.Exec(`ALTER TABLE local_automation_resources ADD COLUMN unknown_provenance TEXT GENERATED ALWAYS AS (uid) VIRTUAL`); err != nil {
					t.Fatal(err)
				}
			} else {
				rows, err := a.c.Query(ctx, `SELECT sql FROM sqlite_schema WHERE name='local_automation_resources'`)
				if err != nil || len(rows) != 1 {
					t.Fatal(rows, err)
				}
				ddl := rows[0].String("sql")
				before := ddl
				switch mode {
				case "type":
					ddl = strings.Replace(ddl, "uid TEXT NOT NULL", "uid BLOB NOT NULL", 1)
				case "nullable":
					ddl = strings.Replace(ddl, "uid TEXT NOT NULL", "uid TEXT", 1)
				case "primary-key":
					ddl = strings.Replace(ddl, "PRIMARY KEY(stage,uid)", "PRIMARY KEY(uid,stage)", 1)
				}
				if ddl == before {
					t.Fatal("schema mutation did not apply")
				}
				if _, err := a.c.db.Exec(`DROP TABLE local_automation_resources`); err != nil {
					t.Fatal(err)
				}
				if _, err := a.c.db.Exec(ddl); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.c.SealVoterGeneration(ctx, 1, "schema shape"); err != nil {
				t.Fatal(err)
			}
			before := automationTypedSnapshot(t, a.c)
			id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
			if err == nil || id != "" {
				t.Error("unsupported source schema shape accepted", id, err)
			}
			if !reflect.DeepEqual(before, automationTypedSnapshot(t, a.c)) {
				t.Fatal("schema refusal mutated projection")
			}
			rows, err := a.c.Query(ctx, `SELECT id FROM local_automation_cuts UNION ALL SELECT cut_id FROM local_automation_cut_records`)
			if err != nil || len(rows) != 0 {
				t.Error("schema refusal published cut", rows, err)
			}
		})
	}
}
