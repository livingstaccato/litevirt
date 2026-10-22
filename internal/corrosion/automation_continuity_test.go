package corrosion

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These genuinely signed historical prerequisites exercise storage and replay;
// they are not fresh enrollment or a native continuity acceptance producer.
func continuityStorageHistory(t *testing.T) (*claimTestVoter, *claimTestVoter, *claimTestVoter, *ClaimVerifier) {
	t.Helper()
	ca, a, b, c := threeVoters(t)
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "continuity-storage-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	automationTypedHistoryFixture(t, a, b, c, verifier)
	head, err := a.c.AutomationHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key, _ := AutomationClaimKey(head.Sequence + 1)
	installAutomationEvidence(t, a.c, key, head.Digest, 1)
	if _, err = a.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	return a, b, c, verifier
}
func continuityStorageFact() contract.IdentityContinuity {
	return contract.IdentityContinuity{ClusterUID: "established-cluster", UID: "principal-uid", OriginalWitness: "principal-source-lifetime", Generation: 1, Parent: contract.ParentLifetime{Kind: "principal", Alias: "principal-alias", Realm: "local", Birth: "parent-birth"}}
}
func continuityStorageRecord(t *testing.T, a, b *claimTestVoter, head contract.Prefix, request string, f contract.IdentityContinuity) AutomationRecord {
	t.Helper()
	body, _ := json.Marshal(contract.IdentityContinuityBody{Version: 1, IdentityContinuity: f})
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: f.ClusterUID, OperationID: request + "-op", RecordedAt: "2026-10-22T00:00:00Z", Continuity: &f})
	d := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: contract.Command{Kind: contract.IdentityContinuityCommand, ClusterUID: f.ClusterUID, PrincipalID: f.UID, ResourceUID: f.UID, Generation: f.Generation, RequestID: request, Body: body}, Assignment: assignment}
	raw, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: raw}}
	key, _ := AutomationClaimKey(d.Sequence)
	ballot := testBallot(2, "a")
	r := AutomationRecord{Value: value, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
	for _, v := range []*claimTestVoter{a, b} {
		s, e := v.signer.Sign(key, 1, ballot, value.MustDigest(), v.inc)
		if e != nil {
			t.Fatal(e)
		}
		r.Certificate.Accepts = append(r.Certificate.Accepts, s)
	}
	return r
}
func TestAutomationContinuityCertifiedStorageReplay(t *testing.T) {
	a, b, _, verifier := continuityStorageHistory(t)
	ctx := context.Background()
	head, err := a.c.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := continuityStorageRecord(t, a, b, head, "continuity-first", continuityStorageFact())
	receipt, err := a.c.AutomationApplyOwned(ctx, &r, verifier, contract.Reduce)
	if err != nil || receipt.Code != "" {
		t.Fatalf("certified continuity must apply and persist original identity: %+v %v", receipt, err)
	}
	rows, err := a.c.Query(ctx, `SELECT uid,generation,original_witness FROM local_automation_identity_continuity WHERE stage=''`)
	if err != nil || len(rows) != 1 || rows[0].String("uid") != "principal-uid" || rows[0].Int64("generation") != 1 || rows[0].String("original_witness") != "principal-source-lifetime" {
		t.Fatalf("continuity projection absent: %+v %v", rows, err)
	}
	if err := a.c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	replay, err := a.c.AutomationApplyOwned(ctx, &r, verifier, contract.Reduce)
	if err != nil || replay != receipt {
		t.Fatalf("original result changed: %+v %+v %v", receipt, replay, err)
	}
}

func TestAutomationContinuityCallbackEffectsAndClone(t *testing.T) {
	f := continuityStorageFact()
	actual := contract.Reduction{ContinuityEffect: &f}
	if err := validateAutomationCallback(actual, contract.Reduction{}); err == nil {
		t.Fatal("callback erased continuity effect")
	}
	if err := validateAutomationCallback(contract.Reduction{}, actual); err == nil {
		t.Fatal("callback invented continuity effect")
	}
	p := contract.Projection{Continuity: &contract.ContinuityProjection{Identity: &contract.IdentityRecord{UID: f.UID}, Existing: &f}}
	copy := cloneAutomationProjection(p)
	copy.Continuity.Identity.UID = "changed"
	copy.Continuity.Existing.Parent.Birth = "changed"
	if p.Continuity.Identity.UID != f.UID || p.Continuity.Existing.Parent.Birth != "parent-birth" {
		t.Fatal("callback mutated authoritative continuity predecessor")
	}
}
func TestAutomationContinuityReaderBoundsAndStage(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"valid", "missing", "wrong-cluster", "wrongtype", "oversized", "invalid-realm", "invalid-kind", "zero-generation", "foreign-generation", "canceled", "sql-error"} {
		t.Run(mode, func(t *testing.T) {
			c := NewTestClientT(t)
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			f := continuityStorageFact()
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if mode != "missing" {
					if err := automationApplyContinuityEffectTx(ctx, tx, "isolated", f.ClusterUID, contract.Reduction{ContinuityEffect: &f}); err != nil {
						return err
					}
				}
				switch mode {
				case "wrong-cluster":
					_, err := tx.Exec(ctx, `UPDATE local_automation_identity_continuity SET cluster_uid='other' WHERE stage='isolated'`)
					if err != nil {
						return err
					}
				case "wrongtype":
					_, err := tx.Exec(ctx, `UPDATE local_automation_identity_continuity SET original_witness=CAST(original_witness AS BLOB) WHERE stage='isolated'`)
					if err != nil {
						return err
					}
				case "oversized":
					_, err := tx.Exec(ctx, `UPDATE local_automation_identity_continuity SET parent_birth=? WHERE stage='isolated'`, strings.Repeat("x", contract.MaxStringBytes+1))
					if err != nil {
						return err
					}
				case "invalid-realm":
					_, err := tx.Exec(ctx, `UPDATE local_automation_identity_continuity SET parent_realm='' WHERE stage='isolated'`)
					if err != nil {
						return err
					}
				case "invalid-kind":
					_, err := tx.Exec(ctx, `UPDATE local_automation_identity_continuity SET parent_kind='vm' WHERE stage='isolated'`)
					if err != nil {
						return err
					}
				case "zero-generation":
					_, err := tx.Exec(ctx, `UPDATE local_automation_identity_continuity SET generation=0 WHERE stage='isolated'`)
					if err != nil {
						return err
					}
				case "sql-error":
					if _, err := tx.tx.ExecContext(ctx, `DROP TABLE local_automation_identity_continuity`); err != nil {
						return err
					}
				}
				readctx := ctx
				if mode == "canceled" {
					var cancel context.CancelFunc
					readctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				generation := uint64(1)
				if mode == "zero-generation" {
					generation = 0
				}
				if mode == "foreign-generation" {
					generation = 2
				}
				got, err := automationContinuityRecordTx(readctx, tx, "isolated", f.ClusterUID, f.UID, generation)
				switch mode {
				case "valid":
					if err != nil || got == nil || *got != f {
						t.Fatalf("exact facts missing: %+v %v", got, err)
					}
				case "missing", "foreign-generation":
					if err != nil || got != nil {
						t.Fatalf("clean missing row: %+v %v", got, err)
					}
				default:
					if err == nil {
						t.Fatal("malformed/error became missing or valid", got)
					}
				}
				if mode != "sql-error" && mode != "canceled" {
					got, err := automationContinuityRecordTx(ctx, tx, "", f.ClusterUID, f.UID, 1)
					if err != nil || got != nil {
						t.Fatal("isolated stage leaked", got, err)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestAutomationContinuityIndexAudit(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "unique", "reordered", "extra", "partial", "collation"} {
		t.Run(mode, func(t *testing.T) {
			c := NewTestClientT(t)
			ctx := context.Background()
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if mode != "valid" && mode != "extra" {
					if _, err := tx.tx.ExecContext(ctx, `DROP INDEX local_automation_identity_continuity_parent`); err != nil {
						return err
					}
				}
				var ddl string
				switch mode {
				case "unique":
					ddl = `CREATE UNIQUE INDEX local_automation_identity_continuity_parent ON local_automation_identity_continuity(stage,cluster_uid,parent_kind,parent_alias,parent_realm,parent_birth,uid,generation)`
				case "reordered":
					ddl = `CREATE INDEX local_automation_identity_continuity_parent ON local_automation_identity_continuity(stage,parent_kind,cluster_uid,parent_alias,parent_realm,parent_birth,uid,generation)`
				case "extra":
					ddl = `CREATE INDEX continuity_extra ON local_automation_identity_continuity(uid)`
				case "partial":
					ddl = `CREATE INDEX local_automation_identity_continuity_parent ON local_automation_identity_continuity(stage,cluster_uid,parent_kind,parent_alias,parent_realm,parent_birth,uid,generation) WHERE stage=''`
				case "collation":
					ddl = `CREATE INDEX local_automation_identity_continuity_parent ON local_automation_identity_continuity(stage,cluster_uid,parent_kind,parent_alias COLLATE NOCASE,parent_realm,parent_birth,uid,generation)`
				}
				if ddl != "" {
					if _, err := tx.tx.ExecContext(ctx, ddl); err != nil {
						return err
					}
				}
				err := automationVerifySemanticSchemaTx(ctx, tx)
				if (err == nil) != (mode == "valid") {
					t.Fatalf("schema/index audit %s: %v", mode, err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestAutomationContinuityRequestsConflictsAndRebuild(t *testing.T) {
	a, b, _, verifier := continuityStorageHistory(t)
	ctx := context.Background()
	f := continuityStorageFact()
	head, _ := a.c.AutomationHead(ctx)
	record := continuityStorageRecord(t, a, b, head, "first", f)
	first, err := a.c.AutomationApplyOwned(ctx, &record, verifier, contract.Reduce)
	if err != nil || first.Code != "" {
		t.Fatal(first, err)
	}
	for _, mode := range []string{"same-request", "identical", "conflict"} {
		head, _ = a.c.AutomationHead(ctx)
		request := mode
		fact := f
		if mode == "same-request" {
			request = "first"
		}
		if mode == "conflict" {
			fact.Parent.Birth = "different-birth"
		}
		record = continuityStorageRecord(t, a, b, head, request, fact)
		receipt, err := a.c.AutomationApplyOwned(ctx, &record, verifier, contract.Reduce)
		if err != nil {
			t.Fatal(mode, err)
		}
		if mode == "same-request" && receipt != first {
			t.Fatal("exact request lost original result", receipt, first)
		}
		if mode == "identical" && receipt.Code != "" {
			t.Fatal(receipt)
		}
		if mode == "conflict" && receipt.Code != contract.CodeOwnershipConflict {
			t.Fatal(receipt)
		}
	}
	before, err := a.c.Query(ctx, `SELECT * FROM local_automation_identity_continuity WHERE stage=''`)
	if err != nil || len(before) != 1 {
		t.Fatal(before, err)
	}
	err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := automationApplyContinuityEffectTx(ctx, tx, "isolated", f.ClusterUID, contract.Reduction{ContinuityEffect: &f}); err != nil {
			return err
		}
		if err := automationResetSemanticProjectionTx(ctx, tx, ""); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM local_automation_prefix`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	after, err := a.c.Query(ctx, `SELECT * FROM local_automation_identity_continuity WHERE stage=''`)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("history rebuild changed original attachment", err)
	}
	isolated, err := a.c.Query(ctx, `SELECT uid FROM local_automation_identity_continuity WHERE stage='isolated'`)
	if err != nil || len(isolated) != 1 {
		t.Fatal("replay destroyed isolated stage", err)
	}
}
func TestAutomationContinuityRejectedEffectNoMutation(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	f := continuityStorageFact()
	r := contract.Reduction{Receipt: contract.Receipt{Code: contract.CodeRetired}, ContinuityEffect: &f}
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		return automationApplySemanticEffectsTx(ctx, tx, "", contract.Prefix{}, contract.Prefix{ClusterUID: f.ClusterUID, Sequence: 1, Digest: strings.Repeat("a", 64)}, r)
	}); err == nil {
		t.Fatal("rejected decision wrote continuity")
	}
}
func TestAutomationContinuityRollbackAndLostReply(t *testing.T) {
	a, b, _, verifier := continuityStorageHistory(t)
	ctx := context.Background()
	head, _ := a.c.AutomationHead(ctx)
	f := continuityStorageFact()
	record := continuityStorageRecord(t, a, b, head, "rollback", f)
	d, err := automationDecision(record.Value)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := a.c.AutomationMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := AutomationClaimKey(d.Sequence)
	if err = verifier.Verify(record.Certificate, CertExpectation{Key: key, ValueDigest: record.Value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members))}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("before commit failure")
	var receipt contract.Receipt
	apply := func(tx *LocalTx) error {
		current, err := automationAuthorityTx(ctx, tx, a.c.hostName, cfg.Generation)
		if err != nil {
			return err
		}
		if current.MembersHash != cfg.MembersHash {
			return errors.New("membership drift")
		}
		receipt, err = automationApplyTx(ctx, tx, record, d, record.Value.MustDigest(), contract.Reduce, automationApplicationProvenance{kind: automationFreshAnchor, sequence: d.Sequence, generation: cfg.Generation, membersHash: cfg.MembersHash}, nil)
		return err
	}
	err = a.c.executeLocal(ctx, apply, &localCommitSeams{beforeCommit: func(*sql.Tx) error { return failure }})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	got, _ := a.c.AutomationHead(ctx)
	if got != head {
		t.Fatal("rolled-back head survived")
	}
	rows, err := a.c.Query(ctx, `SELECT uid FROM local_automation_identity_continuity`)
	if err != nil || len(rows) != 0 {
		t.Fatal("rolled-back projection survived", err)
	}
	stored, err := a.c.AutomationRequest(ctx, AutomationScope(d), "rollback")
	if err != nil || stored != nil {
		t.Fatal("rolled-back request survived", err)
	}
	committed := false
	err = a.c.executeLocal(ctx, apply, &localCommitSeams{afterCommit: func() { committed = true }})
	if err != nil || !committed {
		t.Fatal(err)
	}
	// A lost reply after FULL is represented by discarding the local response;
	// retry traverses the actual owned apply API and returns durable original.
	original := receipt
	receipt = contract.Receipt{}
	retried, err := a.c.AutomationApplyOwned(ctx, &record, verifier, contract.Reduce)
	if err != nil || retried != original {
		t.Fatal("lost reply changed result", retried, original, err)
	}
}

func TestAutomationContinuityFreshGenericAcceptanceStaysClosed(t *testing.T) {
	a, b, _, _ := continuityStorageHistory(t)
	ctx := context.Background()
	head, _ := a.c.AutomationHead(ctx)
	r := continuityStorageRecord(t, a, b, head, "generic-continuity", continuityStorageFact())
	key, _ := AutomationClaimKey(head.Sequence + 1)
	before := localTestMutationLogCount(t, a.c)
	refused, err := a.c.ClaimAccept(ctx, key, testBallot(8, "a"), r.Value, 1, a.signer, nil)
	if err != nil || refused.Accepted || refused.Accept != nil || refused.Refusal != RefusalAutomationUnavailable {
		t.Fatal("fresh continuity native class opened", refused, err)
	}
	// Same current authority/config/head/FULL and signer reach the permitted class.
	_, control := automationFixture(t, head.Sequence+1, head.Digest)
	accepted, err := a.c.ClaimAccept(ctx, key, testBallot(8, "a"), control, 1, a.signer, nil)
	if err != nil || !accepted.Accepted || accepted.Accept == nil {
		t.Fatal("earlier prerequisite masked fresh-class refusal", accepted, err)
	}
	if localTestMutationLogCount(t, a.c) != before {
		t.Fatal("local claim write replicated")
	}
}

func TestAutomationContinuityRetiredIdentityAndProjectionDrift(t *testing.T) {
	for _, mode := range []string{"retired", "missing", "extra", "changed"} {
		t.Run(mode, func(t *testing.T) {
			a, b, _, verifier := continuityStorageHistory(t)
			ctx := context.Background()
			f := continuityStorageFact()
			head, _ := a.c.AutomationHead(ctx)
			if mode == "retired" {
				if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					_, err := tx.Exec(ctx, `UPDATE local_automation_identities SET retired=1 WHERE stage='' AND uid=?`, f.UID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			record := continuityStorageRecord(t, a, b, head, "drift", f)
			receipt, err := a.c.AutomationApplyOwned(ctx, &record, verifier, contract.Reduce)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "retired" {
				if receipt.Code != contract.CodeRetired {
					t.Fatal(receipt)
				}
				rows, err := a.c.Query(ctx, `SELECT uid FROM local_automation_identity_continuity`)
				if err != nil || len(rows) != 0 {
					t.Fatal("retired decision produced effect", err)
				}
				return
			}
			if receipt.Code != "" {
				t.Fatal(receipt)
			}
			err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if err := automationApplyContinuityEffectTx(ctx, tx, "audit", f.ClusterUID, contract.Reduction{ContinuityEffect: &f}); err != nil {
					return err
				}
				// Compare only this descriptor: the remaining derived stages are populated
				// from the exact active rows to make this actual bidirectional source audit.
				for _, d := range automationSemanticTables {
					if d.table == "local_automation_identity_continuity" {
						continue
					}
					rows, err := tx.Query(ctx, "SELECT "+d.columns+" FROM "+d.table+" WHERE stage=''")
					if err != nil {
						return err
					}
					for _, row := range rows {
						values := append([]any(nil), row.Values...)
						values[0] = "audit"
						if _, err := tx.Exec(ctx, "INSERT INTO "+d.table+"("+d.columns+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")+")", values...); err != nil {
							return err
						}
					}
				}
				if err := automationVerifySemanticStageTx(ctx, tx, "audit"); err != nil {
					return err
				}
				switch mode {
				case "missing":
					_, err = tx.Exec(ctx, `DELETE FROM local_automation_identity_continuity WHERE stage=''`)
				case "extra":
					extra := f
					extra.UID = "extra"
					err = automationApplyContinuityEffectTx(ctx, tx, "", f.ClusterUID, contract.Reduction{ContinuityEffect: &extra})
				case "changed":
					_, err = tx.Exec(ctx, `UPDATE local_automation_identity_continuity SET parent_birth='changed' WHERE stage=''`)
				}
				if err != nil {
					return err
				}
				if err = automationVerifySemanticStageTx(ctx, tx, "audit"); err == nil {
					t.Fatal("active continuity drift accepted")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAutomationContinuityFrozen87AndCurrent38Layouts(t *testing.T) {
	old := aggregateLocalTables87()
	independent := automationExecutionCurrent86PrivateLayoutForTest()
	if !reflect.DeepEqual(old, independent) || retainedLocalLayout87Digest() != "5bc44346e864a2ccfa79a754ad45a697f60e71952b6db325d4289b92674a92a3" {
		t.Fatal("immutable signed87 literal changed")
	}
	current := aggregateLocalTables88()
	if len(old) != 37 || len(current) != 38 || len(automationSemanticTables) != 18 {
		t.Fatal("frozen88 descriptor boundary")
	}
	if !reflect.DeepEqual(old[:35], current[:35]) || !reflect.DeepEqual(old[35:], current[36:]) || current[35].table != "local_automation_identity_continuity" {
		t.Fatal("private suffix offsets changed")
	}
	for _, v := range []struct {
		digest string
		count  int
	}{{retainedLocalLayout83Digest(), 31}, {retainedLocalLayout85Digest(), 33}, {retainedLocalLayout87Digest(), 37}, {retainedLocalLayout88Digest(), 38}} {
		got, err := retainedLocalTablesForDigest(v.digest)
		if err != nil || len(got) != v.count {
			t.Fatal("literal layout dispatch", v, err)
		}
	}
}

// The immutable released87 producer supplies historical fixtures through an
// explicit offline path. A later binary never fabricates or restamps87 frames.
func continuity87Fixture(t *testing.T, name, sha string) []byte {
	t.Helper()
	root := os.Getenv("LITEVIRT_CONTINUITY87_FIXTURES")
	if root == "" {
		t.Skip("released genuine87 offline fixture not supplied")
	}
	raw, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if original83Hash(raw) != sha {
		t.Fatal("released signed87 artifact changed", name)
	}
	return raw
}
func TestAutomationContinuityGenuine87PublicCold88(t *testing.T) {
	ctx := context.Background()
	database := continuity87Fixture(t, "public/original87-state.db", "ed2e2f06067ace508bf499721a263444ed4d2c6f075e0f112d787aa817415742")
	raw := continuity87Fixture(t, "public/original87-evidence.json", "382123a4e724660bdce0206f053a3e7053219a8d10a66be0a6126e5b84af1b97")
	var evidence original83FixtureEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Version != 87 || evidence.SourceCommit != "59f09a32a8a22421ac7b8f5c1ff189287143b597" || evidence.SourceTree != "1c34e30860ae7f5b5e670c890966f25fb74c3249" || len(evidence.Ledger) != 207 {
		t.Fatal("actual source87 provenance missing")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if storedVersion(t, c) != 87 {
		t.Fatal("source87 was restamped")
	}
	before, records := cutFixtureRead(t, c, evidence.CutID)
	if before.SourceSchema != 87 || before.Codec != 1 || len(before.Inventory) != 9 || !reflect.DeepEqual(records, evidence.Records) {
		t.Fatal("actual87 archive changed")
	}
	if err = InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, c) != 89 {
		t.Fatal("consumer did not migrate89")
	}
	if len(schemaDDL) != len(evidence.DDL)+2 || !reflect.DeepEqual(schemaDDL[:len(evidence.DDL)], evidence.DDL) {
		t.Fatal("schema88 changed prior DDL")
	}
	for _, old := range evidence.Ledger {
		rows, err := c.Query(ctx, `SELECT checksum,applied_at FROM applied_migrations WHERE id=?`, old.String("id"))
		if err != nil || len(rows) != 1 || rows[0].String("checksum") != old.String("checksum") || rows[0].String("applied_at") != old.String("applied_at") {
			t.Fatal("schema88 changed old ledger", old.String("id"), err)
		}
	}

	after, again := cutFixtureRead(t, c, evidence.CutID)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, again) {
		t.Fatal("migration reinterpreted archived87")
	}
	rows, err := c.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, evidence.CutID)
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("metadata"), evidence.Metadata) || rows[0].String("root") != evidence.Root {
		t.Fatal("archived87 bytes/root changed", err)
	}
	reused, err := c.FreezeAutomationCut(ctx, 1, contract.Reduce)
	if err != nil || reused != evidence.CutID {
		t.Fatal("cold88 cannot reuse genuine87 cut", err)
	}
}

type continuity87PrivateEvidence struct {
	SourceCommit, SourceTree, StateDBSHA256       string
	Version                                       int
	Host, AggregateID, ClaimsDigest, ActiveDigest string
	Header, Binding, PublicTrust                  []byte
	Directory                                     struct {
		Namespace, Source, LocalID string
		Kind                       uint8
		Objects                    int64
	}
}

func TestAutomationContinuityGenuine87PrivateCold88(t *testing.T) {
	ctx := context.Background()
	database := continuity87Fixture(t, "private/private87-state.db", "a33d152b3ddc3845c4fd60225df06fafbebc36951be840e80faa9d9e7a111cca")
	raw := continuity87Fixture(t, "private/private87-evidence.json", "003e6c4abd8f78e60880b1e6ce19dfde9716d04d0f38cdda8693f37392e9b11c")
	var e continuity87PrivateEvidence
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Version != 87 || e.SourceCommit != "59f09a32a8a22421ac7b8f5c1ff189287143b597" || e.SourceTree != "1c34e30860ae7f5b5e670c890966f25fb74c3249" {
		t.Fatal("source87 private provenance")
	}
	hostdir := t.TempDir()
	for name, sha := range map[string]string{"ca.crt": "e1c5deb4893b2986753dd842156390b1c54afff962cea5453d449ad43c5a62df", "host.crt": "815a174202e05ba6889f4ab172f0af4226d10a29b7f020a1498f1700f0d46983", "host.key": "67d1125fbd0d90612a2f087ddf59e95e2a1972481ce6783acd90efd620c9b32a"} {
		data := continuity87Fixture(t, "private/"+name, sha)
		if err := os.WriteFile(filepath.Join(hostdir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	view, err := pki.CaptureHostTrust(ctx, hostdir, e.Host)
	if err != nil {
		t.Fatal(err)
	}
	public, err := view.PublicEvidence()
	if err != nil || !bytes.Equal(public, e.PublicTrust) {
		t.Fatal("actual native historical trust differs", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(dir, e.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if storedVersion(t, c) != 87 {
		t.Fatal("private producer restamped")
	}
	if err = InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, c) != 89 {
		t.Fatal("consumer89 not active")
	}
	header, err := decodeRetainedHeader(e.Header)
	if err != nil || header.LayoutDigest != retainedLocalLayout87Digest() || header.Head.Sequence != 14 {
		t.Fatal("original37 header meaning changed", err)
	}
	directory := retainedDirectoryReader{retainedFrameAddress{e.Directory.Namespace, e.Directory.Source, e.Directory.LocalID, retainedStreamKind(e.Directory.Kind)}, e.Directory.Objects}
	active := receiverActive(t, c)
	tx0, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	before := retainedCompatibilityExecutionRows(t, ctx, tx, "")
	rebuilt, err := rebuildRetainedAggregate(ctx, tx, header, e.Binding, directory, view)
	if err != nil || rebuilt.id != e.AggregateID || rebuilt.claims != e.ClaimsDigest {
		t.Fatal("genuine87 cold rebuild under88", err)
	}
	if !reflect.DeepEqual(before, retainedCompatibilityExecutionRows(t, ctx, tx, "receiver-audit:"+rebuilt.local.store.id)) {
		t.Fatal("old37 original execution projection changed")
	}
	rows, err := tx.Query(ctx, `SELECT uid FROM local_automation_identity_continuity WHERE stage=?`, "receiver-audit:"+rebuilt.local.store.id)
	if err != nil || len(rows) != 0 {
		t.Fatal("old37 invented continuity", err)
	}
	if err = tx0.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, c) != active {
		t.Fatal("historical rebuild mutated ACTIVE")
	}
}

func TestAutomationContinuityCurrent89NonemptySnapshot(t *testing.T) {
	a, b, _, verifier := continuityStorageHistory(t)
	ctx := context.Background()
	head, _ := a.c.AutomationHead(ctx)
	r := continuityStorageRecord(t, a, b, head, "snapshot", continuityStorageFact())
	cfg, err := a.c.AutomationMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(r.Certificate, CertExpectation{Key: r.Certificate.Key, ValueDigest: r.Value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members))}); err != nil {
		t.Fatal(err)
	}
	receipt, err := applySharedAutomation(t, a.c, r, contract.Reduce, automationFreshAnchor)
	if err != nil || receipt.Code != "" {
		t.Fatal(receipt, err)
	}
	before, err := a.c.Query(ctx, `SELECT * FROM local_automation_identity_continuity`)
	if err != nil {
		t.Fatal(err)
	}
	attempt := &AutomationReceiverAttempt{id: "continuity88-snapshot", binding: []byte("continuity88-snapshot")}
	seen := false
	err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var observation aggregateLocalObservation
		var out aggregateLocalAudit
		_, err := aggregateLocalSnapshot(ctx, tx, attempt, a.c, func(section int, n int64, row Row, raw []byte) error {
			if err := observation.observe(&out, section, n, row); err != nil {
				return err
			}
			d := aggregateLocalTables()[section]
			if d.table != "local_automation_identity_continuity" {
				return nil
			}
			seen = true
			if section != 35 || n != 1 {
				t.Fatal("current38 continuity offset")
			}
			decoded, err := decodeAutomationFramedRow(d.descriptor(), n, raw, maxAggregateLocalRecordBytes)
			if err != nil {
				return err
			}
			if decoded.String("uid") != "principal-uid" || decoded.String("parent_birth") != "parent-birth" || decoded.String("original_witness") != "principal-source-lifetime" {
				t.Fatal("nonempty current38 continuity frame changed")
			}
			if _, err := decodeAutomationFramedRow(aggregateLocalTables87()[35].descriptor(), n, raw, maxAggregateLocalRecordBytes); err == nil {
				t.Fatal("new38 decoded as old37 private observation")
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(observation.counts) != 38 || observation.cursor != out.head || !seen {
			t.Fatal("current38 nonempty observer incomplete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := a.c.Query(ctx, `SELECT * FROM local_automation_identity_continuity`)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("snapshot changed active attachment", err)
	}
}

// Historical signed-history prerequisites on actual FULL replicas. This uses
// the existing test-only G1 authority premise, never a fresh native class issuer.
func TestAutomationContinuityCurrent89RetainedWarmCold(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		verifier, err := LoadClaimVerifier(voters[0].pki)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range voters {
			targetCertifiedHistoryOn(t, v.c, voters, verifier)
			head, err := v.c.AutomationHead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := AutomationClaimKey(head.Sequence + 1)
			installAutomationEvidence(t, v.c, key, head.Digest, 1)
			if _, err = v.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			record := continuityStorageRecord(t, voters[0], voters[1], head, "retained38", continuityStorageFact())
			if err := verifier.Verify(record.Certificate, CertExpectation{Key: record.Certificate.Key, ValueDigest: record.Value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(voters...), Quorum: 2}); err != nil {
				t.Fatal(err)
			}
			receipt, err := applySharedAutomation(t, v.c, record, contract.Reduce, automationFreshAnchor)
			if err != nil || receipt.Code != "" {
				t.Fatal("signed continuity storage prerequisite", receipt, err)
			}
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	bundle, err := f.receiver.auditAggregate(ctx, f.attempt)
	if err != nil {
		t.Fatal("current38 authenticated aggregate", err)
	}
	c := f.local.c
	active := receiverActive(t, c)
	dataDir := c.dataDir
	tx0, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	header, directory := retainedCopyOriginalAggregate(t, ctx, tx, f, bundle)
	view := f.attempt.view
	frames := retainedCompatibilityFrames(t, ctx, tx, directory)
	check := func(tx *LocalTx) {
		t.Helper()
		if header.LayoutDigest != retainedLocalLayoutDigest() || header.Head.Sequence != 4 {
			t.Fatal("new38 original header", header.Head.Sequence)
		}
		descriptor, _, err := directory.find(ctx, tx, "local", header.LocalID)
		if err != nil || len(descriptor.ComponentInventories) != 38 || descriptor.ComponentInventories[35].Records != 1 {
			t.Fatal("nonempty continuity38 component missing", err)
		}
		rebuilt, err := rebuildRetainedAggregate(ctx, tx, header, f.attempt.binding, directory, view)
		if err != nil || rebuilt.id != bundle {
			t.Fatal("nonempty continuity38 retained reconstruction", err)
		}
		rows, err := tx.Query(ctx, `SELECT uid,generation,original_witness,parent_birth FROM local_automation_identity_continuity WHERE stage=?`, "receiver-audit:"+rebuilt.local.store.id)
		if err != nil || len(rows) != 1 || rows[0].String("uid") != "principal-uid" || rows[0].Int64("generation") != 1 || rows[0].String("original_witness") != "principal-source-lifetime" || rows[0].String("parent_birth") != "parent-birth" {
			t.Fatal("new38 replay lost original attachment", rows, err)
		}
		if !reflect.DeepEqual(frames, retainedCompatibilityFrames(t, ctx, tx, directory)) {
			t.Fatal("new38 retained frames mutated")
		}
		retainedCompatibilityClean(t, ctx, tx, rebuilt)
	}
	check(tx)
	if err = tx0.Commit(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, c) != active {
		t.Fatal("warm continuity38 rebuild changed ACTIVE")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	cold, err := NewLocalClient(dataDir, f.local.name)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	view, err = pki.CaptureHostTrust(ctx, f.local.pki, f.local.name)
	if err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, cold) != 89 {
		t.Fatal("cold continuity38 source schema")
	}
	coldtx, err := cold.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer coldtx.Rollback()
	check(&LocalTx{tx: coldtx})
	if err = coldtx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, cold) != active {
		t.Fatal("cold continuity38 rebuild changed ACTIVE")
	}
}

func TestAutomationContinuityOwnedCallbackCannotEraseOrForge(t *testing.T) {
	for _, mode := range []string{"erase", "forge", "mutate-predecessor"} {
		t.Run(mode, func(t *testing.T) {
			a, b, _, verifier := continuityStorageHistory(t)
			ctx := context.Background()
			head, _ := a.c.AutomationHead(ctx)
			record := continuityStorageRecord(t, a, b, head, "callback", continuityStorageFact())
			callback := func(p contract.Projection, d contract.Decision) (contract.Reduction, error) {
				if mode == "mutate-predecessor" {
					p.Continuity.Identity.Witness = "forged"
					return contract.Reduce(p, d)
				}
				result, err := contract.Reduce(p, d)
				if err != nil {
					return result, err
				}
				if mode == "erase" {
					result.ContinuityEffect = nil
				} else {
					f := *result.ContinuityEffect
					f.Parent.Birth = "forged"
					result.ContinuityEffect = &f
				}
				return result, nil
			}
			if _, err := a.c.AutomationApplyOwned(ctx, &record, verifier, callback); err == nil {
				t.Fatal("owned callback changed successful continuity semantics")
			}
			got, err := a.c.AutomationHead(ctx)
			if err != nil || got != head {
				t.Fatal("rejected callback changed head", err)
			}
			rows, err := a.c.Query(ctx, `SELECT uid FROM local_automation_identity_continuity`)
			if err != nil || len(rows) != 0 {
				t.Fatal("rejected callback wrote attachment", err)
			}
		})
	}
}
