package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"reflect"
	"strings"
	"testing"
)

// Ignoring typed effects when comparing a callback with the concrete evaluator
// lets a callback invent or erase semantic state without tripping the guard.
func TestAutomationIdentityCallbackCannotChangeEffects(t *testing.T) {
	for _, kind := range []string{"identity", "owner"} {
		t.Run(kind, func(t *testing.T) {
			actual := contract.Reduction{}
			if kind == "identity" {
				actual.IdentityEffect = &contract.IdentityRecord{UID: "uid"}
			} else {
				actual.OwnerEffect = &contract.OwnerRecord{OwnerID: "owner"}
			}
			callback := actual
			callback.IdentityEffect = nil
			callback.OwnerEffect = nil
			if err := validateAutomationCallback(actual, callback); err == nil {
				t.Fatal("callback erased typed semantic effect without rejection")
			}
		})
	}
}

func TestAutomationIdentityProjectionPersistsAtomically(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	effect := contract.Reduction{IdentityEffect: &contract.IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "project-uid", Alias: "acme", Witness: "positive-witness", Generation: 1}}
	head := contract.Prefix{}
	next := contract.Prefix{ClusterUID: "cluster", Sequence: 1, Digest: "digest"}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationApplySemanticEffectsTx(ctx, tx, "", head, next, effect) })
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT uid,generation,witness FROM local_automation_identities WHERE stage=''`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].String("uid") != "project-uid" || rows[0].String("witness") != "positive-witness" || rows[0].Int64("generation") != 1 {
		t.Fatalf("typed effect missing after committed FULL transaction: %+v", rows)
	}
	// A failure after the typed effects must roll all of them back with history.
	rollback := errors.New("injected transaction failure")
	effect.IdentityEffect = &contract.IdentityRecord{ClusterUID: "cluster", Kind: "principal", UID: "principal-uid", Alias: "alice", Witness: "principal-witness", Generation: 1}
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := automationApplySemanticEffectsTx(ctx, tx, "", next, contract.Prefix{ClusterUID: "cluster", Sequence: 2, Digest: "next"}, effect); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	rows, err = c.Query(ctx, `SELECT uid FROM local_automation_identities WHERE stage=''`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rolled-back effect survived: %+v %v", rows, err)
	}
}

func TestAutomationIdentityResetDoesNotRetainFutureState(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Direct projection rows here are a storage-boundary fixture, not enrollment
	// authority or production migration acceptance evidence.
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, stage := range []string{"", "receiver-audit"} {
			if _, err := tx.Exec(ctx, `INSERT INTO local_automation_owners(stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation) VALUES(?,?,?,?,?,?,?,?)`, stage, "cluster", "project", "owner", "principal", "future-session", "principal", 42); err != nil {
				return err
			}
		}
		return automationResetSemanticProjectionTx(ctx, tx, "")
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT stage,activation FROM local_automation_owners ORDER BY stage`)
	if err != nil || len(rows) != 1 || rows[0].String("stage") != "receiver-audit" || rows[0].Int64("activation") != 42 {
		t.Fatalf("replay retained future active owner or destroyed isolated stage: %+v %v", rows, err)
	}
}

func TestAutomationIdentityHistoryAdvancesSemanticHead(t *testing.T) {
	_, a, b, _ := threeVoters(t)
	r := sharedAutomationRecord(t, 1, "", "initialize", "operation", a, b)
	if _, err := applySharedAutomation(t, a.c, r, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	rows, err := a.c.Query(context.Background(), `SELECT sequence,digest FROM local_automation_semantic_heads WHERE stage=''`)
	if err != nil || len(rows) != 1 || rows[0].Int64("sequence") != 1 || rows[0].String("digest") != r.Value.MustDigest() {
		t.Fatalf("history did not atomically advance typed projection: %+v %v", rows, err)
	}
}

func TestAutomationIdentityReplayResetsFutureOwner(t *testing.T) {
	_, a, b, _ := threeVoters(t)
	ctx := context.Background()
	r := sharedAutomationRecord(t, 1, "", "initialize", "operation", a, b)
	if _, err := applySharedAutomation(t, a.c, r, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO local_automation_owners(stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation) VALUES(?,?,?,?,?,?,?,?)`, "", "established-cluster", "project", "owner", "principal", "future-session", "principal", 42); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM local_automation_prefix`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	rows, err := a.c.Query(ctx, `SELECT owner_id FROM local_automation_owners WHERE stage=''`)
	if err != nil || len(rows) != 0 {
		t.Fatalf("real anchored replay kept future semantic state: %+v %v", rows, err)
	}
	receipt, err := a.c.AutomationRequest(ctx, "internal:bootstrap", "initialize")
	if err != nil || receipt == nil || receipt.Receipt.OperationID != "operation" {
		t.Fatal("semantic reset erased permanent receipt", err)
	}
}

func TestAutomationIdentityCallbackCannotMutatePredecessor(t *testing.T) {
	p := contract.Projection{Identity: &contract.IdentityProjection{Alias: &contract.IdentityRecord{UID: "original"}, Assigned: &contract.IdentityRecord{Witness: "original"}}, Ownership: &contract.OwnershipProjection{Owner: &contract.OwnerRecord{Activation: 1}, Principal: &contract.IdentityRecord{UID: "principal"}}}
	p.Identity.Resource = &contract.ResourceRecord{Revision: "original"}
	p.Identity.AssignedResource = &contract.ResourceRecord{Revision: "assigned"}
	p.Identity.Name = &contract.NameRecord{Generation: 3}
	copy := cloneAutomationProjection(p)
	copy.Identity.Resource.Revision = "changed"
	copy.Identity.AssignedResource.Revision = "changed"
	copy.Identity.Name.Generation = 99
	copy.Identity.Alias.UID = "changed"
	copy.Identity.Assigned.Witness = "changed"
	copy.Ownership.Owner.Activation = 99
	copy.Ownership.Principal.UID = "changed"
	if p.Identity.Resource.Revision != "original" || p.Identity.AssignedResource.Revision != "assigned" || p.Identity.Name.Generation != 3 || p.Identity.Alias.UID != "original" || p.Identity.Assigned.Witness != "original" || p.Ownership.Owner.Activation != 1 || p.Ownership.Principal.UID != "principal" {
		t.Fatal("compatibility callback can mutate authoritative predecessor")
	}
}

// This reads typed SQLite projection fixtures; it does not claim the fixtures
// were admitted by a production migration or authentication provider.
func TestAutomationIdentityProjectionReadsOwnerLifetimes(t *testing.T) {
	_, a, b, _ := threeVoters(t)
	ctx := context.Background()
	r := sharedAutomationRecord(t, 1, "", "initialize", "operation", a, b)
	if _, err := applySharedAutomation(t, a.c, r, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, fact := range []struct{ uid, kind, alias string }{{"project", "project", "acme"}, {"principal", "principal", "alice"}} {
			if _, err := tx.Exec(ctx, `INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES(?,?,?,?,?,?,?,?,?)`, "", fact.uid, "established-cluster", "", fact.kind, fact.alias, "positive-witness", 1, 0); err != nil {
				return err
			}
		}
		d := contract.Decision{Sequence: 2, ParentDigest: r.Value.MustDigest(), Command: contract.Command{Kind: "ensure_owner", ClusterUID: "established-cluster", ProjectUID: "project", PrincipalID: "principal", OwnerID: "owner", RequestID: "owner-request", Body: []byte(`{"version":1}`)}, Assignment: []byte(`{"version":1,"cluster_uid":"established-cluster","operation_id":"owner-op","recorded_at":"2026-10-17T00:00:00Z"}`)}
		p, err := automationProjectionTx(ctx, tx, contract.Prefix{ClusterUID: "established-cluster", Sequence: 1, Digest: r.Value.MustDigest()}, d, nil)
		if err != nil {
			return err
		}
		if p.Ownership == nil || p.Ownership.Project == nil || p.Ownership.Project.UID != "project" || p.Ownership.Principal == nil || p.Ownership.Principal.UID != "principal" {
			return errors.New("production point projection omitted enrolled project/principal lifetimes")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAutomationIdentityReplayRepairsMissingSemanticHead(t *testing.T) {
	_, a, b, _ := threeVoters(t)
	ctx := context.Background()
	record := sharedAutomationRecord(t, 1, "", "initialize", "operation", a, b)
	if _, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := tx.Exec(ctx, `DELETE FROM local_automation_semantic_heads WHERE stage=''`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	rows, err := a.c.Query(ctx, `SELECT sequence,digest FROM local_automation_semantic_heads WHERE stage=''`)
	if err != nil || len(rows) != 1 || rows[0].Int64("sequence") != 1 || rows[0].String("digest") != record.Value.MustDigest() {
		t.Fatalf("replay trusted prefix with missing typed projection boundary: %+v %v", rows, err)
	}
}

// Signed test history exercises the actual storage/replay path. The certificates
// are verified here, but this fixture grants no fresh migration/class permit.
func TestAutomationIdentityCertifiedReplayWithoutEnrollmentProvider(t *testing.T) {
	ca, a, b, c := threeVoters(t)
	ctx := context.Background()
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "identity-replay-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	automationTypedHistoryFixture(t, a, b, c, verifier)
	// Populate an isolated audit stage from actual applied rows. Active replay
	// must rebuild every typed table without touching this retained stage.
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, table := range automationTypedTables {
			rows, err := tx.Query(ctx, "SELECT * FROM "+table+" WHERE stage=''")
			if err != nil {
				return err
			}
			for _, row := range rows {
				values := append([]interface{}(nil), row.Values...)
				for i, column := range row.Columns {
					if column == "stage" {
						values[i] = "isolated-replay-audit"
					}
				}
				placeholders := strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")
				if _, err := tx.Exec(ctx, "INSERT INTO "+table+"("+strings.Join(row.Columns, ",")+") VALUES("+placeholders+")", values...); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	typedBefore := automationTypedSnapshot(t, a.c)
	before := sharedActiveRows(t, a.c)
	identities, err := a.c.Query(ctx, `SELECT * FROM local_automation_identities ORDER BY stage,uid`)
	if err != nil {
		t.Fatal(err)
	}
	owners, err := a.c.Query(ctx, `SELECT * FROM local_automation_owners ORDER BY stage,cluster_uid,project_uid,owner_id`)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 8 || len(owners) != 4 || owners[0].Int64("activation") != 2 {
		t.Fatalf("typed history absent: %+v %+v", identities, owners)
	}
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := automationResetSemanticProjectionTx(ctx, tx, ""); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM local_automation_prefix`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	afterIdentities, err := a.c.Query(ctx, `SELECT * FROM local_automation_identities ORDER BY stage,uid`)
	if err != nil {
		t.Fatal(err)
	}
	afterOwners, err := a.c.Query(ctx, `SELECT * FROM local_automation_owners ORDER BY stage,cluster_uid,project_uid,owner_id`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(typedBefore, automationTypedSnapshot(t, a.c)) || !reflect.DeepEqual(identities, afterIdentities) || !reflect.DeepEqual(owners, afterOwners) || !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
		t.Fatal("recorded history did not reproduce exact lifetimes, activation and original receipts")
	}
	// Altering an anchor must fail before reconstruction can bless any state.
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM local_automation_semantic_heads WHERE stage=''`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE local_automation_anchors SET digest=? WHERE sequence=12`, strings.Repeat("c", 64))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	altered := sharedActiveRows(t, a.c)
	typedAltered := automationTypedSnapshot(t, a.c)
	if err := a.c.AutomationReplay(ctx, contract.Reduce, 256); err == nil {
		t.Fatal("changed anchor accepted during typed reconstruction")
	}
	if !reflect.DeepEqual(typedAltered, automationTypedSnapshot(t, a.c)) || !reflect.DeepEqual(altered, sharedActiveRows(t, a.c)) {
		t.Fatal("rejected anchor mutated history")
	}
}

var automationTypedTables = []string{"local_automation_executors", "local_automation_execution_progress", "local_automation_execution_artifacts", "local_automation_execution_terminals", "local_automation_target_operations", "local_automation_target_reservations", "local_automation_identities", "local_automation_aliases", "local_automation_owners", "local_automation_semantic_heads", "local_automation_resources", "local_automation_names", "local_automation_bindings", "local_automation_admissions"}

func automationTypedSnapshot(t *testing.T, c *Client) map[string][]Row {
	t.Helper()
	out := map[string][]Row{}
	for _, table := range automationTypedTables {
		rows, err := c.Query(context.Background(), "SELECT * FROM "+table+" ORDER BY stage,2,3,4")
		if err != nil {
			t.Fatal(err)
		}
		out[table] = rows
	}
	return out
}

func automationTypedHistoryFixture(t *testing.T, a, b, c *claimTestVoter, verifier *ClaimVerifier) {
	automationTypedHistoryFixtureWithDecision(t, a, b, c, verifier, nil)
}

// change is a test-only retained decision variation before signing and verifying
// its certificate. It never supplies a fresh class permit or reducer result.
func automationTypedHistoryFixtureWithDecision(t *testing.T, a, b, c *claimTestVoter, verifier *ClaimVerifier, change func(*contract.Decision)) {
	t.Helper()
	automationTypedHistoryFixtureThroughDecision(t, a, b, c, verifier, change, 12)
}

// The sequence11 boundary retains genuinely signed enrollment before adoption.
// Existing callers retain the complete sequence12 fixture without variation.
func automationTypedHistoryFixtureThroughDecision(t *testing.T, a, b, c *claimTestVoter, verifier *ClaimVerifier, change func(*contract.Decision), through uint64) {
	t.Helper()
	if through != 11 && through != 12 {
		t.Fatal("unsupported typed history boundary", through)
	}
	t.Helper()
	initial := sharedAutomationRecord(t, 1, "", "initialize", "initialize-op", a, b)
	if _, err := applySharedAutomation(t, a.c, initial, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	parent := initial.Value.MustDigest()
	appendDecision := func(d contract.Decision) {
		t.Helper()
		d.ParentDigest = parent
		if change != nil {
			change(&d)
		}
		envelope, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		value := ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}}
		key, _ := AutomationClaimKey(d.Sequence)
		ballot := testBallot(2, "a")
		record := AutomationRecord{Value: value, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
		for _, v := range []*claimTestVoter{a, b} {
			signed, err := v.signer.Sign(key, 1, ballot, value.MustDigest(), v.inc)
			if err != nil {
				t.Fatal(err)
			}
			record.Certificate.Accepts = append(record.Certificate.Accepts, signed)
		}
		if err := verifier.Verify(record.Certificate, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(a, b, c), Quorum: 2}); err != nil {
			t.Fatal(err)
		}
		if receipt, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); err != nil || receipt.Code != "" {
			t.Fatalf("typed certified history: %+v %v", receipt, err)
		}
		parent = value.MustDigest()
	}
	for i, kind := range []string{"project", "principal"} {
		body := contract.IdentityEnrollment{Version: 1, Kind: kind, Alias: kind + "-alias", Witness: kind + "-source-lifetime", EvidenceID: "closed-cutover"}
		bodyJSON, _ := json.Marshal(body)
		assignment := contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: kind + "-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: kind + "-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: body.EvidenceID, ClusterUID: "established-cluster", Kind: kind, Alias: body.Alias, Witness: body.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}}
		assignmentJSON, _ := json.Marshal(assignment)
		appendDecision(contract.Decision{Sequence: uint64(i + 2), Command: contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", PrincipalID: "host", RequestID: kind + "-request", Body: bodyJSON}, Assignment: assignmentJSON})
	}
	for i, kind := range []string{"ensure_owner", "acquire_session", "handoff_session"} {
		command := contract.Command{Kind: kind, ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "owner", RequestID: kind + "-request", Body: []byte(`{"version":1}`)}
		assignment := contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: kind + "-op", RecordedAt: "2026-10-17T00:00:00Z"}
		if i > 0 {
			assignment.Owner = &contract.OwnerAssignment{SessionID: fmt.Sprintf("session-%d", i)}
		}
		if i == 2 {
			command.Session = 1
			command.SessionID = "session-1"
			command.Body = []byte(`{"version":1,"next_principal_uid":"principal-uid"}`)
		}
		assignmentJSON, _ := json.Marshal(assignment)
		appendDecision(contract.Decision{Sequence: uint64(i + 4), Command: command, Assignment: assignmentJSON})
	}
	// The full decision certificate records prepared nonsecret configuration;
	// this fixture supplies no production fresh create or migration permit.
	maxCPU, maxMemory := uint32(2), uint64(1024)
	desired := contract.VMIntent{Name: "machine", CPU: 2, MemoryMiB: 1024}
	prepared := desired
	prepared.MaxCPU = &maxCPU
	prepared.MemoryHotplugMaxMiB = &maxMemory
	prepared.RequestedState = "running"
	prepared.Placement = &contract.PlacementIntent{Policy: "balanced"}
	bodyJSON, _ := json.Marshal(contract.CreateBindingBody{Version: 1, Desired: desired})
	assignmentJSON, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "create-op", RecordedAt: "2026-10-17T00:00:00Z", Binding: &contract.BindingAssignment{PayloadID: "payload-reference", ResourceUID: "resource-uid", BindingGeneration: 1, NameGeneration: 1, Revision: "rev:opaque-alpha", DomainUUID: "domain-uuid", Incarnation: "incarnation", AdmittedGeneration: 1, Configuration: prepared}})
	appendDecision(contract.Decision{Sequence: 7, Command: contract.Command{Kind: "admit_create", ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "owner", ManagementKey: "key", SessionID: "session-2", Session: 2, RequestID: "create-request", Body: bodyJSON, Ciphertext: []byte("retained-encrypted-payload"), SecretIntentTag: []byte("equality-tag"), SecretKeyEpoch: "key-epoch"}, Assignment: assignmentJSON})
	for offset, kind := range []string{"ensure_owner", "acquire_session"} {
		assigned := contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: kind + "-target-op", RecordedAt: "2026-10-17T00:00:00Z"}
		if offset == 1 {
			assigned.Owner = &contract.OwnerAssignment{SessionID: "target-session"}
		}
		encoded, _ := json.Marshal(assigned)
		appendDecision(contract.Decision{Sequence: uint64(8 + offset), Command: contract.Command{Kind: kind, ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "target-owner", RequestID: kind + "-target-request", Body: []byte(`{"version":1}`)}, Assignment: encoded})
	}
	ownership := func(seq uint64, kind, uid, name, revision, incarnation, lastOperation, key string, source *contract.BindingReference) {
		body := contract.OwnershipBody{Version: 1, Resource: contract.ResourceReference{ClusterUID: "established-cluster", ProjectUID: "project-uid", Kind: "vm", UID: uid}, ExpectedRevision: revision, Source: source, Target: contract.BindingKey{ClusterUID: "established-cluster", ProjectUID: "project-uid", OwnerID: "target-owner", ManagementKey: key}}
		command := contract.Command{Kind: kind, ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "target-owner", ManagementKey: key, ResourceUID: uid, Session: 1, SessionID: "target-session", RequestID: kind + "-request"}
		if source != nil {
			command.OwnerID = source.Key.OwnerID
			command.ManagementKey = source.Key.ManagementKey
			command.Generation = source.Generation
			command.Session = 2
			command.SessionID = "session-2"
		}
		command.Body, _ = json.Marshal(body)
		assignment := contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: kind + "-op", RecordedAt: "2026-10-17T00:00:00Z", Ownership: &contract.OwnershipAssignment{Version: 1, TargetSession: contract.RecordedOwnerSession{ID: "target-session", Activation: 1, PrincipalUID: "principal-uid"}, TargetGeneration: 1, Revision: "new-opaque-" + uid, AdmittedGeneration: 1, Quiescence: contract.QuiescenceFacts{Version: 1, ResourceUID: uid, Revision: revision, Incarnation: incarnation, LastOperationID: lastOperation, FenceSequence: seq - 1, EvidenceID: "quiescence-reference", CoverageDigest: strings.Repeat("d", 64)}}}
		for _, purpose := range []string{"source_owner", "target_owner", "resource"} {
			if purpose == "source_owner" && source == nil {
				continue
			}
			permission := contract.PermissionFacts{Purpose: purpose, PrincipalUID: command.PrincipalID, ClusterUID: command.ClusterUID, ProjectUID: command.ProjectUID, ProjectName: "project-alias", Verb: "vm.update", EvidenceID: "permission-reference", CoverageDigest: strings.Repeat("e", 64), FenceSequence: seq - 1}
			switch purpose {
			case "source_owner":
				permission.OwnerID = source.Key.OwnerID
			case "target_owner":
				permission.OwnerID = "target-owner"
			case "resource":
				permission.ResourceUID = uid
				permission.ResourceName = name
			}
			assignment.Ownership.Permissions = append(assignment.Ownership.Permissions, permission)
		}
		encoded, _ := json.Marshal(assignment)
		appendDecision(contract.Decision{Sequence: seq, Command: command, Assignment: encoded})
	}
	ownership(10, "transfer_owner", "resource-uid", "machine", "rev:opaque-alpha", "incarnation", "create-op", "target-key", &contract.BindingReference{Key: contract.BindingKey{ClusterUID: "established-cluster", ProjectUID: "project-uid", OwnerID: "owner", ManagementKey: "key"}, Generation: 1})
	migration := contract.IdentityEnrollment{Version: 1, Kind: "vm", Alias: "legacy-machine", Witness: "positive-legacy-witness", EvidenceID: "closed-cutover"}
	encodedBody, _ := json.Marshal(migration)
	migrationAssignment := contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "migration-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: "legacy-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: migration.EvidenceID, ClusterUID: "established-cluster", ProjectUID: "project-uid", Kind: "vm", Alias: migration.Alias, Witness: migration.Witness, CoverageDigest: strings.Repeat("f", 64), FenceSequence: 1, VM: &contract.VMEnrollmentRuntime{Version: 1, DomainUUID: "legacy-domain", Incarnation: "legacy-incarnation", Revision: "legacy-revision"}}}}
	encodedAssignment, _ := json.Marshal(migrationAssignment)
	appendDecision(contract.Decision{Sequence: 11, Command: contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "host", RequestID: "migration-request", Body: encodedBody}, Assignment: encodedAssignment})
	if through == 12 {
		ownership(12, "adopt_resource", "legacy-uid", "legacy-machine", "legacy-revision", "legacy-incarnation", "migration-op", "legacy-key", nil)
	}
}
