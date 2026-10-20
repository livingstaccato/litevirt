package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func requireNameStorage(t *testing.T, c *Client, name string, state AutomationNameState) AutomationNameObservation {
	t.Helper()
	got, err := c.AutomationObserveName(context.Background(), "established-cluster", name, 12)
	if err != nil || got.State != state || got.Name != name || got.Prefix.Sequence < 12 || (got.Record == nil) != (state == AutomationNameAbsent) {
		t.Fatalf("eligible name %q: %+v %v", name, got, err)
	}
	return got
}

func TestAutomationObserveNameStorageRecords(t *testing.T) {
	c := observeStorageFixture(t, false)
	beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
	for _, name := range []string{"machine", "legacy-machine", "never-enrolled"} {
		t.Run(name, func(t *testing.T) {
			state := AutomationNamePresent
			if name == "never-enrolled" {
				state = AutomationNameAbsent
			}
			got := requireNameStorage(t, c, name, state)
			if state == AutomationNameAbsent {
				return
			}
			r := got.Record
			if r.Project.UID != "project-uid" || r.Project.Alias != "project-alias" || r.Project.Witness != "project-source-lifetime" || r.Owner == nil || r.Binding == nil || r.Resource.OwnerID != "target-owner" || r.Owner.SessionID != "target-session" || r.Binding.OperationID != r.Resource.LastOperationID {
				t.Fatalf("missing exact certified graph: %+v", r)
			}
			if name == "legacy-machine" && (r.VMIdentity.Witness != "positive-legacy-witness" || r.Resource.Incarnation != "legacy-incarnation" || r.Resource.OriginalOperationID != "" || r.Resource.LastOperationID != "adopt_resource-op") {
				t.Fatalf("adoption lost independent enrollment facts: %+v", r)
			}
			copy := *r
			r.Name.Name = "caller-change"
			r.Resource.Revision = "caller-change"
			r.VMIdentity.Witness = "caller-change"
			r.Project.Alias = "caller-change"
			r.Owner.SessionID = "caller-change"
			r.Binding.Revision = "caller-change"
			again := requireNameStorage(t, c, name, AutomationNamePresent)
			if again.Record.Name != copy.Name || again.Record.Resource != copy.Resource || again.Record.VMIdentity != copy.VMIdentity || again.Record.Project != copy.Project || again.Record.Owner.SessionID != "target-session" || again.Record.Binding.Revision != copy.Resource.Revision {
				t.Fatalf("caller pointers changed subsequent observation: %+v", again)
			}
		})
	}
	if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
		t.Fatal("storage observation wrote history/receipts or semantic state")
	}
	original, found, err := c.AutomationOperation(context.Background(), "create-op")
	if err != nil || !found || original.ResourceRevision != "rev:opaque-alpha" || original.Sequence != 7 {
		t.Fatalf("original create changed after transfer observation: %+v %v", original, err)
	}
}

func TestAutomationObserveNameStorageInputAndFrontier(t *testing.T) {
	var absentClient *Client
	for _, tc := range []struct {
		name, cluster, selector string
		min                     uint64
	}{
		{"empty-name", "cluster", "", 1}, {"traversal", "cluster", "..", 1}, {"path", "cluster", "a/b", 1},
		{"nul-name", "cluster", "a\x00b", 1}, {"utf8-name", "cluster", string([]byte{0xff}), 1},
		{"empty-cluster", "", "machine", 1}, {"nul-cluster", "a\x00b", "machine", 1},
		{"utf8-cluster", string([]byte{0xff}), "machine", 1}, {"large-cluster", strings.Repeat("c", contract.MaxStringBytes+1), "machine", 1},
		{"zero-barrier", "cluster", "machine", 0}, {"overflow-barrier", "cluster", "machine", math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := absentClient.AutomationObserveName(context.Background(), tc.cluster, tc.selector, tc.min)
			if contract.Code(err) != contract.CodeValidation || got != (AutomationNameObservation{}) {
				t.Fatalf("invalid input reached dependency or leaked observation: %+v %v", got, err)
			}
		})
	}
	c := observeStorageFixture(t, false)
	for _, tc := range []struct {
		cluster string
		min     uint64
	}{{"foreign", 12}, {"established-cluster", 13}} {
		got, err := c.AutomationObserveName(context.Background(), tc.cluster, "never-enrolled", tc.min)
		if got != (AutomationNameObservation{}) || contract.Code(err) != contract.CodeUnavailable {
			t.Fatalf("frontier mismatch classified absence: %+v %v", got, err)
		}
	}
	requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
}

func TestAutomationObserveNameStoragePartialAndScalars(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	for _, tc := range []struct {
		name, query, sql string
		args             []any
	}{
		{"name-missing", "machine", `DELETE FROM local_automation_names WHERE name='machine'`, nil},
		{"alias-missing", "machine", `DELETE FROM local_automation_aliases WHERE kind='vm' AND alias='machine'`, nil},
		{"resource-missing", "machine", `DELETE FROM local_automation_resources WHERE uid='resource-uid'`, nil},
		{"identity-missing", "machine", `DELETE FROM local_automation_identities WHERE uid='resource-uid'`, nil},
		{"name-generation", "machine", `UPDATE local_automation_names SET generation=2 WHERE name='machine'`, nil},
		{"alias-generation", "machine", `UPDATE local_automation_aliases SET generation=2 WHERE kind='vm' AND alias='machine'`, nil},
		{"identity-project", "machine", `UPDATE local_automation_identities SET project_uid='foreign' WHERE uid='resource-uid'`, nil},
		{"project-alias-missing", "machine", `DELETE FROM local_automation_aliases WHERE kind='project'`, nil},
		{"project-lifetime-missing", "machine", `DELETE FROM local_automation_identities WHERE uid='project-uid'`, nil},
		{"project-alias-wrong-uid", "machine", `UPDATE local_automation_aliases SET uid='principal-uid' WHERE kind='project'`, nil},
		{"owner-missing", "machine", `DELETE FROM local_automation_owners WHERE owner_id='target-owner'`, nil},
		{"founder-missing", "machine", `DELETE FROM local_automation_identities WHERE uid='principal-uid'`, nil},
		{"binding-missing", "machine", `DELETE FROM local_automation_bindings WHERE retired=0 AND resource_uid='resource-uid'`, nil},
		{"binding-operation", "machine", `UPDATE local_automation_bindings SET operation_id='missing' WHERE retired=0 AND resource_uid='resource-uid'`, nil},
		{"binding-project", "machine", `UPDATE local_automation_bindings SET project_uid='foreign' WHERE resource_uid='resource-uid'`, nil},
		{"admission-missing", "machine", `DELETE FROM local_automation_admissions WHERE operation_id='transfer_owner-op'`, nil},
		{"original-missing", "machine", `DELETE FROM local_automation_admissions WHERE operation_id='create-op'`, nil},
		{"source-revision", "machine", `UPDATE local_automation_bindings SET revision='wrong' WHERE resource_uid='resource-uid' AND retired=1`, nil},
		{"source-generation", "machine", `UPDATE local_automation_bindings SET creation_generation=2 WHERE resource_uid='resource-uid' AND retired=1`, nil},
		{"wrong-cluster", "machine", `UPDATE local_automation_resources SET cluster_uid='foreign' WHERE uid='resource-uid'`, nil},
		{"wrong-scope", "machine", `UPDATE local_automation_aliases SET project_scope='project-uid' WHERE kind='vm' AND alias='machine'`, nil},
		{"future-sequence", "machine", `UPDATE local_automation_resources SET applied_sequence=13 WHERE uid='resource-uid'`, nil},
		{"untrusted-operation-anchor", "machine", `UPDATE local_automation_anchors SET digest=? WHERE sequence=10`, []any{strings.Repeat("f", 64)}},
		{"missing-operation-anchor", "machine", `DELETE FROM local_automation_anchors WHERE sequence=10`, nil},
		{"unknown-identity-routing", "never-enrolled", `UPDATE local_automation_identities SET kind='unknown' WHERE uid='resource-uid'`, nil},
		{"unknown-alias-routing", "never-enrolled", `UPDATE local_automation_aliases SET kind='unknown' WHERE kind='vm' AND alias='machine'`, nil},
		{"prefix-missing", "never-enrolled", `DELETE FROM local_automation_prefix`, nil},
		{"semantic-missing", "never-enrolled", `DELETE FROM local_automation_semantic_heads WHERE stage=''`, nil},
		{"semantic-lag", "never-enrolled", `UPDATE local_automation_semantic_heads SET sequence=11 WHERE stage=''`, nil},
		{"prefix-real", "never-enrolled", `UPDATE local_automation_prefix SET sequence=?`, []any{12.5}},
		{"name-real-generation", "machine", `UPDATE local_automation_names SET generation=? WHERE name='machine'`, []any{1.5}},
		{"identity-real-generation", "machine", `UPDATE local_automation_identities SET generation=? WHERE uid='resource-uid'`, []any{1.5}},
		{"binding-real-generation", "machine", `UPDATE local_automation_bindings SET creation_generation=? WHERE retired=0 AND resource_uid='resource-uid'`, []any{1.5}},
		{"admission-real-sequence", "machine", `UPDATE local_automation_admissions SET sequence=? WHERE operation_id='transfer_owner-op'`, []any{10.5}},
		{"owner-real-activation", "machine", `UPDATE local_automation_owners SET activation=? WHERE owner_id='target-owner'`, []any{1.5}},
		{"resource-real-sequence", "machine", `UPDATE local_automation_resources SET applied_sequence=? WHERE uid='resource-uid'`, []any{10.5}},
		{"blob-resource-name", "machine", `UPDATE local_automation_resources SET name=? WHERE uid='resource-uid'`, []any{[]byte("machine")}},
		{"blob-alias-routing", "never-enrolled", `UPDATE local_automation_aliases SET alias=? WHERE kind='vm' AND alias='machine'`, []any{[]byte("machine")}},
		{"blob-name-routing", "never-enrolled", `UPDATE local_automation_names SET name=? WHERE name='machine'`, []any{[]byte("machine")}},
		{"blob-binding-routing", "never-enrolled", `UPDATE local_automation_bindings SET resource_uid=? WHERE retired=0 AND resource_uid='resource-uid'`, []any{[]byte("resource-uid")}},
		{"blob-admission-routing", "never-enrolled", `UPDATE local_automation_admissions SET resource_uid=? WHERE operation_id='transfer_owner-op'`, []any{[]byte("resource-uid")}},
		{"empty-witness", "machine", `UPDATE local_automation_identities SET witness='' WHERE uid='resource-uid'`, nil},
		{"utf8-witness", "machine", `UPDATE local_automation_identities SET witness=? WHERE uid='resource-uid'`, []any{string([]byte{0xff})}},
		{"nul-witness", "machine", `UPDATE local_automation_identities SET witness=? WHERE uid='resource-uid'`, []any{"w\x00suffix"}},
		{"large-witness", "machine", `UPDATE local_automation_identities SET witness=? WHERE uid='resource-uid'`, []any{strings.Repeat("w", contract.MaxStringBytes+1)}},
		{"large-routing", "never-enrolled", `UPDATE local_automation_admissions SET resource_uid=? WHERE operation_id='transfer_owner-op'`, []any{strings.Repeat("u", contract.MaxStringBytes+1)}},
		{"nul-domain", "machine", `UPDATE local_automation_resources SET domain_uuid=? WHERE uid='resource-uid'`, []any{"d\x00suffix"}},
		{"noncanonical-config", "machine", `UPDATE local_automation_admissions SET configuration_json=' null ' WHERE operation_id='transfer_owner-op'`, nil},
		{"invented-retirement", "machine", `UPDATE local_automation_names SET disposition='reusable',retirement_operation_id='not-produced' WHERE name='machine'`, nil},

		{"alias-uid", "machine", `UPDATE local_automation_aliases SET uid='legacy-uid' WHERE kind='vm' AND alias='machine'`, nil},
		{"inverse-name", "machine", `INSERT INTO local_automation_names(stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id) VALUES('','established-cluster','extra-name','resource-uid',1,'reserved','')`, nil},
		{"identity-wrong-kind", "machine", `UPDATE local_automation_identities SET kind='principal' WHERE uid='resource-uid'`, nil},
		{"project-retired", "machine", `UPDATE local_automation_identities SET retired=1 WHERE uid='project-uid'`, nil},
		{"project-scoped", "machine", `UPDATE local_automation_identities SET project_uid='project-uid' WHERE uid='project-uid'`, nil},
		{"principal-wrong-kind", "machine", `UPDATE local_automation_identities SET kind='project' WHERE uid='principal-uid'`, nil},
		{"empty-founder", "machine", `UPDATE local_automation_owners SET founder_principal_uid='' WHERE owner_id='target-owner'`, nil},
		{"session-activation", "machine", `UPDATE local_automation_owners SET activation=0 WHERE owner_id='target-owner'`, nil},
		{"key-partial", "machine", `UPDATE local_automation_resources SET management_key='' WHERE uid='resource-uid'`, nil},
		{"empty-incarnation", "machine", `UPDATE local_automation_resources SET incarnation='' WHERE uid='resource-uid'`, nil},
		{"large-domain", "machine", `UPDATE local_automation_resources SET domain_uuid=? WHERE uid='resource-uid'`, []any{strings.Repeat("d", contract.MaxStringBytes+1)}},
		{"large-configuration", "machine", `UPDATE local_automation_admissions SET configuration_json=? WHERE operation_id='create-op'`, []any{strings.Repeat(" ", (1<<20)+1)}},
		{"blob-configuration", "machine", `UPDATE local_automation_admissions SET configuration_json=? WHERE operation_id='create-op'`, []any{[]byte("null")}},
		{"utf8-configuration", "machine", `UPDATE local_automation_admissions SET configuration_json=? WHERE operation_id='create-op'`, []any{string([]byte{0xff})}},
		{"unowned-downgrade", "machine", `UPDATE local_automation_resources SET owner_id='',management_key='',binding_generation=0 WHERE uid='resource-uid'`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each negative starts and ends with an actually eligible positive.
			requireNameStorage(t, c, "machine", AutomationNamePresent)
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
			rollback := errors.New("rollback one name graph variation")
			var got AutomationNameObservation
			var readErr error
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if _, err := tx.Exec(ctx, tc.sql, tc.args...); err != nil {
					return err
				}
				// Match the existing UID reader's fractional fixtures: bind a
				// float64 through the supported parameter token, then prove
				// SQLite stored REAL rather than coercing an INTEGER or TEXT.
				probe := map[string]string{
					"prefix-real":              `SELECT typeof(sequence) AS storage FROM local_automation_prefix WHERE id=1`,
					"name-real-generation":     `SELECT typeof(generation) AS storage FROM local_automation_names WHERE stage='' AND name='machine'`,
					"identity-real-generation": `SELECT typeof(generation) AS storage FROM local_automation_identities WHERE stage='' AND uid='resource-uid'`,
					"binding-real-generation":  `SELECT typeof(creation_generation) AS storage FROM local_automation_bindings WHERE stage='' AND retired=0 AND resource_uid='resource-uid'`,
					"admission-real-sequence":  `SELECT typeof(sequence) AS storage FROM local_automation_admissions WHERE stage='' AND operation_id='transfer_owner-op'`,
					"owner-real-activation":    `SELECT typeof(activation) AS storage FROM local_automation_owners WHERE stage='' AND owner_id='target-owner'`,
					"resource-real-sequence":   `SELECT typeof(applied_sequence) AS storage FROM local_automation_resources WHERE stage='' AND uid='resource-uid'`,
				}[tc.name]
				if probe != "" {
					rows, err := tx.Query(ctx, probe)
					if err != nil {
						return err
					}
					if len(rows) != 1 || rows[0].String("storage") != "real" {
						return errors.New("fractional name fixture did not store an actual SQL REAL")
					}
				}
				got, readErr = automationObserveNameTx(ctx, tx, "established-cluster", tc.query, 12)
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("fixture mutation did not reach reader: %v", err)
			}
			if readErr == nil || got != (AutomationNameObservation{}) {
				t.Fatalf("partial/corrupt graph became complete: %+v %v", got, readErr)
			}
			requireNameStorage(t, c, "machine", AutomationNamePresent)
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
		})
	}
}

func TestAutomationObserveNameStorageUnnameableReferences(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	for _, keep := range []string{"binding", "create-admission", "transfer-admission", "adopt-admission"} {
		t.Run(keep, func(t *testing.T) {
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
			rollback := errors.New("rollback orphan fixture")
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				for _, query := range []string{
					`DELETE FROM local_automation_names`, `DELETE FROM local_automation_aliases WHERE kind='vm'`,
					`DELETE FROM local_automation_identities WHERE kind='vm'`, `DELETE FROM local_automation_resources`,
				} {
					if _, err := tx.Exec(ctx, query); err != nil {
						return err
					}
				}
				if keep != "binding" {
					if _, err := tx.Exec(ctx, `DELETE FROM local_automation_bindings`); err != nil {
						return err
					}
				}
				operation := map[string]string{"create-admission": "create-op", "transfer-admission": "transfer_owner-op", "adopt-admission": "adopt_resource-op"}[keep]
				if _, err := tx.Exec(ctx, `DELETE FROM local_automation_admissions WHERE operation_id<>?`, operation); err != nil {
					return err
				}
				got, err := automationObserveNameTx(ctx, tx, "established-cluster", "never-enrolled", 12)
				if err == nil || got != (AutomationNameObservation{}) {
					return errors.New("unnameable orphan became absence")
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
		})
	}
}

func TestAutomationObserveNameStorageResetReplayAndCommit(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	requireNameStorage(t, c, "machine", AutomationNamePresent)
	before := sharedActiveRows(t, c)
	rollback := errors.New("rollback name read transaction")
	if err := c.executeLocal(ctx, func(tx *LocalTx) error {
		got, err := automationObserveNameTx(ctx, tx, "established-cluster", "machine", 12)
		if err != nil || got.State != AutomationNamePresent {
			return errors.New("positive read did not reach commit seam")
		}
		return nil
	}, &localCommitSeams{beforeCommit: func(*sql.Tx) error { return rollback }}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, c)) {
		t.Fatal("failed read commit changed retained history")
	}
	readHeld, release := make(chan struct{}), make(chan struct{})
	readDone, resetDone := make(chan error, 1), make(chan error, 1)
	go func() {
		readDone <- c.executeLocal(ctx, func(tx *LocalTx) error {
			got, err := automationObserveNameTx(ctx, tx, "established-cluster", "machine", 12)
			if err != nil || got.State != AutomationNamePresent {
				return errors.New("read lost coherent graph")
			}
			return nil
		}, &localCommitSeams{beforeCommit: func(*sql.Tx) error {
			close(readHeld)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}})
	}()
	select {
	case <-readHeld:
	case err := <-readDone:
		close(release)
		t.Fatalf("reader before seam: %v", err)
	case <-ctx.Done():
		close(release)
		<-readDone
		t.Fatal(ctx.Err())
	}
	resetStarted := make(chan struct{})
	go func() {
		close(resetStarted)
		resetDone <- c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") })
	}()
	<-resetStarted
	var early *error
	select {
	case err := <-resetDone:
		early = &err
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	readErr := <-readDone
	var resetErr error
	if early == nil {
		resetErr = <-resetDone
	} else {
		resetErr = *early
	}
	if readErr != nil || resetErr != nil || early != nil {
		t.Fatalf("snapshot/reset ownership: read=%v reset=%v early=%v", readErr, resetErr, early != nil)
	}
	got, err := c.AutomationObserveName(ctx, "established-cluster", "never-enrolled", 12)
	if err == nil || got != (AutomationNameObservation{}) {
		t.Fatalf("reset became absence: %+v %v", got, err)
	}
	if err := c.AutomationReplay(ctx, contract.Reduce, 1); err == nil {
		t.Fatal("partial replay completed full fixture")
	}
	if got, err := c.AutomationObserveName(ctx, "established-cluster", "never-enrolled", 12); err == nil || got != (AutomationNameObservation{}) {
		t.Fatalf("partial replay became absence: %+v %v", got, err)
	}
	if err := c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	requireNameStorage(t, c, "machine", AutomationNamePresent)
	requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
}

func TestAutomationObserveNameStorageReopenAndErrors(t *testing.T) {
	c := observeStorageFixture(t, true)
	ctx := context.Background()
	beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
	requireNameStorage(t, c, "machine", AutomationNamePresent)
	dir := c.dataDir
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	requireNameStorage(t, reopened, "legacy-machine", AutomationNamePresent)
	if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, reopened)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, reopened)) {
		t.Fatal("reopen/replay rewrote retained facts")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	got, err := reopened.AutomationObserveName(canceled, "established-cluster", "never-enrolled", 12)
	if got != (AutomationNameObservation{}) || !errors.Is(err, context.Canceled) {
		t.Fatalf("storage context cause lost: %+v %v", got, err)
	}
	if _, err := reopened.db.Exec(`ALTER TABLE local_automation_resources RENAME TO hidden_resources`); err != nil {
		t.Fatal(err)
	}
	got, err = reopened.AutomationObserveName(ctx, "established-cluster", "never-enrolled", 12)
	if got != (AutomationNameObservation{}) || err == nil || !strings.Contains(err.Error(), "local_automation_resources") || contract.Code(err) != "" {
		t.Fatalf("SQL cause became classification: %+v %v", got, err)
	}
}

// Retained consumer history, signed and verified before the real reducer. This
// is deliberately not fresh business acceptance or a quiescence producer.
func TestAutomationObserveNameStorageTransferBack(t *testing.T) {
	ca, a, b, c := threeVoters(t)
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "name-transfer-back-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	automationTypedHistoryFixture(t, a, b, c, verifier)
	requireNameStorage(t, a.c, "machine", AutomationNamePresent)
	ctx := context.Background()
	original, found, err := a.c.AutomationRecord(ctx, 10)
	if err != nil || !found {
		t.Fatalf("missing transfer template: %v", err)
	}
	d, err := contract.DecodeDecision(original.Value.Automation.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := contract.DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.DecodeOwnershipBody(d.Command)
	if err != nil {
		t.Fatal(err)
	}
	head, err := a.c.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d.Sequence, d.ParentDigest = 13, head.Digest
	d.Command.RequestID = "transfer-back-request"
	d.Command.OwnerID, d.Command.ManagementKey = "target-owner", "target-key"
	d.Command.Session, d.Command.SessionID = 1, "target-session"
	body.Source = &contract.BindingReference{Key: contract.BindingKey{ClusterUID: "established-cluster", ProjectUID: "project-uid", OwnerID: "target-owner", ManagementKey: "target-key"}, Generation: 1}
	body.Target = contract.BindingKey{ClusterUID: "established-cluster", ProjectUID: "project-uid", OwnerID: "owner", ManagementKey: "key"}
	body.ExpectedRevision = "new-opaque-resource-uid"
	body.ExpectedTargetGeneration = 1
	d.Command.Body, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	assignment.OperationID = "transfer-back-op"
	o := assignment.Ownership
	o.TargetSession = contract.RecordedOwnerSession{ID: "session-2", Activation: 2, PrincipalUID: "principal-uid"}
	o.TargetGeneration, o.Revision = 2, "transfer-back-revision"
	o.Quiescence.Revision, o.Quiescence.LastOperationID, o.Quiescence.FenceSequence = "new-opaque-resource-uid", "transfer_owner-op", 12
	for i := range o.Permissions {
		p := &o.Permissions[i]
		p.FenceSequence = 12
		if p.Purpose == "source_owner" {
			p.OwnerID = "target-owner"
		}
		if p.Purpose == "target_owner" {
			p.OwnerID = "owner"
		}
	}
	d.Assignment, err = json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}}
	key, _ := AutomationClaimKey(d.Sequence)
	ballot := testBallot(3, "a")
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
	receipt, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor)
	if err != nil || receipt.Code != "" {
		t.Fatalf("retained transfer-back failed: %+v %v", receipt, err)
	}
	got := requireNameStorage(t, a.c, "machine", AutomationNamePresent)
	if got.Record.Resource.OwnerID != "owner" || got.Record.Resource.ManagementKey != "key" || got.Record.Resource.BindingGeneration != 2 || got.Record.Binding.Generation != 2 || got.Record.Resource.OriginalOperationID != "create-op" || got.Record.Resource.LastOperationID != "transfer-back-op" {
		t.Fatalf("selected old binding on transfer-back: %+v", got)
	}
	old, err := a.c.Query(ctx, `SELECT creation_generation,retired,operation_id,revision FROM local_automation_bindings WHERE stage='' AND owner_id='owner' AND management_key='key' ORDER BY creation_generation`)
	if err != nil || len(old) != 2 || old[0].Int64("retired") != 1 || old[0].String("operation_id") != "create-op" || old[0].String("revision") != "rev:opaque-alpha" || old[1].Int64("retired") != 0 {
		t.Fatalf("historical binding was rewritten: %+v %v", old, err)
	}
	requireNameStorage(t, a.c, "never-enrolled", AutomationNameAbsent)
}

func TestAutomationObserveNameStorageOlderGenerationMapping(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	// Structural projection variations only. No retirement producer or completed
	// retirement provenance is asserted by retaining an older retired occupant.
	for _, variant := range []string{"older-other-project", "equal-generation", "live-old", "same-incarnation", "orphan-old", "dangling-old-alias", "selected-retired"} {
		t.Run(variant, func(t *testing.T) {
			requireNameStorage(t, c, "legacy-machine", AutomationNamePresent)
			rollback := errors.New("rollback structural generations")
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				queries := []string{
					`INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES('','old-project','established-cluster','','project','old-project-alias','old-project-witness',1,1)`,
					`UPDATE local_automation_names SET generation=2 WHERE name='legacy-machine'`,
					`UPDATE local_automation_aliases SET generation=2 WHERE kind='vm' AND alias='legacy-machine'`,
					`UPDATE local_automation_identities SET generation=2 WHERE uid='legacy-uid'`,
					`INSERT INTO local_automation_resources(stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence) VALUES('','old-uid','established-cluster','old-project','legacy-machine','old-domain','old-incarnation','','',0,'old-revision',1,'old-enrollment','',11)`,
					`INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES('','old-uid','established-cluster','old-project','vm','legacy-machine','old-witness',1,1)`,
				}
				for _, q := range queries {
					if _, err := tx.Exec(ctx, q); err != nil {
						return err
					}
				}
				mutation := map[string]string{
					"equal-generation":   `UPDATE local_automation_identities SET generation=2 WHERE uid='old-uid'`,
					"live-old":           `UPDATE local_automation_identities SET retired=0 WHERE uid='old-uid'`,
					"same-incarnation":   `UPDATE local_automation_resources SET incarnation='legacy-incarnation' WHERE uid='old-uid'`,
					"orphan-old":         `DELETE FROM local_automation_resources WHERE uid='old-uid'`,
					"dangling-old-alias": `INSERT INTO local_automation_aliases(stage,cluster_uid,project_scope,kind,alias,uid,generation) VALUES('','established-cluster','','vm','old-alias','old-uid',1)`,
					"selected-retired":   `UPDATE local_automation_resources SET retired=1 WHERE uid='legacy-uid'`,
				}[variant]
				if mutation != "" {
					if _, err := tx.Exec(ctx, mutation); err != nil {
						return err
					}
				}
				if variant == "selected-retired" {
					for _, q := range []string{
						`UPDATE local_automation_identities SET retired=1 WHERE uid='legacy-uid'`,
						`UPDATE local_automation_bindings SET retired=1 WHERE resource_uid='legacy-uid'`,
						`UPDATE local_automation_names SET disposition='reusable',retirement_operation_id='unsupported-retirement' WHERE resource_uid='legacy-uid'`,
					} {
						if _, err := tx.Exec(ctx, q); err != nil {
							return err
						}
					}
				}
				got, err := automationObserveNameTx(ctx, tx, "established-cluster", "legacy-machine", 12)
				if variant == "older-other-project" {
					if err != nil || got.State != AutomationNamePresent || got.Record == nil || got.Record.Resource.UID != "legacy-uid" || got.Record.VMIdentity.Generation != 2 || got.Record.Project.UID != "project-uid" {
						t.Errorf("selected wrong lifetime: %+v %v", got, err)
					}
				} else if err == nil || got != (AutomationNameObservation{}) {
					t.Errorf("contradictory structural mapping became complete: %+v %v", got, err)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			requireNameStorage(t, c, "legacy-machine", AutomationNamePresent)
		})
	}
}

func TestAutomationObserveNameStorageOwnerOnlyAndTypedControl(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	rollback := errors.New("rollback owner-only control")
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO local_automation_owners(stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation) VALUES('','established-cluster','project-uid','unreferenced-owner','principal-uid','','',0)`); err != nil {
			return err
		}
		for _, q := range []string{
			`INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES('','host-uid','established-cluster','','host','host-alias','host-witness',1,0)`,
			`INSERT INTO local_automation_aliases(stage,cluster_uid,project_scope,kind,alias,uid,generation) VALUES('','established-cluster','','host','host-alias','host-uid',1)`,
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		// SQLite affinity turns numeric text into a genuine integer. It is a benign
		// control, not a pretend malformed-TEXT-in-INTEGER negative witness.
		if _, err := tx.Exec(ctx, `UPDATE local_automation_names SET generation='1' WHERE name='machine'`); err != nil {
			return err
		}
		got, err := automationObserveNameTx(ctx, tx, "established-cluster", "never-enrolled", 12)
		if err != nil || got.State != AutomationNameAbsent {
			t.Errorf("unreferenced owner or typed scalar blocked absence: %+v %v", got, err)
		}
		got, err = automationObserveNameTx(ctx, tx, "established-cluster", "machine", 12)
		if err != nil || got.State != AutomationNamePresent {
			t.Errorf("typed control unavailable: %+v %v", got, err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
}

// Round1 I1: a complete unused-name observation must follow owners referenced
// by retained resources/bindings/admissions, while an unreferenced owner is not
// a name reservation. Every variation is rolled back to the eligible fixture.
func TestAutomationObserveNameStorageReferencedOwnerAbsence(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	for _, tc := range []struct {
		name, mutation string
		absent         bool
	}{
		{"missing-founder", `UPDATE local_automation_owners SET founder_principal_uid='missing-principal' WHERE owner_id='target-owner'`, false},
		{"missing-session-principal", `UPDATE local_automation_owners SET session_principal_uid='missing-principal' WHERE owner_id='target-owner'`, false},
		{"activation-zero-with-session", `UPDATE local_automation_owners SET activation=0 WHERE owner_id='target-owner'`, false},
		{"activation-without-session", `UPDATE local_automation_owners SET session_id='' WHERE owner_id='target-owner'`, false},
		{"session-without-principal", `UPDATE local_automation_owners SET session_principal_uid='' WHERE owner_id='target-owner'`, false},
		{"wrong-founder-kind", `UPDATE local_automation_owners SET founder_principal_uid='project-uid' WHERE owner_id='target-owner'`, false},
		{"unreferenced-owner", `INSERT INTO local_automation_owners(stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation) VALUES('','established-cluster','project-uid','unreferenced-owner','missing-founder','unreferenced-session','missing-session-principal',0)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireNameStorage(t, c, "machine", AutomationNamePresent)
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
			rollback := errors.New("rollback referenced owner absence regression")
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if _, err := tx.Exec(ctx, tc.mutation); err != nil {
					return err
				}
				got, readErr := automationObserveNameTx(ctx, tx, "established-cluster", "never-enrolled", 12)
				if tc.absent {
					if readErr != nil || got.State != AutomationNameAbsent || got.Record != nil || got.Name != "never-enrolled" || got.Prefix.Sequence != 12 {
						t.Errorf("unreferenced owner became a reservation: %+v %v", got, readErr)
					}
					present, presentErr := automationObserveNameTx(ctx, tx, "established-cluster", "machine", 12)
					if presentErr != nil || present.State != AutomationNamePresent || present.Record == nil || present.Record.Resource.OwnerID != "target-owner" {
						t.Errorf("unreferenced owner damaged eligible present: %+v %v", present, presentErr)
					}
				} else if readErr == nil || got != (AutomationNameObservation{}) {
					t.Errorf("incomplete referenced owner graph became complete unused-name observation: %+v %v", got, readErr)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			requireNameStorage(t, c, "machine", AutomationNamePresent)
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
		})
	}
}

// Round1 I2: retained retired projects do not require their old global alias to
// remain selected. These are structural projection fixtures, never retirement
// production or effect authority. Retained identity corruption still fails.
func TestAutomationObserveNameStorageHistoricalProjectAbsence(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	for _, variant := range []string{"retained-without-current-alias", "alias-retargeted", "missing-retained-project", "wrong-retained-kind", "wrong-retained-cluster", "scoped-retained-project"} {
		t.Run(variant, func(t *testing.T) {
			requireNameStorage(t, c, "legacy-machine", AutomationNamePresent)
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
			rollback := errors.New("rollback historical project absence regression")
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				for _, q := range []string{
					`INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES('','old-project','established-cluster','','project','old-project-alias','old-project-witness',1,1)`,
					`UPDATE local_automation_names SET generation=2 WHERE name='legacy-machine'`,
					`UPDATE local_automation_aliases SET generation=2 WHERE kind='vm' AND alias='legacy-machine'`,
					`UPDATE local_automation_identities SET generation=2 WHERE uid='legacy-uid'`,
					`INSERT INTO local_automation_resources(stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence) VALUES('','old-uid','established-cluster','old-project','legacy-machine','old-domain','old-incarnation','','',0,'old-revision',1,'old-enrollment','',11)`,
					`INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES('','old-uid','established-cluster','old-project','vm','legacy-machine','old-witness',1,1)`,
				} {
					if _, err := tx.Exec(ctx, q); err != nil {
						return err
					}
				}
				if variant == "alias-retargeted" {
					for _, q := range []string{
						`INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES('','new-project','established-cluster','','project','old-project-alias','new-project-witness',2,0)`,
						`INSERT INTO local_automation_aliases(stage,cluster_uid,project_scope,kind,alias,uid,generation) VALUES('','established-cluster','','project','old-project-alias','new-project',2)`,
					} {
						if _, err := tx.Exec(ctx, q); err != nil {
							return err
						}
					}
					refs, err := tx.Query(ctx, `SELECT i.uid,i.generation,i.retired,a.uid AS selected_uid,a.generation AS selected_generation FROM local_automation_identities i JOIN local_automation_aliases a ON a.stage=i.stage AND a.cluster_uid=i.cluster_uid AND a.kind='project' AND a.project_scope='' AND a.alias=i.alias WHERE i.stage='' AND i.uid='old-project'`)
					if err != nil {
						return err
					}
					if len(refs) != 1 || refs[0].String("uid") != "old-project" || refs[0].Int64("generation") != 1 || refs[0].Int64("retired") != 1 || refs[0].String("selected_uid") != "new-project" || refs[0].Int64("selected_generation") != 2 {
						return errors.New("superseded project alias fixture not independently established")
					}
				}
				mutation := map[string]string{
					"missing-retained-project": `DELETE FROM local_automation_identities WHERE uid='old-project'`,
					"wrong-retained-kind":      `UPDATE local_automation_identities SET kind='principal' WHERE uid='old-project'`,
					"wrong-retained-cluster":   `UPDATE local_automation_identities SET cluster_uid='foreign' WHERE uid='old-project'`,
					"scoped-retained-project":  `UPDATE local_automation_identities SET project_uid='project-uid' WHERE uid='old-project'`,
				}[variant]
				if mutation != "" {
					if _, err := tx.Exec(ctx, mutation); err != nil {
						return err
					}
				}
				present, presentErr := automationObserveNameTx(ctx, tx, "established-cluster", "legacy-machine", 12)
				absent, absentErr := automationObserveNameTx(ctx, tx, "established-cluster", "never-enrolled", 12)
				if mutation == "" {
					if presentErr != nil || present.State != AutomationNamePresent || present.Record == nil || present.Record.Resource.UID != "legacy-uid" || present.Record.VMIdentity.Generation != 2 || present.Record.Project.UID != "project-uid" {
						t.Errorf("historical project selected wrong live lifetime: %+v %v", present, presentErr)
					}
					if absentErr != nil || absent.State != AutomationNameAbsent || absent.Name != "never-enrolled" || absent.Record != nil || absent.Prefix.Sequence != 12 {
						t.Errorf("obsolete historical project alias blocked complete unrelated absence: %+v %v", absent, absentErr)
					}
				} else {
					if presentErr == nil || present != (AutomationNameObservation{}) {
						t.Errorf("corrupt retained project became Present: %+v %v", present, presentErr)
					}
					if absentErr == nil || absent != (AutomationNameObservation{}) {
						t.Errorf("corrupt retained project became Absent: %+v %v", absent, absentErr)
					}
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			requireNameStorage(t, c, "legacy-machine", AutomationNamePresent)
			requireNameStorage(t, c, "never-enrolled", AutomationNameAbsent)
		})
	}
}
