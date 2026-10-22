package corrosion

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"modernc.org/sqlite"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// No native issuer is exercised by these storage fixtures. The actual migration
// must be composed before table-dependent tests can run; no test-only DDL here.
func TestLegacyTargetCallbackIsolation(t *testing.T) {
	original := AutomationProjection{Target: &contract.TargetProjection{Keys: []contract.TargetKeyProjection{{Key: contract.TargetKey{Kind: "vm_name", Name: "machine"}, Name: &contract.NameRecord{Name: "machine"}, Reservation: &contract.TargetReservation{OperationID: "original"}}}}}
	cloned := cloneAutomationProjection(original)
	cloned.Target.Keys[0].Name.Name = "changed"
	cloned.Target.Keys[0].Reservation.OperationID = "changed"
	cloned.Target.Keys[0].Key.Name = "changed"
	if original.Target.Keys[0].Name.Name != "machine" || original.Target.Keys[0].Reservation.OperationID != "original" || original.Target.Keys[0].Key.Name != "machine" {
		t.Fatal("TARGET_CALLBACK_ALIAS: callback changed authoritative target projection")
	}
}

func targetStorageEffect() contract.Reduction {
	return contract.Reduction{Receipt: contract.Receipt{OperationID: "operation", Sequence: 1, State: "accepted"}, TargetEffect: &contract.TargetOperationRecord{ClusterUID: "cluster", OperationID: "operation", Kind: contract.LegacyRebuildCommand, PrincipalUID: "principal", RequestID: "request", TargetName: "machine", Sequence: 1, Body: []byte(`{}`), Assignment: []byte(`{}`)}, TargetReservations: []contract.TargetReservation{{ClusterUID: "cluster", Key: `["vm_name","machine"]`, OperationID: "operation", Sequence: 1}}}
}

func TestLegacyTargetRejectedEffects(t *testing.T) {
	for _, which := range []string{"operation", "reservation"} {
		t.Run(which, func(t *testing.T) {
			c := NewTestClientT(t)
			ctx := context.Background()
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			r := targetStorageEffect()
			r.Receipt.Code = contract.CodeOwnershipConflict
			if which == "operation" {
				r.TargetReservations = nil
			} else {
				r.TargetEffect = nil
			}
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				return automationApplySemanticEffectsTx(ctx, tx, "", contract.Prefix{}, contract.Prefix{ClusterUID: "cluster", Sequence: 1, Digest: strings.Repeat("a", 64)}, r)
			})
			if err == nil || !strings.Contains(err.Error(), "rejected decision has semantic effects") {
				t.Fatalf("TARGET_REJECTED_EFFECT: %v", err)
			}
		})
	}
}

func TestLegacyTargetOperationRecordCopies(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Explicit corruption fixture: not an accepted history or a native permit.
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO local_automation_target_operations(stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json) VALUES('','cluster','operation','admit_legacy_rebuild','','principal','request','','machine',1,?,'{}','{}')`, strings.Repeat("a", 64))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var first, second *contract.TargetOperationRecord
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		first, err = automationTargetOperationRecordTx(ctx, tx, "", "cluster", "operation")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	first.Body[0] = '!'
	first.Assignment[0] = '!'
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		second, err = automationTargetOperationRecordTx(ctx, tx, "", "cluster", "operation")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.Body, []byte(`{}`)) || !bytes.Equal(second.Assignment, []byte(`{}`)) {
		t.Fatal("target row bytes alias caller")
	}
}

func TestLegacyTargetResetIsolation(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Explicit projection corruption fixture checks reset ownership, not admission.
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, stage := range []string{"", "isolated"} {
			if _, err := tx.Exec(ctx, `INSERT INTO local_automation_target_reservations(stage,cluster_uid,target_key,operation_id,sequence) VALUES(?,?,?,?,1)`, stage, "cluster", `["vm_name","machine"]`, "operation"); err != nil {
				return err
			}
		}
		return automationResetSemanticProjectionTx(ctx, tx, "")
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT stage FROM local_automation_target_reservations ORDER BY stage`)
	if err != nil || len(rows) != 1 || rows[0].String("stage") != "isolated" {
		t.Fatal("reset crossed target stage boundary", rows, err)
	}
}

func TestLegacyTargetTransactionFailure(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	before := automationTypedSnapshot(t, c)
	rollback := errors.New("after target mutation")
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO local_automation_target_reservations(stage,cluster_uid,target_key,operation_id,sequence) VALUES('','cluster','key','operation',1)`); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, automationTypedSnapshot(t, c)) {
		t.Fatal("target transaction escaped rollback")
	}
	rows, err := c.Query(ctx, `SELECT operation_id FROM local_automation_target_reservations`)
	if err != nil || len(rows) != 0 {
		t.Fatal("target reservation survived rollback", err)
	}
}

// These certificates exercise retained consumer application only. No fresh
// business-class ClaimAccept or issuer permit is supplied by this helper.
func targetCertifiedFixture(t *testing.T, kind string) (*Client, AutomationRecord) {
	t.Helper()
	c, r, _, _ := targetCertifiedFixtureAt(t, kind, "")
	return c, r
}
func targetCertifiedFixtureAt(t *testing.T, kind, dir string) (*Client, AutomationRecord, func(contract.Decision) AutomationRecord, *ClaimSigner) {
	t.Helper()
	ca := newClaimTestCA(t)
	a, b, c := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c")
	if dir != "" {
		disk, err := NewLocalClient(dir, "a")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = disk.Close() })
		if err := InitSchema(context.Background(), disk); err != nil {
			t.Fatal(err)
		}
		disk.SetVoterConfigGate(func() bool { return true })
		inc, err := disk.VoterIncarnation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_ = a.c.Close()
		a.c = disk
		a.inc = inc
	}
	adoptHandBuilt(t, 1, membersOf(a, b, c), a, b, c)
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "target-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	signed, parent := targetCertifiedHistoryOn(t, a.c, []*claimTestVoter{a, b, c}, verifier)
	key := contract.TargetKey{Kind: "vm_name", Name: "ordinary"}
	expected := contract.TargetPredecessor{Kind: "none"}
	snapshot := contract.OrdinarySnapshot{CreatedAt: "retained-lifetime", HostName: "a", IdentityHash: strings.Repeat("a", 64)}
	desired := contract.VMIntent{Name: "ordinary", CPU: 2, MemoryMiB: 1024}
	maxCPU, maxMemory := uint32(2), uint64(1024)
	config := desired
	config.MaxCPU = &maxCPU
	config.MemoryHotplugMaxMiB = &maxMemory
	config.Placement = &contract.PlacementIntent{Policy: "balanced"}
	config.RequestedState = "running"
	journal, err := contract.TargetJournalDigest("", "idle", []contract.TargetJournalStep{})
	if err != nil {
		t.Fatal(err)
	}
	prep := contract.TargetPreparation{Key: key, Expected: expected, EvidenceID: "retained-preparation", Host: contract.TargetHostFact{Host: "a", AdmittedAt: "2026-10-20T00:00:00Z", AdmissionSerial: "retained-admission"}, DomainUUID: "11111111-1111-4111-8111-111111111111", JournalState: "idle", JournalSteps: []contract.TargetJournalStep{}, JournalFrontierDigest: journal, OwnerPreparationID: "retained-owner", EffectScopeDigest: strings.Repeat("b", 64)}
	target := &contract.TargetAssignment{Version: 1, AttemptID: "attempt", ParentSequence: 3, ParentDigest: parent, MembershipGeneration: 1, ConfigDigest: strings.Repeat("c", 64), Project: contract.TargetProjectFact{Name: "project-alias", Kind: "project", Lifetime: "project-source-lifetime", CertifiedUID: "project-uid"}, Permission: contract.PermissionFacts{Purpose: "legacy_rebuild", PrincipalUID: "principal-uid", ClusterUID: "established-cluster", ProjectUID: "project-uid", ProjectName: "project-alias", ResourceName: "ordinary", Verb: "vm.rebuild", EvidenceID: "retained-permission", CoverageDigest: strings.Repeat("d", 64), FenceSequence: 3}, Preparations: []contract.TargetPreparation{prep}, Configuration: config}
	var body []byte
	if kind == contract.LegacyRebuildCommand {
		target.Preparations[0].Snapshot = &snapshot
		body, _ = json.Marshal(contract.LegacyRebuildBody{Version: 1, Name: "ordinary", ProjectName: "project-alias", Snapshot: snapshot, Expected: expected, Keys: []contract.TargetKey{key}})
	} else {
		target.Permission.Purpose = "ordinary_create"
		target.Permission.Verb = "vm.create"
		target.Allocation = &contract.OrdinaryAllocation{ResourceUID: "ordinary-uid", DomainUUID: prep.DomainUUID, Incarnation: "ordinary-incarnation", NameGeneration: 1, Revision: "ordinary-revision"}
		body, _ = json.Marshal(contract.OrdinaryCreateBody{Version: 1, Desired: desired, Expected: expected, Keys: []contract.TargetKey{key}})
	}
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "target-op", RecordedAt: "2026-10-20T00:00:00Z", Target: target})
	return a.c, signed(contract.Decision{Sequence: 4, ParentDigest: parent, Command: contract.Command{Kind: kind, ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", RequestID: "target-request", Body: body}, Assignment: assignment}), signed, a.signer
}

// Reuse retained certified history with the existing caller-owned electorate.
// No client, CA, membership, native permit or fresh business issuer is created.
func targetCertifiedHistoryOn(t *testing.T, client *Client, voters []*claimTestVoter, verifier *ClaimVerifier) (func(contract.Decision) AutomationRecord, string) {
	t.Helper()
	if len(voters) != 3 || client == nil || verifier == nil {
		t.Fatal("three existing initialized retained-history voters required")
	}
	initial := sharedAutomationRecord(t, 1, "", "initialize", "initialize-op", voters[:2]...)
	if _, err := applySharedAutomation(t, client, initial, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	parent := initial.Value.MustDigest()
	signed := func(d contract.Decision) AutomationRecord {
		t.Helper()
		envelope, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		value := ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}}
		key, _ := AutomationClaimKey(d.Sequence)
		ballot := testBallot(2, "a")
		r := AutomationRecord{Value: value, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
		for _, v := range voters[:2] {
			accept, err := v.signer.Sign(key, 1, ballot, value.MustDigest(), v.inc)
			if err != nil {
				t.Fatal(err)
			}
			r.Certificate.Accepts = append(r.Certificate.Accepts, accept)
		}
		if err := verifier.Verify(r.Certificate, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(voters...), Quorum: 2}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	for i, k := range []string{"project", "principal"} {
		body := contract.IdentityEnrollment{Version: 1, Kind: k, Alias: k + "-alias", Witness: k + "-source-lifetime", EvidenceID: "retained-cutover"}
		raw, _ := json.Marshal(body)
		assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: k + "-op", RecordedAt: "2026-10-20T00:00:00Z", Identity: &contract.IdentityAssignment{UID: k + "-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: body.EvidenceID, ClusterUID: "established-cluster", Kind: k, Alias: body.Alias, Witness: body.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
		r := signed(contract.Decision{Sequence: uint64(i + 2), ParentDigest: parent, Command: contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", PrincipalID: "host", RequestID: k + "-request", Body: raw}, Assignment: assignment})
		if _, err := applySharedAutomation(t, client, r, contract.Reduce, automationFreshAnchor); err != nil {
			t.Fatal(err)
		}
		parent = r.Value.MustDigest()
	}
	return signed, parent
}

func TestLegacyTargetWholeEntryApply(t *testing.T) {
	for _, kind := range []string{contract.LegacyRebuildCommand, contract.OrdinaryCreateCommand} {
		t.Run(kind, func(t *testing.T) {
			c, record := targetCertifiedFixture(t, kind)
			before := sharedActiveRows(t, c)
			beforeTyped := automationTypedSnapshot(t, c)
			rollback := errors.New("after complete target apply")
			d, err := automationDecision(record.Value)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := AdoptedVoterConfig(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			err = c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
				source := automationApplicationProvenance{kind: automationFreshAnchor, sequence: d.Sequence, generation: 1, membersHash: cfg.MembersHash}
				if _, err := automationApplyTx(context.Background(), tx, record, d, record.Value.MustDigest(), contract.Reduce, source, nil); err != nil {
					return err
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal("target apply never reached rollback boundary", err)
			}
			if !reflect.DeepEqual(before, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
				t.Fatal("target failed transaction changed history/receipt/prefix/projections")
			}
			for _, table := range []string{"local_automation_target_operations", "local_automation_target_reservations"} {
				rows, err := c.Query(context.Background(), "SELECT * FROM "+table)
				if err != nil || len(rows) != 0 {
					t.Fatal("target partial transaction survived", table, err)
				}
			}
			first, err := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor)
			if err != nil || first.State != "accepted" {
				t.Fatal("retained target apply", first, err)
			}
			again, err := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor)
			if err != nil || again != first {
				t.Fatal("target retry changed receipt", again, err)
			}
			rows, err := c.Query(context.Background(), `SELECT sequence,decision_digest FROM local_automation_target_operations WHERE stage=''`)
			if err != nil || len(rows) != 1 || rows[0].Int64("sequence") != 4 || rows[0].String("decision_digest") != record.Value.MustDigest() {
				t.Fatal("target value digest not retained", rows, err)
			}
			rows, err = c.Query(context.Background(), `SELECT operation_id FROM local_automation_target_reservations WHERE stage=''`)
			if err != nil || len(rows) != 1 || rows[0].String("operation_id") != "target-op" {
				t.Fatal("target reservation not retained", rows, err)
			}
		})
	}
}

func TestOrdinaryCreateNameObservation(t *testing.T) {
	c, record := targetCertifiedFixture(t, contract.OrdinaryCreateCommand)
	if _, err := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	observed, err := c.AutomationObserveName(context.Background(), "established-cluster", "ordinary", 4)
	if err != nil || observed.State != AutomationNamePresent || observed.Record == nil || observed.Record.Owner != nil || observed.Record.Binding != nil || observed.Record.Resource.OriginalOperationID != "target-op" || observed.Record.VMIdentity.Witness != "ordinary-incarnation" {
		t.Fatal("ordinary allocation origin not observable", observed, err)
	}
	before := observed.Record.Resource
	if err := c.AutomationReplay(context.Background(), contract.Reduce, 100); err != nil {
		t.Fatal(err)
	}
	observed, err = c.AutomationObserveName(context.Background(), "established-cluster", "ordinary", 4)
	if err != nil || observed.Record == nil || observed.Record.Resource != before {
		t.Fatal("ordinary replay changed origin", observed, err)
	}
	if err := c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		_, err := tx.Exec(context.Background(), `UPDATE local_automation_target_operations SET assignment_json='{}' WHERE operation_id='target-op'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	observed, err = c.AutomationObserveName(context.Background(), "established-cluster", "ordinary", 4)
	if err == nil || observed != (AutomationNameObservation{}) {
		t.Fatal("corrupt target origin leaked name", observed, err)
	}
}

func TestLegacyTargetCallbackCannotEraseResult(t *testing.T) {
	for _, which := range []string{"operation", "keys"} {
		t.Run(which, func(t *testing.T) {
			actual := targetStorageEffect()
			callback := actual
			if which == "operation" {
				callback.TargetEffect = nil
			} else {
				callback.TargetReservations = nil
			}
			if err := validateAutomationCallback(actual, callback); err == nil {
				t.Fatal("TARGET_CALLBACK_ERASURE: callback erased target result")
			}
		})
	}
}

func TestLegacyTargetColdReopenReplay(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c, record, _, _ := targetCertifiedFixtureAt(t, contract.OrdinaryCreateCommand, dir)
	receipt, err := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor)
	if err != nil {
		t.Fatal(err)
	}
	before := automationTypedSnapshot(t, c)
	history := sharedActiveRows(t, c)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetVoterConfigGate(func() bool { return true })
	// New storage handles only: no runtime VM row or in-memory projection oracle.
	if err := reopened.AutomationReplay(ctx, contract.Reduce, 100); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, automationTypedSnapshot(t, reopened)) || !reflect.DeepEqual(history, sharedActiveRows(t, reopened)) {
		t.Fatal("cold target replay changed exact projection/history")
	}
	got, found, err := reopened.AutomationOperation(ctx, receipt.OperationID)
	if err != nil || !found || got != receipt {
		t.Fatal("cold target receipt changed", got, err)
	}
	observed, err := reopened.AutomationObserveName(ctx, "established-cluster", "ordinary", 4)
	if err != nil || observed.Record == nil || observed.Record.Resource.OriginalOperationID != receipt.OperationID {
		t.Fatal("cold ordinary origin lost", observed, err)
	}
}

func TestLegacyTargetActualCallbackTampering(t *testing.T) {
	for _, which := range []string{"projection", "result"} {
		t.Run(which, func(t *testing.T) {
			c, record := targetCertifiedFixture(t, contract.OrdinaryCreateCommand)
			before := sharedActiveRows(t, c)
			receipt, err := applySharedAutomation(t, c, record, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
				r, err := contract.Reduce(p, d)
				if err != nil {
					return r, err
				}
				if which == "result" {
					r.TargetReservations = nil
				} else {
					p.Target.Keys[0].Key.Name = "changed"
					p.Target.Project.Alias = "changed"
				}
				return r, nil
			}, automationFreshAnchor)
			if which == "result" {
				if err == nil || !strings.Contains(err.Error(), "automation reducer result drift") {
					t.Fatal("actual callback erasure reached commit", err)
				}
				if !reflect.DeepEqual(before, sharedActiveRows(t, c)) {
					t.Fatal("callback rejection advanced history")
				}
				return
			}
			if err != nil || receipt.State != "accepted" {
				t.Fatal("isolated callback projection changed authoritative evaluator", receipt, err)
			}
			got, err := c.AutomationObserveName(context.Background(), "established-cluster", "ordinary", 4)
			if err != nil || got.Record == nil || got.Record.Resource.Name != "ordinary" || got.Record.Project.Alias != "project-alias" {
				t.Fatal("callback projection alias escaped", got, err)
			}
		})
	}
}

func TestOrdinaryTargetOriginCorruption(t *testing.T) {
	c, record := targetCertifiedFixture(t, contract.OrdinaryCreateCommand)
	if _, err := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	names := []string{"body", "assignment", "digest", "original-operation", "fake-managed-adoption", "missing-reservation"}
	for i, query := range []string{
		`UPDATE local_automation_target_operations SET body_json='{}' WHERE operation_id='target-op'`,
		`UPDATE local_automation_target_operations SET assignment_json='{}' WHERE operation_id='target-op'`,
		`UPDATE local_automation_target_operations SET decision_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE operation_id='target-op'`,
		`UPDATE local_automation_resources SET original_operation_id='foreign' WHERE uid='ordinary-uid'`,
		`UPDATE local_automation_resources SET owner_id='fake',management_key='fake',binding_generation=1 WHERE uid='ordinary-uid'`,
		`DELETE FROM local_automation_target_reservations WHERE operation_id='target-op'`,
	} {
		t.Run(names[i], func(t *testing.T) {
			// A real positive precedes each mutation; rollback restores it for the next.
			got, err := c.AutomationObserveName(context.Background(), "established-cluster", "ordinary", 4)
			if err != nil || got.Record == nil {
				t.Fatal("positive origin fixture unavailable", got, err)
			}
			rollback := errors.New("restore origin corruption")
			err = c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
				if _, err := tx.Exec(context.Background(), query); err != nil {
					return err
				}
				got, err := automationObserveNameTx(context.Background(), tx, "established-cluster", "ordinary", 4)
				if err == nil || got != (AutomationNameObservation{}) {
					return fmt.Errorf("corrupt ordinary origin or fake managed adoption leaked observation: %+v %v", got, err)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
		})
	}
}

func TestOrdinaryCreateActiveReservationRefusesAdoption(t *testing.T) {
	ctx := context.Background()
	c, record, sign, _ := targetCertifiedFixtureAt(t, contract.OrdinaryCreateCommand, "")
	if _, err := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	parent := record.Value.MustDigest()
	for i, kind := range []string{"ensure_owner", "acquire_session"} {
		assignment := contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: kind + "-ordinary", RecordedAt: "2026-10-20T00:00:00Z"}
		if i == 1 {
			assignment.Owner = &contract.OwnerAssignment{SessionID: "ordinary-session"}
		}
		raw, _ := json.Marshal(assignment)
		r := sign(contract.Decision{Sequence: uint64(5 + i), ParentDigest: parent, Command: contract.Command{Kind: kind, ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "ordinary-owner", RequestID: kind + "-ordinary", Body: []byte(`{"version":1}`)}, Assignment: raw})
		if _, err := applySharedAutomation(t, c, r, contract.Reduce, automationFreshAnchor); err != nil {
			t.Fatal(err)
		}
		parent = r.Value.MustDigest()
	}
	key := contract.BindingKey{ClusterUID: "established-cluster", ProjectUID: "project-uid", OwnerID: "ordinary-owner", ManagementKey: "ordinary-key"}
	body, _ := json.Marshal(contract.OwnershipBody{Version: 1, Resource: contract.ResourceReference{ClusterUID: key.ClusterUID, ProjectUID: key.ProjectUID, Kind: "vm", UID: "ordinary-uid"}, ExpectedRevision: "ordinary-revision", Target: key})
	assignment := contract.Assignment{Version: 1, ClusterUID: key.ClusterUID, OperationID: "ordinary-adopt", RecordedAt: "2026-10-20T00:00:00Z", Ownership: &contract.OwnershipAssignment{Version: 1, TargetSession: contract.RecordedOwnerSession{ID: "ordinary-session", Activation: 1, PrincipalUID: "principal-uid"}, TargetGeneration: 1, Revision: "adopted-revision", AdmittedGeneration: 1, Quiescence: contract.QuiescenceFacts{Version: 1, ResourceUID: "ordinary-uid", Revision: "ordinary-revision", Incarnation: "ordinary-incarnation", LastOperationID: "target-op", FenceSequence: 6, EvidenceID: "retained-quiescence", CoverageDigest: strings.Repeat("a", 64)}}}
	for _, purpose := range []string{"target_owner", "resource"} {
		p := contract.PermissionFacts{Purpose: purpose, PrincipalUID: "principal-uid", ClusterUID: key.ClusterUID, ProjectUID: key.ProjectUID, ProjectName: "project-alias", Verb: "vm.update", EvidenceID: "retained-authorization", CoverageDigest: strings.Repeat("b", 64), FenceSequence: 6}
		if purpose == "target_owner" {
			p.OwnerID = key.OwnerID
		} else {
			p.ResourceUID = "ordinary-uid"
			p.ResourceName = "ordinary"
		}
		assignment.Ownership.Permissions = append(assignment.Ownership.Permissions, p)
	}
	raw, _ := json.Marshal(assignment)
	d := contract.Decision{Sequence: 7, ParentDigest: parent, Command: contract.Command{Kind: "adopt_resource", ClusterUID: key.ClusterUID, ProjectUID: key.ProjectUID, PrincipalID: "principal-uid", OwnerID: key.OwnerID, ManagementKey: key.ManagementKey, ResourceUID: "ordinary-uid", Session: 1, SessionID: "ordinary-session", RequestID: "ordinary-adopt", Body: body}, Assignment: raw}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		p, err := automationProjectionTx(ctx, tx, contract.Prefix{ClusterUID: key.ClusterUID, Sequence: 6, Digest: parent}, d, nil)
		if err != nil {
			return err
		}
		if p.Target == nil || len(p.Target.Keys) != 1 || p.Target.Keys[0].Reservation == nil || p.Target.Keys[0].Reservation.OperationID != "target-op" {
			return errors.New("real retained reservation not loaded")
		}
		// Counterfactual pure-consumer control only; no row or release is changed.
		p.Target.Keys[0].Reservation = nil
		r, err := contract.Reduce(p, d)
		if err != nil || r.Receipt.Code != "" || r.ResourceEffect == nil {
			return fmt.Errorf("adoption failed for a reason other than retained reservation: %+v %v", r, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := applySharedAutomation(t, c, sign(d), contract.Reduce, automationFreshAnchor)
	if err != nil || receipt.Code != contract.CodeOwnershipConflict {
		t.Fatal("active ordinary reservation allowed adoption", receipt, err)
	}
	observed, err := c.AutomationObserveName(ctx, key.ClusterUID, "ordinary", 7)
	if err != nil || observed.Record == nil || observed.Record.Owner != nil || observed.Record.Resource.OriginalOperationID != "target-op" {
		t.Fatal("refused adoption changed ordinary origin", observed, err)
	}
}

func targetTestArtifact(object string) contract.TargetKey {
	return contract.TargetKey{Kind: "artifact", Artifact: &contract.TargetArtifactKey{OwnerKind: "pool", OwnerUID: "retained-pool", ObjectID: object}}
}
func targetRetainedVariation(t *testing.T, base AutomationRecord, sign func(contract.Decision) AutomationRecord, name, operation string, sequence uint64, parent string, keys []contract.TargetKey) AutomationRecord {
	t.Helper()
	d, err := automationDecision(base.Value)
	if err != nil {
		t.Fatal(err)
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil || a.Target == nil {
		t.Fatal(err)
	}
	keys = append([]contract.TargetKey(nil), keys...)
	sort.Slice(keys, func(i, j int) bool {
		x, _ := contract.TargetKeyEncoding(keys[i])
		y, _ := contract.TargetKeyEncoding(keys[j])
		return x < y
	})
	d.Sequence = sequence
	d.ParentDigest = parent
	d.Command.RequestID = operation + "-request"
	a.OperationID = operation
	a.Target.AttemptID = operation + "-attempt"
	a.Target.ParentSequence = sequence - 1
	a.Target.ParentDigest = parent
	a.Target.Permission.FenceSequence = sequence - 1
	a.Target.Permission.ResourceName = name
	a.Target.Configuration.Name = name
	prototype := a.Target.Preparations[0]
	a.Target.Preparations = nil
	for _, key := range keys {
		p := prototype
		p.Key = key
		if key.Kind == "artifact" {
			p.Snapshot = nil
			p.DomainUUID = ""
		}
		a.Target.Preparations = append(a.Target.Preparations, p)
	}
	if d.Command.Kind == contract.LegacyRebuildCommand {
		b, err := contract.DecodeLegacyRebuildBody(d.Command)
		if err != nil {
			t.Fatal(err)
		}
		b.Name = name
		b.Keys = keys
		d.Command.Body, _ = json.Marshal(b)
	} else {
		b, err := contract.DecodeOrdinaryCreateBody(d.Command)
		if err != nil {
			t.Fatal(err)
		}
		b.Desired.Name = name
		b.Keys = keys
		d.Command.Body, _ = json.Marshal(b)
		a.Target.Allocation.ResourceUID = operation + "-uid"
		a.Target.Allocation.Incarnation = operation + "-incarnation"
	}
	d.Assignment, _ = json.Marshal(a)
	if err := contract.ValidateSupportedDecision(d); err != nil {
		t.Fatal("retained variation setup", err)
	}
	return sign(d)
}

func TestLegacyTargetProjectionRequiresInverseKeys(t *testing.T) {
	for _, which := range []string{"missing-name", "moved-name", "missing-artifact", "moved-artifact", "partial-multikey", "missing-operation", "missing-operation-and-keys"} {
		t.Run(which, func(t *testing.T) {
			ctx := context.Background()
			c, base, sign, _ := targetCertifiedFixtureAt(t, contract.LegacyRebuildCommand, "")
			d, _ := automationDecision(base.Value)
			name := contract.TargetKey{Kind: "vm_name", Name: "ordinary"}
			artifact := targetTestArtifact("shared")
			other := targetTestArtifact("other")
			winner := targetRetainedVariation(t, base, sign, "ordinary", "winner", 4, d.ParentDigest, []contract.TargetKey{name, artifact, other})
			receipt, err := applySharedAutomation(t, c, winner, contract.Reduce, automationFreshAnchor)
			if err != nil || receipt.State != "accepted" {
				t.Fatal("genuine retained multikey setup", receipt, err)
			}
			keys := []contract.TargetKey{name}
			victim, _ := contract.TargetKeyEncoding(name)
			if strings.Contains(which, "artifact") || which == "partial-multikey" {
				keys = []contract.TargetKey{{Kind: "vm_name", Name: "next"}, artifact}
				victim, _ = contract.TargetKeyEncoding(artifact)
			}
			err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if strings.HasPrefix(which, "missing-operation") {
					if which == "missing-operation-and-keys" {
						if _, err := tx.Exec(ctx, `DELETE FROM local_automation_target_reservations WHERE stage='' AND operation_id='winner'`); err != nil {
							return err
						}
					}
					_, err := tx.Exec(ctx, `DELETE FROM local_automation_target_operations WHERE stage='' AND operation_id='winner'`)
					return err
				}
				if strings.HasPrefix(which, "moved") {
					moved, _ := contract.TargetKeyEncoding(targetTestArtifact("moved"))
					if which == "moved-name" {
						moved, _ = contract.TargetKeyEncoding(contract.TargetKey{Kind: "vm_name", Name: "moved"})
					}
					_, err := tx.Exec(ctx, `UPDATE local_automation_target_reservations SET target_key=? WHERE stage='' AND target_key=?`, moved, victim)
					return err
				}
				if which == "missing-artifact" {
					encoded, _ := contract.TargetKeyEncoding(other)
					_, err := tx.Exec(ctx, `DELETE FROM local_automation_target_reservations WHERE stage='' AND target_key IN (?,?)`, victim, encoded)
					return err
				}
				_, err := tx.Exec(ctx, `DELETE FROM local_automation_target_reservations WHERE stage='' AND target_key=?`, victim)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
			nextName := "ordinary"
			if keys[0].Name == "next" {
				nextName = "next"
			}
			next := targetRetainedVariation(t, base, sign, nextName, "contender", 5, winner.Value.MustDigest(), keys)
			_, err = applySharedAutomation(t, c, next, contract.Reduce, automationFreshAnchor)
			if err == nil || !strings.Contains(err.Error(), "target inverse") {
				t.Fatalf("TARGET_INVERSE_CLOSURE: corrupt retained keys became free: %v", err)
			}
			if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
				t.Fatal("projection refusal changed history/receipt/prefix/projection")
			}
		})
	}
}

// This delegates actual SQLite writes and fails only AFTER the designated real
// INSERT returned success. It supplies no reducer/receipt/authority substitute.
type targetInsertFault struct {
	table         string
	ordinal, seen int
	fired         bool
	failure       error
}
type targetInsertDriver struct {
	driver.Driver
	fault *targetInsertFault
}
type targetInsertConn struct {
	driver.Conn
	fault *targetInsertFault
}

var targetInsertDriverID atomic.Uint64

func (d targetInsertDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return targetInsertConn{c, d.fault}, nil
}
func (c targetInsertConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c targetInsertConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c targetInsertConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	r, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err != nil {
		return r, err
	}
	if strings.HasPrefix(strings.TrimSpace(q), "INSERT INTO "+c.fault.table+"(") {
		c.fault.seen++
		if c.fault.seen == c.fault.ordinal {
			c.fault.fired = true
			return nil, c.fault.failure
		}
	}
	return r, nil
}
func targetInjectInsert(t *testing.T, c *Client, fault *targetInsertFault) {
	t.Helper()
	name := fmt.Sprintf("target-insert-fault-%d", targetInsertDriverID.Add(1))
	sql.Register(name, targetInsertDriver{Driver: &sqlite.Driver{}, fault: fault})
	db, err := sql.Open(name, c.dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	c.mu.Lock()
	old := c.db
	c.db = db
	c.mu.Unlock()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyTargetPerInsertRollback(t *testing.T) {
	for _, tc := range []struct {
		name, table string
		ordinal     int
	}{{"operation", "local_automation_target_operations", 1}, {"key-first", "local_automation_target_reservations", 1}, {"key-middle", "local_automation_target_reservations", 2}, {"key-last", "local_automation_target_reservations", 3}, {"allocation-identity", "local_automation_identities", 1}, {"allocation-alias", "local_automation_aliases", 1}, {"allocation-resource", "local_automation_resources", 1}, {"allocation-name", "local_automation_names", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			c, base, sign, _ := targetCertifiedFixtureAt(t, contract.OrdinaryCreateCommand, "")
			d, _ := automationDecision(base.Value)
			r := targetRetainedVariation(t, base, sign, "ordinary", "fault-target", 4, d.ParentDigest, []contract.TargetKey{targetTestArtifact("one"), targetTestArtifact("two"), {Kind: "vm_name", Name: "ordinary"}})
			beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
			injected := errors.New("designated completed target insert failure")
			fault := &targetInsertFault{table: tc.table, ordinal: tc.ordinal, failure: injected}
			targetInjectInsert(t, c, fault)
			_, err := applySharedAutomation(t, c, r, contract.Reduce, automationFreshAnchor)
			if !fault.fired || fault.seen != tc.ordinal || !errors.Is(err, injected) {
				t.Fatalf("TARGET_INSERT_BOUNDARY: did not reach actual %s/%d insert: fired=%t count=%d err=%v", tc.table, tc.ordinal, fault.fired, fault.seen, err)
			}
			if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
				t.Fatal("partial insert survived FULL rollback")
			}
		})
	}
}

func TestLegacyTargetOverlapAndDisjointProgress(t *testing.T) {
	c, base, sign, _ := targetCertifiedFixtureAt(t, contract.LegacyRebuildCommand, "")
	d, _ := automationDecision(base.Value)
	shared := targetTestArtifact("shared")
	winner := targetRetainedVariation(t, base, sign, "winner-name", "winner", 4, d.ParentDigest, []contract.TargetKey{shared, {Kind: "vm_name", Name: "winner-name"}})
	loser := targetRetainedVariation(t, base, sign, "loser-name", "loser", 5, winner.Value.MustDigest(), []contract.TargetKey{shared, {Kind: "vm_name", Name: "loser-name"}})
	cfg, err := AdoptedVoterConfig(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type attempt struct {
		name    string
		receipt contract.Receipt
		err     error
	}
	done := make(chan attempt, 2)
	start := make(chan struct{})
	for _, input := range []struct {
		name   string
		record AutomationRecord
	}{{"winner", winner}, {"loser", loser}} {
		go func(name string, record AutomationRecord) {
			<-start
			decision, err := automationDecision(record.Value)
			var receipt contract.Receipt
			if err == nil {
				err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					var e error
					receipt, e = automationApplyTx(ctx, tx, record, decision, record.Value.MustDigest(), contract.Reduce, automationApplicationProvenance{kind: automationFreshAnchor, sequence: decision.Sequence, generation: 1, membersHash: cfg.MembersHash}, nil)
					return e
				})
			}
			done <- attempt{name, receipt, err}
		}(input.name, input.record)
	}
	close(start)
	results := map[string]attempt{}
	for i := 0; i < 2; i++ {
		r := <-done
		results[r.name] = r
	}
	if r := results["winner"]; r.err != nil || r.receipt.Code != "" {
		t.Fatal("first ordered overlapping attempt failed", r.receipt, r.err)
	}
	// If the future successor reached the FULL boundary first it must refuse its
	// missing predecessor; retry only after both original attempts have returned.
	if r := results["loser"]; r.err != nil && !strings.Contains(r.err.Error(), "predecessor") {
		t.Fatal("unexpected competing transaction failure", r.err)
	}
	if r, err := applySharedAutomation(t, c, loser, contract.Reduce, automationFreshAnchor); err != nil || r.Code != contract.CodeOwnershipConflict {
		t.Fatal("overlapping key set did not have one winner", r, err)
	}
	rows, err := c.Query(context.Background(), `SELECT operation_id FROM local_automation_target_reservations WHERE operation_id='loser'`)
	if err != nil || len(rows) != 0 {
		t.Fatal("loser partially acquired its disjoint name", rows, err)
	}
	disjoint := targetRetainedVariation(t, base, sign, "disjoint-name", "disjoint", 6, loser.Value.MustDigest(), []contract.TargetKey{targetTestArtifact("different"), {Kind: "vm_name", Name: "disjoint-name"}})
	if r, err := applySharedAutomation(t, c, disjoint, contract.Reduce, automationFreshAnchor); err != nil || r.Code != "" {
		t.Fatal("unrelated target/artifact blocked", r, err)
	}
	rows, err = c.Query(context.Background(), `SELECT operation_id,count(*) AS n FROM local_automation_target_reservations GROUP BY operation_id ORDER BY operation_id`)
	if err != nil || len(rows) != 2 || rows[0].String("operation_id") != "disjoint" || rows[1].String("operation_id") != "winner" || rows[0].Int64("n") != 2 || rows[1].Int64("n") != 2 {
		t.Fatal("atomic complete key sets not preserved", rows, err)
	}
}

func TestLegacyTargetActualFreshClaimAcceptClosed(t *testing.T) {
	ctx := context.Background()
	// A separate genuine initialized control reaches actual ClaimAccept success;
	// no accepted claim is erased to make the following business tests eligible.
	control, controlBase, _, controlSigner := targetCertifiedFixtureAt(t, contract.LegacyRebuildCommand, "")
	bootstrapKey, _ := AutomationClaimKey(1)
	installAutomationEvidence(t, control, bootstrapKey, "", 1)
	original, err := automationDecision(controlBase.Value)
	if err != nil {
		t.Fatal(err)
	}
	controlKey, barrier := automationFixture(t, 4, original.ParentDigest)
	accepted, err := control.ClaimAccept(ctx, controlKey, testBallot(3, "a"), barrier, 1, controlSigner, nil)
	if err != nil || !accepted.Accepted || accepted.Accept == nil {
		t.Fatal("initialized actual control ClaimAccept failed before business-class witness", accepted, err)
	}
	for _, kind := range []string{contract.LegacyRebuildCommand, contract.OrdinaryCreateCommand} {
		t.Run(kind, func(t *testing.T) {
			c, business, _, signer := targetCertifiedFixtureAt(t, kind, "")
			installAutomationEvidence(t, c, bootstrapKey, "", 1)
			d, err := automationDecision(business.Value)
			if err != nil || contract.ValidateSupportedDecision(d) != nil {
				t.Fatal("otherwise-valid business value setup", err)
			}
			head, err := c.AutomationHead(ctx)
			if err != nil || head.Sequence != 3 || d.Sequence != 4 || d.ParentDigest != head.Digest {
				t.Fatal("business successor setup", head, err)
			}
			beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
			key, _ := AutomationClaimKey(d.Sequence)
			result, err := c.ClaimAccept(ctx, key, testBallot(3, "a"), business.Value, 1, signer, nil)
			if err != nil || result.Accepted || result.Accept != nil || result.Refusal != RefusalAutomationUnavailable {
				t.Fatal("TARGET_FRESH_CLASS: retained assignment minted a native accept", result, err)
			}
			if _, found, err := c.ClaimState(ctx, key); err != nil || found {
				t.Fatal("refused fresh class changed claim state", found, err)
			}
			if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
				t.Fatal("fresh class refusal changed history/receipt/prefix/projections")
			}
		})
	}
}

func TestLegacyTargetInverseStageAndHistoryOwner(t *testing.T) {
	ctx := context.Background()
	c, base, sign, _ := targetCertifiedFixtureAt(t, contract.LegacyRebuildCommand, "")
	d, _ := automationDecision(base.Value)
	key := targetTestArtifact("source-owned")
	winner := targetRetainedVariation(t, base, sign, "ordinary", "winner", 4, d.ParentDigest, []contract.TargetKey{key, {Kind: "vm_name", Name: "ordinary"}})
	if receipt, err := applySharedAutomation(t, c, winner, contract.Reduce, automationFreshAnchor); err != nil || receipt.State != "accepted" {
		t.Fatal("retained stage source setup", receipt, err)
	}
	_, barrier := automationFixture(t, 5, winner.Value.MustDigest())
	next, err := automationDecision(barrier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applySharedAutomation(t, c, sign(next), contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
	visited := 0
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := auditAutomationCutTx(ctx, tx, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
			result, err := contract.Reduce(p, d)
			if err != nil || d.Sequence != 5 {
				return result, err
			}
			visited++
			// The real audit has reconstructed stage4 from actual certified history;
			// no copied projection is being supplied as a replacement authority.
			const stage = "source-cut-audit"
			if err := automationTargetInverseClosureTx(ctx, tx, stage, p.Head, nil); err != nil {
				return result, fmt.Errorf("real reconstructed inverse positive: %w", err)
			}
			wrong := p.Head
			wrong.Digest = strings.Repeat("f", 64)
			if err := automationTargetInverseClosureTx(ctx, tx, stage, wrong, nil); err == nil {
				return result, errors.New("wrong semantic head accepted")
			}
			missing := receiverAutomationKeySource{receiverAuditStore{tx: tx, id: "missing-receiver-history"}}
			if err := automationTargetInverseClosureTx(ctx, tx, stage, p.Head, missing); err == nil || !strings.Contains(err.Error(), "required indexed source fact missing") {
				return result, fmt.Errorf("receiver history owner fell back to active history: %v", err)
			}
			encoded, _ := contract.TargetKeyEncoding(key)
			if _, err := tx.Exec(ctx, `DELETE FROM local_automation_target_reservations WHERE stage=? AND target_key=?`, stage, encoded); err != nil {
				return result, err
			}
			if err := automationTargetInverseClosureTx(ctx, tx, stage, p.Head, nil); err == nil {
				return result, errors.New("staged missing artifact became unreserved")
			}
			active, err := automationSemanticHeadTx(ctx, tx, "")
			if err != nil {
				return result, err
			}
			if err := automationTargetInverseClosureTx(ctx, tx, "", active, nil); err != nil {
				return result, fmt.Errorf("staged mutation contaminated active inverse closure: %w", err)
			}
			// Restore only the explicitly mutated test row, then allow the real audit
			// to finish its full comparison and normal scratch reset.
			if _, err := tx.Exec(ctx, `INSERT INTO local_automation_target_reservations(stage,cluster_uid,target_key,operation_id,sequence) VALUES(?,?,?,?,?)`, stage, "established-cluster", encoded, "winner", 4); err != nil {
				return result, err
			}
			return result, nil
		})
		return err
	})
	if err != nil || visited != 1 {
		t.Fatal("actual staged replay did not reach source-bound closure control", visited, err)
	}
	if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
		t.Fatal("stage/source inverse tests changed committed history or projections")
	}
}

// The reducer deliberately retains an assigned-operation collision with no
// operation index. It is rejected work, not an accepted origin or a release.
func TestLegacyTargetRetainedOperationCollisionProgress(t *testing.T) {
	for _, kind := range []string{contract.LegacyRebuildCommand, contract.OrdinaryCreateCommand} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			c, base, sign, _ := targetCertifiedFixtureAt(t, kind, "")
			first, err := applySharedAutomation(t, c, base, contract.Reduce, automationFreshAnchor)
			if err != nil || first.State != "accepted" || first.OperationID != "target-op" {
				t.Fatal("SETUP actual accepted target", first, err)
			}
			if again, err := applySharedAutomation(t, c, base, contract.Reduce, automationFreshAnchor); err != nil || again != first {
				t.Fatal("accepted duplicate drift", again, err)
			}
			collision := targetRetainedVariation(t, base, sign, "collision-name", "target-op", 5, base.Value.MustDigest(), []contract.TargetKey{{Kind: "vm_name", Name: "collision-name"}})
			collisionDecision, err := automationDecision(collision.Value)
			if err != nil {
				t.Fatal(err)
			}
			rejected, err := applySharedAutomation(t, c, collision, contract.Reduce, automationFreshAnchor)
			if err != nil || rejected.Code != contract.CodeValidation || rejected.State != "rejected" || rejected.OperationID != "" || rejected.Sequence != 5 || rejected.RequestID != collisionDecision.Command.RequestID {
				t.Fatal("SETUP real collision rejection not retained", rejected, err)
			}
			request, err := c.AutomationRequest(ctx, AutomationScope(collisionDecision), collisionDecision.Command.RequestID)
			if err != nil || request == nil || request.Receipt != rejected {
				t.Fatal("collision permanent receipt absent", request, err)
			}
			encoded, err := contract.TargetKeyEncoding(contract.TargetKey{Kind: "vm_name", Name: "collision-name"})
			if err != nil {
				t.Fatal(err)
			}
			rows, err := c.Query(ctx, `SELECT target_key FROM local_automation_target_reservations WHERE stage='' AND (sequence=5 OR target_key=?)`, encoded)
			if err != nil || len(rows) != 0 {
				t.Fatal("rejected collision acquired keys", rows, err)
			}
			rows, err = c.Query(ctx, `SELECT operation_id FROM local_automation_target_operations WHERE stage='' AND sequence=5`)
			if err != nil || len(rows) != 0 {
				t.Fatal("rejected collision created operation", rows, err)
			}
			retained, err := c.Query(ctx, `SELECT receipt_json FROM local_automation_history WHERE sequence=5`)
			if err != nil || len(retained) != 1 {
				t.Fatal("collision history receipt absent", retained, err)
			}
			disjoint := targetRetainedVariation(t, base, sign, "disjoint-name", "disjoint-op", 6, collision.Value.MustDigest(), []contract.TargetKey{{Kind: "vm_name", Name: "disjoint-name"}})
			if receipt, err := applySharedAutomation(t, c, disjoint, contract.Reduce, automationFreshAnchor); err != nil || receipt.State != "accepted" || receipt.OperationID != "disjoint-op" {
				t.Fatal("RETAINED_COLLISION_BLOCKED_DISJOINT_PROGRESS", receipt, err)
			}
			// Real later-sequence retries preserve the original accepted and rejected
			// receipts, including the latter's empty operation and earlier sequence.
			retry := targetRetainedVariation(t, base, sign, "ordinary", "accepted-retry", 7, disjoint.Value.MustDigest(), []contract.TargetKey{{Kind: "vm_name", Name: "ordinary"}})
			retryDecision, err := automationDecision(retry.Value)
			if err != nil {
				t.Fatal(err)
			}
			original, err := automationDecision(base.Value)
			if err != nil {
				t.Fatal(err)
			}
			retryDecision.Command = original.Command
			retry = sign(retryDecision)
			if receipt, err := applySharedAutomation(t, c, retry, contract.Reduce, automationFreshAnchor); err != nil || receipt != first {
				t.Fatal("accepted retained retry changed receipt", receipt, err)
			}
			rejectedRetry := targetRetainedVariation(t, base, sign, "collision-name", "rejected-retry", 8, retry.Value.MustDigest(), []contract.TargetKey{{Kind: "vm_name", Name: "collision-name"}})
			rejectedRetryDecision, err := automationDecision(rejectedRetry.Value)
			if err != nil {
				t.Fatal(err)
			}
			rejectedRetryDecision.Command = collisionDecision.Command
			rejectedRetry = sign(rejectedRetryDecision)
			if receipt, err := applySharedAutomation(t, c, rejectedRetry, contract.Reduce, automationFreshAnchor); err != nil || receipt != rejected {
				t.Fatal("collision retained retry changed empty-operation receipt", receipt, err)
			}
			beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
			if err := c.AutomationReplay(ctx, contract.Reduce, 100); err != nil {
				t.Fatal("retained collision replay refused", err)
			}
			if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				head, err := auditAutomationCutTx(ctx, tx, contract.Reduce)
				if err == nil && (head.Sequence != 8 || head.Digest != rejectedRetry.Value.MustDigest()) {
					return errors.New("cut audit returned wrong retained collision frontier")
				}
				return err
			}); err != nil {
				t.Fatal("retained collision source-cut audit refused", err)
			}
			if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
				t.Fatal("collision replay/cut changed history/receipt/prefix/projection")
			}
			after, err := c.Query(ctx, `SELECT receipt_json FROM local_automation_history WHERE sequence=5`)
			if err != nil || !reflect.DeepEqual(retained, after) {
				t.Fatal("collision replay/cut rewrote original receipt bytes", after, err)
			}
			request, err = c.AutomationRequest(ctx, AutomationScope(collisionDecision), collisionDecision.Command.RequestID)
			if err != nil || request == nil || request.Receipt != rejected {
				t.Fatal("collision replay/cut lost permanent rejection", request, err)
			}
			// The generalized rejected-history reader must not relax accepted origins.
			corrupt := first
			corrupt.OperationID = ""
			raw, err := json.Marshal(corrupt)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				_, err := tx.Exec(ctx, `UPDATE local_automation_history SET receipt_json=? WHERE sequence=4`, string(raw))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			corruptHistory, corruptTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
			next := targetRetainedVariation(t, base, sign, "after-corruption", "after-corruption", 9, rejectedRetry.Value.MustDigest(), []contract.TargetKey{{Kind: "vm_name", Name: "after-corruption"}})
			if _, err := applySharedAutomation(t, c, next, contract.Reduce, automationFreshAnchor); err == nil || !strings.Contains(err.Error(), "target certified receipt mismatch") {
				t.Fatal("accepted empty-operation corruption was treated as rejected work", err)
			}
			if !reflect.DeepEqual(corruptHistory, sharedActiveRows(t, c)) || !reflect.DeepEqual(corruptTyped, automationTypedSnapshot(t, c)) {
				t.Fatal("accepted-origin refusal changed retained state")
			}
		})
	}
}

// SQL84 is a real additive migration. Target projections are local derived
// state, never extra certified cut sections or a native business-class permit.
func TestAutomationTargetSchema84(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, mutation, replacement string }{
		{"fresh_reopen", "", ""},
		{"missing_sequence_index", `DROP INDEX automation_target_sequence`, ""},
		{"missing_operation_index", `DROP INDEX automation_target_operation_keys`, ""},
		{"extra_target_index", `CREATE INDEX unexpected_target_index ON local_automation_target_operations(stage)`, ""},
		{"wrong_sequence_uniqueness", `DROP INDEX automation_target_sequence`, `CREATE INDEX automation_target_sequence ON local_automation_target_operations(stage,cluster_uid,sequence)`},
		{"wrong_operation_index_order", `DROP INDEX automation_target_operation_keys`, `CREATE INDEX automation_target_operation_keys ON local_automation_target_reservations(cluster_uid,stage,operation_id)`},
		{"extra_target_column", `ALTER TABLE local_automation_target_operations ADD COLUMN unexpected TEXT`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			c := custodyLifetimeFileClient(t, dir)
			t.Cleanup(func() { _ = c.Close() })
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal("SETUP current schema86", err)
			}
			if CurrentSchemaVersion != 86 || automationCutSourceSchema != 86 || storedVersion(t, c) != 86 {
				t.Fatal("TARGET84_CURRENT_PROVENANCE")
			}
			units := map[string]bool{"local_automation_target_operations": false, "local_automation_target_reservations": false}
			for _, m := range schemaMigrationLedger {
				if m.Version == 84 {
					_, ok := units[m.Target]
					if !ok || units[m.Target] || m.Kind != kindCreateTable || m.ID != "t_"+m.Target {
						t.Fatal("TARGET84_LEDGER", m)
					}
					units[m.Target] = true
				}
			}
			for table, present := range units {
				if !present || !IsNodeLocalClaimTable(table) || IsReplicatedTable(table) {
					t.Fatal("TARGET84_LOCAL", table)
				}
			}
			if !supportedAutomationCutDescriptor(83, 1) || !supportedAutomationCutDescriptor(84, 1) || !supportedAutomationCutDescriptor(85, 1) || !supportedAutomationCutDescriptor(86, 1) || supportedAutomationCutDescriptor(87, 1) {
				t.Fatal("TARGET84_DESCRIPTOR_BOUNDARY")
			}
			before, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
			if err != nil {
				t.Fatal(err)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			c = custodyLifetimeFileClient(t, dir)
			if err = InitSchema(ctx, c); err != nil {
				t.Fatal("TARGET84_REOPEN", err)
			}
			after, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("TARGET84_LEDGER_REWRITTEN", err)
			}
			if err = c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) }); err != nil {
				t.Fatal("SETUP actual target schema guard", err)
			}
			if tc.mutation != "" {
				if err = c.execLocal(ctx, tc.mutation); err != nil {
					t.Fatal("SETUP malformed target schema", err)
				}
				if tc.replacement != "" {
					if err = c.execLocal(ctx, tc.replacement); err != nil {
						t.Fatal("SETUP wrong target index", err)
					}
				}
				err = c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) })
				if err == nil {
					t.Fatal("TARGET84_MALFORMED_SCHEMA_ACCEPTED")
				}
			}
		})
	}
}

// Malicious history cannot hide a replay-derived target projection behind an
// archived layout that predates those operations. This uses the real source
// audit replay stage, not a caller-provided projection or a fake permit.
func TestRetainedOriginal83RejectsReplayTargetHistory(t *testing.T) {
	ctx := context.Background()
	c, record, sign, _ := targetCertifiedFixtureAt(t, contract.OrdinaryCreateCommand, "")
	if _, err := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	_, barrier := automationFixture(t, 5, record.Value.MustDigest())
	decision, err := automationDecision(barrier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applySharedAutomation(t, c, sign(decision), contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	visited := 0
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := auditAutomationCutTx(ctx, tx, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
			reduction, err := contract.Reduce(p, d)
			if err != nil || d.Sequence != 5 {
				return reduction, err
			}
			visited++
			const stage = "source-cut-audit"
			const original = "synthetic-omitted-target-history"
			for section, table := range aggregateLocalTables83() {
				if section < 18 || section >= 29 {
					continue
				}
				err = walkAggregateLocalTable(ctx, tx, table, stage, func(n int64, row Row) error {
					row.Values[0] = ""
					raw, err := encodeAggregateLocalRecord(table.descriptor().name, n, row)
					if err != nil {
						return err
					}
					return aggregateLocalSaveRow(ctx, tx, original, section, n, raw)
				})
				if err != nil {
					return reduction, err
				}
			}
			rows, err := tx.Query(ctx, `SELECT operation_id FROM local_automation_target_operations WHERE stage=?`, stage)
			if err != nil || len(rows) != 1 {
				return reduction, fmt.Errorf("SETUP real target replay missing: %v", err)
			}
			store := receiverAuditStore{tx: tx, localProjectionID: original, localLayoutDigest: retainedLocalLayout83Digest()}
			if err = store.compareLocalSemantic(ctx, stage); err == nil || !strings.Contains(err.Error(), "local_automation_target_operations") {
				return reduction, fmt.Errorf("RETAINED83_REPLAY_TARGET_HIDDEN: %v", err)
			}
			_, err = tx.Exec(ctx, `DELETE FROM local_automation_local_rows WHERE local_id=?`, original)
			return reduction, err
		})
		return err
	})
	if err != nil || visited != 1 {
		t.Fatal("actual replay compatibility negative", visited, err)
	}
}
