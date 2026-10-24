package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// These fixtures authenticate the inner FULL owner only. They do not pass the
// native business acceptor, issue a runtime permit, or execute a VM.
func updateFixture(t *testing.T) *executionStorageFixture {
	t.Helper()
	f, _ := executionReplayCompletedFixture(t)
	t.Log("native-issuance=false runtime-effects=false authority=certified-history-fixture")
	return f
}

func updateDecision(t *testing.T, f *executionStorageFixture, patch string, config contract.VMIntent, revision string, previousDesired contract.HistoryReference) contract.Decision {
	t.Helper()
	ctx := context.Background()
	head, err := f.c.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var v *contract.ResourceRecord
	var owner *contract.OwnerRecord
	if err = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var e error
		v, e = automationResourceRecordTx(ctx, tx, "", "resource-uid")
		if e != nil {
			return e
		}
		owner, e = automationOwnerRecordTx(ctx, tx, "", v.ClusterUID, v.ProjectUID, v.OwnerID)
		return e
	}); err != nil || v == nil {
		t.Fatal("resource prerequisite", err)
	}
	d := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: contract.Command{Kind: "admit_update", ClusterUID: v.ClusterUID, ProjectUID: v.ProjectUID, PrincipalID: "principal-uid", OwnerID: v.OwnerID, ManagementKey: v.ManagementKey, ResourceUID: v.UID, Generation: v.BindingGeneration, Session: owner.Activation, SessionID: owner.SessionID, RequestID: fmt.Sprintf("update-request-%d", head.Sequence+1)}}
	d.Command.Body = []byte(fmt.Sprintf(`{"version":1,"resource":{"cluster_uid":%q,"project_uid":%q,"kind":"vm","uid":"resource-uid"},"expected_revision":%q,"patch":%s,"permitted_disruption":"live"}`, v.ClusterUID, v.ProjectUID, v.Revision, patch))
	rows, err := f.c.Query(ctx, `SELECT digest FROM local_automation_history WHERE sequence=?`, v.AppliedSequence)
	if err != nil || len(rows) != 1 {
		t.Fatal("mutation reference prerequisite", err)
	}
	previousOperation := contract.HistoryReference{Sequence: v.AppliedSequence, Digest: rows[0].String("digest")}
	origin := contract.HistoryReference{Sequence: 10, Digest: f.admission.Value.MustDigest()}
	facts := map[string]any{"version": 1, "resource_uid": v.UID, "revision": v.Revision, "incarnation": v.Incarnation, "last_operation_id": v.LastOperationID, "runtime_owner_epoch": 1, "fence_sequence": head.Sequence, "evidence_id": "fixture-quiescence", "coverage_digest": strings.Repeat("c", 64)}
	applicability := map[string]any{"version": 1, "resource_uid": v.UID, "domain_uuid": v.DomainUUID, "incarnation": v.Incarnation, "previous_revision": v.Revision, "previous_operation": v.LastOperationID, "host_uid": "host-uid", "host_incarnation": "positive-host-uid", "runtime_owner_epoch": 1, "fence_sequence": head.Sequence, "evidence_id": "fixture-applicability", "coverage_digest": strings.Repeat("d", 64), "mechanism": "metadata", "cpu_live_min": 0, "cpu_live_max": 0, "memory_live_min_mib": 0, "memory_live_max_mib": 0, "memory_mode": "none", "cpu_pinned": false, "runtime_state": "running"}
	var previous *contract.AdmissionRecord
	if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		rows, e := tx.Query(ctx, `SELECT operation_id FROM local_automation_admissions WHERE stage='' AND sequence=?`, previousDesired.Sequence)
		if e != nil {
			return e
		}
		if len(rows) != 1 {
			return fmt.Errorf("desired fixture prerequisite")
		}
		previous, e = automationAdmissionRecordTx(ctx, tx, "", rows[0].String("operation_id"))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if string(automationExecutionJSON(t, config)) == string(automationExecutionJSON(t, previous.PinnedConfiguration)) {
		applicability["mechanism"] = "none"
	}
	permission := map[string]any{"purpose": "resource", "principal_uid": "principal-uid", "cluster_uid": v.ClusterUID, "project_uid": v.ProjectUID, "project_name": "acme", "owner_id": v.OwnerID, "resource_uid": v.UID, "resource_name": v.Name, "verb": "vm.update", "evidence_id": "fixture-permission", "coverage_digest": strings.Repeat("e", 64), "fence_sequence": head.Sequence}
	// The actual fixture project alias is authenticated rather than guessed.
	var alias string
	if err = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		p, e := automationIdentityRecordTx(ctx, tx, "", v.ProjectUID)
		if e == nil && p != nil {
			alias = p.Alias
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	permission["project_name"] = alias
	d.Assignment = automationExecutionJSON(t, map[string]any{"version": 3, "cluster_uid": v.ClusterUID, "operation_id": fmt.Sprintf("update-op-%d", head.Sequence+1), "recorded_at": "2026-10-23T20:00:00Z", "update": map[string]any{"version": 1, "previous_desired": previousDesired, "previous_operation": previousOperation, "origin": origin, "revision": revision, "admitted_generation": 1, "configuration": config, "payload_id": "", "quiescence": facts, "permissions": []any{permission}, "applicability": applicability}})
	return d
}
func updateOrigin(f *executionStorageFixture) contract.HistoryReference {
	return contract.HistoryReference{Sequence: 10, Digest: f.admission.Value.MustDigest()}
}
func updateRecord(t *testing.T, f *executionStorageFixture, d contract.Decision) AutomationRecord {
	t.Helper()
	return f.sign(d)
}
func updateConfig(t *testing.T, v contract.VMIntent) contract.VMIntent {
	t.Helper()
	var out contract.VMIntent
	if err := json.Unmarshal(automationExecutionJSON(t, v), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Missing reducer/storage dispatch must fail at positive FULL acceptance.
func TestAutomationUpdateFULLRequiredAdmission(t *testing.T) {
	f := updateFixture(t)
	config := updateConfig(t, f.config)
	config.Labels = map[string]string{"role": "db"}
	record := updateRecord(t, f, updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:update-1", updateOrigin(f)))
	before := executionStorageSnapshot(t, f.c)
	receipt, err := applySharedAutomation(t, f.c, record, contract.Reduce, automationFreshAnchor)
	if err != nil || receipt.Code != "" || receipt.State != "accepted" || receipt.ResourceUID != "resource-uid" || receipt.Generation != 1 || receipt.ResourceRevision != "rev:update-1" {
		t.Fatalf("FULL supported metadata update must admit: %+v %v", receipt, err)
	}
	after := executionStorageSnapshot(t, f.c)
	for _, table := range append(executionStorageTables, "local_automation_names", "local_automation_identities") {
		if !reflect.DeepEqual(before[table], after[table]) {
			t.Fatal("update changed immutable artifacts/name/identity", table)
		}
	}
	if err = f.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		v, e := automationResourceRecordTx(context.Background(), tx, "", "resource-uid")
		if e != nil {
			return e
		}
		a, e := automationAdmissionRecordTx(context.Background(), tx, "", receipt.OperationID)
		if e != nil {
			return e
		}
		if v.OriginalOperationID != "create-op" || v.DomainUUID != "domain-uuid" || v.Incarnation != "runtime-incarnation" || v.Revision != "rev:update-1" || a == nil || a.Method != "admit_update" || !reflect.DeepEqual(a.PinnedConfiguration, &config) {
			return fmt.Errorf("FULL update lost birth/configuration: %+v %+v", v, a)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func updateTransfer(t *testing.T, f *executionStorageFixture) AutomationRecord {
	return updateTransferTo(t, f, "successor")
}
func updateTransferTo(t *testing.T, f *executionStorageFixture, nextOwner string) AutomationRecord {
	t.Helper()
	ctx := context.Background()
	for _, kind := range []string{"ensure_owner", "acquire_session"} {
		head, e := f.c.AutomationHead(ctx)
		if e != nil {
			t.Fatal(e)
		}
		a := contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: kind + "-" + nextOwner + "-op", RecordedAt: "2026-10-23T20:00:00Z"}
		if kind == "acquire_session" {
			a.Owner = &contract.OwnerAssignment{SessionID: nextOwner + "-session"}
		}
		d := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: contract.Command{Kind: kind, ClusterUID: head.ClusterUID, ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: nextOwner, RequestID: kind + "-" + nextOwner + "-request", Body: []byte(`{"version":1}`)}, Assignment: automationExecutionJSON(t, a)}
		f.apply(t, f.sign(d))
	}
	head, e := f.c.AutomationHead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var v *contract.ResourceRecord
	var project *contract.IdentityRecord
	var sourceOwner *contract.OwnerRecord
	if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var e error
		v, e = automationResourceRecordTx(ctx, tx, "", "resource-uid")
		if e != nil {
			return e
		}
		project, e = automationIdentityRecordTx(ctx, tx, "", "project-uid")
		if e != nil {
			return e
		}
		sourceOwner, e = automationOwnerRecordTx(ctx, tx, "", v.ClusterUID, v.ProjectUID, v.OwnerID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	source := contract.BindingKey{ClusterUID: head.ClusterUID, ProjectUID: "project-uid", OwnerID: v.OwnerID, ManagementKey: v.ManagementKey}
	target := contract.BindingKey{ClusterUID: head.ClusterUID, ProjectUID: "project-uid", OwnerID: nextOwner, ManagementKey: nextOwner + "-key"}
	body := contract.OwnershipBody{Version: 1, Resource: contract.ResourceReference{ClusterUID: head.ClusterUID, ProjectUID: "project-uid", Kind: "vm", UID: v.UID}, ExpectedRevision: v.Revision, Source: &contract.BindingReference{Key: source, Generation: v.BindingGeneration}, Target: target}
	o := &contract.OwnershipAssignment{Version: 1, TargetSession: contract.RecordedOwnerSession{ID: nextOwner + "-session", Activation: 1, PrincipalUID: "principal-uid"}, TargetGeneration: 1, Revision: "rev:ownership:" + nextOwner, AdmittedGeneration: 1, Quiescence: contract.QuiescenceFacts{Version: 1, ResourceUID: v.UID, Revision: v.Revision, Incarnation: v.Incarnation, LastOperationID: v.LastOperationID, RuntimeOwnerEpoch: 1, FenceSequence: head.Sequence, EvidenceID: "fixture-transfer-quiescence", CoverageDigest: strings.Repeat("c", 64)}}
	for _, purpose := range []string{"source_owner", "target_owner", "resource"} {
		p := contract.PermissionFacts{Purpose: purpose, PrincipalUID: "principal-uid", ClusterUID: head.ClusterUID, ProjectUID: "project-uid", ProjectName: project.Alias, Verb: "vm.update", EvidenceID: "fixture-transfer-permission", CoverageDigest: strings.Repeat("d", 64), FenceSequence: head.Sequence}
		switch purpose {
		case "source_owner":
			p.OwnerID = v.OwnerID
		case "target_owner":
			p.OwnerID = nextOwner
		case "resource":
			p.ResourceUID = v.UID
			p.ResourceName = v.Name
		}
		o.Permissions = append(o.Permissions, p)
	}
	d := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: contract.Command{Kind: "transfer_owner", ClusterUID: head.ClusterUID, ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: v.OwnerID, ManagementKey: v.ManagementKey, ResourceUID: v.UID, Generation: v.BindingGeneration, Session: sourceOwner.Activation, SessionID: sourceOwner.SessionID, RequestID: "transfer-" + nextOwner + "-request", Body: automationExecutionJSON(t, body)}, Assignment: automationExecutionJSON(t, contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: "transfer-" + nextOwner + "-op", RecordedAt: "2026-10-23T20:00:00Z", Ownership: o})}
	record := f.sign(d)
	if r := f.apply(t, record); r.State != "succeeded" {
		t.Fatal("ownership result", r)
	}
	return record
}
func TestAutomationUpdateFULLRepeatedAndOwnership(t *testing.T) {
	f := updateFixture(t)
	config := updateConfig(t, f.config)
	config.Labels = map[string]string{"role": "db"}
	first := f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:first", updateOrigin(f)))
	r := f.apply(t, first)
	ref := contract.HistoryReference{Sequence: r.Sequence, Digest: first.Value.MustDigest()}
	updateTransfer(t, f)
	second := f.sign(updateDecision(t, f, `{"labels":{"values":{}}}`, func() contract.VMIntent { v := updateConfig(t, config); v.Labels = map[string]string{}; return v }(), "rev:second", ref))
	r = f.apply(t, second)
	if r.ResourceRevision != "rev:second" || r.Generation != 1 {
		t.Fatal("second update lost new-owner/current desired", r)
	}
	var admission *contract.AdmissionRecord
	if e := f.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		var e error
		admission, e = automationAdmissionRecordTx(context.Background(), tx, "", r.OperationID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if admission.OwnerID != "successor" || admission.ManagementKey != "successor-key" || len(admission.PinnedConfiguration.Labels) != 0 || admission.PinnedConfiguration.Disks[0].SizeBytes != 4096 {
		t.Fatal("second update reset desired or artifact lineage", admission)
	}
}

func TestAutomationUpdateFULLNoopThenChangeAndConcurrentRevision(t *testing.T) {
	f, first, config := updateFirst(t)
	ctx := context.Background()
	d, _ := automationDecision(first.Value)
	ref := contract.HistoryReference{Sequence: d.Sequence, Digest: first.Value.MustDigest()}
	noop := f.sign(updateDecision(t, f, `{}`, config, "rev:first", ref))
	before := updateSnapshot(t, f.c)
	n := f.apply(t, noop)
	if n.State != "accepted" || n.ResourceRevision != "rev:first" || n.Generation != 1 {
		t.Fatal("FULL no-op changed desired revision or reported terminal success", n)
	}
	after := updateSnapshot(t, f.c)
	for _, table := range append(executionStorageTables, "local_automation_names", "local_automation_identities") {
		if !reflect.DeepEqual(before[table], after[table]) {
			t.Fatal("FULL no-op changed identity/artifacts", table)
		}
	}
	next := updateNext(t, f, noop, config)
	loser := next
	loser.Command.RequestID = "revision-racer-loser"
	a, _ := contract.DecodeAssignment(loser)
	a.OperationID = "revision-racer-loser-op"
	loser.Assignment = automationExecutionJSON(t, a)
	winner := f.sign(next)
	w := f.apply(t, winner)
	if w.ResourceRevision != "rev:next" {
		t.Fatal(w)
	}
	loser.Sequence++
	loser.ParentDigest = winner.Value.MustDigest()
	business := updateSnapshot(t, f.c)
	r, e := applySharedAutomation(t, f.c, f.sign(loser), contract.Reduce, automationFreshAnchor)
	if e != nil || r.Code != contract.CodeRevisionConflict {
		t.Fatal("two requests using one opaque revision both advanced", r, e)
	}
	after = updateSnapshot(t, f.c)
	for _, descriptor := range automationSemanticTables {
		if descriptor.table == "local_automation_semantic_heads" {
			continue
		}
		if !reflect.DeepEqual(business[descriptor.table], after[descriptor.table]) {
			t.Fatal("stale concurrent request emitted effects", descriptor.table)
		}
	}
	rows, e := f.c.Query(ctx, `SELECT count(*) AS n FROM local_automation_admissions WHERE stage='' AND sequence=?`, loser.Sequence)
	if e != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
		t.Fatal("stale request persisted admission", rows, e)
	}
}
