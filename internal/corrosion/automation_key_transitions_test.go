package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"weak"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
)

// This fixture starts from explicitly already-certified historical authority.
// It never enables fresh class admission or simulates a custody provider.
func keyActivationHistory(t *testing.T) (*claimTestVoter, AutomationRecord, AutomationRecord) {
	t.Helper()
	_, a, b, c := threeVoters(t)
	genesis := sharedAutomationRecord(t, 1, "", "initialize", "initialize-operation", a, b)
	if _, e := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); e != nil {
		t.Fatal(e)
	}
	return a, genesis, keyActivationRecordFor(t, a, genesis, []*claimTestVoter{a, b, c})
}
func keyActivationRecordFor(t *testing.T, a *claimTestVoter, genesis AutomationRecord, voters []*claimTestVoter) AutomationRecord {
	t.Helper()
	cfg, e := AdoptedVoterConfig(context.Background(), a.c)
	if e != nil {
		t.Fatal(e)
	}
	gd, _ := automationDecision(genesis.Value)
	body := contract.ActivateKeyEpochBody{Version: 1, MembershipGeneration: 1, ConfigDigest: cfg.MembersHash, RecipientEpoch: "recipient-1", EqualityEpoch: "equality-1", Prefix: contract.HistoryReference{Sequence: 1, Digest: genesis.Value.MustDigest()}}
	ref := body.Prefix
	facts := &contract.KeyTransitionAssignment{Class: "bootstrap", Bootstrap: &ref, RetainedInventory: []contract.RetainedPayload{}, Coverage: []contract.PayloadCoverage{}}
	for i, v := range voters {
		id, e := age.GenerateX25519Identity()
		if e != nil {
			t.Fatal(e)
		}
		facts.Recipients = append(facts.Recipients, contract.RecipientBinding{ClusterUID: "established-cluster", MembershipGeneration: 1, ConfigDigest: cfg.MembersHash, Host: v.name, HostIncarnation: uint64(17 + i), AdmittedAt: "2026-10-18T00:00:00Z", AdmissionSerial: fmt.Sprintf("a%d", i), VoterIncarnation: v.inc, RecipientEpoch: "recipient-1", KeyID: fmt.Sprintf("candidate-%d", i), Recipient: id.Recipient().String(), Enrollment: ref, RecipientAck: ref, EqualityAck: ref})
	}
	raw, _ := json.Marshal(body)
	assigned, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "activate-operation", RecordedAt: "2026-10-18T00:00:00Z", KeyTransition: facts})
	d := contract.Decision{Sequence: 2, ParentDigest: genesis.Value.MustDigest(), Command: contract.Command{Kind: "activate_key_epoch", ClusterUID: "established-cluster", PrincipalID: gd.Command.PrincipalID, RequestID: "activate-request", Body: raw}, Assignment: assigned}
	return keyCertifiedDecision(t, d, voters...)
}
func keyCertifiedDecision(t *testing.T, d contract.Decision, voters ...*claimTestVoter) AutomationRecord {
	t.Helper()
	raw, e := contract.EncodeDecision(d)
	if e != nil {
		t.Fatal(e)
	}
	v := ClaimValue{Automation: &AutomationClaimValue{Envelope: raw}}
	key, _ := AutomationClaimKey(d.Sequence)
	ballot := testBallot(2, "a")
	r := AutomationRecord{Value: v, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: v.MustDigest()}}
	for _, voter := range voters {
		a, e := voter.signer.Sign(key, 1, ballot, v.MustDigest(), voter.inc)
		if e != nil {
			t.Fatal(e)
		}
		r.Certificate.Accepts = append(r.Certificate.Accepts, a)
	}
	return r
}
func TestAutomationKeyTransitionFullHistoryAndStagedReplay(t *testing.T) {
	a, _, r := keyActivationHistory(t)
	if _, e := applySharedAutomation(t, a.c, r, contract.Reduce, automationFreshAnchor); e != nil {
		t.Fatalf("certified activation did not persist in FULL history transaction: %v", e)
	}
	rows, e := a.c.Query(context.Background(), `SELECT recipient_epoch,equality_epoch,activation_sequence FROM local_automation_key_epochs WHERE stage=''`)
	if e != nil || len(rows) != 1 || rows[0].String("recipient_epoch") != "recipient-1" || rows[0].String("equality_epoch") != "equality-1" || rows[0].Int64("activation_sequence") != 2 {
		t.Fatal("derived epoch missing", e)
	}
	before := sharedActiveRows(t, a.c)
	e = a.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		_, e := auditAutomationCutTx(context.Background(), tx, contract.Reduce)
		return e
	})
	if e != nil {
		t.Fatal("source causal reconstruction failed", e)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
		t.Fatal("audit rewrote immutable history")
	}
	if _, e = applySharedAutomation(t, a.c, r, contract.Reduce, automationAnchoredReplay); e != nil {
		t.Fatal(e)
	}
}
func TestAutomationKeyTransitionCallbackCannotEraseOrMutate(t *testing.T) {
	r := contract.Reduction{EpochEffect: &contract.KeyEpochRecord{RecipientEpoch: "original"}}
	if e := validateAutomationCallback(r, contract.Reduction{}); e == nil {
		t.Fatal("callback erased activation effect")
	}
	p := AutomationProjection{KeyTransition: &contract.KeyTransitionProjection{History: []contract.HistoricalDecision{{EqualityTag: []byte("immutable")}}, Recipients: []contract.KeyRecipientRecord{{Binding: contract.RecipientBinding{KeyID: "original"}}}}}
	copy := cloneAutomationProjection(p)
	copy.KeyTransition.History[0].EqualityTag[0] = 'X'
	copy.KeyTransition.Recipients[0].Binding.KeyID = "changed"
	if string(p.KeyTransition.History[0].EqualityTag) != "immutable" || p.KeyTransition.Recipients[0].Binding.KeyID != "original" {
		t.Fatal("callback mutated causal transition facts")
	}
}
func TestAutomationKeyTransitionSchemaIsClassified(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if e := InitSchema(ctx, c); e != nil {
		t.Fatal(e)
	}
	if e := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) }); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"local_automation_key_epochs", "local_automation_key_recipients", "local_automation_payload_wrappings"} {
		if _, e := c.Query(ctx, "SELECT * FROM "+table+" LIMIT 1"); e != nil {
			t.Fatal("used derived table missing", e)
		}
	}
	if !supportedAutomationCutDescriptor(77, 1) || !supportedAutomationCutDescriptor(78, 1) || !supportedAutomationCutDescriptor(79, 1) || !supportedAutomationCutDescriptor(80, 1) || !supportedAutomationCutDescriptor(81, 1) || !supportedAutomationCutDescriptor(82, 1) || !supportedAutomationCutDescriptor(83, 1) || !supportedAutomationCutDescriptor(84, 1) || !supportedAutomationCutDescriptor(85, 1) || !supportedAutomationCutDescriptor(86, 1) || supportedAutomationCutDescriptor(87, 1) {
		t.Fatal("new schema descriptor not explicitly classified")
	}
}

func TestAutomationKeyTransitionFreshDirectAcceptRefuses(t *testing.T) {
	a, genesis, r := keyActivationHistory(t)
	ctx := context.Background()
	key, _ := AutomationClaimKey(2)
	installAutomationEvidence(t, a.c, key, genesis.Value.MustDigest(), 1)
	before := sharedActiveRows(t, a.c)
	result, e := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), r.Value, 1, a.signer, unreachable)
	if e != nil || result.Accepted || result.Refusal != RefusalAutomationUnavailable {
		t.Fatal("fresh key transition inherited historical authority", result, e)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
		t.Fatal("refused fresh transition mutated history")
	}
	rows, e := a.c.Query(ctx, `SELECT count(*) AS n FROM local_automation_key_epochs`)
	if e != nil || rows[0].Int64("n") != 0 {
		t.Fatal("fresh refusal installed epoch", e)
	}
}
func TestAutomationKeyTransitionStorageRollbackAndShape(t *testing.T) {
	a, _, r := keyActivationHistory(t)
	ctx := context.Background()
	before := sharedActiveRows(t, a.c)
	d, _ := automationDecision(r.Value)
	err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		head, e := automationHeadTx(ctx, tx)
		if e != nil {
			return e
		}
		request, e := automationPrepareKeyLookup(ctx, d, r.Certificate)
		if e != nil {
			return e
		}
		prepared := AutomationProjection{Head: head}
		if e = automationResolveKeyProjectionTx(ctx, tx, "", &prepared, request, nil); e != nil {
			return e
		}
		p, e := automationProjectionTx(ctx, tx, head, d, prepared.KeyTransition)
		if e != nil {
			return e
		}
		effect, e := contract.Reduce(p, d)
		if e != nil {
			return e
		}
		if e = automationApplySemanticEffectsTx(ctx, tx, "", head, contract.Prefix{ClusterUID: head.ClusterUID, Sequence: 2, Digest: r.Value.MustDigest()}, effect); e != nil {
			return e
		}
		return fmt.Errorf("injected after all transition effects")
	})
	if err == nil || !strings.Contains(err.Error(), "injected after") {
		t.Fatal("rollback did not reach effects", err)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
		t.Fatal("rollback changed immutable history")
	}
	for _, table := range []string{"local_automation_key_epochs", "local_automation_key_recipients", "local_automation_payload_wrappings"} {
		rows, e := a.c.Query(ctx, "SELECT count(*) AS n FROM "+table)
		if e != nil || rows[0].Int64("n") != 0 {
			t.Fatal("rollback retained partial transition", e)
		}
	}
	if _, e := a.c.db.Exec(`DROP INDEX automation_key_recipient`); e != nil {
		t.Fatal(e)
	}
	if e := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) }); e == nil {
		t.Fatal("missing freshness index accepted")
	}
}

func appendKeyPayloadHistory(t *testing.T, a *claimTestVoter, voters []*claimTestVoter) {
	t.Helper()
	appendKeyPayloadHistoryWithBytes(t, a, voters, nil)
}
func appendKeyPayloadHistoryWithBytes(t *testing.T, a *claimTestVoter, voters []*claimTestVoter, ciphertext []byte) {
	t.Helper()
	ctx := context.Background()
	verifier, e := LoadClaimVerifier(a.pki)
	if e != nil {
		t.Fatal(e)
	}
	var activation AutomationRecord
	automationTypedHistoryFixtureWithDecision(t, a, voters[1], voters[2], verifier, func(d *contract.Decision) {
		if d.Sequence == 2 {
			genesis, found, e := a.c.AutomationRecord(ctx, 1)
			if e != nil || !found {
				t.Fatal(e)
			}
			activation = keyActivationRecordFor(t, a, genesis, voters)
			if _, e = applySharedAutomation(t, a.c, activation, contract.Reduce, automationFreshAnchor); e != nil {
				t.Fatal(e)
			}
			d.ParentDigest = activation.Value.MustDigest()
		}
		d.Sequence++
		assignment, e := contract.DecodeAssignment(*d)
		if e != nil {
			t.Fatal(e)
		}
		if assignment.Binding != nil {
			assignment.Binding.RecipientEpoch = "recipient-1"
			if ciphertext != nil {
				d.Command.Ciphertext = ciphertext
			}
			d.Command.SecretIntentTag = bytes.Repeat([]byte{0x31}, 32)
		}
		if assignment.Ownership != nil {
			assignment.Ownership.Quiescence.FenceSequence++
			for i := range assignment.Ownership.Permissions {
				assignment.Ownership.Permissions[i].FenceSequence++
			}
		}
		d.Assignment, _ = json.Marshal(assignment)
	})
	original, found, e := a.c.AutomationRecord(ctx, 8)
	if e != nil || !found {
		t.Fatal(e)
	}
	originalBytes, _ := json.Marshal(original)
	od, _ := automationDecision(original.Value)
	oa, _ := contract.DecodeAssignment(od)
	ad, _ := automationDecision(activation.Value)
	aa, _ := contract.DecodeAssignment(ad)
	recipients := append([]contract.RecipientBinding(nil), aa.KeyTransition.Recipients...)
	for i := range recipients {
		id, e := age.GenerateX25519Identity()
		if e != nil {
			t.Fatal(e)
		}
		recipients[i].RecipientEpoch = "recipient-2"
		recipients[i].KeyID += "-rotation"
		recipients[i].Recipient = id.Recipient().String()
	}
	head, e := a.c.AutomationHead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	originalRef := contract.HistoryReference{Sequence: 8, Digest: original.Value.MustDigest()}
	replacement := []byte("replacement-certified-encrypted-payload")
	if ciphertext != nil {
		replacement = bytes.Repeat([]byte{0x78}, len(ciphertext))
	}
	wb := contract.RewrapPayloadBody{Version: 1, MembershipGeneration: 1, ConfigDigest: recipients[0].ConfigDigest, RecipientEpoch: "recipient-2", AdmissionSequence: 8, OperationID: "create-op", PayloadID: oa.Binding.PayloadID, PreviousWrapping: originalRef}
	body, _ := json.Marshal(wb)
	facts := &contract.KeyTransitionAssignment{Recipients: recipients, OriginalHistory: &originalRef, Binding: &contract.PayloadBinding{ClusterUID: od.Command.ClusterUID, ProjectUID: od.Command.ProjectUID, ResourceUID: oa.Binding.ResourceUID, OperationID: oa.OperationID, PayloadID: oa.Binding.PayloadID, AdmittedGeneration: oa.Binding.AdmittedGeneration}, EqualityEpoch: od.Command.SecretKeyEpoch, EqualityTag: od.Command.SecretIntentTag, Preparation: &contract.RewrapPreparation{Purpose: "bootstrap-equivalence/v1", SourceWrapping: originalRef, ReplacementDigest: contract.CiphertextDigest(replacement)}}
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: "rewrap-op", RecordedAt: "2026-10-18T00:00:00Z", KeyTransition: facts})
	d := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: contract.Command{Kind: "rewrap_payload", ClusterUID: head.ClusterUID, ProjectUID: od.Command.ProjectUID, ResourceUID: oa.Binding.ResourceUID, PrincipalID: od.Command.PrincipalID, RequestID: "rewrap-request", Body: body, Ciphertext: replacement, SecretKeyEpoch: od.Command.SecretKeyEpoch, SecretIntentTag: od.Command.SecretIntentTag}, Assignment: assignment}
	wrapping := keyCertifiedDecision(t, d, voters...)
	if receipt, e := applySharedAutomation(t, a.c, wrapping, contract.Reduce, automationFreshAnchor); e != nil || receipt.Code != "" {
		t.Fatal("historical replacement failed", receipt, e)
	}
	ab := contract.ActivateKeyEpochBody{Version: 1, MembershipGeneration: 1, ConfigDigest: wb.ConfigDigest, RecipientEpoch: "recipient-2", EqualityEpoch: "equality-2", PreviousActivation: 2, Prefix: contract.HistoryReference{Sequence: d.Sequence, Digest: wrapping.Value.MustDigest()}}
	body, _ = json.Marshal(ab)
	facts = &contract.KeyTransitionAssignment{Class: "protocol", Recipients: recipients, RetainedInventory: []contract.RetainedPayload{{OperationID: oa.OperationID, PayloadID: oa.Binding.PayloadID, Admission: originalRef}}, Coverage: []contract.PayloadCoverage{{OperationID: oa.OperationID, Wrapping: ab.Prefix}}}
	assignment, _ = json.Marshal(contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: "rotate-op", RecordedAt: "2026-10-18T00:00:00Z", KeyTransition: facts})
	rotation := keyCertifiedDecision(t, contract.Decision{Sequence: d.Sequence + 1, ParentDigest: wrapping.Value.MustDigest(), Command: contract.Command{Kind: "activate_key_epoch", ClusterUID: head.ClusterUID, PrincipalID: od.Command.PrincipalID, RequestID: "rotate-request", Body: body}, Assignment: assignment}, voters...)
	if receipt, e := applySharedAutomation(t, a.c, rotation, contract.Reduce, automationFreshAnchor); e != nil || receipt.Code != "" {
		t.Fatal("historical rotation failed", receipt, e)
	}
	later, _, e := a.c.AutomationRecord(ctx, 8)
	if e != nil {
		t.Fatal(e)
	}
	laterBytes, _ := json.Marshal(later)
	if !bytes.Equal(originalBytes, laterBytes) {
		t.Fatal("rewrap rewrote original admission ciphertext or certificate")
	}
}
func TestAutomationKeyTransitionRetainedPayloadReplay(t *testing.T) {
	_, a, b, c := threeVoters(t)
	appendKeyPayloadHistory(t, a, []*claimTestVoter{a, b, c})
	ctx := context.Background()
	before := keyTransitionSnapshot(t, a.c)
	immutable := sharedActiveRows(t, a.c)
	if e := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") }); e != nil {
		t.Fatal(e)
	}
	for seq := uint64(1); seq <= 15; seq++ {
		r, found, e := a.c.AutomationRecord(ctx, seq)
		if e != nil || !found {
			t.Fatal("history missing", seq, e)
		}
		if _, e = applySharedAutomation(t, a.c, r, contract.Reduce, automationAnchoredReplay); e != nil {
			t.Fatal("causal retained payload replay failed", seq, e)
		}
	}
	if !reflect.DeepEqual(before, keyTransitionSnapshot(t, a.c)) || !reflect.DeepEqual(immutable, sharedActiveRows(t, a.c)) {
		t.Fatal("replay diverged or changed original history")
	}
	if e := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, e := auditAutomationCutTx(ctx, tx, contract.Reduce); return e }); e != nil {
		t.Fatal("source reconstruction failed", e)
	}
	rows, e := a.c.Query(ctx, `SELECT operation_id,admission_sequence,wrapping_sequence,recipient_epoch FROM local_automation_payload_wrappings WHERE stage=''`)
	if e != nil || len(rows) != 1 || rows[0].String("operation_id") != "create-op" || rows[0].Int64("admission_sequence") != 8 || rows[0].Int64("wrapping_sequence") != 14 || rows[0].String("recipient_epoch") != "recipient-2" {
		t.Fatal("immutable pointer mismatch", e)
	}
}
func TestAutomationKeyTransitionReceiverUsesSourceHistory(t *testing.T) {
	p, r, q, exportCtx, _ := receiverAuditFixture(t, 0, func(a *claimTestVoter, voters []*claimTestVoter) {
		// Existing fixture's original request and native bootstrap identity must
		// match; only the already-certified premise authorizes these history tests.
		installAutomationEvidence(t, a.c, func() ClaimKey { k, _ := AutomationClaimKey(1); return k }(), "", 1)
		appendKeyPayloadHistory(t, a, voters)
		if _, e := a.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); e != nil {
			t.Fatal(e)
		}
	})
	ctx := context.Background()
	attempt, e := r.Begin(ctx, q.Intent, nil)
	if e != nil {
		t.Fatal(e)
	}
	receiverThrough(t, p, r, attempt, q, exportCtx, 11)
	before := receiverActive(t, r.client)
	if e = r.AuditSource(ctx, attempt, "a"); e != nil {
		t.Fatal("receiver did not reconstruct original wrapping history", e)
	}
	if receiverActive(t, r.client) != before {
		t.Fatal("receiver historical audit activated local state")
	}
	rows, e := r.client.Query(ctx, `SELECT recipient_epoch,activation_sequence FROM local_automation_key_epochs WHERE stage<>'' ORDER BY activation_sequence`)
	if e != nil || len(rows) != 2 || rows[0].Int64("activation_sequence") != 2 || rows[1].Int64("activation_sequence") != 15 || rows[1].String("recipient_epoch") != "recipient-2" {
		t.Fatal("receiver staged epochs differ", e)
	}
	local, e := r.client.Query(ctx, `SELECT count(*) AS n FROM local_automation_history`)
	if e != nil || local[0].Int64("n") != 0 {
		t.Fatal("receiver imported history as active authority", e)
	}
}

func keyTransitionSnapshot(t *testing.T, c *Client) map[string][]Row {
	t.Helper()
	out := automationTypedSnapshot(t, c)
	for _, table := range []string{"local_automation_key_epochs", "local_automation_key_recipients", "local_automation_payload_wrappings"} {
		rows, e := c.Query(context.Background(), "SELECT * FROM "+table+" ORDER BY stage,2,3,4")
		if e != nil {
			t.Fatal(e)
		}
		out[table] = rows
	}
	return out
}

func TestAutomationKeyTransitionArchived76Unchanged(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err := a.c.SealVoterGeneration(ctx, 1, "archive76"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.db.Exec(`UPDATE schema_state SET version=76 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, records := cutFixtureRead(t, a.c, id)
	if before.SourceSchema != 76 {
		t.Fatal("wrong archived descriptor")
	}
	if _, err = a.c.db.Exec(`UPDATE schema_state SET version=85 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	later, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || later != id {
		t.Fatal("archive76 reuse changed", err)
	}
	after, laterRecords := cutFixtureRead(t, a.c, later)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, laterRecords) {
		t.Fatal("new schema relabeled archived76 bytes/root")
	}
}

// Direct storage-adapter fixture: these unrelated derived admissions are not
// claimed to authenticate history or provide bootstrap/class authority.
func TestAutomationKeyTransitionInventoryPagesUnrelatedAdmissions(t *testing.T) {
	a, genesis, activation := keyActivationHistory(t)
	d, _ := automationDecision(activation.Value)
	ctx := context.Background()
	err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for i := 0; i < 257; i++ {
			_, e := tx.Exec(ctx, `INSERT INTO local_automation_admissions(stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "inventory", fmt.Sprintf("unrelated-%04d", i), "established-cluster", "project", "owner", "key", "resource", fmt.Sprintf("request-%04d", i), "principal", "transfer_owner", "", 1, 1, i+2, "null")
			if e != nil {
				return e
			}
		}
		p := contract.Projection{Head: contract.Prefix{ClusterUID: "established-cluster", Sequence: 300, Digest: genesis.Value.MustDigest()}}
		request, e := automationPrepareKeyLookup(ctx, d, activation.Certificate)
		if e != nil {
			return e
		}
		if e := automationResolveKeyProjectionTx(ctx, tx, "inventory", &p, request, nil); e != nil {
			return e
		}
		if len(p.KeyTransition.Admissions) != 0 {
			return fmt.Errorf("unrelated admissions were retained as payload inventory")
		}
		return nil
	})
	if err != nil {
		t.Fatal("bounded pages must not cap unrelated admissions at retained payload capacity", err)
	}
}

func TestAutomationKeyTransitionNearNativeBodyKeepsOnlySummary(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 0, func(a *claimTestVoter, voters []*claimTestVoter) {
		installAutomationEvidence(t, a.c, func() ClaimKey { k, _ := AutomationClaimKey(1); return k }(), "", 1)
		appendKeyPayloadHistoryWithBytes(t, a, voters, bytes.Repeat([]byte{0x67}, 1<<20))
		if _, e := a.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); e != nil {
			t.Fatal(e)
		}
		e := a.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
			summary, e := (localAutomationKeySource{tx}).keyHistory(context.Background(), 8)
			if e != nil {
				return e
			}
			raw, e := json.Marshal(summary)
			if e != nil {
				return e
			}
			if len(raw) > 16<<10 {
				return fmt.Errorf("original adapter retained complete near-native envelope: summary bytes=%d", len(raw))
			}
			t.Logf("actual local original read returned finite summary bytes=%d", len(raw))
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	ctx := context.Background()
	attempt, e := r.Begin(ctx, q.Intent, nil)
	if e != nil {
		t.Fatal(e)
	}
	receiverThrough(t, p, r, attempt, q, peer, 11)
	before := receiverActive(t, r.client)
	state := receiverAuditInstrument(t, r)
	state.enabled = true
	e = r.AuditSource(ctx, attempt, "a")
	state.enabled = false
	if e != nil {
		t.Fatal("near-native receiver original reconstruction", e)
	}
	if state.maxRows != 1 || state.maxBytes < 1<<20 || state.maxBytes > maxAutomationCutRecordBytes || len(state.bad) != 0 {
		t.Fatal("actual original read bounds", state.maxRows, state.maxBytes, state.bad)
	}
	if receiverActive(t, r.client) != before {
		t.Fatal("receiver changed live state")
	}
	t.Logf("actual near-native receiver maxfieldbytes=%d maxrows=%d bodyreads=%d", state.maxBytes, state.maxRows, state.bodies)
}

// Weak pointers track actual decoded ciphertext allocations across the entire
// caller stack. They do not keep the body alive and are not query-size counters.
func keyWholeStackObserver(t *testing.T) (context.Context, *int) {
	t.Helper()
	var current []weak.Pointer[byte]
	checks := new(int)
	observe := func(sequence uint64, body []byte) {
		if sequence == 14 && len(body) >= 1<<20 {
			current = append(current, weak.Make(&body[0]))
			return
		}
		if sequence == 8 && body == nil && len(current) != 0 {
			runtime.GC()
			*checks++
			for _, allocation := range current {
				if allocation.Value() != nil {
					t.Error("near-native CURRENT envelope or ciphertext remains reachable while REFERENCED original is opened")
				}
			}
		}
	}
	return context.WithValue(context.Background(), automationKeyBodyObserverKey{}, observe), checks
}
func TestAutomationKeyTransitionWholeStackBodies(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 0, func(a *claimTestVoter, voters []*claimTestVoter) {
		installAutomationEvidence(t, a.c, func() ClaimKey { k, _ := AutomationClaimKey(1); return k }(), "", 1)
		appendKeyPayloadHistoryWithBytes(t, a, voters, bytes.Repeat([]byte{0x67}, 1<<20))
		if _, e := a.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); e != nil {
			t.Fatal(e)
		}
		t.Run("source", func(t *testing.T) {
			ctx, checks := keyWholeStackObserver(t)
			e := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, e := auditAutomationCutTx(ctx, tx, contract.Reduce); return e })
			if e != nil {
				t.Fatal(e)
			}
			if *checks == 0 {
				t.Fatal("whole-stack source assertion did not run")
			}
		})
	})
	t.Run("receiver", func(t *testing.T) {
		ctx, checks := keyWholeStackObserver(t)
		attempt, e := r.Begin(ctx, q.Intent, nil)
		if e != nil {
			t.Fatal(e)
		}
		receiverThrough(t, p, r, attempt, q, peer, 11)
		before := receiverActive(t, r.client)
		if e = r.AuditSource(ctx, attempt, "a"); e != nil {
			t.Fatal(e)
		}
		if *checks == 0 {
			t.Fatal("whole-stack receiver assertion did not run")
		}
		if receiverActive(t, r.client) != before {
			t.Fatal("audit changed active state")
		}
	})
}

func TestAutomationKeyTransitionOriginalElectorate(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	genesis := sharedAutomationRecord(t, 1, "", "initialize", "initialize-operation", a, b)
	if _, e := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); e != nil {
		t.Fatal(e)
	}
	current := keyActivationRecordFor(t, a, genesis, []*claimTestVoter{a, b, c})
	cfgA, e := AdoptedVoterConfig(ctx, a.c)
	if e != nil {
		t.Fatal(e)
	}
	cfgB := VoterConfigValue{Generation: 2, Members: membersOf(a, b), Change: VoterChangeRm("c"), CreatedBy: "a", CreatedAt: "t2"}
	cfgKey := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 1}
	cfgValue := ClaimValue{Config: &cfgB}
	cfgCert := ClaimCertificate{Key: cfgKey, Ballot: testBallot(7, "a"), ConfigGeneration: 1, ValueDigest: cfgValue.MustDigest()}
	for _, voter := range []*claimTestVoter{a, b, c} {
		accept, e := voter.signer.Sign(cfgKey, 1, cfgCert.Ballot, cfgCert.ValueDigest, voter.inc)
		if e != nil {
			t.Fatal(e)
		}
		cfgCert.Accepts = append(cfgCert.Accepts, accept)
	}
	raw, e := cfgCert.Encode()
	if e != nil {
		t.Fatal(e)
	}
	view, e := pki.CaptureHostTrust(ctx, a.pki, "a")
	if e != nil {
		t.Fatal(e)
	}
	verifier := &ClaimVerifier{sourceTrust: view, pinned: true}
	if e = VerifyVoterConfigRow(verifier, cfgA, &VoterConfig{VoterConfigValue: cfgB, MembersHash: MembersHash(cfgB.Members), Certificate: raw}); e != nil {
		t.Fatal("real B membership certificate", e)
	}
	if e = WriteVoterConfig(ctx, a.c, cfgB, cfgCert); e != nil {
		t.Fatal(e)
	}
	current.Certificate.ConfigGeneration = 2
	current.Certificate.Accepts = nil
	for _, voter := range []*claimTestVoter{a, b} {
		accept, e := voter.signer.Sign(current.Certificate.Key, 2, current.Certificate.Ballot, current.Certificate.ValueDigest, voter.inc)
		if e != nil {
			t.Fatal(e)
		}
		current.Certificate.Accepts = append(current.Certificate.Accepts, accept)
	}
	if e = verifier.Verify(current.Certificate, CertExpectation{Key: current.Certificate.Key, ValueDigest: current.Value.MustDigest(), ConfigGeneration: 2, Electorate: cfgB.Members, Quorum: MajorityOf(len(cfgB.Members))}); e != nil {
		t.Fatal("real B transition certificate", e)
	}
	before := sharedActiveRows(t, a.c)
	beforeKeys := keyTransitionSnapshot(t, a.c)
	receipt, e := applySharedAutomation(t, a.c, current, contract.Reduce, automationFreshAnchor)
	if e == nil && receipt.Code == "" {
		t.Error("valid B certificate installed coherent A transition")
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) || !reflect.DeepEqual(beforeKeys, keyTransitionSnapshot(t, a.c)) {
		t.Error("electorate mismatch left history or derived effects")
	}
}
