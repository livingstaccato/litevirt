package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"filippo.io/age"
)

// This fixture assumes already-certified historical preparation. It exercises
// deterministic parsing/reduction only: these references are not host enrollment,
// plaintext-equivalence evidence, a class permit, or a live custody provider.
func historicalKeyTransition(t *testing.T, kind string) Decision {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	ref := map[string]any{"sequence": uint64(8), "digest": digest}
	roster := []any{map[string]any{
		"cluster_uid": "cluster", "membership_generation": uint64(3), "config_digest": digest,
		"host": "voter-a", "host_incarnation": uint64(17),
		"admitted_at": "2026-10-18T00:00:00Z", "admission_serial": "a1",
		"voter_incarnation": "voter-database-a", "recipient_epoch": "recipient-2",
		"key_id": "candidate-key-2", "recipient": key.Recipient().String(),
		"enrollment": ref, "recipient_ack": ref, "equality_ack": ref,
	}}
	body := map[string]any{
		"version": 1, "membership_generation": uint64(3), "config_digest": digest,
		"recipient_epoch": "recipient-2",
	}
	facts := map[string]any{"recipients": roster}
	c := Command{Kind: kind, ClusterUID: "cluster", PrincipalID: "protocol-principal", RequestID: kind + "-request"}
	if kind == "rewrap_payload" {
		body["admission_sequence"] = uint64(7)
		body["operation_id"] = "original-operation"
		body["payload_id"] = "original-payload"
		body["previous_wrapping"] = map[string]any{"sequence": uint64(7), "digest": digest}
		facts["original_history"] = map[string]any{"sequence": uint64(7), "digest": digest}
		facts["binding"] = map[string]any{
			"cluster_uid": "cluster", "project_uid": "project", "resource_uid": "resource",
			"operation_id": "original-operation", "payload_id": "original-payload", "admitted_generation": uint64(2),
		}
		facts["equality_epoch"] = "equality-original"
		facts["equality_tag"] = bytes.Repeat([]byte{0x31}, 32)
		facts["preparation"] = map[string]any{"purpose": "bootstrap-equivalence/v1", "source_wrapping": map[string]any{"sequence": uint64(7), "digest": digest}, "replacement_digest": CiphertextDigest([]byte("historical-certified-replacement-envelope"))}
		c.ProjectUID = "project"
		c.ResourceUID = "resource"
		// Opaque envelope bytes are deliberately not represented as verified
		// native-age plaintext. Pure historical parsing never opens them.
		c.Ciphertext = []byte("historical-certified-replacement-envelope")
		c.SecretKeyEpoch = "equality-original"
		c.SecretIntentTag = bytes.Repeat([]byte{0x31}, 32)
	} else {
		body["previous_activation"] = uint64(4)
		body["equality_epoch"] = "equality-2"
		body["prefix"] = map[string]any{"sequence": uint64(9), "digest": digest}
		facts["retained_inventory"] = []any{}
		facts["coverage"] = []any{}
	}
	assignment := map[string]any{
		"version": 1, "cluster_uid": "cluster", "operation_id": "transition-operation", "recorded_at": "2026-10-18T00:00:00Z",
		"key_transition": facts,
	}
	c.Body, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	a, err := json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	return Decision{Sequence: 10, ParentDigest: digest, Command: c, Assignment: a}
}

func TestAutomationKeyTransitionHistoricalSchemas(t *testing.T) {
	for _, kind := range []string{"rewrap_payload", "activate_key_epoch"} {
		t.Run(kind, func(t *testing.T) {
			d := historicalKeyTransition(t, kind)
			if err := ValidateSupportedDecision(d); err != nil {
				t.Fatalf("already-certified historical transition schema refused: %v", err)
			}
			encoded, err := EncodeDecision(d)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeDecision(encoded)
			if err != nil || !bytes.Equal(decoded.Assignment, d.Assignment) || !bytes.Equal(decoded.Command.Ciphertext, d.Command.Ciphertext) {
				t.Fatal("historical transition changed exact accepted bytes")
			}
		})
	}
}

func TestAutomationKeyTransitionStrictHistoricalFacts(t *testing.T) {
	for _, kind := range []string{"rewrap_payload", "activate_key_epoch"} {
		for _, mutation := range []struct {
			name   string
			change func(*Decision)
		}{
			{"body_unknown", func(d *Decision) {
				d.Command.Body = bytes.Replace(d.Command.Body, []byte(`"version":1`), []byte(`"version":1,"complete":true`), 1)
			}},
			{"body_case_alias", func(d *Decision) {
				d.Command.Body = bytes.Replace(d.Command.Body, []byte(`"recipient_epoch"`), []byte(`"Recipient_Epoch"`), 1)
			}},
			{"body_duplicate", func(d *Decision) {
				d.Command.Body = bytes.Replace(d.Command.Body, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			}},
			{"zero_host_lifetime", func(d *Decision) {
				d.Assignment = bytes.Replace(d.Assignment, []byte(`"host_incarnation":17`), []byte(`"host_incarnation":0`), 1)
			}},
			{"missing_admission_stamp", func(d *Decision) {
				d.Assignment = bytes.Replace(d.Assignment, []byte(`"admission_serial":"a1"`), []byte(`"admission_serial":""`), 1)
			}},
			{"roster_case_alias", func(d *Decision) {
				d.Assignment = bytes.Replace(d.Assignment, []byte(`"host_incarnation"`), []byte(`"Host_Incarnation"`), 1)
			}},
			{"caller_complete_assertion", func(d *Decision) {
				d.Assignment = bytes.Replace(d.Assignment, []byte(`"key_transition":{`), []byte(`"key_transition":{"complete":true,`), 1)
			}},
			{"recipient_epoch_mismatch", func(d *Decision) {
				d.Command.Body = bytes.Replace(d.Command.Body, []byte(`"recipient-2"`), []byte(`"different-epoch"`), 1)
			}},
		} {
			t.Run(kind+"/"+mutation.name, func(t *testing.T) {
				d := historicalKeyTransition(t, kind)
				mutation.change(&d)
				if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
					t.Fatalf("malformed historical facts must fail validation: %v", err)
				}
			})
		}
	}
}

func TestAutomationKeyTransitionRecognitionDoesNotAdmitFreshCommand(t *testing.T) {
	for _, kind := range []string{"rewrap_payload", "activate_key_epoch"} {
		d := historicalKeyTransition(t, kind)
		if err := ValidateSupportedCommand(d.Command); Code(err) != CodeUnsupported {
			t.Fatalf("historical recognition enabled fresh command without provider: %v", err)
		}
	}
}

func TestAutomationKeyTransitionMissingHistoricalProjectionRefuses(t *testing.T) {
	for _, kind := range []string{"rewrap_payload", "activate_key_epoch"} {
		d := historicalKeyTransition(t, kind)
		r, err := Reduce(Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 9, Digest: d.ParentDigest}}, d)
		if Code(err) != CodeUnavailable || !noBindingEffects(r) || r.OwnerEffect != nil {
			t.Fatalf("missing causal history must be unavailable without effects: %v", err)
		}
	}
}

func TestAutomationKeyTransitionHistoricalDuplicatePreservesReceipt(t *testing.T) {
	for _, kind := range []string{"rewrap_payload", "activate_key_epoch"} {
		d := historicalKeyTransition(t, kind)
		identity, err := CanonicalCommand(d.Command)
		if err != nil {
			t.Fatal(err)
		}
		receipt := Receipt{RequestID: d.Command.RequestID, OperationID: "original-transition", ResourceUID: "cluster", Sequence: 9, State: "succeeded"}
		p := Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 9, Digest: d.ParentDigest}, Existing: &Request{Identity: identity, Receipt: receipt}}
		r, err := Reduce(p, d)
		if err != nil || r.Receipt != receipt || r.SaveRequest || !noBindingEffects(r) || r.OwnerEffect != nil {
			t.Fatalf("duplicate transition did not return immutable receipt without effects: %v", err)
		}
		changed := d
		changed.Command.Body = bytes.Replace(d.Command.Body, []byte(`"recipient-2"`), []byte(`"different-epoch"`), 1)
		changed.Assignment = bytes.ReplaceAll(d.Assignment, []byte(`"recipient-2"`), []byte(`"different-epoch"`))
		r, err = Reduce(p, changed)
		if err != nil || r.Receipt.Code != CodeIdempotencyConflict || !noBindingEffects(r) || r.SaveRequest {
			t.Fatalf("changed transition retry did not reject without effects: %v", err)
		}
	}
}

// An already-certified history premise, as for the other semantic owners. No
// API here grants the missing current class/custody/enrollment authority.
func historicalWrappingFacts(t *testing.T) (Projection, Decision) {
	t.Helper()
	d := historicalKeyTransition(t, "rewrap_payload")
	a, err := DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	original := createBindingDecision()
	oa, err := DecodeAssignment(original)
	if err != nil {
		t.Fatal(err)
	}
	oa.OperationID = "original-operation"
	oa.Binding.PayloadID = "original-payload"
	oa.Binding.ResourceUID = "resource"
	oa.Binding.AdmittedGeneration = 2
	oa.Binding.RecipientEpoch = "recipient-1"
	original.Command.Ciphertext = []byte("original-certified-envelope")
	original.Command.SecretIntentTag = bytes.Repeat([]byte{0x31}, 32)
	original.Command.SecretKeyEpoch = "equality-original"
	original.Assignment, _ = json.Marshal(oa)
	f := &KeyTransitionProjection{References: []HistoricalReference{{Reference: HistoryReference{8, strings.Repeat("a", 64)}, ClusterUID: "cluster", MembershipGeneration: 3}}, MembershipGeneration: 3, ConfigDigest: strings.Repeat("a", 64), Members: []KeyMember{{"voter-a", "voter-database-a"}}, Epochs: []KeyEpochRecord{{ClusterUID: "cluster", RecipientEpoch: "recipient-1", EqualityEpoch: "equality-1", MembershipGeneration: 3, ConfigDigest: strings.Repeat("a", 64), ActivationSequence: 4}}, Admissions: []AdmissionRecord{{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource", OperationID: "original-operation", PayloadID: "original-payload", AdmittedGeneration: 2, Sequence: 7, Method: "admit_create"}}, History: []HistoricalDecision{keyHistoryTestSummary(t, original, a.KeyTransition.OriginalHistory.Digest)}}
	return Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 9, Digest: d.ParentDigest}, KeyTransition: f}, d
}
func TestAutomationKeyTransitionRewrapPreservesOriginal(t *testing.T) {
	p, d := historicalWrappingFacts(t)
	before, _ := json.Marshal(p)
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.WrappingEffect == nil || r.EpochEffect != nil || len(r.RecipientEffects) != 1 || !noBindingEffects(r) {
		t.Fatalf("certified rewrap did not append only replacement pointer: %v", err)
	}
	w := r.WrappingEffect
	if w.OperationID != "original-operation" || w.PayloadID != "original-payload" || w.AdmissionSequence != 7 || w.WrappingSequence != 10 || w.RecipientEpoch != "recipient-2" || w.WrappingDigest != "" {
		t.Fatal("rewrap altered original identities or invented enclosing digest")
	}
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatal("pure reducer mutated original history")
	}
}
func TestAutomationKeyTransitionRewrapCausalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Projection, *Decision)
	}{
		{"missing_original", func(p *Projection, d *Decision) { p.KeyTransition.Admissions = nil }},
		{"legacy_resource", func(p *Projection, d *Decision) { p.KeyTransition.Admissions[0].Method = "adopt_resource" }},
		{"changed_admitted_generation", func(p *Projection, d *Decision) { p.KeyTransition.Admissions[0].AdmittedGeneration++ }},
		{"changed_original_equality", func(p *Projection, d *Decision) { p.KeyTransition.History[0].EqualityEpoch = "wrong" }},
		{"missing_original_epoch", func(p *Projection, d *Decision) {
			p.KeyTransition.History[0].RecipientEpoch = ""
		}},
		{"changed_config", func(p *Projection, d *Decision) { p.KeyTransition.ConfigDigest = strings.Repeat("b", 64) }},
		{"changed_voter", func(p *Projection, d *Decision) { p.KeyTransition.Members[0].VoterIncarnation = "other-database" }},
		{"stale_predecessor", func(p *Projection, d *Decision) {
			p.KeyTransition.Wrappings = []PayloadWrappingRecord{{ClusterUID: "cluster", OperationID: "original-operation", PayloadID: "original-payload", AdmissionSequence: 7, WrappingSequence: 8, WrappingDigest: strings.Repeat("b", 64), RecipientEpoch: "intermediate"}}
		}},
		{"future_predecessor", func(p *Projection, d *Decision) {
			p.KeyTransition.Wrappings = []PayloadWrappingRecord{{OperationID: "original-operation", PayloadID: "original-payload", AdmissionSequence: 7, WrappingSequence: 11}}
		}},
		{"reused_recipient", func(p *Projection, d *Decision) {
			a, _ := DecodeAssignment(*d)
			r := a.KeyTransition.Recipients[0]
			r.RecipientEpoch = "old"
			p.KeyTransition.Recipients = []KeyRecipientRecord{{Binding: r, FirstSequence: 4}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, d := historicalWrappingFacts(t)
			tc.edit(&p, &d)
			r, e := Reduce(p, d)
			if e == nil && r.Receipt.Code == "" {
				t.Fatal("invalid causal rewrap succeeded")
			}
			if r.WrappingEffect != nil || r.EpochEffect != nil || len(r.RecipientEffects) > 0 {
				t.Fatal("refused rewrap mutated derived state")
			}
		})
	}
}
func historicalActivationFacts(t *testing.T) (Projection, Decision) {
	t.Helper()
	d := historicalKeyTransition(t, "activate_key_epoch")
	a, e := DecodeAssignment(d)
	if e != nil {
		t.Fatal(e)
	}
	b, e := DecodeActivateKeyEpochBody(d.Command)
	if e != nil {
		t.Fatal(e)
	}
	b.PreviousActivation = 0
	d.Command.Body, _ = json.Marshal(b)
	a.KeyTransition.Class = "bootstrap"
	a.KeyTransition.Bootstrap = &HistoryReference{Sequence: 1, Digest: strings.Repeat("b", 64)}
	d.Assignment, _ = json.Marshal(a)
	genesis := Decision{Sequence: 1, Command: Command{Kind: "initialize_cluster", PrincipalID: d.Command.PrincipalID, RequestID: "init", Body: []byte(`{"version":1}`)}, Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"init-operation","recorded_at":"2026-10-18T00:00:00Z"}`)}
	return Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 9, Digest: d.ParentDigest}, KeyTransition: &KeyTransitionProjection{References: []HistoricalReference{{Reference: HistoryReference{8, strings.Repeat("a", 64)}, ClusterUID: "cluster", MembershipGeneration: 3}}, MembershipGeneration: 3, ConfigDigest: strings.Repeat("a", 64), Members: []KeyMember{{"voter-a", "voter-database-a"}}, History: []HistoricalDecision{keyHistoryTestSummary(t, genesis, strings.Repeat("b", 64))}}}, d
}
func TestAutomationKeyTransitionInitialActivationRequiresBootstrapAndEmptyInventory(t *testing.T) {
	p, d := historicalActivationFacts(t)
	r, e := Reduce(p, d)
	if e != nil || r.Receipt.Code != "" || r.EpochEffect == nil || r.EpochEffect.PredecessorActivationSequence != 0 || r.EpochEffect.ActivationSequence != 10 || r.EpochEffect.EqualityEpoch != "equality-2" || r.EpochEffect.RecipientEpoch != "recipient-2" {
		t.Fatalf("explicit historical bootstrap activation failed: %v", e)
	}
	for _, tc := range []struct {
		name string
		edit func(*Projection, *Decision)
	}{
		{"ordinary_protocol", func(p *Projection, d *Decision) {
			a, _ := DecodeAssignment(*d)
			a.KeyTransition.Class = "protocol"
			d.Assignment, _ = json.Marshal(a)
		}},
		{"missing_bootstrap", func(p *Projection, d *Decision) { p.KeyTransition.History = nil }},
		{"wrong_bootstrap_principal", func(p *Projection, d *Decision) { p.KeyTransition.History[0].PrincipalID = "other" }},
		{"nonempty_retained", func(p *Projection, d *Decision) {
			p.KeyTransition.Admissions = []AdmissionRecord{{Method: "admit_create", PayloadID: "retained", OperationID: "old", Sequence: 7}}
		}},
		{"changed_prefix", func(p *Projection, d *Decision) { p.Head.Digest = strings.Repeat("c", 64) }},
		{"future_active_epoch", func(p *Projection, d *Decision) {
			p.KeyTransition.Epochs = []KeyEpochRecord{{ActivationSequence: 11, RecipientEpoch: "future", EqualityEpoch: "future-equality"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, d := historicalActivationFacts(t)
			tc.edit(&p, &d)
			r, e := Reduce(p, d)
			if e == nil && r.Receipt.Code == "" {
				t.Fatal("invalid initial activation succeeded")
			}
			if r.EpochEffect != nil || len(r.RecipientEffects) > 0 {
				t.Fatal("refusal emitted epoch effects")
			}
		})
	}
}
func TestAutomationKeyTransitionLaterActivationRequiresExactPendingCoverage(t *testing.T) {
	p, wrap := historicalWrappingFacts(t)
	wr, e := Reduce(p, wrap)
	if e != nil || wr.WrappingEffect == nil {
		t.Fatal(e)
	}
	w := *wr.WrappingEffect
	w.WrappingDigest = strings.Repeat("c", 64)
	p.KeyTransition.Wrappings = []PayloadWrappingRecord{w}
	p.KeyTransition.Recipients = wr.RecipientEffects
	p.Head.Sequence = 10
	p.Head.Digest = w.WrappingDigest
	d := historicalKeyTransition(t, "activate_key_epoch")
	d.Sequence = 11
	d.ParentDigest = p.Head.Digest
	b, _ := DecodeActivateKeyEpochBody(d.Command)
	b.Prefix = HistoryReference{10, p.Head.Digest}
	d.Command.Body, _ = json.Marshal(b)
	a, _ := DecodeAssignment(d)
	wa, _ := DecodeAssignment(wrap)
	a.KeyTransition.Recipients = wa.KeyTransition.Recipients
	a.KeyTransition.Class = "protocol"
	a.KeyTransition.RetainedInventory = []RetainedPayload{{"original-operation", "original-payload", HistoryReference{7, strings.Repeat("a", 64)}}}
	a.KeyTransition.Coverage = []PayloadCoverage{{"original-operation", HistoryReference{10, w.WrappingDigest}}}
	d.Assignment, _ = json.Marshal(a)
	r, e := Reduce(p, d)
	if e != nil || r.Receipt.Code != "" || r.EpochEffect == nil || len(r.RecipientEffects) != 0 {
		t.Fatalf("certified coverage did not activate exact epoch: %v", e)
	}
	a.KeyTransition.Coverage[0].Wrapping.Digest = strings.Repeat("d", 64)
	d.Assignment, _ = json.Marshal(a)
	r, e = Reduce(p, d)
	if e != nil || r.Receipt.Code != CodeRevisionConflict || r.EpochEffect != nil {
		t.Fatalf("changed coverage was not rejected without activation: %v", e)
	}
}

func TestAutomationKeyTransitionEqualityFactRequiresCanonicalByteString(t *testing.T) {
	d := historicalKeyTransition(t, "rewrap_payload")
	var a map[string]json.RawMessage
	if err := json.Unmarshal(d.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	var facts map[string]json.RawMessage
	if err := json.Unmarshal(a["key_transition"], &facts); err != nil {
		t.Fatal(err)
	}
	facts["equality_tag"] = []byte("[" + strings.TrimSuffix(strings.Repeat("49,", 32), ",") + "]")
	a["key_transition"], _ = json.Marshal(facts)
	d.Assignment, _ = json.Marshal(a)
	if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
		t.Fatal("alternate byte array accepted in certified facts", err)
	}
}

func TestAutomationKeyTransitionLaterEmptyRotationKeepsElectorate(t *testing.T) {
	p, d := historicalActivationFacts(t)
	a, _ := DecodeAssignment(d)
	a.KeyTransition.Class = "protocol"
	a.KeyTransition.Bootstrap = nil
	d.Assignment, _ = json.Marshal(a)
	b, _ := DecodeActivateKeyEpochBody(d.Command)
	b.PreviousActivation = 4
	d.Command.Body, _ = json.Marshal(b)
	p.KeyTransition.Epochs = []KeyEpochRecord{{ClusterUID: "cluster", RecipientEpoch: "recipient-old", EqualityEpoch: "equality-old", MembershipGeneration: 2, ConfigDigest: strings.Repeat("c", 64), ActivationSequence: 4}}
	r, e := Reduce(p, d)
	if e == nil && r.Receipt.Code == "" {
		t.Fatal("empty rotation crossed certified electorate without successor adoption")
	}
	if r.EpochEffect != nil || len(r.RecipientEffects) != 0 {
		t.Fatal("changed electorate emitted effects")
	}
}
func TestAutomationKeyTransitionRecipientEvidenceCannotUseFuturePrefix(t *testing.T) {
	for _, field := range []string{"enrollment", "recipient_ack", "equality_ack"} {
		t.Run(field, func(t *testing.T) {
			p, d := historicalActivationFacts(t)
			a, _ := DecodeAssignment(d)
			r := &a.KeyTransition.Recipients[0]
			switch field {
			case "enrollment":
				r.Enrollment.Sequence = 10
			case "recipient_ack":
				r.RecipientAck.Sequence = 10
			case "equality_ack":
				r.EqualityAck.Sequence = 10
			}
			d.Assignment, _ = json.Marshal(a)
			reduced, e := Reduce(p, d)
			if e == nil && reduced.Receipt.Code == "" {
				t.Fatal("recipient evidence used uncertified future prefix")
			}
			if reduced.EpochEffect != nil || len(reduced.RecipientEffects) != 0 {
				t.Fatal("future recipient evidence emitted effects")
			}
		})
	}
}

func TestAutomationKeyTransitionRecipientReferenceMustResolveDigest(t *testing.T) {
	p, d := historicalActivationFacts(t)
	a, _ := DecodeAssignment(d)
	a.KeyTransition.Recipients[0].Enrollment = HistoryReference{Sequence: 1, Digest: strings.Repeat("f", 64)}
	d.Assignment, _ = json.Marshal(a)
	r, e := Reduce(p, d)
	if e == nil && r.Receipt.Code == "" {
		t.Fatal("recipient acknowledgement digest was not resolved against actual history")
	}
}
func TestAutomationKeyTransitionRetainedCapacity1024(t *testing.T) {
	d := historicalKeyTransition(t, "activate_key_epoch")
	a, _ := DecodeAssignment(d)
	for i := 0; i < 1024; i++ {
		op := fmt.Sprintf("operation-%d", i)
		a.KeyTransition.RetainedInventory = append(a.KeyTransition.RetainedInventory, RetainedPayload{OperationID: op, PayloadID: fmt.Sprintf("payload-%d", i), Admission: HistoryReference{7, strings.Repeat("a", 64)}})
		a.KeyTransition.Coverage = append(a.KeyTransition.Coverage, PayloadCoverage{OperationID: op, Wrapping: HistoryReference{8, strings.Repeat("b", 64)}})
	}
	d.Assignment, _ = json.Marshal(a)
	if len(d.Assignment) > 1<<20 {
		t.Fatal("fixture exceeds native assignment cap")
	}
	if _, e := EncodeDecision(d); e != nil {
		t.Fatal("fixture exceeds native complete envelope cap", e)
	}
	if e := ValidateSupportedDecision(d); e != nil {
		t.Fatal("1024 retained entries within native envelope bounds refused", e)
	}
	a.KeyTransition.RetainedInventory = append(a.KeyTransition.RetainedInventory, RetainedPayload{OperationID: "overflow", PayloadID: "overflow", Admission: HistoryReference{7, strings.Repeat("a", 64)}})
	d.Assignment, _ = json.Marshal(a)
	if e := ValidateSupportedDecision(d); Code(e) != CodeValidation {
		t.Fatal("retained inventory overflow accepted", e)
	}
}

func keyHistoryTestSummary(t *testing.T, d Decision, digest string) HistoricalDecision {
	t.Helper()
	h, e := SummarizeKeyHistory(d, digest, 3)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
