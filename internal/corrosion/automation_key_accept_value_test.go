package corrosion

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"reflect"
	"strings"
	"testing"
)

func invocationHistoricalCustodyImport(t *testing.T) contract.Decision {
	t.Helper()
	digest := strings.Repeat("a", 64)
	source := map[string]any{"host": "a", "host_incarnation": 0, "admitted_at": "2026-10-24T00:00:00Z", "admission_serial": "a1", "voter_incarnation": "db-a"}
	genesis := map[string]any{"sequence": 1, "digest": digest}
	var members []any
	for _, host := range []string{"a", "b", "c"} {
		key, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		target := map[string]any{"host": host, "host_incarnation": 0, "admitted_at": "2026-10-24T00:00:00Z", "admission_serial": "a1", "voter_incarnation": "db-" + host}
		candidate := map[string]any{"cluster_uid": "cluster", "attempt": "attempt", "membership_generation": 3, "config_digest": digest, "recipient_epoch": "recipients", "equality_epoch": "equality", "expires_at": "2026-10-24T00:01:30Z", "genesis": genesis, "source": source, "target": target, "voter_key_id": "voter-" + host, "source_equality_key_id": "equality-a", "equality_key_id": "equality-" + host}
		recipient := map[string]any{"version": 1, "purpose": "automation-custody-recipient", "candidate": candidate, "recipient": key.Recipient().String(), "recorded_at": "2026-10-24T00:01:00Z", "chain": [][]byte{[]byte("inert-chain")}, "trust": []byte("inert-trust"), "signature": []byte("inert-signature")}
		// The declared transcript digest is an inert structural field in this test;
		// cryptographic transcript verification belongs to the native evidence owner.
		completion := map[string]any{"version": 1, "purpose": "automation-custody-import-completion", "candidate": candidate, "recipient": key.Recipient().String(), "recipient_digest": digest, "capsule_digest": digest, "recorded_at": "2026-10-24T00:01:01Z", "chain": [][]byte{[]byte("inert-chain")}, "trust": []byte("inert-trust"), "signature": []byte("inert-signature")}
		members = append(members, map[string]any{"recipient": recipient, "completion": completion})
	}
	body := map[string]any{"version": 1, "attempt": "attempt", "membership_generation": 3, "config_digest": digest, "recipient_epoch": "recipients", "equality_epoch": "equality", "genesis": genesis}
	record := map[string]any{"version": 1, "cluster_uid": "cluster", "attempt": "attempt", "membership_generation": 3, "config_digest": digest, "recipient_epoch": "recipients", "equality_epoch": "equality", "genesis": genesis, "expires_at": "2026-10-24T00:01:30Z", "members": members}
	assignment := map[string]any{"version": 4, "cluster_uid": "cluster", "operation_id": "import-op", "recorded_at": "2026-10-24T00:01:02Z", "custody_import": record}
	b, _ := json.Marshal(body)
	a, _ := json.Marshal(assignment)
	return contract.Decision{Sequence: 2, ParentDigest: digest, Command: contract.Command{Kind: "record_custody_import", ClusterUID: "cluster", PrincipalID: "genesis-principal", RequestID: "import-request", Body: b}, Assignment: a}
}

func invocationHistoricalKeyTransition(t *testing.T, kind string) contract.Decision {
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
	c := contract.Command{Kind: kind, ClusterUID: "cluster", PrincipalID: "protocol-principal", RequestID: kind + "-request"}
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
		facts["preparation"] = map[string]any{"purpose": "bootstrap-equivalence/v1", "source_wrapping": map[string]any{"sequence": uint64(7), "digest": digest}, "replacement_digest": contract.CiphertextDigest([]byte("historical-certified-replacement-envelope"))}
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
	return contract.Decision{Sequence: 10, ParentDigest: digest, Command: c, Assignment: a}
}

// Inert structural inputs only; no native authority is manufactured here.
func invocationValues(t *testing.T) []ClaimValue {
	imported := invocationHistoricalCustodyImport(t)
	activation := invocationHistoricalKeyTransition(t, "activate_key_epoch")
	var a contract.Assignment
	if err := json.Unmarshal(activation.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	a.Version = 4
	a.KeyTransition.Class = "bootstrap"
	a.KeyTransition.Bootstrap = &contract.HistoryReference{Sequence: 1, Digest: strings.Repeat("a", 64)}
	var body contract.ActivateKeyEpochBody
	if err := json.Unmarshal(activation.Command.Body, &body); err != nil {
		t.Fatal(err)
	}
	body.PreviousActivation = 0
	activation.Command.Body, _ = json.Marshal(body)
	activation.Assignment, _ = json.Marshal(a)
	var out []ClaimValue
	for _, d := range []contract.Decision{imported, activation} {
		raw, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ClaimValue{Automation: &AutomationClaimValue{Envelope: raw}})
	}
	return out
}
func invocationVariants(t *testing.T, original ClaimValue) map[string]ClaimValue {
	t.Helper()
	raw := original.Automation.Envelope
	variants := map[string]ClaimValue{"valid": original, "nil": {}, "null-envelope": {Automation: &AutomationClaimValue{}}, "source-host": {Automation: original.Automation, SourceHost: "a"}, "mixture-config": {Automation: original.Automation, Config: &VoterConfigValue{}}, "mixture-lease": {Automation: original.Automation, LeaseTerm: &LeaseTermValue{}}}
	for name, b := range map[string][]byte{
		"empty": {}, "null": []byte("null"), "array": []byte("[]"), "trailing": append(bytes.Clone(raw), 'x'), "outer-unknown": append([]byte(`{"Unknown":0,`), raw[1:]...), "outer-duplicate": append([]byte(`{"Version":1,`), raw[1:]...), "outer-version": bytes.Replace(raw, []byte(`"Version":1`), []byte(`"Version":2`), 1), "wire-bound": bytes.Repeat([]byte{'x'}, contract.MaxDecisionBytes+1),
	} {
		variants[name] = ClaimValue{Automation: &AutomationClaimValue{Envelope: b}}
	}
	d, err := invocation11bDecision(original)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"assignment-null": []byte("null"), "assignment-unknown": append([]byte(`{"unknown":1,`), d.Assignment[1:]...), "assignment-duplicate": append([]byte(`{"version":4,`), d.Assignment[1:]...), "assignment-whitespace": append([]byte(" "), d.Assignment...), "assignment-version": bytes.Replace(d.Assignment, []byte(`"version":4`), []byte(`"version":3`), 1), "assignment-nonutf8": bytes.Replace(d.Assignment, []byte(`"cluster"`), []byte{'"', 255, '"'}, 1), "assignment-deep": []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)), "assignment-bound": bytes.Repeat([]byte{'x'}, (1<<20)+1),
	} {
		changed := d
		changed.Assignment = b
		encoded, _ := json.Marshal(struct {
			Version  uint32
			Decision contract.Decision
		}{1, changed})
		variants[name] = ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	}
	for _, kind := range []string{"read_barrier", "ensure_owner", "identity_continuity", "rewrap_payload", "unknown"} {
		changed := d
		changed.Command.Kind = kind
		encoded, _ := json.Marshal(struct {
			Version  uint32
			Decision contract.Decision
		}{1, changed})
		variants["kind-"+kind] = ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	}
	variants["mixture-empty-proof"] = ClaimValue{Automation: original.Automation, Proof: &ActionProof{}}
	variants["mixture-lun"] = ClaimValue{Automation: original.Automation, LUN: &LUNAllocation{}}
	if d.Command.Kind == contract.CustodyImportCommand {
		for name, b := range map[string][]byte{
			"nested-duplicate": bytes.Replace(d.Assignment, []byte(`"candidate":{`), []byte(`"candidate":{"attempt":"attempt",`), 1),
			"nested-unknown":   bytes.Replace(d.Assignment, []byte(`"candidate":{`), []byte(`"candidate":{"unknown":true,`), 1),
			"nested-null":      bytes.Replace(d.Assignment, []byte(`"host":"a"`), []byte(`"host":null`), 1),
			"base64-newline":   bytes.Replace(d.Assignment, []byte(`aW5lcnQtc2lnbmF0dXJl`), []byte(`aW5lcnQtc2ln\nbmF0dXJl`), 1),
			"base64-invalid":   bytes.Replace(d.Assignment, []byte(`aW5lcnQtc2lnbmF0dXJl`), []byte(`!W5lcnQtc2lnbmF0dXJl`), 1),
		} {
			if bytes.Equal(b, d.Assignment) {
				t.Fatal("mutation did not change fixture", name)
			}
			changed := d
			changed.Assignment = b
			encoded, _ := json.Marshal(struct {
				Version  uint32
				Decision contract.Decision
			}{1, changed})
			variants[name] = ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
		}
	}
	// Valid legacy values must retain their original path, not just malformed
	// cross-kind refusals. They never acquire a custody incoming summary.
	_, legacy := automationFixture(t, 2, strings.Repeat("a", 64))
	variants["valid-legacy-barrier"] = legacy
	for _, kind := range []string{"activate_key_epoch", "rewrap_payload"} {
		d := invocationHistoricalKeyTransition(t, kind)
		b, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		variants["valid-legacy-"+kind] = ClaimValue{Automation: &AutomationClaimValue{Envelope: b}}
	}
	return variants
}
func TestAutomationKeyAcceptValueFrozenCharacterization(t *testing.T) {
	for i, v := range invocationValues(t) {
		for name, v := range invocationVariants(t, v) {
			t.Run(fmt.Sprintf("%d/%s", i, name), func(t *testing.T) {
				want, we := invocation11bDecision(v)
				got, ge := automationDecision(v)
				if fmt.Sprint(ge) != fmt.Sprint(we) || ge == nil && !reflect.DeepEqual(got, want) {
					t.Fatal("decision differs from frozen 11b", ge, we)
				}
				if isAutomationNativeKeyValue(v) != invocation11bKeyClass(v) {
					t.Fatal("class differs")
				}
				if v.Automation != nil {
					gd, ge := v.Digest()
					wd, we := invocation11bDigest(v)
					if gd != wd || fmt.Sprint(ge) != fmt.Sprint(we) {
						t.Fatal("digest differs", ge, we)
					}
				}
			})
		}
	}
}

// These fail if incoming preparation retains the caller's envelope or if a
// later call borrows a previous call's validated digest/decision.
func TestAutomationKeyAcceptValueOwnedInvocation(t *testing.T) {
	for i, v := range invocationValues(t) {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			original := bytes.Clone(v.Automation.Envelope)
			owned := prepareKeyAcceptValue(v)
			if owned == nil {
				t.Fatal("valid custody value not prepared")
			}
			digest, err := invocation11bDigest(v)
			if err != nil {
				t.Fatal(err)
			}
			v.Automation.Envelope[0] = '!'
			if !bytes.Equal(owned.value.Automation.Envelope, original) {
				t.Fatal("incoming snapshot aliases caller envelope")
			}
			if owned.digest != digest {
				t.Fatal("owned digest changed")
			}
			if _, err := invocation11bDecision(owned.value); err != nil {
				t.Fatal("owned value no longer canonical", err)
			}
			if prepareKeyAcceptValue(v) != nil {
				t.Fatal("new invocation reused prior validation for mutated input")
			}
		})
	}
}
func TestAutomationKeyAcceptValueInvocationDifferential(t *testing.T) {
	for i, v := range invocationValues(t) {
		for name, v := range invocationVariants(t, v) {
			t.Run(fmt.Sprintf("%d/%s", i, name), func(t *testing.T) {
				owned := prepareKeyAcceptValue(v)
				d, err := invocation11bDecision(v)
				valid := err == nil && invocation11bKeyClass(v) && contract.ValidateSupportedDecision(d) == nil
				if (owned != nil) != valid {
					t.Fatalf("preparation differs from strict original: got=%t want=%t", owned != nil, valid)
				}
				if !valid {
					return
				}
				digest, err := invocation11bDigest(v)
				if err != nil {
					t.Fatal(err)
				}
				if owned.digest != digest || !reflect.DeepEqual(owned.decision, d) || !bytes.Equal(owned.value.Automation.Envelope, v.Automation.Envelope) {
					t.Fatal("prepared exact value differs")
				}
			})
		}
	}
}
func TestAutomationKeyAcceptValueFreshCalls(t *testing.T) {
	values := invocationValues(t)
	first := prepareKeyAcceptValue(values[0])
	second := prepareKeyAcceptValue(values[1])
	again := prepareKeyAcceptValue(values[0])
	if first == nil || second == nil || again == nil {
		t.Fatal("missing preparation")
	}
	if first == again || first == second || first.digest == second.digest || again.digest != first.digest {
		t.Fatal("incoming summary reused across invocations")
	}
	first.value.Automation.Envelope[0] = '!'
	if _, err := invocation11bDecision(again.value); err != nil {
		t.Fatal("separate invocations share envelope", err)
	}
}
