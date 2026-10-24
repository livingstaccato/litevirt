package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func laterCiphertextDecision(kind string) Decision {
	d := ciphertextDecision()
	d.Sequence = 2
	d.ParentDigest = strings.Repeat("a", 64)
	d.Command.ClusterUID = "cluster"
	d.Command.Kind = kind
	return d
}

// Explicit expected codes prevent an invalid positive seed from passing merely
// because both implementations reject it at the same earlier check.
func checkDecisionEncoding(t *testing.T, d Decision, wantCode string) {
	t.Helper()
	old, oldErr := legacyEncodeDecision(d)
	got, err := EncodeDecision(d)
	for name, e := range map[string]error{"legacy": oldErr, "current": err} {
		if wantCode == "" {
			if e != nil {
				t.Fatalf("%s positive encoder refused fixture: %v", name, e)
			}
		} else if e == nil || Code(e) != wantCode || e.Error() != "automation: "+wantCode {
			t.Fatalf("%s encoder: want %q, got %v", name, wantCode, e)
		}
	}
	if !bytes.Equal(old, got) || fmt.Sprint(oldErr) != fmt.Sprint(err) {
		t.Fatal("encoder differs from frozen oracle")
	}
	raw := rawDecision(t, d)
	compareDecisionOracle(t, raw)
	decoded, decodeErr := DecodeDecision(raw)
	if wantCode != "" {
		if old != nil || got != nil {
			t.Fatal("failed encoder published bytes")
		}
		if decodeErr == nil || Code(decodeErr) != CodeValidation || decodeErr.Error() != "automation: validation" || !reflect.DeepEqual(decoded, Decision{}) {
			t.Fatal("invalid decision did not preserve decode error/zero output", decodeErr)
		}
		return
	}
	if decodeErr != nil || !reflect.DeepEqual(decoded, d) || !bytes.Equal(got, raw) {
		t.Fatal("positive decision lost exact fields or bytes", decodeErr)
	}
	fast, ok := decodeDecisionCiphertext(raw)
	if len(d.Command.Ciphertext) > 0 {
		if !ok || !reflect.DeepEqual(fast, d) {
			t.Fatal("canonical positive did not take exact fast path")
		}
	} else if ok || !reflect.DeepEqual(fast, Decision{}) {
		t.Fatal("nil/empty ciphertext did not fall back with zero output")
	}
}

func TestDecisionCiphertextCanonicalPositives(t *testing.T) {
	// Literal whitelist matrix, independent of the production switch. These are
	// generic codec positives; per-kind typed reducer validation stays separate.
	for _, kind := range []string{"initialize_cluster", "assign_identity", "ensure_owner", "acquire_session", "handoff_session", "adopt_resource", "transfer_owner", "admit_create", "admit_update", "admit_delete", "claim_executor", "record_progress", "complete_operation", "retire_artifact", "rewrap_payload", "activate_key_epoch", "read_barrier"} {
		t.Run("kind/"+kind, func(t *testing.T) {
			d := laterCiphertextDecision(kind)
			if kind == "initialize_cluster" {
				d = ciphertextDecision()
			}
			if kind == "admit_update" {
				// The frozen codec recognized the vocabulary before there
				// was an update handler. Keep that old positive assertion;
				// its generic v1 seed is invalid in the new strict v3 domain.
				legacy, err := legacyEncodeDecision(d)
				if err != nil || !bytes.Equal(legacy, rawDecision(t, d)) {
					t.Fatal("frozen v1 update vocabulary bytes changed", err)
				}
				if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
					t.Fatal("generic v1 seed became valid update authority", err)
				}
				if raw, err := EncodeDecision(d); Code(err) != CodeValidation || raw != nil {
					t.Fatal("invalid update seed published bytes", err)
				}
				if decoded, err := DecodeDecision(legacy); Code(err) != CodeValidation || !reflect.DeepEqual(decoded, Decision{}) {
					t.Fatal("invalid update seed lost refusal/zero output", err)
				}
				_, valid := updateContractFixture(t)
				if err := ValidateSupportedDecision(valid); err != nil {
					t.Fatal("actual update3 positive invalid", err)
				}
				raw, err := EncodeDecision(valid)
				if err != nil {
					t.Fatal("actual update3 positive could not encode", err)
				}
				if decoded, err := DecodeDecision(raw); err != nil || !reflect.DeepEqual(decoded, valid) {
					t.Fatal("actual update3 positive lost exact round trip", err)
				}
				return
			}
			checkDecisionEncoding(t, d, "")
		})
	}
	// Every byte field has independent nil, allocated-empty and nonempty positive
	// cases. Tag nonemptiness is paired with its equality epoch, as required.
	for _, field := range []string{"Body", "Assignment", "Ciphertext", "SecretIntentTag"} {
		for _, state := range []string{"nil", "empty", "nonempty"} {
			t.Run("bytes/"+field+"/"+state, func(t *testing.T) {
				var value []byte
				if state == "empty" {
					value = []byte{}
				} else if state == "nonempty" {
					value = []byte{0, 255, 128, 1}
					if field == "Body" || field == "Assignment" {
						value = []byte("{\n \"version\":1.0,\"x\":10e-1}")
					}
				}
				d := laterCiphertextDecision("read_barrier")
				switch field {
				case "Body":
					d.Command.Body = value
				case "Assignment":
					d.Assignment = value
				case "Ciphertext":
					d.Command.Ciphertext = value
				case "SecretIntentTag":
					d.Command.SecretIntentTag = value
					if len(value) > 0 {
						d.Command.SecretKeyEpoch = "epoch"
					}
				}
				checkDecisionEncoding(t, d, "")
			})
		}
	}
	for n := 1; n <= 6; n++ {
		t.Run(fmt.Sprintf("ciphertext-length/%d", n), func(t *testing.T) {
			d := laterCiphertextDecision("read_barrier")
			d.Command.Ciphertext = []byte{0, 255, 128, 1, 254, 127}[:n]
			checkDecisionEncoding(t, d, "")
		})
	}
	t.Run("ciphertext-all-byte-values", func(t *testing.T) {
		d := laterCiphertextDecision("read_barrier")
		d.Command.Ciphertext = make([]byte, 256)
		for i := range d.Command.Ciphertext {
			d.Command.Ciphertext[i] = byte(i)
		}
		checkDecisionEncoding(t, d, "")
	})
	for _, session := range []string{"", "authority-session"} {
		t.Run("session/"+fmt.Sprint(session != ""), func(t *testing.T) {
			d := laterCiphertextDecision("read_barrier")
			d.Command.SessionID = session
			d.Command.Session = 17
			checkDecisionEncoding(t, d, "")
		})
	}
}

func TestDecisionCiphertextEncoderErrorOrder(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*Decision)
	}{
		{"unsupported", CodeUnsupported, func(*Decision) {}},
		{"sequence-before-kind", CodeValidation, func(d *Decision) { d.Sequence = 0 }},
		{"parent-before-kind", CodeValidation, func(d *Decision) { d.ParentDigest = "bad" }},
		{"string-bound-before-kind", CodeValidation, func(d *Decision) { d.Command.ProjectUID = strings.Repeat("x", MaxStringBytes+1) }},
		{"tag-bound-before-kind", CodeValidation, func(d *Decision) { d.Command.SecretIntentTag = make([]byte, 257) }},
		{"kind-before-request", CodeUnsupported, func(d *Decision) { d.Command.RequestID = "" }},
		{"kind-before-tag-pair", CodeUnsupported, func(d *Decision) { d.Command.SecretKeyEpoch = "epoch" }},
		{"kind-before-body", CodeUnsupported, func(d *Decision) { d.Command.Body = []byte(`invalid`) }},
		{"kind-before-assignment", CodeUnsupported, func(d *Decision) { d.Assignment = []byte(`invalid`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := laterCiphertextDecision("unsupported")
			tc.change(&d)
			checkDecisionEncoding(t, d, tc.code)
		})
	}
}

func TestDecisionCiphertextNativeRewrapPositive(t *testing.T) {
	// Reuse the actual historical rewrap fixture's recipient/reference/binding
	// Body and Assignment; replace only its opaque payload and matching digest.
	d := historicalKeyTransition(t, "rewrap_payload")
	assignment, err := DecodeAssignment(d)
	if err != nil {
		t.Fatal("original typed rewrap fixture", err)
	}
	d.Command.Ciphertext = bytes.Repeat([]byte{0, 255, 128, 1}, 1<<18)
	assignment.KeyTransition.Preparation.ReplacementDigest = CiphertextDigest(d.Command.Ciphertext)
	d.Assignment, err = json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateSupportedDecision(d); err != nil {
		t.Fatal("native typed rewrap fixture", err)
	}
	checkDecisionEncoding(t, d, "")
}
