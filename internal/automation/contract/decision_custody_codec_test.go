package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Catch a fast decoder that repairs or widens the certified byte domain, skips
// semantic checks, or reuses validation after the caller mutates a Decision.
func custodyCodecFixtures(t *testing.T) []Decision {
	t.Helper()
	imported := historicalCustodyImport(t)
	var a Assignment
	if err := json.Unmarshal(imported.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	imported.Assignment, _ = json.Marshal(a)
	activation := historicalKeyTransition(t, "activate_key_epoch")
	// Decode into a fresh object: the preceding import must not survive an
	// omitted field in this fixture, just as no validated state may be cached.
	a = Assignment{}
	if err := json.Unmarshal(activation.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	a.Version = 4
	a.KeyTransition.Class = "bootstrap"
	a.KeyTransition.Bootstrap = &HistoryReference{Sequence: 1, Digest: strings.Repeat("a", 64)}
	var b ActivateKeyEpochBody
	if err := json.Unmarshal(activation.Command.Body, &b); err != nil {
		t.Fatal(err)
	}
	b.PreviousActivation = 0
	activation.Command.Body, _ = json.Marshal(b)
	activation.Assignment, _ = json.Marshal(a)
	return []Decision{imported, activation}
}

func checkCustodyCodecOracle(t *testing.T, d Decision) {
	t.Helper()
	wantA, wantErr := ec941DecodeAssignment(d)
	gotA, gotErr := DecodeAssignment(d)
	if Code(gotErr) != Code(wantErr) || gotErr == nil && !reflect.DeepEqual(gotA, wantA) {
		t.Fatalf("assignment differs from frozen codec: got=%v want=%v", gotErr, wantErr)
	}
	if got, want := Code(ValidateSupportedDecision(d)), Code(ec941ValidateSupportedDecision(d)); got != want {
		t.Fatalf("supported semantic result differs: got=%q want=%q", got, want)
	}
	want, wantErr := ec941EncodeDecision(d)
	got, gotErr := EncodeDecision(d)
	if Code(gotErr) != Code(wantErr) || !bytes.Equal(got, want) {
		t.Fatalf("encoding differs: got=%v want=%v", gotErr, wantErr)
	}
	// Construct the full envelope even for a decision the encoder refuses.
	// The decoder must independently refuse it, not rely on a good encoder.
	raw, err := json.Marshal(decisionEnvelope{1, d})
	if err != nil {
		t.Fatal(err)
	}
	checkCustodyCodecWire(t, raw)
	if wantErr == nil {
		decoded, err := DecodeDecision(got)
		if err != nil || !reflect.DeepEqual(decoded, d) {
			t.Fatalf("exact round trip: %v", err)
		}
	}
}

func checkCustodyCodecWire(t *testing.T, raw []byte) {
	t.Helper()
	want, wantErr := ec941DecodeDecision(raw)
	got, gotErr := DecodeDecision(raw)
	if Code(gotErr) != Code(wantErr) || gotErr == nil && !reflect.DeepEqual(got, want) {
		t.Fatalf("wire decoding differs: got=%v want=%v", gotErr, wantErr)
	}
}

func TestCustodyCodecFrozenDifferential(t *testing.T) {
	for _, original := range custodyCodecFixtures(t) {
		t.Run(original.Command.Kind, func(t *testing.T) {
			if err := ec941ValidateSupportedDecision(original); err != nil {
				t.Fatal("invalid structural fixture", err)
			}
			checkCustodyCodecOracle(t, original)
			raw := original.Assignment
			variants := map[string][]byte{
				"nil": nil, "empty": {}, "null": []byte("null"), "array": []byte("[]"),
				"trailing":           append(bytes.Clone(raw), '{', '}'),
				"duplicate-version":  append([]byte(`{"version":4,`), raw[1:]...),
				"unknown":            append([]byte(`{"unknown":true,`), raw[1:]...),
				"case-field":         bytes.Replace(raw, []byte(`"cluster_uid"`), []byte(`"CLUSTER_UID"`), 1),
				"escaped-field":      bytes.Replace(raw, []byte(`"cluster_uid"`), []byte(`"cluster_\u0075id"`), 1),
				"invalid-utf8":       bytes.Replace(raw, []byte(`"cluster"`), []byte{'"', 0xff, '"'}, 1),
				"unpaired-surrogate": bytes.Replace(raw, []byte(`"operation_id":`), []byte(`"operation_id":"\ud800","ignored":`), 1),
				"deep-unknown":       append([]byte(`{"unknown":`+strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65)+","), raw[1:]...),
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, raw, "", "  "); err != nil {
				t.Fatal(err)
			}
			variants["whitespace"] = pretty.Bytes()
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			variants["sorted-fields"], _ = json.Marshal(object)
			for _, version := range []string{"0", "1", "2", "3", "5", "4.0", "4e0", "\"4\"", "null", "-4", "18446744073709551616"} {
				variants["version-"+version] = bytes.Replace(raw, []byte(`"version":4`), []byte(`"version":`+version), 1)
			}
			for _, field := range []string{"cluster_uid", "operation_id", "recorded_at"} {
				for _, value := range []string{`null`, `""`, `"\ud800"`, `"\ud83d\ude00"`, `"\ufffd"`} {
					copyObject := map[string]json.RawMessage{}
					for k, v := range object {
						copyObject[k] = v
					}
					copyObject[field] = json.RawMessage(value)
					variants[field+"-"+value], _ = json.Marshal(copyObject)
				}
				copyObject := map[string]json.RawMessage{}
				for k, v := range object {
					if k != field {
						copyObject[k] = v
					}
				}
				variants["missing-"+field], _ = json.Marshal(copyObject)
			}
			for _, field := range []string{"custody_import", "continuity", "execution", "key_transition", "ownership", "binding", "owner", "identity", "target"} {
				if _, present := object[field]; present {
					continue
				}
				for _, value := range []string{"null", "{}"} {
					variants["cross-class-"+field+value] = append([]byte(`{"`+field+`":`+value+`,`), raw[1:]...)
				}
			}
			for name, assignment := range variants {
				t.Run(name, func(t *testing.T) { d := original; d.Assignment = assignment; checkCustodyCodecOracle(t, d) })
			}
			for _, kind := range []string{"read_barrier", "rewrap_payload", "ensure_owner", "acquire_session", "admit_update", "unknown", "record_custody_import", "activate_key_epoch"} {
				t.Run("kind-"+kind, func(t *testing.T) {
					d := original
					d.Command.Kind = kind
					if kind != "admit_update" {
						checkCustodyCodecOracle(t, d)
						return
					}
					// Update is newly supported. The frozen oracle still
					// refuses its old unknown command domain; current code
					// must reject these foreign v4/v1 assignments as invalid.
					for _, version := range []int{4, 1} {
						var assignment Assignment
						if err := json.Unmarshal(original.Assignment, &assignment); err != nil {
							t.Fatal(err)
						}
						assignment.Version = version
						d.Assignment, _ = json.Marshal(assignment)
						if err := ec941ValidateSupportedDecision(d); Code(err) != CodeUnsupported {
							t.Fatal("frozen unknown update domain changed", err)
						}
						if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
							t.Fatal("foreign update assignment validated", version, err)
						}
						if _, err := EncodeDecision(d); Code(err) != CodeValidation {
							t.Fatal("foreign update assignment encoded", version, err)
						}
						wire, err := json.Marshal(decisionEnvelope{1, d})
						if err != nil {
							t.Fatal(err)
						}
						if _, err := DecodeDecision(wire); Code(err) != CodeValidation {
							t.Fatal("foreign update assignment decoded", version, err)
						}
					}
				})
			}
			// Valid noncanonical assignment forms are accepted by the old API.
			// This specifically catches treating a fast-path miss as rejection.
			for _, name := range []string{"whitespace", "sorted-fields", "escaped-field"} {
				d := original
				d.Assignment = variants[name]
				if _, err := ec941EncodeDecision(d); err != nil {
					t.Fatalf("expected old accepted variant %s: %v", name, err)
				}
			}
		})
	}
}

func TestCustodyCodecNestedAndMutation(t *testing.T) {
	d := custodyCodecFixtures(t)[0]
	var a Assignment
	if err := json.Unmarshal(d.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"duplicate", "unknown", "missing", "null", "invalid-utf8", "base64-newline", "base64-padding", "base64-escape", "recipient-link", "member-order", "wrong-genesis", "member-limit"} {
		t.Run(mutation, func(t *testing.T) {
			changed := d
			raw := bytes.Clone(d.Assignment)
			switch mutation {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"candidate":{`), []byte(`"candidate":{"attempt":"attempt",`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"candidate":{`), []byte(`"candidate":{"unknown":null,`), 1)
			case "missing":
				raw = bytes.Replace(raw, []byte(`"admission_serial":"a1",`), nil, 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"chain":[`), []byte(`"chain":null,"unknown":[`), 1)
			case "invalid-utf8":
				raw = bytes.Replace(raw, []byte(`"attempt":"attempt"`), append([]byte(`"attempt":"`), 0xff, '"'), 1)
			case "base64-newline":
				raw = bytes.Replace(raw, []byte(`"trust":"`), []byte(`"trust":"\n`), 1)
			case "base64-padding":
				raw = bytes.Replace(raw, []byte(`"trust":"`), []byte(`"trust":"=`), 1)
			case "base64-escape":
				raw = bytes.Replace(raw, []byte(`aW5lcnQtdHJ1c3Q=`), []byte(`\u0061W5lcnQtdHJ1c3Q=`), 1)
			default:
				var copyA Assignment
				if err := json.Unmarshal(raw, &copyA); err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "recipient-link":
					copyA.CustodyImport.Members[0].Completion.Recipient = copyA.CustodyImport.Members[1].Recipient.Recipient
				case "member-order":
					copyA.CustodyImport.Members[0], copyA.CustodyImport.Members[1] = copyA.CustodyImport.Members[1], copyA.CustodyImport.Members[0]
				case "wrong-genesis":
					copyA.CustodyImport.Genesis.Sequence = 2
				case "member-limit":
					for len(copyA.CustodyImport.Members) <= MaxKeyRecipients {
						copyA.CustodyImport.Members = append(copyA.CustodyImport.Members, copyA.CustodyImport.Members[0])
					}
				}
				raw, _ = json.Marshal(copyA)
			}
			if bytes.Equal(raw, d.Assignment) {
				t.Fatal("mutation did not change fixture")
			}
			changed.Assignment = raw
			checkCustodyCodecOracle(t, changed)
		})
	}
	// First validate, then modify the same backing slice. Cached validation
	// keyed by a Decision, slice address or a previous decode must not survive.
	checkCustodyCodecOracle(t, d)
	i := bytes.Index(d.Assignment, []byte(`"version":4`)) + len(`"version":`)
	d.Assignment[i] = '3'
	checkCustodyCodecOracle(t, d)
	if _, err := EncodeDecision(d); err == nil {
		t.Fatal("mutated reserved version accepted")
	}
	d.Assignment[i] = '4'
	d.Command.Kind = "read_barrier"
	checkCustodyCodecOracle(t, d)
	if _, err := EncodeDecision(d); err == nil {
		t.Fatal("mutated command kind accepted")
	}
	for _, original := range custodyCodecFixtures(t) {
		decoded, err := DecodeAssignment(original)
		if err != nil {
			t.Fatal(err)
		}
		decoded.OperationID = "changed"
		if decoded.CustodyImport != nil {
			decoded.CustodyImport.Members[0].Recipient.Chain[0][0] ^= 1
		}
		checkCustodyCodecOracle(t, original)
	}
}

// A recognized union field in canonical struct order must still be rejected
// when it belongs to another command. Re-encoding the unrestricted Assignment
// instead of the allowed subset would admit these exact bytes.
func TestCustodyCodecCanonicalCrossClass(t *testing.T) {
	for _, original := range custodyCodecFixtures(t) {
		for _, field := range []string{"CustodyImport", "Continuity", "Execution", "KeyTransition", "Ownership", "Binding", "Owner", "Identity", "Target"} {
			if original.Command.Kind == CustodyImportCommand && field == "CustodyImport" || original.Command.Kind == "activate_key_epoch" && field == "KeyTransition" {
				continue
			}
			t.Run(original.Command.Kind+"/"+field, func(t *testing.T) {
				var a Assignment
				if err := json.Unmarshal(original.Assignment, &a); err != nil {
					t.Fatal(err)
				}
				f := reflect.ValueOf(&a).Elem().FieldByName(field)
				f.Set(reflect.New(f.Type().Elem()))
				d := original
				d.Assignment, _ = json.Marshal(a)
				if _, err := ec941DecodeAssignment(d); err == nil {
					t.Fatal("cross-class fixture unexpectedly allowed")
				}
				checkCustodyCodecOracle(t, d)
			})
		}
	}
}

func TestCustodyCodecNestedNulls(t *testing.T) {
	d := custodyCodecFixtures(t)[0]
	for _, field := range []string{"candidate", "chain", "trust", "signature", "recipient", "recorded_at"} {
		t.Run(field, func(t *testing.T) {
			var a map[string]any
			if err := json.Unmarshal(d.Assignment, &a); err != nil {
				t.Fatal(err)
			}
			r := a["custody_import"].(map[string]any)["members"].([]any)[0].(map[string]any)["recipient"].(map[string]any)
			r[field] = nil
			changed := d
			changed.Assignment, _ = json.Marshal(a)
			if err := ec941ValidateSupportedDecision(changed); err == nil {
				t.Fatal("null transcript fixture unexpectedly allowed")
			}
			checkCustodyCodecOracle(t, changed)
		})
	}
}

func TestCustodyCodecBoundariesAndWire(t *testing.T) {
	d := custodyCodecFixtures(t)[0]
	for _, size := range []int{(1 << 20) - 1, 1 << 20, (1 << 20) + 1} {
		t.Run(fmt.Sprintf("assignment-bytes-%d", size), func(t *testing.T) {
			changed := d
			changed.Assignment = append(bytes.Clone(d.Assignment), bytes.Repeat([]byte(" "), size-len(d.Assignment))...)
			checkCustodyCodecOracle(t, changed)
			if _, err := DecodeAssignment(changed); (err == nil) != (size <= 1<<20) {
				t.Fatal("assignment byte bound changed", err)
			}
		})
	}
	for _, depth := range []int{63, 64, 65} {
		d.Assignment = []byte(`{"version":1,"extra":` + strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth) + "}")
		checkCustodyCodecOracle(t, d)
	}
	d = custodyCodecFixtures(t)[0]
	raw, err := ec941EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range [][]byte{nil, {}, []byte("null"), append(bytes.Clone(raw), ' '), append(bytes.Clone(raw), '0'), append([]byte(`{"Version":1,`), raw[1:]...), bytes.Replace(raw, []byte(`"Version":1`), []byte(`"Version":2`), 1), bytes.Replace(raw, []byte(`"Version":1`), []byte(`"Version":1,"Unknown":null`), 1), bytes.Repeat([]byte(" "), MaxDecisionBytes+1)} {
		checkCustodyCodecWire(t, wire)
	}
	legacy := historicalKeyTransition(t, "rewrap_payload")
	checkCustodyCodecOracle(t, legacy)
}
