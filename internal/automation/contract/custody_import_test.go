package contract

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	"strings"
	"testing"
)

// Losing this command's canonical identity would prevent certified custody
// imports from sharing the permanent request/replay contract.
func TestCustodyCommandCanonicalIdentity(t *testing.T) {
	c := Command{Kind: "record_custody_import", ClusterUID: "cluster", PrincipalID: "principal", RequestID: "attempt", Body: []byte(`{"version":1,"recipient_epoch":"epoch-a"}`)}
	a, err := CanonicalCommand(c)
	if err != nil {
		t.Fatalf("custody import must have a canonical request identity: %v", err)
	}
	c.Body = []byte(`{ "recipient_epoch": "epoch-a", "version": 1 }`)
	b, err := CanonicalCommand(c)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("equivalent custody requests lost their original identity")
	}
	c.Body = []byte(`{"version":1,"recipient_epoch":"epoch-b"}`)
	b, err = CanonicalCommand(c)
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("a changed custody epoch must conflict with the original request")
	}
	c.Kind = "unknown_custody_command"
	if _, err := CanonicalCommand(c); err == nil {
		t.Fatal("unknown command admitted")
	}
}

// Outer4 is a key-only initial activation contract; widening it to legacy
// rewrap/control commands or accepting a successor epoch is a downgrade bug.
func TestCustodyAssignmentVersionInitialOnly(t *testing.T) {
	d := historicalKeyTransition(t, "activate_key_epoch")
	var a map[string]any
	var b map[string]any
	if json.Unmarshal(d.Assignment, &a) != nil || json.Unmarshal(d.Command.Body, &b) != nil {
		t.Fatal("fixture decode")
	}
	a["version"] = 4
	facts := a["key_transition"].(map[string]any)
	facts["class"] = "bootstrap"
	facts["bootstrap"] = map[string]any{"sequence": 1, "digest": strings.Repeat("a", 64)}
	b["previous_activation"] = 0
	d.Assignment, _ = json.Marshal(a)
	d.Command.Body, _ = json.Marshal(b)
	if err := ValidateSupportedDecision(d); err != nil {
		t.Fatalf("initial native key assignment refused: %v", err)
	}
	for _, version := range []int{0, 2, 3, 5} {
		a["version"] = version
		d.Assignment, _ = json.Marshal(a)
		if err := ValidateSupportedDecision(d); err == nil {
			t.Fatal("unallocated key version admitted")
		}
	}
	a["version"] = 4
	d.Assignment, _ = json.Marshal(a)
	b["previous_activation"] = 4
	d.Command.Body, _ = json.Marshal(b)
	if err := ValidateSupportedDecision(d); err == nil {
		t.Fatal("outer4 successor activation admitted")
	}
	for _, kind := range []string{"rewrap_payload", "read_barrier"} {
		d = historicalKeyTransition(t, "rewrap_payload")
		d.Command.Kind = kind
		if json.Unmarshal(d.Assignment, &a) != nil {
			t.Fatal("fixture")
		}
		a["version"] = 4
		d.Assignment, _ = json.Marshal(a)
		if _, err := DecodeAssignment(d); err == nil {
			t.Fatal("outer4 widened to another kind")
		}
	}
}

// These are inert already-certified structural facts, not native custody or
// signatures. Native storage tests must obtain the transitions from the issuer.
func historicalCustodyImport(t *testing.T) Decision {
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
	return Decision{Sequence: 2, ParentDigest: digest, Command: Command{Kind: "record_custody_import", ClusterUID: "cluster", PrincipalID: "genesis-principal", RequestID: "import-request", Body: b}, Assignment: a}
}

func TestCustodyImportClosedCompleteStructure(t *testing.T) {
	d := historicalCustodyImport(t)
	if err := ValidateSupportedDecision(d); err != nil {
		t.Fatalf("complete typed import refused: %v", err)
	}
	for _, mutation := range []string{"legacy", "duplicate-member", "recipient-mismatch", "completion-at-expiry", "foreign-attempt", "unknown"} {
		t.Run(mutation, func(t *testing.T) {
			var a map[string]any
			if json.Unmarshal(d.Assignment, &a) != nil {
				t.Fatal("fixture")
			}
			record := a["custody_import"].(map[string]any)
			members := record["members"].([]any)
			member := members[0].(map[string]any)
			completion := member["completion"].(map[string]any)
			switch mutation {
			case "legacy":
				a["version"] = 1
			case "duplicate-member":
				members[1] = members[0]
			case "recipient-mismatch":
				completion["recipient"] = members[1].(map[string]any)["recipient"].(map[string]any)["recipient"]
			case "completion-at-expiry":
				completion["recorded_at"] = record["expires_at"]
			case "foreign-attempt":
				completion["candidate"].(map[string]any)["attempt"] = "foreign"
			case "unknown":
				record["authority"] = true
			}
			changed := d
			changed.Assignment, _ = json.Marshal(a)
			if err := ValidateSupportedDecision(changed); err == nil {
				t.Fatal("invalid custody record admitted")
			}
		})
	}
}

// Replacing typed import references with same-generation genesis must fail even
// though the archived legacy resolver accepts that historical reference shape.
func TestCustodyInitialActivationRequiresTypedImport(t *testing.T) {
	imported := historicalCustodyImport(t)
	assignment, err := DecodeAssignment(imported)
	if err != nil {
		t.Fatal(err)
	}
	importDigest := strings.Repeat("b", 64)
	summary, err := SummarizeKeyHistory(imported, importDigest, 3)
	if err != nil {
		t.Fatal(err)
	}
	genesis := HistoricalDecision{Sequence: 1, Digest: strings.Repeat("a", 64), Kind: "initialize_cluster", ClusterUID: "cluster", PrincipalID: "genesis-principal", MembershipGeneration: 3}
	projection := Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 2, Digest: importDigest}, KeyTransition: &KeyTransitionProjection{MembershipGeneration: 3, ConfigDigest: strings.Repeat("a", 64), History: []HistoricalDecision{genesis, summary}}}
	facts := &KeyTransitionAssignment{Class: "bootstrap", Bootstrap: &HistoryReference{Sequence: 1, Digest: strings.Repeat("a", 64)}}
	for _, member := range assignment.CustodyImport.Members {
		c := member.Recipient.Candidate
		h := c.Target
		projection.KeyTransition.Members = append(projection.KeyTransition.Members, KeyMember{Host: h.Host, VoterIncarnation: h.VoterIncarnation})
		ref := HistoryReference{Sequence: 2, Digest: importDigest}
		facts.Recipients = append(facts.Recipients, RecipientBinding{ClusterUID: "cluster", MembershipGeneration: 3, ConfigDigest: c.ConfigDigest, Host: h.Host, HostIncarnation: h.HostIncarnation, AdmittedAt: h.AdmittedAt, AdmissionSerial: h.AdmissionSerial, VoterIncarnation: h.VoterIncarnation, RecipientEpoch: c.RecipientEpoch, KeyID: c.VoterKeyID, Recipient: member.Recipient.Recipient, Enrollment: ref, RecipientAck: ref, EqualityAck: ref})
	}
	body, _ := json.Marshal(ActivateKeyEpochBody{Version: 1, MembershipGeneration: 3, ConfigDigest: strings.Repeat("a", 64), RecipientEpoch: "recipients", EqualityEpoch: "equality", Prefix: HistoryReference{Sequence: 2, Digest: importDigest}})
	a := Assignment{Version: 4, ClusterUID: "cluster", OperationID: "activate", RecordedAt: "2026-10-24T00:01:03Z", KeyTransition: facts}
	encoded, _ := json.Marshal(a)
	d := Decision{Sequence: 3, ParentDigest: importDigest, Command: Command{Kind: "activate_key_epoch", ClusterUID: "cluster", PrincipalID: "genesis-principal", RequestID: "activate", Body: body}, Assignment: encoded}
	out, err := Reduce(projection, d)
	if err != nil || out.Receipt.Code != "" || out.EpochEffect == nil || len(out.RecipientEffects) != 3 {
		t.Fatalf("matching typed import activation failed: %v %s", err, out.Receipt.Code)
	}
	for _, mutation := range []string{"genesis-reference", "wrong-recipient", "wrong-equality", "majority-only"} {
		t.Run(mutation, func(t *testing.T) {
			changed := d
			var copied Assignment
			if json.Unmarshal(encoded, &copied) != nil {
				t.Fatal("fixture")
			}
			switch mutation {
			case "genesis-reference":
				for i := range copied.KeyTransition.Recipients {
					copied.KeyTransition.Recipients[i].Enrollment = *facts.Bootstrap
					copied.KeyTransition.Recipients[i].RecipientAck = *facts.Bootstrap
					copied.KeyTransition.Recipients[i].EqualityAck = *facts.Bootstrap
				}
			case "wrong-recipient":
				copied.KeyTransition.Recipients[0].KeyID = "foreign-key"
			case "wrong-equality":
				var b ActivateKeyEpochBody
				json.Unmarshal(body, &b)
				b.EqualityEpoch = "foreign"
				changed.Command.Body, _ = json.Marshal(b)
			case "majority-only":
				copied.KeyTransition.Recipients = copied.KeyTransition.Recipients[:2]
			}
			changed.Assignment, _ = json.Marshal(copied)
			got, err := Reduce(projection, changed)
			if err == nil && got.Receipt.Code == "" {
				t.Fatal("unproven custody activated")
			}
		})
	}
}

// The complete certified envelope must admit the allocated key-only assignment,
// not merely its independently decoded structural facts.
func TestCustodyCompleteEnvelopeVersion(t *testing.T) {
	imported := historicalCustodyImport(t)
	activation := historicalKeyTransition(t, "activate_key_epoch")
	var assignment, body map[string]any
	if json.Unmarshal(activation.Assignment, &assignment) != nil || json.Unmarshal(activation.Command.Body, &body) != nil {
		t.Fatal("fixture decode")
	}
	assignment["version"] = 4
	facts := assignment["key_transition"].(map[string]any)
	facts["class"] = "bootstrap"
	facts["bootstrap"] = map[string]any{"sequence": 1, "digest": strings.Repeat("a", 64)}
	body["previous_activation"] = 0
	activation.Assignment, _ = json.Marshal(assignment)
	activation.Command.Body, _ = json.Marshal(body)
	for _, d := range []Decision{imported, activation} {
		t.Run(d.Command.Kind, func(t *testing.T) {
			raw, err := EncodeDecision(d)
			if err != nil {
				t.Fatalf("allocated custody assignment cannot enter certified envelope: %v", err)
			}
			decoded, err := DecodeDecision(raw)
			if err != nil || !bytes.Equal(decoded.Assignment, d.Assignment) {
				t.Fatalf("custody envelope lost exact assignment: %v", err)
			}
			var a map[string]any
			_ = json.Unmarshal(d.Assignment, &a)
			for _, version := range []int{0, 2, 3, 5} {
				a["version"] = version
				other := d
				other.Assignment, _ = json.Marshal(a)
				if _, err := EncodeDecision(other); err == nil {
					t.Fatalf("reserved or unallocated version%d admitted", version)
				}
			}
		})
	}
	for _, kind := range []string{"read_barrier", "rewrap_payload", "ensure_owner"} {
		other := imported
		other.Command.Kind = kind
		if _, err := EncodeDecision(other); err == nil {
			t.Fatalf("outer4 envelope widened to %s", kind)
		}
	}
}
