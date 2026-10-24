package contract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
)

// Losing either kind-specific branch must fail an accepted real decision or its
// exact encoded round trip. These are certified-contract fixtures, not native
// admission or runtime authority.
func TestAutomationUpdateCustodyCoexistenceAcceptedDecisions(t *testing.T) {
	p, update := updateContractFixture(t)
	r, err := Reduce(p, update)
	if err != nil || r.Receipt.Code != "" || r.AdmissionEffect == nil || r.AdmissionEffect.Method != "admit_update" {
		t.Fatalf("update3 lost at current custody boundary: %+v %v", r.Receipt, err)
	}
	decisions := append([]Decision{update}, custodyCodecFixtures(t)...)
	for _, d := range decisions {
		t.Run(d.Command.Kind, func(t *testing.T) {
			if err := ValidateSupportedDecision(d); err != nil {
				t.Fatal("accepted kind-specific assignment refused", err)
			}
			raw, err := EncodeDecision(d)
			if err != nil {
				t.Fatal("accepted assignment cannot encode", err)
			}
			again, err := DecodeDecision(raw)
			if err != nil || !reflect.DeepEqual(d, again) {
				t.Fatal("accepted assignment lost exact round trip", err)
			}
			if d.Command.Kind != "admit_update" {
				// This oracle is frozen at the accepted custody codec. In
				// particular its typed nil byte/slice members remain null.
				checkCustodyCodecOracle(t, d)
			}
		})
	}
}

func TestAutomationUpdateCustodyCoexistenceVersionAndMemberSeparation(t *testing.T) {
	_, update := updateContractFixture(t)
	decisions := append([]Decision{update}, custodyCodecFixtures(t)...)
	for _, original := range decisions {
		t.Run(original.Command.Kind, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(original.Assignment, &fields); err != nil {
				t.Fatal(err)
			}
			wanted := 4
			if original.Command.Kind == "admit_update" {
				wanted = 3
			}
			for _, version := range []int{0, 1, 2, 3, 4, 5} {
				d := original
				fields["version"] = json.RawMessage(strconv.Itoa(version))
				d.Assignment, _ = json.Marshal(fields)
				wantValid := version == wanted
				if original.Command.Kind != "admit_update" {
					// The original key protocol also has a v1 activation
					// domain. Preserve the frozen kind-specific meaning.
					wantValid = ec941ValidateSupportedDecision(d) == nil
				}
				err := ValidateSupportedDecision(d)
				if (err == nil) != wantValid {
					t.Fatalf("version %d on %s: %v", version, d.Command.Kind, err)
				}
			}
			fields["version"] = json.RawMessage(strconv.Itoa(wanted))
			for _, other := range []string{"update", "custody_import", "key_transition", "owner_coverage"} {
				if other == "update" && original.Command.Kind == "admit_update" || other == "custody_import" && original.Command.Kind == CustodyImportCommand || other == "key_transition" && original.Command.Kind == "activate_key_epoch" {
					continue
				}
				for _, value := range []string{"null", "{}"} {
					d := original
					fields[other] = json.RawMessage(value)
					d.Assignment, _ = json.Marshal(fields)
					if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
						t.Fatalf("foreign %s=%s accepted on %s: %v", other, value, d.Command.Kind, err)
					}
					delete(fields, other)
				}
			}
		})
	}
}

func TestAutomationUpdateCustodyCoexistenceRawStrictnessAndLegacyBytes(t *testing.T) {
	_, update := updateContractFixture(t)
	for name, raw := range map[string][]byte{
		"duplicate-version": append([]byte(`{"version":3,`), update.Assignment[1:]...),
		"unknown-null":      append([]byte(`{"unknown":null,`), update.Assignment[1:]...),
		"custody-null":      append([]byte(`{"custody_import":null,`), update.Assignment[1:]...),
		"trailing":          append(bytes.Clone(update.Assignment), '{', '}'),
	} {
		t.Run(name, func(t *testing.T) {
			d := update
			d.Assignment = raw
			if _, err := EncodeDecision(d); Code(err) != CodeValidation {
				t.Fatalf("invalid update3 assignment encoded: %v", err)
			}
			wire, marshalErr := json.Marshal(decisionEnvelope{1, d})
			if marshalErr == nil {
				if _, err := DecodeDecision(wire); Code(err) != CodeValidation {
					t.Fatalf("invalid update3 assignment decoded: %v", err)
				}
			}
		})
	}
	_, legacy := bindingPinnedFixture(t)
	old, oldErr := ec941EncodeDecision(legacy)
	current, err := EncodeDecision(legacy)
	if oldErr != nil || err != nil || !bytes.Equal(old, current) {
		t.Fatalf("v1 create assignment bytes changed: frozen=%v current=%v", oldErr, err)
	}
	var a Assignment
	if err := json.Unmarshal(legacy.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{2, 3, 4} {
		d := legacy
		a.Version = version
		d.Assignment, _ = json.Marshal(a)
		if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
			t.Fatalf("v1 create acquired another kind's version %d: %v", version, err)
		}
	}
}
