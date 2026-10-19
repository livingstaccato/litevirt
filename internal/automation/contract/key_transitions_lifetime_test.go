package contract

import (
	"bytes"
	"strconv"
	"testing"
)

// This uses the existing certified-history premise. It grants no fresh
// enrollment, class admission, or current custody authority.
func TestAutomationKeyTransitionHostLifetimeDomain(t *testing.T) {
	t.Run("explicit_zero_whole_second", func(t *testing.T) {
		p, d := historicalActivationFacts(t)
		if err := ValidateSupportedDecision(d); err != nil {
			t.Fatalf("SETUP canonical historical activation invalid: %v", err)
		}
		d.Assignment = lifetimeReplace(t, d.Assignment, `"host_incarnation":17`, `"host_incarnation":0`)
		if err := ValidateSupportedDecision(d); err != nil {
			t.Fatalf("HOST_LIFETIME_VALID_REFUSED: %v", err)
		}
		encoded, err := EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeDecision(encoded)
		if err != nil || !bytes.Equal(decoded.Assignment, d.Assignment) {
			t.Fatalf("HOST_LIFETIME_EXACT_BYTES_CHANGED: %v", err)
		}
		r, err := Reduce(p, decoded)
		if err != nil || r.Receipt.Code != "" || r.EpochEffect == nil || len(r.RecipientEffects) != 1 {
			t.Fatalf("HOST_LIFETIME_ACTIVATION_REFUSED: receipt=%+v err=%v", r.Receipt, err)
		}
		binding := r.RecipientEffects[0].Binding
		if binding.HostIncarnation != 0 || binding.AdmittedAt != "2026-10-18T00:00:00Z" || binding.AdmissionSerial != "a1" {
			t.Fatal("HOST_LIFETIME_BINDING_CHANGED")
		}
	})
	for _, tc := range []struct {
		name, token string
	}{
		{"absent", ""},
		{"null", `"host_incarnation":null,`},
		{"string", `"host_incarnation":"0",`},
		{"negative", `"host_incarnation":-1,`},
		{"overflow", `"host_incarnation":9223372036854775808,`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, d := historicalActivationFacts(t)
			if err := ValidateSupportedDecision(d); err != nil {
				t.Fatalf("SETUP canonical historical activation invalid: %v", err)
			}
			d.Assignment = lifetimeReplace(t, d.Assignment, `"host_incarnation":17,`, tc.token)
			if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
				t.Fatalf("HOST_LIFETIME_INVALID_ACCEPTED: %v", err)
			}
		})
	}
}

func lifetimeReplace(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	if bytes.Count(raw, []byte(old)) != 1 {
		t.Fatalf("SETUP expected exactly one lifetime token %q", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}

func TestAutomationKeyTransitionHostLifetimeBoundsAndExactAt(t *testing.T) {
	for _, tc := range []struct {
		name, number, at string
	}{
		{"max_signed", "9223372036854775807", "2026-10-18T00:00:00Z"},
		{"fractional_exact", "17", "2026-10-18T00:00:00.123400Z"},
		{"offset_exact", "17", "2026-10-18T01:00:00+01:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, d := historicalActivationFacts(t)
			d.Assignment = lifetimeReplace(t, d.Assignment, `"host_incarnation":17`, `"host_incarnation":`+tc.number)
			d.Assignment = lifetimeReplace(t, d.Assignment, `"admitted_at":"2026-10-18T00:00:00Z"`, `"admitted_at":"`+tc.at+`"`)
			r, err := Reduce(p, d)
			if err != nil || r.Receipt.Code != "" || len(r.RecipientEffects) != 1 {
				t.Fatalf("valid lifetime refused: %+v %v", r.Receipt, err)
			}
			if got := r.RecipientEffects[0].Binding; strconv.FormatUint(got.HostIncarnation, 10) != tc.number || got.AdmittedAt != tc.at {
				t.Fatal("exact lifetime bytes changed")
			}
		})
	}
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"membership_zero", `"membership_generation":3`, `"membership_generation":0`},
		{"prefix_zero", `"sequence":9`, `"sequence":0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, d := historicalActivationFacts(t)
			d.Command.Body = lifetimeReplace(t, d.Command.Body, tc.old, tc.replacement)
			if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
				t.Fatalf("other positive counter relaxed: %v", err)
			}
		})
	}
}

func TestAutomationKeyTransitionHostLifetimeImmutableBinding(t *testing.T) {
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"same_instant_different_at_bytes", `"admitted_at":"2026-10-18T00:00:00Z"`, `"admitted_at":"2026-10-18T00:00:00.000Z"`},
		{"changed_admission_serial", `"admission_serial":"a1"`, `"admission_serial":"a2"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, d := historicalActivationFacts(t)
			a, err := DecodeAssignment(d)
			if err != nil {
				t.Fatal(err)
			}
			old := a.KeyTransition.Recipients[0]
			p.KeyTransition.Recipients = []KeyRecipientRecord{{Binding: old, FirstSequence: 8}}
			baseline, err := Reduce(p, d)
			if err != nil || baseline.Receipt.Code != "" || baseline.EpochEffect == nil {
				t.Fatalf("unchanged binding refused: %+v %v", baseline.Receipt, err)
			}
			d.Assignment = lifetimeReplace(t, d.Assignment, tc.old, tc.replacement)
			r, err := Reduce(p, d)
			if err != nil || r.Receipt.Code != CodeRevisionConflict || r.EpochEffect != nil || len(r.RecipientEffects) != 0 || p.KeyTransition.Recipients[0].Binding != old {
				t.Fatalf("immutable lifetime rebound: %+v %v", r.Receipt, err)
			}
		})
	}
}

func TestAutomationKeyTransitionHostLifetimeAtDomain(t *testing.T) {
	for _, tc := range []struct {
		name, token string
	}{
		{"absent", ""},
		{"null", `"admitted_at":null,`},
		{"empty", `"admitted_at":"",`},
		{"malformed", `"admitted_at":"not-a-time",`},
		{"invalid_utf8", "\"admitted_at\":\"\xff\","},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, d := historicalActivationFacts(t)
			d.Assignment = lifetimeReplace(t, d.Assignment, `"admitted_at":"2026-10-18T00:00:00Z",`, tc.token)
			if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
				t.Fatalf("invalid At accepted: %v", err)
			}
		})
	}
	t.Run("oversized_parseable_fraction", func(t *testing.T) {
		_, d := historicalActivationFacts(t)
		at := "2026-10-18T00:00:00."
		for len(at) <= MaxStringBytes {
			at += "1"
		}
		at += "Z"
		d.Assignment = lifetimeReplace(t, d.Assignment, `"admitted_at":"2026-10-18T00:00:00Z"`, `"admitted_at":"`+at+`"`)
		if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
			t.Fatalf("oversized admitted_at accepted: %v", err)
		}
	})
}
