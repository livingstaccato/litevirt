package corrosion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Literal pre-optimization decoder: a semantic oracle, not a replacement for
// the production call. In particular, errors may leave a partially filled value.
func oldAutomationOuterDecode(key ClaimKey, s string, v *ClaimValue) error {
	if !key.IsAutomation() {
		return json.Unmarshal([]byte(s), v)
	}
	if len(s) > MaxAutomationClaimBytes {
		return fmt.Errorf("corrupt automation claim value")
	}
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return fmt.Errorf("corrupt automation claim value")
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) != s {
		return fmt.Errorf("noncanonical automation claim value")
	}
	return nil
}

func TestAutomationOuterDecodeCompatibility(t *testing.T) {
	wrap := func(encoded string) string { return `{"automation":{"envelope":"` + encoded + `"}}` }
	canonical := func(body []byte) string {
		b, err := json.Marshal(ClaimValue{Automation: &AutomationClaimValue{Envelope: body}})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cases := []struct{ name, raw string }{
		{"empty-object", `{}`}, {"null-value", `null`}, {"nil-envelope", `{"automation":{"envelope":null}}`},
		{"empty-envelope", wrap("")}, {"canonical-one", wrap("AA==")}, {"canonical-two", wrap("AAA=")}, {"canonical-three", wrap("AAAA")},
		{"pad-bits-one", wrap("AB==")}, {"pad-bits-two", wrap("AAB=")}, {"missing-pad", wrap("AA")}, {"extra-pad", wrap("AA===")},
		{"pad-middle", wrap("AA==AAAA")}, {"url-alphabet", wrap("____")}, {"standard-alphabet", wrap("////")},
		{"literal-cr", wrap("AA\r==")}, {"literal-lf", wrap("AA\n==")}, {"escaped-lf", wrap(`AA\n==`)}, {"escaped-cr", wrap(`AA\r==`)},
		{"escaped-ascii", wrap(`\u0041A==`)}, {"escaped-slash", wrap(`\/\/\/\/`)}, {"space", wrap("AA ==")},
		{"leading-space", " " + wrap("AA==")}, {"trailing-space", wrap("AA==") + " "}, {"trailing-object", wrap("AA==") + `{}`},
		{"outer-duplicate", `{"automation":null,"automation":{"envelope":"AA=="}}`},
		{"inner-duplicate", `{"automation":{"envelope":"AA==","envelope":"AAA="}}`},
		{"unknown-outer", `{"automation":{"envelope":"AA=="},"unknown":1}`},
		{"unknown-inner", `{"automation":{"envelope":"AA==","unknown":1}}`},
		{"field-case", `{"Automation":{"envelope":"AA=="}}`},
		{"byte-array", `{"automation":{"envelope":[0]}}`},
		{"mixed-empty-proof", `{"proof":{},"automation":{"envelope":"AA=="}}`},
		{"mixed-source", `{"source_host":"h","automation":{"envelope":"AA=="}}`},
		{"partial-type-error", `{"source_host":"h","automation":{"envelope":7}}`},
		{"partial-base64-error", `{"source_host":"h","automation":{"envelope":"!"}}`},
		{"legacy-proof", `{"proof":{}}`}, {"legacy-source", `{"source_host":"h"}`},
		{"other-null", `{"lease_term":null}`}, {"invalid-utf8", wrap(string([]byte{0xff}))},
		{"raw-inner-corruption", canonical([]byte("not a decision"))},
	}
	for n := 1; n <= 12; n++ {
		cases = append(cases, struct{ name, raw string }{fmt.Sprintf("bytes-%d", n), canonical(bytes.Repeat([]byte{byte(n * 19)}, n))})
	}
	for _, extra := range []ClaimValue{{Config: &VoterConfigValue{}}, {LUN: &LUNAllocation{}}, {LeaseTerm: &LeaseTermValue{}}} {
		extra.Automation = &AutomationClaimValue{Envelope: []byte{1, 2, 3}}
		b, e := json.Marshal(extra)
		if e != nil {
			t.Fatal(e)
		}
		cases = append(cases, struct{ name, raw string }{fmt.Sprintf("mixed-%d", len(cases)), string(b)})
	}
	key, _ := AutomationClaimKey(2)
	destinations := []struct {
		name string
		make func() *ClaimValue
	}{
		{"zero", func() *ClaimValue { return &ClaimValue{} }}, {"nil", func() *ClaimValue { return nil }},
		{"source", func() *ClaimValue { return &ClaimValue{SourceHost: "retained"} }},
		{"automation", func() *ClaimValue {
			return &ClaimValue{Automation: &AutomationClaimValue{Envelope: []byte("retained")}}
		}},
		{"empty-proof", func() *ClaimValue { return &ClaimValue{Proof: &ActionProof{}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []ClaimKey{key, workloadKey()} {
				for _, dst := range destinations {
					got, want := dst.make(), dst.make()
					actual, old := decodeClaimValue(k, tc.raw, got), oldAutomationOuterDecode(k, tc.raw, want)
					if fmt.Sprintf("%T:%v", actual, actual) != fmt.Sprintf("%T:%v", old, old) || !reflect.DeepEqual(got, want) {
						t.Fatalf("kind=%s destination=%s: error %v vs %v; output differs=%v", k.TargetKind, dst.name, actual, old, !reflect.DeepEqual(got, want))
					}
				}
			}
		})
	}
}

func TestAutomationOuterDecodeNativeBoundary(t *testing.T) {
	key, _ := AutomationClaimKey(2)
	d := contract.Decision{Sequence: 2, ParentDigest: strings.Repeat("a", 64), Command: contract.Command{Kind: "read_barrier", ClusterUID: "cluster", RequestID: "outer", Body: []byte(`{"version":1}`), Ciphertext: bytes.Repeat([]byte{0x67}, 1<<20)}, Assignment: []byte(`{"version":1}`)}
	envelope, e := contract.EncodeDecision(d)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}})
	if e != nil {
		t.Fatal(e)
	}
	shell := len(`{"automation":{"envelope":""}}`)
	maxEncoded := (MaxAutomationClaimBytes - shell) / 4 * 4
	for _, s := range []string{string(raw), strings.Repeat(" ", MaxAutomationClaimBytes-1), strings.Repeat(" ", MaxAutomationClaimBytes), strings.Repeat(" ", MaxAutomationClaimBytes+1), `{"automation":{"envelope":"` + strings.Repeat("A", maxEncoded) + `"}}`} {
		var got, want ClaimValue
		a, b := decodeClaimValue(key, s, &got), oldAutomationOuterDecode(key, s, &want)
		if fmt.Sprint(a) != fmt.Sprint(b) || !reflect.DeepEqual(got, want) {
			t.Fatalf("native bytes=%d: %v vs %v", len(s), a, b)
		}
	}
	var value ClaimValue
	if e = decodeClaimValue(key, string(raw), &value); e != nil {
		t.Fatal(e)
	}
	if e = validateAutomationValue(key, value); e != nil {
		t.Fatal("actual near-native decision", e)
	}
	if !bytes.Equal(value.Automation.Envelope, envelope) {
		t.Fatal("changed original envelope")
	}
	value.Automation.Envelope[0] ^= 1
	if bytes.Equal(value.Automation.Envelope, envelope) {
		t.Fatal("decoded envelope aliases input")
	}
}
