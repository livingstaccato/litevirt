package corrosion

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Literal pre-size-optimization function. Keep the real decoder and marshal:
// this oracle must not acquire the production arithmetic or helper.
func oldAutomationDecision(v ClaimValue) (contract.Decision, error) {
	if v.Automation == nil || v.Proof != nil || v.Config != nil || v.LUN != nil || v.LeaseTerm != nil || v.SourceHost != "" {
		return contract.Decision{}, fmt.Errorf("invalid automation alternative")
	}
	d, err := contract.DecodeDecision(v.Automation.Envelope)
	if err != nil {
		return d, fmt.Errorf("invalid automation envelope")
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxAutomationClaimBytes {
		return d, fmt.Errorf("automation value exceeds storage limit")
	}
	return d, nil
}

func outerSizeFixture(t *testing.T, ciphertextBytes int) (contract.Decision, []byte) {
	t.Helper()
	d := contract.Decision{Sequence: 2, ParentDigest: strings.Repeat("a", 64), Command: contract.Command{Kind: "read_barrier", ClusterUID: "cluster", RequestID: "outer-size", Body: []byte(`{"version":1}`), Ciphertext: bytes.Repeat([]byte{0x67}, ciphertextBytes)}, Assignment: []byte(`{"version":1}`)}
	b, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal("real codec fixture", err)
	}
	return d, b
}

func TestAutomationDecisionMarshalCompatibility(t *testing.T) {
	_, native := outerSizeFixture(t, 1<<20)
	_, small := outerSizeFixture(t, 1)
	initialization, err := contract.EncodeDecision(contract.Decision{Sequence: 1, Command: contract.Command{Kind: "initialize_cluster", RequestID: "init", Body: []byte(`{"version":1}`)}, Assignment: []byte(`{"version":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		raw   []byte
		valid bool
	}{
		{"initialization", initialization, true}, {"read-barrier", small, true}, {"native-1MiB-ciphertext", native, true},
		{"nil", nil, false}, {"empty", []byte{}, false}, {"invalid-json", []byte(`{"Version":`), false}, {"invalid-utf8", []byte{255}, false},
	}
	replace := func(name, old, replacement string) {
		if !bytes.Contains(small, []byte(old)) {
			t.Fatalf("missing fixture token %s", name)
		}
		cases = append(cases, struct {
			name  string
			raw   []byte
			valid bool
		}{name, bytes.Replace(small, []byte(old), []byte(replacement), 1), false})
	}
	replace("unknown", `"Version":1`, `"Version":1,"unknown":0`)
	replace("duplicate", `"Sequence":2`, `"Sequence":2,"Sequence":2`)
	replace("invalid-version", `"Version":1`, `"Version":2`)
	replace("noncanonical-ciphertext", `"Ciphertext":"Zw=="`, `"Ciphertext":"Zg==" `)
	replace("pad-bit-ciphertext", `"Ciphertext":"Zw=="`, `"Ciphertext":"Zx=="`)
	cases = append(cases, struct {
		name  string
		raw   []byte
		valid bool
	}{"trailing-bytes", append(bytes.Clone(small), ' '), false})
	d, _ := outerSizeFixture(t, 1)
	for _, field := range []string{"body", "assignment"} {
		bad := d
		if field == "body" {
			bad.Command.Body = []byte(`{"version":0}`)
		} else {
			bad.Assignment = []byte(`{"version":0}`)
		}
		b, e := json.Marshal(struct {
			Version  uint32
			Decision contract.Decision
		}{1, bad})
		if e != nil {
			t.Fatal(e)
		}
		cases = append(cases, struct {
			name  string
			raw   []byte
			valid bool
		}{"invalid-" + field, b, false})
	}
	// Reach the inner limit with the real codec, rather than padding malformed
	// JSON and labelling it valid. The +1 input is explicitly oversized.
	near, base := outerSizeFixture(t, (contract.MaxDecisionBytes-1024)*3/4)
	for _, n := range []int{contract.MaxDecisionBytes - 1, contract.MaxDecisionBytes, contract.MaxDecisionBytes + 1} {
		v := near
		v.Command.ProjectUID = strings.Repeat("x", n-len(base))
		b, e := contract.EncodeDecision(v)
		valid := n <= contract.MaxDecisionBytes
		if valid {
			if e != nil || len(b) != n {
				t.Fatalf("real inner boundary %d: length %d, error %v", n, len(b), e)
			}
		} else {
			if e == nil {
				t.Fatal("real codec accepted oversized fixture")
			}
			b, e = json.Marshal(struct {
				Version  uint32
				Decision contract.Decision
			}{1, v})
			if e != nil || len(b) != n {
				t.Fatal("oversized fixture", e, len(b))
			}
		}
		cases = append(cases, struct {
			name  string
			raw   []byte
			valid bool
		}{fmt.Sprintf("inner-%d", n), b, valid})
	}
	for _, n := range []int{1572839, 1572840, 1572841, 1572842} {
		cases = append(cases, struct {
			name  string
			raw   []byte
			valid bool
		}{fmt.Sprintf("malformed-outer-crossing-%d", n), bytes.Repeat([]byte{' '}, n), false})
	}
	for i := 0; i < 256; i++ {
		cases = append(cases, struct {
			name  string
			raw   []byte
			valid bool
		}{fmt.Sprintf("one-byte-%02x", i), []byte{byte(i)}, false})
	}
	compare := func(t *testing.T, v ClaimValue) error {
		t.Helper()
		got, ge := automationDecision(v)
		want, we := oldAutomationDecision(v)
		if !reflect.DeepEqual(got, want) || fmt.Sprintf("%T:%v", ge, ge) != fmt.Sprintf("%T:%v", we, we) {
			t.Fatalf("decision/error mismatch: %v vs %v; decision differs=%v", ge, we, !reflect.DeepEqual(got, want))
		}
		return ge
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := compare(t, ClaimValue{Automation: &AutomationClaimValue{Envelope: tc.raw}})
			if (e == nil) != tc.valid {
				t.Fatalf("fixture valid=%v, error=%v", tc.valid, e)
			}
		})
	}
	alternatives := []struct {
		name string
		set  func(*ClaimValue)
	}{
		{"proof", func(v *ClaimValue) { v.Proof = &ActionProof{} }}, {"config", func(v *ClaimValue) { v.Config = &VoterConfigValue{} }},
		{"lun", func(v *ClaimValue) { v.LUN = &LUNAllocation{} }}, {"lease", func(v *ClaimValue) { v.LeaseTerm = &LeaseTermValue{} }},
		{"source", func(v *ClaimValue) { v.SourceHost = "host" }},
		{"combined", func(v *ClaimValue) {
			v.Proof = &ActionProof{}
			v.Config = &VoterConfigValue{}
			v.LUN = &LUNAllocation{}
			v.LeaseTerm = &LeaseTermValue{}
			v.SourceHost = "host"
		}},
	}
	for _, a := range alternatives {
		for _, raw := range []struct {
			name string
			b    []byte
		}{{"valid", small}, {"malformed", []byte("bad")}, {"oversized", bytes.Repeat([]byte{' '}, contract.MaxDecisionBytes+1)}} {
			t.Run("alternative/"+a.name+"/"+raw.name, func(t *testing.T) {
				for _, automation := range []*AutomationClaimValue{nil, {Envelope: raw.b}} {
					v := ClaimValue{Automation: automation}
					a.set(&v)
					if e := compare(t, v); e == nil || e.Error() != "invalid automation alternative" {
						t.Fatal("alternative did not precede decoding", e)
					}
				}
			})
		}
	}
	if e := compare(t, ClaimValue{}); e == nil || e.Error() != "invalid automation alternative" {
		t.Fatal(e)
	}
	invalidKey := ClaimKey{}
	malformed := ClaimValue{Automation: &AutomationClaimValue{Envelope: []byte("bad")}}
	if got, want := validateAutomationValue(invalidKey, malformed), invalidKey.Validate(); want == nil || fmt.Sprintf("%T:%v", got, got) != fmt.Sprintf("%T:%v", want, want) {
		t.Fatal("key validation precedence", got, want)
	}
	key, _ := AutomationClaimKey(3)
	if e := validateAutomationValue(key, ClaimValue{Automation: &AutomationClaimValue{Envelope: small}}); e == nil || e.Error() != "automation value does not match key" {
		t.Fatal("sequence binding", e)
	}
}

// Real json.Marshal is the independent oracle for nilness, bytes, tags,
// base64 residues and the complete storage bound; no second size formula.
func TestAutomationOuterSizeJSONOracle(t *testing.T) {
	check := func(envelope []byte) {
		t.Helper()
		raw, e := json.Marshal(ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}})
		if e != nil {
			t.Fatal(e)
		}
		got := automationOuterSize(envelope)
		if got != uint64(len(raw)) {
			t.Fatalf("nil=%v len=%d cap=%d: size=%d json=%d", envelope == nil, len(envelope), cap(envelope), got, len(raw))
		}
		if (got <= uint64(MaxAutomationClaimBytes)) != (len(raw) <= MaxAutomationClaimBytes) {
			t.Fatal("storage-bound decision differs from real JSON")
		}
	}
	check(nil)
	check([]byte{})
	for b := 0; b < 256; b++ {
		for n := 1; n <= 3; n++ {
			check(bytes.Repeat([]byte{byte(b)}, n))
		}
	}
	cycle := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}
	for n := 0; n <= 1024; n++ {
		check(cycle(n))
	}
	for _, n := range []int{(1 << 20) - 1, 1 << 20, (1 << 20) + 1, contract.MaxDecisionBytes - 1, contract.MaxDecisionBytes, contract.MaxDecisionBytes + 1, 1572839, 1572840, 1572841, 1572842} {
		check(cycle(n))
	}
	backing := cycle(2048)
	for _, span := range [][2]int{{0, 0}, {1, 1}, {0, 1}, {1, 2}, {17, 19}, {11, 14}, {17, 1041}} {
		check(backing[span[0]:span[1]])
	}
	// These are adjacent attainable encodings around 2 MiB. Neither reaches
	// the production size check: each raw envelope exceeds MaxDecisionBytes.
	for _, tc := range []struct {
		n, want int
		fits    bool
	}{{1572840, 2097150, true}, {1572841, 2097154, false}} {
		raw, e := json.Marshal(ClaimValue{Automation: &AutomationClaimValue{Envelope: make([]byte, tc.n)}})
		if e != nil || len(raw) != tc.want || (len(raw) <= MaxAutomationClaimBytes) != tc.fits {
			t.Fatal("actual adjacent JSON boundary", tc, len(raw), e)
		}
	}
}

// The arithmetic depends on this complete schema, even fields omitted for zero
// values. A failure requires re-proof, not silently updating expected fields.
func TestAutomationOuterSizeShape(t *testing.T) {
	type field struct {
		name string
		typ  reflect.Type
		tag  reflect.StructTag
	}
	shapes := []struct {
		typ    reflect.Type
		fields []field
	}{
		{reflect.TypeOf(ClaimValue{}), []field{
			{"Proof", reflect.TypeOf((*ActionProof)(nil)), `json:"proof,omitempty"`},
			{"SourceHost", reflect.TypeOf(""), `json:"source_host,omitempty"`},
			{"Config", reflect.TypeOf((*VoterConfigValue)(nil)), `json:"config,omitempty"`},
			{"LUN", reflect.TypeOf((*LUNAllocation)(nil)), `json:"lun,omitempty"`},
			{"Automation", reflect.TypeOf((*AutomationClaimValue)(nil)), `json:"automation,omitempty"`},
			{"LeaseTerm", reflect.TypeOf((*LeaseTermValue)(nil)), `json:"lease_term,omitempty"`},
		}},
		{reflect.TypeOf(AutomationClaimValue{}), []field{{"Envelope", reflect.TypeOf([]byte(nil)), `json:"envelope"`}}},
	}
	for _, shape := range shapes {
		if shape.typ.NumField() != len(shape.fields) {
			t.Fatalf("%s shape changed: re-prove outer size or restore Marshal", shape.typ)
		}
		for i, want := range shape.fields {
			got := shape.typ.Field(i)
			if got.Anonymous || got.Name != want.name || got.Type != want.typ || got.Tag != want.tag {
				t.Fatalf("%s field %d changed: re-prove outer size or restore Marshal", shape.typ, i)
			}
		}
		for _, typ := range []reflect.Type{shape.typ, reflect.PointerTo(shape.typ)} {
			for _, marshaler := range []reflect.Type{reflect.TypeOf((*json.Marshaler)(nil)).Elem(), reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()} {
				if typ.Implements(marshaler) {
					t.Fatalf("%s implements %s: re-prove outer size or restore Marshal", typ, marshaler)
				}
			}
		}
	}
}
