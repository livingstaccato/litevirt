package contract

import (
	"bytes"
	"reflect"
	"testing"
)

func TestDecisionCiphertextFastPath(t *testing.T) {
	for _, n := range []int{1, 2, 3, 1 << 20} {
		d := ciphertextDecision()
		d.Command.Ciphertext = bytes.Repeat([]byte{103}, n)
		b := rawDecision(t, d)
		got, ok := decodeDecisionCiphertext(b)
		if !ok || !reflect.DeepEqual(got, d) {
			t.Fatal("canonical nonempty ciphertext did not take fast path", n)
		}
		compareDecisionOracle(t, b)
	}
	for _, ciphertext := range [][]byte{nil, {}} {
		d := ciphertextDecision()
		d.Command.Ciphertext = ciphertext
		b := rawDecision(t, d)
		got, ok := decodeDecisionCiphertext(b)
		if ok || !reflect.DeepEqual(got, Decision{}) {
			t.Fatal("nil/empty must fall back without publishing")
		}
		compareDecisionOracle(t, b)
	}
}

// Each maps to one isolated causal mutant; these are behavioral rejections,
// not source-text assertions or successful encode/decode-only checks.
func TestDecisionCiphertextRequiredChecks(t *testing.T) {
	b := rawDecision(t, ciphertextDecision())
	for name, bad := range map[string][]byte{
		"shell-equality":   bytes.Replace(b, []byte(`"Sequence":1,"ParentDigest":""`), []byte(`"ParentDigest":"","Sequence":1`), 1),
		"strict-padbits":   bytes.Replace(b, []byte(`"Ciphertext":"Zg=="`), []byte(`"Ciphertext":"Zh=="`), 1),
		"actual-semantics": bytes.Replace(b, []byte(`"Sequence":1`), []byte(`"Sequence":0`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := decodeDecisionCiphertext(bad)
			if ok || !reflect.DeepEqual(got, Decision{}) {
				t.Fatal("invalid actual bytes accepted by specialized decoder")
			}
			compareDecisionOracle(t, bad)
		})
	}
}

func TestDecisionCiphertextOwnership(t *testing.T) {
	d := ciphertextDecision()
	d.Command.Ciphertext = bytes.Repeat([]byte{103}, 1<<20)
	b := rawDecision(t, d)
	original := bytes.Clone(b)
	got, err := DecodeDecision(b)
	if err != nil {
		t.Fatal(err)
	}
	got.Command.Ciphertext[0] ^= 255
	if !bytes.Equal(b, original) {
		t.Fatal("returned ciphertext aliases input")
	}
	got.Command.Ciphertext[0] ^= 255
	at := bytes.Index(b, []byte(`,"Ciphertext":"`)) + len(`,"Ciphertext":"`)
	b[at] = '!'
	if !bytes.Equal(got.Command.Ciphertext, d.Command.Ciphertext) {
		t.Fatal("input aliases returned ciphertext")
	}
	if again, err := DecodeDecision(b); err == nil || !reflect.DeepEqual(again, Decision{}) {
		t.Fatal("second decode trusted prior bytes")
	}
	b[at] = original[at]
	if _, err := DecodeDecision(b); err != nil {
		t.Fatal("restored bytes refused", err)
	}
}

func TestDecisionCiphertextFalsePublishesZero(t *testing.T) {
	b := rawDecision(t, ciphertextDecision())
	cases := [][]byte{nil, {}, []byte(`{}`), bytes.Repeat([]byte{' '}, MaxDecisionBytes+1), b[:bytes.Index(b, []byte(`Zg==`))+4], bytes.Replace(b, []byte(`Zg==`), []byte(`!g==`), 1), append(bytes.Clone(b), ' '), bytes.Replace(b, []byte(`"Version":1`), []byte(`"Version":2`), 1), bytes.Replace(b, []byte(`Zg==`), []byte("Zg\r\n==AA"), 1)}
	for _, bad := range cases {
		got, ok := decodeDecisionCiphertext(bad)
		if ok || !reflect.DeepEqual(got, Decision{}) {
			t.Fatal("recognition failure published a value")
		}
		compareDecisionOracle(t, bad)
	}
}
