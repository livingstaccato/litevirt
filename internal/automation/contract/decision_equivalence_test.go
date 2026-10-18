package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func ciphertextDecision() Decision {
	return Decision{Sequence: 1, Command: Command{Kind: "initialize_cluster", RequestID: "req", Body: []byte(`{"version":1}`), Ciphertext: []byte("f")}, Assignment: []byte(`{"version":1}`)}
}

func rawDecision(t *testing.T, d Decision) []byte {
	t.Helper()
	b, err := json.Marshal(decisionEnvelope{1, d})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The frozen oracle detects acceptance, error, exact-body and nil/empty drift.
func compareDecisionOracle(t *testing.T, b []byte) {
	t.Helper()
	before := bytes.Clone(b)
	want, we := legacyDecodeDecision(b)
	got, ge := DecodeDecision(b)
	if Code(we) != Code(ge) || fmt.Sprint(we) != fmt.Sprint(ge) || !reflect.DeepEqual(want, got) {
		t.Fatalf("decode differs from frozen oracle: codes %q/%q errors %v/%v", Code(we), Code(ge), we, ge)
	}
	if !bytes.Equal(before, b) {
		t.Fatal("decode mutated input")
	}
	if ge == nil {
		wb, we := legacyEncodeDecision(want)
		gb, ge := EncodeDecision(got)
		if fmt.Sprint(we) != fmt.Sprint(ge) || !bytes.Equal(wb, gb) || !bytes.Equal(gb, b) {
			t.Fatal("exact re-encoding changed")
		}
	}
}

func TestDecisionCiphertextAdversarial(t *testing.T) {
	b := rawDecision(t, ciphertextDecision())
	cases := map[string][]byte{"canonical": b, "trailing-space": append(bytes.Clone(b), ' '), "trailing-object": append(bytes.Clone(b), []byte(`{}`)...), "trailing-garbage": append(bytes.Clone(b), 'x')}
	replace := func(name, old, value string) { cases[name] = bytes.Replace(b, []byte(old), []byte(value), 1) }
	for _, level := range []struct{ name, key string }{{"envelope", `"Version":1`}, {"decision", `"Sequence":1`}, {"command", `"Kind":"initialize_cluster"`}} {
		replace(level.name+"-duplicate", level.key, level.key+","+level.key)
		replace(level.name+"-unknown", level.key, `"unknown":0,`+level.key)
		replace(level.name+"-whitespace", level.key, " "+level.key)
	}
	replace("shell-order", `"Sequence":1,"ParentDigest":""`, `"ParentDigest":"","Sequence":1`)
	replace("envelope-order", `{"Version":1,"Decision":`, `{"Decision":`)
	cases["envelope-order"] = append(cases["envelope-order"][:len(cases["envelope-order"])-1], []byte(`,"Version":1}`)...)
	replace("command-order", `"Kind":"initialize_cluster","ClusterUID":""`, `"ClusterUID":"","Kind":"initialize_cluster"`)
	for _, v := range []string{"0", "2", "1.0", "1e0", "null", "-1"} {
		replace("version-"+v, `"Version":1`, `"Version":`+v)
	}
	for _, field := range []string{"Sequence", "Session", "Generation", "ExpectedRevision"} {
		old := `"` + field + `":0`
		if field == "Sequence" {
			old = `"Sequence":1`
		}
		for _, v := range []string{"0", "-1", "01", "1.0", "1e0", "null", "9223372036854775807", "9223372036854775808", "18446744073709551615", "18446744073709551616"} {
			replace(field+"-"+v, old, `"`+field+`":`+v)
		}
	}
	for name, token := range map[string]string{"padbits": "Zh==", "missing-padding": "Zg", "excess-padding": "Zg===", "interior-padding": "Z=g=", "url-alphabet": "_w==", "raw-alphabet": "/w", "CR": "Zg\r==", "LF": "Zg\n==", "escaped-ASCII": `\u005ag==`, "escaped-slash": `\/w==`, "invalid-byte": "!g==", "empty": "", "unterminated": `Zg==\`} {
		replace("base64-"+name, `"Ciphertext":"Zg=="`, `"Ciphertext":"`+token+`"`)
	}
	for name, token := range map[string]string{"null": "null", "empty": `""`, "array": "[102]"} {
		replace("ciphertext-"+name, `"Ciphertext":"Zg=="`, `"Ciphertext":`+token)
	}
	replace("ciphertext-omitted", `,"Ciphertext":"Zg=="`, "")
	replace("ciphertext-case", `"Ciphertext"`, `"ciphertext"`)
	replace("ciphertext-escaped-name", `"Ciphertext"`, `"Cipherte\u0078t"`)
	replace("ciphertext-duplicate-before", `"Ciphertext":"Zg=="`, `"Ciphertext":"Zg==","Ciphertext":"Zg=="`)
	replace("ciphertext-duplicate-after", `"Ciphertext":"Zg=="`, `"Ciphertext":"Zg==","Ciphertext":null`)
	replace("ciphertext-wrong-nesting", `"Version":1`, `"Version":1,"Ciphertext":"Zg=="`)
	for name, value := range map[string]string{"quote": `a\"b`, "backslash": `a\\b`, "control": `a\nb`, "html": "<>&", "line-separator": "\u2028\u2029", "invalid-utf8": string([]byte{255}), "lone-surrogate": `\ud800`, "paired-surrogate": `\ud83d\ude00`, "escaped-request": `\u0072eq`, "marker": `x,\"Ciphertext\":\"Zg==\"`} {
		replace("metadata-"+name, `"RequestID":"req"`, `"RequestID":"`+value+`"`)
	}
	for _, kind := range []string{"unsupported", "read_barrier", "initialize_cluster"} {
		replace("kind-"+kind, `"Kind":"initialize_cluster"`, `"Kind":"`+kind+`"`)
	}
	marker := bytes.Index(b, []byte(`,"Ciphertext":"`))
	end := marker + len(`,"Ciphertext":"Zg=="`)
	for _, center := range []int{marker, marker + len(`,"Ciphertext":"`), end, len(b)} {
		for delta := -2; delta <= 2; delta++ {
			n := center + delta
			if n >= 0 && n < len(b) {
				cases[fmt.Sprintf("truncate-%d", n)] = bytes.Clone(b[:n])
			}
		}
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) { compareDecisionOracle(t, input) })
	}
}

func TestDecisionCiphertextBodySemantics(t *testing.T) {
	bodies := map[string][]byte{"nil": nil, "empty": {}, "whitespace-number": []byte("{\n \"version\":1.0,\"x\":10e-1}"), "duplicate": []byte(`{"version":1,"x":{"a":1,"a":1}}`), "utf8": []byte("{\"version\":1,\"x\":\"\xff\"}"), "surrogate": []byte(`{"version":1,"x":"\ud800"}`), "null": []byte(`null`), "array": []byte(`[]`), "scalar": []byte(`1`), "version0": []byte(`{"version":0}`), "version2": []byte(`{"version":2}`)}
	for _, depth := range []int{63, 64, 65} {
		bodies[fmt.Sprintf("depth-%d", depth)] = []byte(`{"version":1,"x":` + strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1) + "}")
	}
	for _, exponent := range []string{"1000000000", "-1000000000", "1000000001", "-1000000001", "9223372036854775808"} {
		bodies["exponent-"+exponent] = []byte(`{"version":1,"x":1e` + exponent + `}`)
	}
	for name, body := range bodies {
		for _, field := range []string{"Body", "Assignment"} {
			t.Run(field+"/"+name, func(t *testing.T) {
				d := ciphertextDecision()
				if field == "Body" {
					d.Command.Body = body
				} else {
					d.Assignment = body
				}
				compareDecisionOracle(t, rawDecision(t, d))
			})
		}
	}
}

func TestDecisionCiphertextMutationCorpus(t *testing.T) {
	seed := rawDecision(t, ciphertextDecision())
	seeds := [][]byte{seed, bytes.Replace(seed, []byte(`"Ciphertext":"Zg=="`), []byte(`"Ciphertext":null`), 1), append(bytes.Clone(seed), ' ')}
	rng := rand.New(rand.NewSource(641))
	for i := 0; i < 4096; i++ {
		b := bytes.Clone(seeds[i%len(seeds)])
		n := rng.Intn(len(b))
		switch i % 4 {
		case 0:
			b[n] = byte(rng.Intn(256))
		case 1:
			b = append(b[:n], b[n+1:]...)
		case 2:
			b = append(b[:n], append([]byte{byte(rng.Intn(256))}, b[n:]...)...)
		case 3:
			b = b[:n]
		}
		if len(b) > 8192 {
			t.Fatal("small corpus exceeded 8 KiB")
		}
		t.Run(fmt.Sprintf("mutation-%04d", i), func(t *testing.T) { compareDecisionOracle(t, b) })
	}
}

// Direct encoder comparisons also cover semantic limits whose JSON cannot fit.
func TestDecisionCiphertextBounds(t *testing.T) {
	check := func(t *testing.T, d Decision) {
		t.Helper()
		wb, we := legacyEncodeDecision(d)
		gb, ge := EncodeDecision(d)
		if Code(we) != Code(ge) || fmt.Sprint(we) != fmt.Sprint(ge) || !bytes.Equal(wb, gb) {
			t.Fatal("encoder differs from frozen oracle")
		}
		compareDecisionOracle(t, rawDecision(t, d))
	}
	for _, field := range []string{"Kind", "ClusterUID", "ProjectUID", "PrincipalID", "OwnerID", "ManagementKey", "RequestID", "ResourceUID", "SecretKeyEpoch", "SessionID"} {
		for _, n := range []int{4095, 4096, 4097} {
			t.Run(fmt.Sprintf("%s-%d", field, n), func(t *testing.T) {
				d := laterCiphertextDecision("read_barrier")
				if field == "SecretKeyEpoch" {
					d.Command.SecretIntentTag = []byte{1}
				}
				reflect.ValueOf(&d.Command).Elem().FieldByName(field).SetString(strings.Repeat("x", n))
				wantCode := ""
				if n > MaxStringBytes {
					wantCode = CodeValidation
				} else if field == "Kind" {
					wantCode = CodeUnsupported
				}
				checkDecisionEncoding(t, d, wantCode)
				check(t, d)
			})
		}
	}
	for _, n := range []int{255, 256, 257} {
		t.Run(fmt.Sprintf("tag-%d", n), func(t *testing.T) {
			d := ciphertextDecision()
			d.Command.SecretIntentTag = bytes.Repeat([]byte{1}, n)
			d.Command.SecretKeyEpoch = "epoch"
			check(t, d)
		})
	}
	for _, field := range []string{"Body", "Assignment"} {
		for _, n := range []int{(1 << 20) - 1, 1 << 20, (1 << 20) + 1} {
			t.Run(fmt.Sprintf("%s-%d", field, n), func(t *testing.T) {
				d := ciphertextDecision()
				body := []byte(`{"version":1,"x":"` + strings.Repeat("x", n-len(`{"version":1,"x":""}`)) + `"}`)
				if field == "Body" {
					d.Command.Body = body
				} else {
					d.Assignment = body
				}
				check(t, d)
			})
		}
	}
	for _, n := range []int{(1 << 20) - 1, 1 << 20, (1 << 20) + 1, MaxDecisionBytes - 1, MaxDecisionBytes, MaxDecisionBytes + 1} {
		t.Run(fmt.Sprintf("ciphertext-%d", n), func(t *testing.T) {
			d := ciphertextDecision()
			d.Command.Ciphertext = bytes.Repeat([]byte{103}, n)
			check(t, d)
		})
	}
	// Adjust a harmless metadata string to hit the complete envelope boundary.
	d := ciphertextDecision()
	d.Command.Ciphertext = bytes.Repeat([]byte{103}, (MaxDecisionBytes-1024)*3/4)
	for _, n := range []int{MaxDecisionBytes - 1, MaxDecisionBytes, MaxDecisionBytes + 1} {
		t.Run(fmt.Sprintf("envelope-%d", n), func(t *testing.T) {
			v := d
			v.Command.ProjectUID = strings.Repeat("x", n-len(rawDecision(t, v)))
			if len(rawDecision(t, v)) != n {
				t.Fatal("boundary fixture size")
			}
			check(t, v)
		})
	}
	for _, n := range []uint64{0, 1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64} {
		t.Run(fmt.Sprintf("sequence-%d", n), func(t *testing.T) {
			d := ciphertextDecision()
			d.Sequence = n
			if n > 1 {
				d.ParentDigest = strings.Repeat("a", 64)
				d.Command.ClusterUID = "cluster"
				d.Command.Kind = "read_barrier"
			}
			check(t, d)
		})
	}
}
