package automation_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation"
	"gopkg.in/yaml.v3"
)

func TestBootstrapPreservesBytes(t *testing.T) {
	user := []byte("#cloud-config\nruncmd:\n - echo ready\n")
	network := []byte("version: 2\nethernets: {}\n")
	gotUser, meta, gotNetwork, err := automation.NormalizeBootstrap("resource-1", "node-1", user, []byte("local-hostname: chosen\n"), network)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(user, gotUser) || !bytes.Equal(network, gotNetwork) {
		t.Fatal("caller payload changed")
	}
	var got map[string]any
	if err := yaml.Unmarshal(meta, &got); err != nil {
		t.Fatal("normalized metadata is invalid")
	}
	if got["instance-id"] != "resource-1" || got["local-hostname"] != "chosen" {
		t.Fatal("assigned identity or explicit hostname lost")
	}
	_, _, _, err = automation.NormalizeBootstrap("resource-1", "node-1", user, []byte("instance-id: foreign\n"), network)
	if err == nil {
		t.Fatal("conflicting instance-id accepted")
	}
}

func TestBootstrapPreservesOpaquePayloadPresence(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"absent", nil}, {"empty", []byte{}}, {"crlf", []byte("\xef\xbb\xbf#cloud-config\r\n \r\n")},
		{"binary", []byte{0, 255, 254, '\r', '\n', 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, _, network, err := automation.NormalizeBootstrap("resource-1", "node-1", tc.data, nil, tc.data)
			if err != nil {
				t.Fatal(err)
			}
			wantUser := tc.data
			if tc.data == nil {
				wantUser = []byte("#cloud-config\n{}\n")
			}
			if !reflect.DeepEqual(user, wantUser) || !reflect.DeepEqual(network, tc.data) {
				t.Fatal("opaque payload bytes or nil/empty presence changed")
			}
		})
	}
}

func TestBootstrapDefaultsOnlyAbsentMetadataKeys(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    []byte
		hostname string
	}{
		{"absent document", nil, "node-1"},
		{"empty mapping", []byte("{}\n"), "node-1"},
		{"missing hostname", []byte("instance-id: resource-1\ncustom: {nested: [one, 2, true]}\n"), "node-1"},
		{"missing identity", []byte("local-hostname: chosen.example\ncustom: {nested: [one, 2, true]}\n"), "chosen.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.input)
			_, meta, _, err := automation.NormalizeBootstrap("resource-1", "node-1", nil, tc.input, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tc.input, original) {
				t.Fatal("input metadata mutated")
			}
			var got map[string]any
			if err := yaml.Unmarshal(meta, &got); err != nil {
				t.Fatal("normalized metadata is invalid")
			}
			if got["instance-id"] != "resource-1" || got["local-hostname"] != tc.hostname {
				t.Fatal("metadata defaults or caller hostname incorrect")
			}
			if tc.name == "missing hostname" || tc.name == "missing identity" {
				want := map[string]any{"nested": []any{"one", 2, true}}
				if !reflect.DeepEqual(got["custom"], want) {
					t.Fatal("caller metadata value changed")
				}
			}
		})
	}
}

func TestBootstrapPreservesCompleteMetadataBytes(t *testing.T) {
	for _, input := range []string{
		"# keep comment\r\nlocal-hostname: 'chosen'\r\ninstance-id: resource-1\r\ncustom: {b: 2, a: [true, null]}\r\n",
		"{\"instance-id\": \"resource-1\", \"local-hostname\": \"chosen.example\", \"custom\": \"value\"}",
		"---\ninstance-id: resource-1\nlocal-hostname: chosen\n...\n",
		"instance-id: resource-1\nlocal-hostname: chosen\n'<<': literal\ncustom: &unused value\n",
	} {
		_, meta, _, err := automation.NormalizeBootstrap("resource-1", "node-1", nil, []byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(meta, []byte(input)) {
			t.Fatal("complete metadata bytes changed")
		}
	}
}

func TestBootstrapRejectsInvalidMetadata(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"empty", ""}, {"whitespace", " \n"}, {"comment only", "# comment\n"},
		{"null", "null\n"}, {"scalar", "plain\n"}, {"sequence", "[one, two]\n"},
		{"malformed", "key: [unterminated\n"}, {"foreign identity", "instance-id: foreign\n"},
		{"numeric identity", "instance-id: 42\n"}, {"null identity", "instance-id: null\n"},
		{"sequence identity", "instance-id: [resource-1]\n"}, {"empty identity", "instance-id: ''\n"},
		{"numeric hostname", "local-hostname: 42\n"}, {"null hostname", "local-hostname: null\n"},
		{"mapping hostname", "local-hostname: {}\n"}, {"empty hostname", "local-hostname: ''\n"},
		{"duplicate", "custom: one\ncustom: two\n"}, {"duplicate identity", "instance-id: resource-1\ninstance-id: resource-1\n"},
		{"quoted duplicate", "custom: one\n'custom': two\n"}, {"nested duplicate", "custom: {key: one, key: two}\n"},
		{"nonstring key", "42: value\n"}, {"complex key", "? [one, two]\n: value\n"},
		{"nested nonstring key", "custom: {true: value}\n"},
		{"alias", "custom: &value [one]\nother: *value\n"},
		{"merge", "custom: {<<: {key: value}}\n"},
		{"multiple documents", "{}\n---\n{}\n"}, {"trailing empty document", "{}\n---\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, meta, network, err := automation.NormalizeBootstrap("resource-1", "node-1", []byte("private-user"), []byte(tc.input), []byte("private-network"))
			if err == nil {
				t.Fatal("invalid metadata accepted")
			}
			if user != nil || meta != nil || network != nil {
				t.Fatal("failure returned partial payload")
			}
		})
	}
}

func TestBootstrapRejectsUnboundedMetadata(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"bytes", "custom: '" + strings.Repeat("x", 256*1024) + "'\n"},
		{"depth", "custom: " + strings.Repeat("[", 80) + "0" + strings.Repeat("]", 80) + "\n"},
		{"nodes", "custom: [" + strings.Repeat("0,", 17000) + "]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := automation.NormalizeBootstrap("resource-1", "node-1", nil, []byte(tc.input), nil); err == nil {
				t.Fatal("unbounded metadata accepted")
			}
		})
	}
}

func TestBootstrapDeterministicAndIdempotent(t *testing.T) {
	input := []byte("custom: {z: 3, a: [one, true]}\n")
	_, first, _, err := automation.NormalizeBootstrap("resource-1", "node-1", nil, input, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, second, _, err := automation.NormalizeBootstrap("resource-1", "node-1", nil, input, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, replay, _, err := automation.NormalizeBootstrap("resource-1", "renamed-node", nil, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || !bytes.Equal(first, replay) {
		t.Fatal("normalization changed across repetition or rename")
	}
}

func TestBootstrapOwnsReturnedData(t *testing.T) {
	user := []byte("user")
	metadata := []byte("instance-id: resource-1\nlocal-hostname: chosen\n")
	network := []byte("network")
	originals := [][]byte{bytes.Clone(user), bytes.Clone(metadata), bytes.Clone(network)}
	u, m, n, err := automation.NormalizeBootstrap("resource-1", "node-1", user, metadata, network)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{u, m, n} {
		data[0] ^= 1
	}
	for i, data := range [][]byte{user, metadata, network} {
		if !bytes.Equal(data, originals[i]) {
			t.Fatal("returned payload aliases caller storage")
		}
	}
	u, m, n, err = automation.NormalizeBootstrap("resource-1", "node-1", user, metadata, network)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{user, metadata, network} {
		data[0] ^= 1
	}
	for i, data := range [][]byte{u, m, n} {
		if !bytes.Equal(data, originals[i]) {
			t.Fatal("caller mutation changed admitted payload")
		}
	}
}

func TestBootstrapErrorsDoNotDisclosePayloads(t *testing.T) {
	for _, metadata := range []string{"private-marker: [unterminated\n", "instance-id: private-marker\n", "local-hostname: [private-marker]\n"} {
		_, _, _, err := automation.NormalizeBootstrap("resource-1", "node-1", []byte("private-user"), []byte(metadata), []byte("private-network"))
		if err == nil {
			t.Fatal("invalid metadata accepted")
		}
		for _, marker := range []string{"private-marker", "private-user", "private-network"} {
			if strings.Contains(err.Error(), marker) {
				t.Fatal("error disclosed caller payload")
			}
		}
	}
}

func TestBootstrapRejectsDefaultsExceedingMetadataBudget(t *testing.T) {
	for _, input := range []string{
		"custom: [" + strings.Repeat("0,", 16380) + "]\n",
		"custom: '" + strings.Repeat("x", 256*1024-20) + "'\n",
	} {
		_, _, _, err := automation.NormalizeBootstrap("resource-1", "node-1", nil, []byte(input), nil)
		if err == nil {
			t.Fatal("normalization accepted metadata whose defaults exceed the safety budget")
		}
	}
}

func TestBootstrapDefaultsAbsentUserDataWithCompleteMetadata(t *testing.T) {
	metadata := []byte("instance-id: resource-1\nlocal-hostname: chosen\n")
	user, meta, _, err := automation.NormalizeBootstrap("resource-1", "node-1", nil, metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(user, []byte("#cloud-config\n{}\n")) || !bytes.Equal(meta, metadata) {
		t.Fatal("absent user-data default or complete metadata changed")
	}
}

func TestBootstrapRejectsMissingAdmittedFacts(t *testing.T) {
	for _, facts := range []struct{ uid, name string }{
		{"", "node-1"},
		{"resource-1", ""},
	} {
		for _, metadata := range [][]byte{nil, []byte("instance-id: resource-1\nlocal-hostname: chosen\n")} {
			user, meta, network, err := automation.NormalizeBootstrap(facts.uid, facts.name, []byte("user"), metadata, []byte("network"))
			if err == nil {
				t.Fatal("missing assigned UID or admitted name accepted")
			}
			if user != nil || meta != nil || network != nil {
				t.Fatal("failure returned partial payload")
			}
		}
	}
}
