package contract

import (
	"bytes"
	"reflect"
	"testing"
)

// Mutation: use retry identity instead of the full command, or normalize Body.
func TestDecisionCompleteCanonicalBytes(t *testing.T) {
	d := Decision{Sequence: 1, Command: Command{Kind: "initialize_cluster", ClusterUID: "", RequestID: "req", Session: 9, Body: []byte("{\n \"version\":1}"), Ciphertext: []byte{0, 255, 3}, SecretIntentTag: []byte{4}, SecretKeyEpoch: "epoch"}, Assignment: []byte(`{"version":1,"operation":"op"}`)}
	b, err := EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDecision(b)
	if err != nil || !reflect.DeepEqual(d, got) {
		t.Fatal("complete bytes lost", err)
	}
	identity, _ := CanonicalCommand(d.Command)
	d.Command.Session++
	d.Command.Ciphertext[0]++
	retry, _ := CanonicalCommand(d.Command)
	if !bytes.Equal(identity, retry) {
		t.Fatal("retry identity changed")
	}
	changed, _ := EncodeDecision(d)
	if bytes.Equal(b, changed) {
		t.Fatal("recovery bytes not bound")
	}
	for _, bad := range [][]byte{append(b, ' '), bytes.Replace(b, []byte(`"Version":1`), []byte(`"Version":2`), 1), bytes.Replace(b, []byte(`"Version":1`), []byte(`"Version":1,"Version":1`), 1)} {
		if _, err := DecodeDecision(bad); err == nil {
			t.Fatal("noncanonical envelope accepted")
		}
	}
}
