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

// Adding a client authority handle must not change any previously certified
// control bytes, including the enclosing byte-slice encodings.
func TestAutomationSessionHandlePreservesControlEncoding(t *testing.T) {
	const old = `{"Version":1,"Decision":{"Sequence":1,"ParentDigest":"","Command":{"Kind":"initialize_cluster","ClusterUID":"","ProjectUID":"","PrincipalID":"host","OwnerID":"","ManagementKey":"","RequestID":"request","ResourceUID":"","Session":0,"Generation":0,"ExpectedRevision":0,"Body":"eyJ2ZXJzaW9uIjoxfQ==","Ciphertext":null,"SecretIntentTag":null,"SecretKeyEpoch":""},"Assignment":"eyJ2ZXJzaW9uIjoxLCJjbHVzdGVyX3VpZCI6ImNsdXN0ZXIiLCJvcGVyYXRpb25faWQiOiJvcCIsInJlY29yZGVkX2F0IjoiMjAyNi0xMC0xN1QwMDowMDowMFoifQ=="}}`
	d, err := DecodeDecision([]byte(old))
	if err != nil {
		t.Fatal("old certified bytes no longer decode", err)
	}
	b, err := EncodeDecision(d)
	if err != nil || string(b) != old {
		t.Fatal("old certified control bytes changed", err)
	}
	before, err := CanonicalCommand(d.Command)
	if err != nil {
		t.Fatal(err)
	}
	d.Command.SessionID = "successor-session"
	d.Command.Session = 42
	after, err := CanonicalCommand(d.Command)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("authority handoff changed immutable request identity", err)
	}
	withSession, err := EncodeDecision(d)
	if err != nil || bytes.Equal(b, withSession) {
		t.Fatal("certified decision did not bind session handle", err)
	}
}
