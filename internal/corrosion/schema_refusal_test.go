package corrosion

import (
	"testing"
	"time"
)

// A peer that left the membership is no longer pushed to, so nothing would
// ever replace its last schema answer: syncPeers drops it, and a refusal
// from a removed host does not re-raise its resolved condition (m2).
func TestSyncPeers_DropsSchemaStateOfDepartedPeers(t *testing.T) {
	c := NewTestClientT(t)
	members := []PeerInfo{{Name: "kept", Addr: "127.0.0.1"}}
	c.SetMembersForTests(func() []PeerInfo { return members })
	r := NewReplicator(c, "", RelayConfig{})
	t.Cleanup(r.Stop)

	now := time.Now()
	r.noteSchemaRefusal("kept", 68, 67, now)
	r.noteSchemaRefusal("gone", 68, 67, now)
	r.noteSchemaAccepted("gone-too", 68, now)
	r.syncPeers()

	got := r.SchemaRefusals(now)
	if _, ok := got["gone"]; ok {
		t.Error("a departed peer's refusal outlived its membership")
	}
	if _, ok := got["kept"]; !ok {
		t.Error("a member's refusal was dropped")
	}
	if _, ok := r.SchemaAccepted("gone-too", now); ok {
		t.Error("a departed peer's acceptance outlived its membership")
	}
}

// A refusal records when its run began, so a refusal that lasts can be told
// from the brief one every peer gives mid pre-stage. An accepted push ends
// the run.
func TestSchemaRefusal_RecordsWhenTheRunBegan(t *testing.T) {
	c := NewTestClientT(t)
	r := NewReplicator(c, "", RelayConfig{})
	t0 := time.Now().Add(-time.Minute)
	r.noteSchemaRefusal("p", 68, 67, t0)
	r.noteSchemaRefusal("p", 68, 67, t0.Add(30*time.Second))
	got := r.SchemaRefusals(t0.Add(30 * time.Second))["p"]
	if !got.Since.Equal(t0) || !got.At.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("refusal %+v: want since %v, at %v", got, t0, t0.Add(30*time.Second))
	}

	r.noteSchemaAccepted("p", 68, t0.Add(40*time.Second))
	r.noteSchemaRefusal("p", 69, 68, t0.Add(50*time.Second))
	if got := r.SchemaRefusals(t0.Add(50 * time.Second))["p"]; !got.Since.Equal(t0.Add(50 * time.Second)) {
		t.Fatalf("refusal after an accepted push %+v: want a new run from %v", got, t0.Add(50*time.Second))
	}
}
