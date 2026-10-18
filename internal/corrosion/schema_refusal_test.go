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
