package custody

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func equalityFixture(t *testing.T, epoch string, material byte) BootstrapEqualityKey {
	t.Helper()
	key, err := NewBootstrapEqualityKey(epoch, bytes.Repeat([]byte{material}, 32))
	if err != nil {
		t.Fatal("valid equality key refused")
	}
	return key
}
func TestAutomationSecretRawIntentEquality(t *testing.T) {
	key := equalityFixture(t, "epoch-old", 0x37)
	scope := IntentScope{"cluster", "owner/request-namespace", "CreateVM"}
	raw := RawBootstrapIntent{Present: true, UserData: []byte("user\x00\xff\r\n"), Metadata: []byte("local-hostname: name\n"), NetworkConfig: []byte{}}
	tag, err := key.IntentTag("epoch-old", scope, raw)
	if err != nil || len(tag) != 32 {
		t.Fatal("raw tag unavailable")
	}
	// Independent fixed HMAC vector pins the domain, version/lengths and presence.
	expected, _ := hex.DecodeString("29db7b670ca6f585307faa819f0eac62a1a5fa502aef29cf5a891ecefe44247f")
	if !bytes.Equal(tag, expected) {
		t.Fatal("private intent framing fixture changed")
	}
	same, err := key.CompareIntent("epoch-old", scope, raw, tag)
	if err != nil || !same {
		t.Fatal("same raw input failed comparison")
	}
	variations := []RawBootstrapIntent{
		{Present: false}, {Present: true},
		{Present: true, UserData: nil, Metadata: raw.Metadata, NetworkConfig: raw.NetworkConfig},
		{Present: true, UserData: []byte{}, Metadata: raw.Metadata, NetworkConfig: raw.NetworkConfig},
		{Present: true, UserData: append(bytes.Clone(raw.UserData), 'x'), Metadata: raw.Metadata, NetworkConfig: raw.NetworkConfig},
		{Present: true, UserData: raw.UserData, Metadata: []byte("local-hostname: 'name'\n"), NetworkConfig: raw.NetworkConfig},
		{Present: true, UserData: raw.UserData, Metadata: raw.Metadata, NetworkConfig: nil},
		{Present: true, UserData: raw.UserData, Metadata: raw.Metadata, NetworkConfig: []byte("network")},
	}
	for _, changed := range variations {
		same, err := key.CompareIntent("epoch-old", scope, changed, tag)
		if err != nil || same {
			t.Fatal("changed raw bytes or presence retained equality")
		}
	}
	for _, changed := range []IntentScope{{"other", scope.Namespace, scope.Method}, {scope.ClusterUID, "other", scope.Method}, {scope.ClusterUID, scope.Namespace, "UpdateVM"}} {
		same, err := key.CompareIntent("epoch-old", changed, raw, tag)
		if err != nil || same {
			t.Fatal("changed cluster/namespace/method retained equality")
		}
	}
	absent, _ := key.IntentTag("epoch-old", scope, RawBootstrapIntent{})
	empty, _ := key.IntentTag("epoch-old", scope, RawBootstrapIntent{Present: true})
	if bytes.Equal(absent, empty) {
		t.Fatal("outer message presence erased")
	}
	// Field boundaries cannot collide even when concatenated bytes are equal.
	left, _ := key.IntentTag("epoch-old", scope, RawBootstrapIntent{Present: true, UserData: []byte("ab"), Metadata: []byte("c")})
	right, _ := key.IntentTag("epoch-old", scope, RawBootstrapIntent{Present: true, UserData: []byte("a"), Metadata: []byte("bc")})
	if bytes.Equal(left, right) {
		t.Fatal("field length framing ambiguous")
	}
}

func TestAutomationSecretEqualityHistoricalEpochAndUnavailable(t *testing.T) {
	old := equalityFixture(t, "old", 1)
	active := equalityFixture(t, "new", 2)
	scope := IntentScope{"cluster", "namespace", "CreateVM"}
	raw := RawBootstrapIntent{Present: true, UserData: []byte{}}
	original, err := old.IntentTag("old", scope, raw)
	if err != nil {
		t.Fatal("historical tag unavailable")
	}
	same, err := old.CompareIntent("old", scope, raw, original)
	if err != nil || !same {
		t.Fatal("historical retry lost equality")
	}
	next, err := active.IntentTag("new", scope, raw)
	if err != nil || bytes.Equal(original, next) {
		t.Fatal("independent epoch key did not change tag")
	}
	for _, key := range []BootstrapEqualityKey{active, {}} {
		tag, err := key.IntentTag("old", scope, raw)
		if err == nil || tag != nil || err.Error() != "bootstrap equality key unavailable" {
			t.Fatal("wrong or missing epoch fabricated a tag")
		}
	}
	for _, material := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := NewBootstrapEqualityKey("old", material); err == nil {
			t.Fatal("invalid key length accepted")
		}
	}
	if _, err := NewBootstrapEqualityKey("", make([]byte, 32)); err == nil {
		t.Fatal("missing epoch accepted")
	}
	for _, bad := range []RawBootstrapIntent{{UserData: []byte{}}, {Metadata: []byte("SECRET-MARKER")}, {NetworkConfig: []byte{}}} {
		tag, err := old.IntentTag("old", scope, bad)
		if err == nil || tag != nil || err.Error() != "invalid bootstrap intent" {
			t.Fatal("inconsistent message presence accepted or leaked")
		}
	}
	for _, bad := range []IntentScope{{}, {"cluster", "", "CreateVM"}, {"cluster", "namespace", ""}} {
		tag, err := old.IntentTag("old", bad, raw)
		if err == nil || tag != nil {
			t.Fatal("missing equality scope accepted")
		}
	}
	for _, tag := range [][]byte{nil, make([]byte, 31), make([]byte, 33), bytes.Repeat([]byte{9}, 32)} {
		same, err := old.CompareIntent("old", scope, raw, tag)
		if err != nil || same {
			t.Fatal("invalid or unequal tag matched")
		}
	}
	// Import copies material; subsequent caller edits cannot change history.
	material := bytes.Repeat([]byte{1}, 32)
	owned, err := NewBootstrapEqualityKey("old", material)
	if err != nil {
		t.Fatal("import failed")
	}
	material[0]++
	same, err = owned.CompareIntent("old", scope, raw, original)
	if err != nil || !same {
		t.Fatal("key aliases imported material")
	}
}

func TestAutomationSecretIntentAggregateBoundsAndEveryFieldPresence(t *testing.T) {
	key := equalityFixture(t, "epoch", 9)
	scope := IntentScope{"cluster", "namespace", "method"}
	absent, err := key.IntentTag("epoch", scope, RawBootstrapIntent{Present: true})
	if err != nil {
		t.Fatal("absent fields failed")
	}
	for _, raw := range []RawBootstrapIntent{{Present: true, UserData: []byte{}}, {Present: true, Metadata: []byte{}}, {Present: true, NetworkConfig: []byte{}}} {
		tag, err := key.IntentTag("epoch", scope, raw)
		if err != nil || bytes.Equal(tag, absent) {
			t.Fatal("individual field presence erased")
		}
	}
	for _, raw := range []RawBootstrapIntent{{Present: true, UserData: make([]byte, bootstrapPlaintextMaxBytes)}, {Present: true, UserData: make([]byte, bootstrapPlaintextMaxBytes/2), Metadata: make([]byte, bootstrapPlaintextMaxBytes/2)}} {
		tag, err := key.IntentTag("epoch", scope, raw)
		if err == nil || tag != nil || err.Error() != "invalid bootstrap intent" {
			t.Fatal("oversized aggregate intent accepted")
		}
	}
}
