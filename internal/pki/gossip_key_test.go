package pki

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewGossipKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewGossipKey_IsAES256AndRandom(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	if len(a) != GossipKeySize || GossipKeySize != 32 {
		t.Fatalf("key is %d bytes, want 32 (AES-256)", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated keys are identical")
	}
}

// The file is a keyring, primary first. Order is the whole meaning of it: the
// first key is the only one memberlist ENCRYPTS with, so a round trip that
// reorders keys would silently change which key a node sends under.
func TestGossipKeyring_RoundTripKeepsOrder(t *testing.T) {
	k1, k2, k3 := mustKey(t), mustKey(t), mustKey(t)
	for _, ring := range [][][]byte{{k1}, {k1, k2}, {k3, k1, k2}} {
		got, err := ParseGossipKeyring(FormatGossipKeyring(ring))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(ring) {
			t.Fatalf("round trip kept %d of %d keys", len(got), len(ring))
		}
		for i := range ring {
			if !bytes.Equal(got[i], ring[i]) {
				t.Fatalf("key %d changed position or content in the round trip", i)
			}
		}
	}
}

func TestParseGossipKeyring_SkipsCommentsAndBlankLines(t *testing.T) {
	k := mustKey(t)
	data := "# a comment\n\n  " + base64.StdEncoding.EncodeToString(k) + "  \n\n"
	got, err := ParseGossipKeyring([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], k) {
		t.Fatal("did not read the one key")
	}
}

func TestParseGossipKeyring_Refuses(t *testing.T) {
	k := mustKey(t)
	enc := base64.StdEncoding.EncodeToString(k)
	short := base64.StdEncoding.EncodeToString(k[:16])
	for name, data := range map[string]string{
		"empty":         "",
		"only comments": "# nothing\n",
		"not base64":    "this is not base64!!\n",
		// memberlist accepts 16 and 24 bytes too. The cluster key is AES-256 and
		// nothing else, so a truncated key is an error rather than a weaker cipher.
		"AES-128 key": short + "\n",
		"duplicate":   enc + "\n" + enc + "\n",
	} {
		if _, err := ParseGossipKeyring([]byte(data)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

// An error about the key file must never carry the key. The daemon logs these
// and the CLI prints them, and a key in a journal is a key anyone with log
// access can join gossip with.
func TestParseGossipKeyring_ErrorsNeverEchoKeyMaterial(t *testing.T) {
	k := mustKey(t)
	enc := base64.StdEncoding.EncodeToString(k)
	for _, data := range []string{
		enc[:20] + "\n",                // truncated key
		enc + "\n" + enc + "\n",        // duplicate
		enc + "\n" + enc[:40] + "!!\n", // one good, one corrupt
	} {
		_, err := ParseGossipKeyring([]byte(data))
		if err == nil {
			t.Fatalf("parsed %q", "(redacted)")
		}
		for _, frag := range []string{enc[:12], enc[20:32]} {
			if strings.Contains(err.Error(), frag) {
				t.Fatalf("error echoes key material: %v", err)
			}
		}
	}
}

func TestGossipKeyID_StableDistinctAndNotTheKey(t *testing.T) {
	k1, k2 := mustKey(t), mustKey(t)
	if GossipKeyID(k1) != GossipKeyID(k1) {
		t.Fatal("ID is not stable")
	}
	if GossipKeyID(k1) == GossipKeyID(k2) {
		t.Fatal("two keys share an ID")
	}
	id := GossipKeyID(k1)
	if len(id) != 16 {
		t.Fatalf("ID %q is not 16 hex chars", id)
	}
	if strings.Contains(base64.StdEncoding.EncodeToString(k1), id) ||
		strings.Contains(strings.ToLower(string(k1)), id) {
		t.Fatal("ID is a substring of the key")
	}
}

func TestWriteGossipKeyring_Is0600AndLoadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), GossipKeyName)
	k1, k2 := mustKey(t), mustKey(t)
	if err := WriteGossipKeyring(path, [][]byte{k1, k2}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("gossip.key is %o, want 0600", fi.Mode().Perm())
	}
	got, err := LoadGossipKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0], k1) || !bytes.Equal(got[1], k2) {
		t.Fatal("loaded keyring differs from what was written")
	}
}

// A key file anyone on the host can read is a key anyone on the host can join
// gossip with. Refuse it rather than use it, the way ssh refuses a loose
// private key.
func TestLoadGossipKeyring_RefusesALooseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), GossipKeyName)
	if err := os.WriteFile(path, FormatGossipKeyring([][]byte{mustKey(t)}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGossipKeyring(path); err == nil {
		t.Fatal("loaded a world-readable gossip key")
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGossipKeyring(path); err != nil {
		t.Fatalf("refused a 0400 key: %v", err)
	}
}

func TestLoadGossipKeyring_Missing(t *testing.T) {
	_, err := LoadGossipKeyring(filepath.Join(t.TempDir(), GossipKeyName))
	if !os.IsNotExist(err) {
		t.Fatalf("missing file: got %v, want a not-exist error", err)
	}
}

func TestGossipKeyringState_RoundTrip(t *testing.T) {
	k1, k2 := mustKey(t), mustKey(t)
	s := NewGossipKeyringState("staged", [][]byte{k1, k2}, 7)
	got, err := ParseGossipKeyringState(s.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "staged" || got.Primary != GossipKeyID(k1) || got.Rejected != 7 ||
		len(got.Keys) != 2 || got.Keys[0] != GossipKeyID(k1) || got.Keys[1] != GossipKeyID(k2) {
		t.Fatalf("state round trip: %+v", got)
	}
	if bytes.Contains(s.Marshal(), []byte(base64.StdEncoding.EncodeToString(k1))) {
		t.Fatal("state file carries the key")
	}
	off, err := ParseGossipKeyringState(NewGossipKeyringState("off", nil, 0).Marshal())
	if err != nil || off.Mode != "off" || off.Primary != "" || len(off.Keys) != 0 {
		t.Fatalf("off state: %+v %v", off, err)
	}
}
