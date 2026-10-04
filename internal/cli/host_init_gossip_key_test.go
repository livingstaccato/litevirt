package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// A new cluster has no plaintext behaviour to preserve, so it starts enforced —
// the same reasoning as the shared-storage floor. There is no rollout to walk:
// every host `lv host add` brings in receives the key and this block together.
func TestNewClusterEnforcement_EnforcesGossipEncryption(t *testing.T) {
	stage, err := enforcementGossipStage(newClusterEnforcement)
	if err != nil {
		t.Fatal(err)
	}
	if stage != corrosion.GossipEncryptionEnforced {
		t.Fatalf("a new cluster starts at gossip stage %v, want enforced", stage)
	}
}

func TestEnforcementGossipStage(t *testing.T) {
	for block, want := range map[string]corrosion.GossipEncryption{
		"":                                   corrosion.GossipEncryptionOff,
		"enforcement:\n  lease_term: true\n": corrosion.GossipEncryptionOff,
		"enforcement:\n  gossip_encryption: install\n":            corrosion.GossipEncryptionInstall,
		"enforcement:\n  gossip_encryption: staged   # comment\n": corrosion.GossipEncryptionStaged,
		"enforcement:\n  gossip_encryption: true\n":               corrosion.GossipEncryptionEnforced,
	} {
		got, err := enforcementGossipStage(block)
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", block, got, err, want)
		}
	}
	if _, err := enforcementGossipStage("enforcement:\n  gossip_encryption: maybe\n"); err == nil {
		t.Error("a bad stage parsed")
	}
}

// The bootstrap mints the key once, 0600, and reuses it after.
func TestEnsureLocalGossipKey(t *testing.T) {
	dir := t.TempDir()
	path, minted, err := ensureLocalGossipKey(dir)
	if err != nil || !minted || path != filepath.Join(dir, pki.GossipKeyName) {
		t.Fatalf("first call: path=%s minted=%v err=%v", path, minted, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("gossip.key: %v mode %v", err, fi.Mode())
	}
	first, _ := os.ReadFile(path)
	if _, minted, err := ensureLocalGossipKey(dir); err != nil || minted {
		t.Fatalf("second call minted=%v err=%v", minted, err)
	}
	again, _ := os.ReadFile(path)
	if !bytes.Equal(first, again) {
		t.Fatal("a second bootstrap replaced the cluster key")
	}
}

// `lv host add` must not provision a host into a cluster whose enforcement
// block says gossip is keyed when it has no key to give it: the new daemon
// would refuse to start (or, worse, the operator "fixes" that by editing the
// flag off on one node). Refuse before anything is minted or pushed.
func TestGossipKeyToPush(t *testing.T) {
	dir := t.TempDir()
	for _, block := range []string{"enforcement:\n  gossip_encryption: install\n", newClusterEnforcement} {
		if _, ok, err := gossipKeyToPush(dir, block); err == nil || ok ||
			!strings.Contains(err.Error(), "install-gossip-key") {
			t.Fatalf("keyed cluster, no local key: ok=%v err=%v", ok, err)
		}
	}
	if _, ok, err := gossipKeyToPush(dir, "enforcement:\n  lease_term: true\n"); err != nil || ok {
		t.Fatalf("plaintext cluster, no local key: ok=%v err=%v — adding a host to a cluster "+
			"that never installed a key must keep working", ok, err)
	}
	if _, _, err := ensureLocalGossipKey(dir); err != nil {
		t.Fatal(err)
	}
	for _, block := range []string{"", newClusterEnforcement} {
		path, ok, err := gossipKeyToPush(dir, block)
		if err != nil || !ok || path != filepath.Join(dir, pki.GossipKeyName) {
			t.Fatalf("local key present (%q): path=%s ok=%v err=%v", block, path, ok, err)
		}
	}
}
