package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

func loadConfigText(t *testing.T, text string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("host_name: n\n"+text), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", path)
	return LoadConfig()
}

// enforcement.gossip_encryption is a bool that also takes the two named
// rollout stages. The bool spellings are the documented ones, so they must
// parse as a YAML bool would be written.
func TestLoadConfig_GossipEncryption(t *testing.T) {
	for text, want := range map[string]corrosion.GossipEncryption{
		"": corrosion.GossipEncryptionOff,
		"enforcement:\n  gossip_encryption: false\n":   corrosion.GossipEncryptionOff,
		"enforcement:\n  gossip_encryption: install\n": corrosion.GossipEncryptionInstall,
		"enforcement:\n  gossip_encryption: staged\n":  corrosion.GossipEncryptionStaged,
		"enforcement:\n  gossip_encryption: true\n":    corrosion.GossipEncryptionEnforced,
	} {
		cfg, err := loadConfigText(t, text)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if got := cfg.Enforcement.GossipEncryption; got != want {
			t.Errorf("%q: stage %v, want %v", text, got, want)
		}
	}
	if _, err := loadConfigText(t, "enforcement:\n  gossip_encryption: yes-please\n"); err == nil {
		t.Fatal("a typo'd stage loaded")
	}
}

func TestGossipKeysFor(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{PKIDir: dir}

	// Off: the file is not even read, so a key that is present but unused is
	// not held in memory.
	cfg.Enforcement.GossipEncryption = corrosion.GossipEncryptionOff
	if err := os.WriteFile(filepath.Join(dir, pki.GossipKeyName), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if keys, err := gossipKeysFor(cfg); err != nil || keys != nil {
		t.Fatalf("off: keys=%v err=%v", keys, err)
	}

	// Any other stage without a usable key refuses to start, naming the command.
	if err := os.Remove(filepath.Join(dir, pki.GossipKeyName)); err != nil {
		t.Fatal(err)
	}
	for _, m := range []corrosion.GossipEncryption{
		corrosion.GossipEncryptionInstall, corrosion.GossipEncryptionStaged, corrosion.GossipEncryptionEnforced,
	} {
		cfg.Enforcement.GossipEncryption = m
		_, err := gossipKeysFor(cfg)
		if err == nil || !strings.Contains(err.Error(), "lv host install-gossip-key") {
			t.Fatalf("%v with no key file: %v", m, err)
		}
	}

	k, _ := pki.NewGossipKey()
	if err := pki.WriteGossipKeyring(filepath.Join(dir, pki.GossipKeyName), [][]byte{k}); err != nil {
		t.Fatal(err)
	}
	keys, err := gossipKeysFor(cfg)
	if err != nil || len(keys) != 1 || pki.GossipKeyID(keys[0]) != pki.GossipKeyID(k) {
		t.Fatalf("enforced with a key file: keys=%v err=%v", keys, err)
	}
}
