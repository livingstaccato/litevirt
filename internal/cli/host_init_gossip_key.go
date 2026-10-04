package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// ensureLocalGossipKey mints the cluster gossip key into pkiDir the first time a
// cluster is bootstrapped from this machine, beside the CA it mints then too,
// and reuses it after. It never replaces one: that is a rotation.
func ensureLocalGossipKey(pkiDir string) (path string, minted bool, err error) {
	path = filepath.Join(pkiDir, pki.GossipKeyName)
	if _, err := os.Stat(path); err == nil {
		return path, false, nil
	} else if !os.IsNotExist(err) {
		return "", false, err
	}
	k, err := pki.NewGossipKey()
	if err != nil {
		return "", false, err
	}
	if err := pki.WriteGossipKeyring(path, [][]byte{k}); err != nil {
		return "", false, fmt.Errorf("write %s: %w", path, err)
	}
	slog.Info("generated cluster gossip key", "key_id", pki.GossipKeyID(k), "path", path)
	return path, true, nil
}

// enforcementGossipStage reads enforcement.gossip_encryption out of an
// enforcement block as the daemon will parse it.
func enforcementGossipStage(block string) (corrosion.GossipEncryption, error) {
	var cfg struct {
		Enforcement struct {
			GossipEncryption corrosion.GossipEncryption `yaml:"gossip_encryption"`
		} `yaml:"enforcement"`
	}
	if err := yaml.Unmarshal([]byte(block), &cfg); err != nil {
		return 0, fmt.Errorf("parse the enforcement block: %w", err)
	}
	return cfg.Enforcement.GossipEncryption, nil
}

// gossipKeyToPush decides what `lv host add` does about the gossip key: push
// this machine's copy when it has one; otherwise refuse when the block the new
// host will boot with says gossip is keyed (it would refuse to start, or be
// deaf to its peers), and carry on when it does not (a cluster that never
// installed a key).
func gossipKeyToPush(pkiDir, enforcementBlock string) (path string, ok bool, err error) {
	path = filepath.Join(pkiDir, pki.GossipKeyName)
	if _, statErr := os.Stat(path); statErr == nil {
		return path, true, nil
	}
	stage, err := enforcementGossipStage(enforcementBlock)
	if err != nil {
		return "", false, err
	}
	if stage == corrosion.GossipEncryptionOff {
		return "", false, nil
	}
	return "", false, fmt.Errorf("the cluster runs enforcement.gossip_encryption: %s, but this machine has no "+
		"gossip key at %s to give the new host, which could not join gossip without it. Run `lv host add` "+
		"from the machine that holds the cluster's gossip key (the one that ran `lv host init` or "+
		"`lv host install-gossip-key`), or copy that machine's %s here, mode 0600",
		stage, path, pki.GossipKeyName)
}
