package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// gossipKeyReloadInterval is how often the daemon re-reads gossip.key. The
// rotate command waits on the state file rather than on this number, so it
// only bounds how long each rotation phase takes.
const gossipKeyReloadInterval = 5 * time.Second

// gossipKeysFor loads the gossip keyring the configured stage needs.
//
// Off reads nothing, so a key that is installed but unused is not held in
// memory. Every other stage requires a usable pki_dir/gossip.key and refuses to
// start without one: "enforced, but nothing to enforce with" would be a node
// that joins plaintext under a flag that says it does not.
func gossipKeysFor(cfg *Config) (corrosion.GossipKeys, error) {
	mode := cfg.Enforcement.GossipEncryption
	if mode == corrosion.GossipEncryptionOff {
		return nil, nil
	}
	path := filepath.Join(cfg.PKIDir, pki.GossipKeyName)
	keys, err := pki.LoadGossipKeyring(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("enforcement.gossip_encryption is %s but %s does not exist: install the "+
			"cluster gossip key first with `lv host install-gossip-key` (docs/auth.md, \"Gossip "+
			"encryption\"), or set the flag back to false", mode, path)
	}
	if err != nil {
		return nil, fmt.Errorf("enforcement.gossip_encryption is %s but the gossip key cannot be used: %w", mode, err)
	}
	return corrosion.GossipKeys(keys), nil
}
