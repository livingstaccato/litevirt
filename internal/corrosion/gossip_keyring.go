package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/secretfile"
)

// Gossip encryption (colonelpanik/litevirt#259, step 2).
//
// Step 1 (gossip_admission.go) made memberlist admit only hosts in the hosts
// table. That is admission, not authentication: anyone who can reach port 7946
// can still send a packet claiming to be a member, and read who the members
// are. Step 2 is memberlist's own keyring — AES-256-GCM over every gossip packet
// and stream, keyed by a cluster-wide secret held in pki_dir/gossip.key.
//
// # Stages
//
// memberlist cannot switch encryption on under a running cluster in one step: a
// node that sends encrypted is unreadable to a peer without the key, and a node
// that refuses plaintext is deaf to a peer that still sends it. Its answer is
// two knobs, GossipVerifyOutgoing and GossipVerifyIncoming, and litevirt exposes
// the walk between them as four stages of enforcement.gossip_encryption:
//
//	stage     keyring  sends       accepts
//	off       none     plaintext   plaintext           (today; false)
//	install   loaded   plaintext   plaintext+encrypted
//	staged    loaded   encrypted   plaintext+encrypted
//	enforced  loaded   encrypted   encrypted only      (true)
//
// Two nodes interoperate exactly when their stages are ADJACENT (see
// gossipStagesCompatible, and the real-memberlist matrix test that checks it).
// A rolling restart moves each node one stage, so every pair during the roll is
// at most one stage apart and the cluster never splits — provided the roll
// finishes on EVERY node before the next one starts. "install" is the stage
// people want to skip and must not: without it the first node to send encrypted
// is unreadable to every node still without a keyring.
//
// The stage is config, read once at startup, because memberlist reads the two
// verify flags without a lock for the life of the process. The KEYS are not:
// memberlist's Keyring is built for live change, and WatchGossipKeyFile applies
// a new gossip.key without a restart, which is what makes rotation cheap.
//
// # Why there is no capability token
//
// CLAUDE.md: ask where the guarantee is enforced before adding one. Here it is
// enforced by the RECEIVER, locally — a node in "enforced" drops what it cannot
// authenticate, whatever any peer believes. No node relies on a peer honouring
// anything for correctness, and a peer on the wrong stage costs availability
// (that pair cannot talk), never data: replication rides mTLS gRPC and is
// untouched. A token could not help the rollout either — a latch observed at
// runtime cannot change memberlist's verify flags, so it would only take effect
// at the next restart, which is the operator's rolling restart anyway. And it
// would be circular: ReplicationGated latches are confirmed against gossip
// membership, the thing a mis-staged node would be missing from. So the
// sequence is the operator's, verified per host by the state file the daemon
// writes (pki.GossipKeyringState) and its rejection count.

// GossipEncryption is a node's gossip encryption stage. Its zero value is off.
// Order matters: each stage is one step from its neighbours.
type GossipEncryption int

const (
	GossipEncryptionOff GossipEncryption = iota
	GossipEncryptionInstall
	GossipEncryptionStaged
	GossipEncryptionEnforced
)

func (m GossipEncryption) String() string {
	switch m {
	case GossipEncryptionOff:
		return "off"
	case GossipEncryptionInstall:
		return "install"
	case GossipEncryptionStaged:
		return "staged"
	case GossipEncryptionEnforced:
		return "enforced"
	}
	return fmt.Sprintf("GossipEncryption(%d)", int(m))
}

// UnmarshalText reads enforcement.gossip_encryption. The flag is documented as
// a bool defaulting to false, so false and true are its ends (true is the full
// guarantee, not a half-way stage); install and staged are the steps between.
// Anything else is an error, so a typo stops the daemon rather than quietly
// selecting some stage.
func (m *GossipEncryption) UnmarshalText(b []byte) error {
	switch string(b) {
	case "", "false", "off":
		*m = GossipEncryptionOff
	case "install":
		*m = GossipEncryptionInstall
	case "staged":
		*m = GossipEncryptionStaged
	case "true", "enforced":
		*m = GossipEncryptionEnforced
	default:
		return fmt.Errorf("gossip_encryption: %q is not a stage; use false, install, staged or true", string(b))
	}
	return nil
}

// MarshalText writes the flag's own spelling: false and true at the ends.
func (m GossipEncryption) MarshalText() ([]byte, error) {
	switch m {
	case GossipEncryptionOff:
		return []byte("false"), nil
	case GossipEncryptionEnforced:
		return []byte("true"), nil
	case GossipEncryptionInstall, GossipEncryptionStaged:
		return []byte(m.String()), nil
	}
	return nil, fmt.Errorf("unknown gossip encryption stage %d", int(m))
}

// hasKey, sendsEncrypted and verifiesIncoming are the three facts a stage
// fixes; configureGossipEncryption and gossipStagesCompatible both derive from
// them, so the model the operator sequence rests on and the memberlist config
// cannot drift apart.
func (m GossipEncryption) hasKey() bool           { return m != GossipEncryptionOff }
func (m GossipEncryption) sendsEncrypted() bool   { return m >= GossipEncryptionStaged }
func (m GossipEncryption) verifiesIncoming() bool { return m == GossipEncryptionEnforced }

// gossipStagesCompatible reports whether nodes in stages a and b can gossip in
// both directions: whatever one sends encrypted the other can decrypt, and
// whatever one refuses unencrypted the other does not send unencrypted.
func gossipStagesCompatible(a, b GossipEncryption) bool {
	oneWay := func(from, to GossipEncryption) bool {
		if from.sendsEncrypted() && !to.hasKey() {
			return false
		}
		if to.verifiesIncoming() && !from.sendsEncrypted() {
			return false
		}
		return true
	}
	return oneWay(a, b) && oneWay(b, a)
}

// GossipKeys is a gossip keyring, primary first. It formats as key IDs only —
// under every fmt verb, slog and JSON — so a Config or keyring that ends up in
// a log line or an error carries nothing anyone could join gossip with.
type GossipKeys [][]byte

func (k GossipKeys) redacted() string {
	return "GossipKeys[" + strings.Join(pki.GossipKeyIDs(k), ",") + "]"
}

// Format implements fmt.Formatter for every verb, %#v and %x included.
func (k GossipKeys) Format(f fmt.State, _ rune) { fmt.Fprint(f, k.redacted()) }

// LogValue implements slog.LogValuer.
func (k GossipKeys) LogValue() slog.Value { return slog.StringValue(k.redacted()) }

// MarshalJSON implements json.Marshaler.
func (k GossipKeys) MarshalJSON() ([]byte, error) { return json.Marshal(k.redacted()) }

// validate is ParseGossipKeyring's rules for a keyring handed over in memory.
func (k GossipKeys) validate() error {
	if len(k) == 0 {
		return fmt.Errorf("gossip keyring is empty")
	}
	for i, key := range k {
		if len(key) != pki.GossipKeySize {
			return fmt.Errorf("gossip key %d is %d bytes; the cluster key is %d (AES-256)", i+1, len(key), pki.GossipKeySize)
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(k[j], key) {
				return fmt.Errorf("gossip key %d repeats key %d", i+1, j+1)
			}
		}
	}
	return nil
}

// configureGossipEncryption applies a stage and keyring to a memberlist config,
// returning the keyring memberlist will use (nil when off) so it can be changed
// live. A stage that needs a key and has none is an error: coming up plaintext
// under "enforced" is the silent downgrade this whole step exists to prevent.
func configureGossipEncryption(cfg *memberlist.Config, mode GossipEncryption, keys GossipKeys) (*memberlist.Keyring, error) {
	switch mode {
	case GossipEncryptionOff:
		cfg.Keyring, cfg.SecretKey = nil, nil
		return nil, nil
	case GossipEncryptionInstall, GossipEncryptionStaged, GossipEncryptionEnforced:
	default:
		return nil, fmt.Errorf("unknown gossip encryption stage %d", int(mode))
	}
	if err := keys.validate(); err != nil {
		return nil, fmt.Errorf("enforcement.gossip_encryption is %s: %w", mode, err)
	}
	ring, err := memberlist.NewKeyring(keys[1:], keys[0])
	if err != nil {
		return nil, fmt.Errorf("gossip keyring: %w", err)
	}
	cfg.Keyring, cfg.SecretKey = ring, nil
	cfg.GossipVerifyOutgoing = mode.sendsEncrypted()
	cfg.GossipVerifyIncoming = mode.verifiesIncoming()
	return ring, nil
}

// SetGossipKeys replaces the live keyring with keys, keys[0] becoming the key
// this node encrypts with. It adds before it promotes and promotes before it
// removes, so no instant ever holds fewer keys than either end state.
//
// The CALLER owns the cluster-wide ordering — a key must be on every node
// before any node encrypts with it, and every node must have moved off a key
// before any node drops it. `lv host rotate-gossip-key` is that caller.
//
// Refused when the node is off: turning encryption on is a stage change, and a
// stage change is a restart (see the package comment above).
func (c *Client) SetGossipKeys(keys GossipKeys) error {
	if c.gossipKeyring == nil {
		return fmt.Errorf("gossip encryption is off on this node; set enforcement.gossip_encryption and restart to use a keyring")
	}
	if err := keys.validate(); err != nil {
		return err
	}
	c.gossipKeyMu.Lock()
	defer c.gossipKeyMu.Unlock()
	ring := c.gossipKeyring
	for _, k := range keys {
		if err := ring.AddKey(k); err != nil {
			return fmt.Errorf("add gossip key %s: %w", pki.GossipKeyID(k), err)
		}
	}
	if err := ring.UseKey(keys[0]); err != nil {
		return fmt.Errorf("use gossip key %s: %w", pki.GossipKeyID(keys[0]), err)
	}
	installed := append([][]byte(nil), ring.GetKeys()...)
	for _, have := range installed {
		keep := false
		for _, k := range keys {
			if bytes.Equal(have, k) {
				keep = true
				break
			}
		}
		if !keep {
			if err := ring.RemoveKey(have); err != nil {
				return fmt.Errorf("remove gossip key %s: %w", pki.GossipKeyID(have), err)
			}
		}
	}
	return nil
}

// GossipKeyring describes the keyring this node is USING, by key ID.
func (c *Client) GossipKeyring() pki.GossipKeyringState {
	var keys [][]byte
	if c.gossipKeyring != nil {
		keys = c.gossipKeyring.GetKeys()
	}
	return pki.NewGossipKeyringState(c.gossipMode.String(), keys, c.gossipRejected.Load())
}

// GossipAuthRejections counts gossip this node dropped because it was
// unencrypted or under a key it does not hold.
func (c *Client) GossipAuthRejections() uint64 { return c.gossipRejected.Load() }

// gossipRejectionMarkers are memberlist's log lines for a packet or stream it
// dropped on encryption grounds (memberlist v0.5.4, net.go). memberlist has no
// counter of its own; TestGossip_EnforcedClusterRefusesANodeWithoutTheKey pins
// that these still match, so an upgrade that rewords them fails a test instead
// of silently zeroing the count.
var gossipRejectionMarkers = []string{
	"Decrypt packet failed",
	"no installed keys could decrypt",
	"encryption is configured but remote state is not encrypted",
	"remote state is encrypted and encryption is not configured",
}

func (c *Client) observeGossipLog(line string) {
	for _, m := range gossipRejectionMarkers {
		if strings.Contains(line, m) {
			c.gossipRejected.Add(1)
			return
		}
	}
}

// WatchGossipKeyFile keeps the live keyring in step with keyPath and reports
// what it is using to statePath, every interval until ctx ends.
//
// It never lets a bad file take a key away. A missing, loose, unparseable or
// empty file is logged and the keys in use are kept: an empty keyring would
// switch memberlist to plaintext on the spot, and a partial one could cut this
// node off mid-rotation. The state file is what `lv host rotate-gossip-key`
// reads back as its barrier between phases, so it reports the LIVE keyring —
// a file that has been written is not a keyring that has been loaded.
//
// An off node loads nothing and reports off.
func (c *Client) WatchGossipKeyFile(ctx context.Context, keyPath, statePath string, interval time.Duration) {
	var lastState, lastErr string
	tick := func() {
		if c.gossipKeyring != nil {
			keys, err := pki.LoadGossipKeyring(keyPath)
			switch {
			case err != nil:
				if err.Error() != lastErr {
					lastErr = err.Error()
					slog.Warn("gossip keyring: the key file cannot be used; keeping the keys in use",
						"path", keyPath, "error", err, "in_use", c.GossipKeyring().Keys)
				}
			case !pki.SameGossipKeyring(pki.GossipKeyIDs(keys), c.GossipKeyring().Keys):
				lastErr = ""
				if err := c.SetGossipKeys(keys); err != nil {
					slog.Warn("gossip keyring: could not apply the key file; keeping the keys in use",
						"path", keyPath, "error", err)
				} else {
					s := c.GossipKeyring()
					slog.Info("gossip keyring reloaded", "primary", s.Primary, "keys", s.Keys)
				}
			default:
				lastErr = ""
			}
		}
		state := string(c.GossipKeyring().Marshal())
		if state == lastState {
			return
		}
		if err := secretfile.Write(statePath, []byte(state), 0o644); err != nil {
			slog.Warn("gossip keyring: could not write the state file", "path", statePath, "error", err)
			return
		}
		lastState = state
	}
	tick()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
