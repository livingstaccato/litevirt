package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// The cluster gossip key (colonelpanik/litevirt#259, step 2).
//
// Gossip (memberlist, port 7946) carries membership only — application data is
// replicated over mTLS gRPC — but membership is load-bearing: relay election,
// replication and anti-entropy targets, and capability activation all count
// gossip members. mTLS cannot cover it because memberlist speaks raw UDP/TCP, so
// it is authenticated and encrypted by a shared symmetric keyring instead.
//
// The key lives in its OWN file beside ca.crt, never in config.yaml, never in
// the replicated database and so never in a state dump: whoever holds it can
// speak gossip as a member, so it is distributed exactly the way the CA
// certificate is — pushed over SSH by `lv host init`, `lv host add`,
// `lv host install-gossip-key` and `lv host rotate-gossip-key`.
const (
	// GossipKeyName is the keyring file in the PKI directory.
	GossipKeyName = "gossip.key"
	// GossipKeyringStateName is what a daemon reports about the keyring it is
	// actually USING (key IDs, never keys). The rotate command reads it back as
	// its barrier between phases: a file that has been written is not a keyring
	// that has been loaded.
	GossipKeyringStateName = "gossip-keyring.state"
	// GossipKeySize is AES-256. memberlist also accepts 16 and 24 bytes; the
	// cluster key is 32 and nothing else, so a truncated key is an error rather
	// than a quietly weaker cipher.
	GossipKeySize = 32
)

// NewGossipKey returns a fresh random AES-256 gossip key.
func NewGossipKey() ([]byte, error) {
	k := make([]byte, GossipKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("generate gossip key: %w", err)
	}
	return k, nil
}

// GossipKeyID names a key without revealing it: a truncated, domain-separated
// SHA-256. It is what logs, the state file and the CLI print — the key itself
// is never printed anywhere.
func GossipKeyID(key []byte) string {
	h := sha256.New()
	h.Write([]byte("litevirt gossip key id\x00"))
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// GossipKeyIDs is GossipKeyID over a keyring, order kept.
func GossipKeyIDs(keys [][]byte) []string {
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = GossipKeyID(k)
	}
	return ids
}

const gossipKeyringHeader = `# litevirt cluster gossip keyring. One base64 AES-256 key per line.
# The FIRST key encrypts; every key decrypts. Distributed by lv host init / add /
# install-gossip-key / rotate-gossip-key; edit by hand only if you have read
# docs/auth.md "Gossip encryption". Keep this file 0600.
`

// FormatGossipKeyring renders a keyring file, primary first.
func FormatGossipKeyring(keys [][]byte) []byte {
	var b bytes.Buffer
	b.WriteString(gossipKeyringHeader)
	for _, k := range keys {
		b.WriteString(base64.StdEncoding.EncodeToString(k))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// ParseGossipKeyring reads a keyring file: one base64 key per line, blank lines
// and '#' comments ignored, the first key primary. It refuses an empty ring, a
// key that is not exactly GossipKeySize bytes, and a duplicate.
//
// Errors name the LINE, never its content: they end up in the journal and on
// the operator's terminal.
func ParseGossipKeyring(data []byte) ([][]byte, error) {
	var keys [][]byte
	seen := map[string]int{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("gossip keyring line %d is not base64", i+1)
		}
		if len(k) != GossipKeySize {
			return nil, fmt.Errorf("gossip keyring line %d is a %d-byte key; the cluster key is %d bytes (AES-256)",
				i+1, len(k), GossipKeySize)
		}
		id := GossipKeyID(k)
		if prev, dup := seen[id]; dup {
			return nil, fmt.Errorf("gossip keyring line %d repeats the key on line %d", i+1, prev)
		}
		seen[id] = i + 1
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("gossip keyring holds no keys")
	}
	return keys, nil
}

// LoadGossipKeyring reads and parses a keyring file, refusing one that group or
// other can read: a key anyone on the host can read is a key anyone on the host
// can join gossip with. A missing file returns an error satisfying
// os.IsNotExist.
func LoadGossipKeyring(path string) ([][]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %04o; the gossip key must not be readable by group or "+
			"other (chmod 600 %s)", path, perm, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys, err := ParseGossipKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return keys, nil
}

// WriteGossipKeyring atomically replaces path with keys, at most 0600.
func WriteGossipKeyring(path string, keys [][]byte) error {
	if len(keys) == 0 {
		return fmt.Errorf("refusing to write an empty gossip keyring")
	}
	return secretfile.Write(path, FormatGossipKeyring(keys), 0o600)
}

// GossipKeyringState is what a daemon reports about the keyring it is USING.
type GossipKeyringState struct {
	// Mode is the node's enforcement.gossip_encryption stage: off, install,
	// staged or enforced.
	Mode string
	// Primary is the ID of the key this node encrypts with; empty when off.
	Primary string
	// Keys are the IDs of every key this node decrypts with, primary first.
	Keys []string
	// Rejected counts gossip messages this node has dropped since it started
	// because they were unencrypted or under a key it does not hold. It should
	// stay flat through every step of a rollout or rotation; a rising count is
	// a peer this node cannot hear.
	Rejected uint64
}

// NewGossipKeyringState describes a live keyring by its key IDs.
func NewGossipKeyringState(mode string, keys [][]byte, rejected uint64) GossipKeyringState {
	s := GossipKeyringState{Mode: mode, Rejected: rejected, Keys: GossipKeyIDs(keys)}
	if len(s.Keys) > 0 {
		s.Primary = s.Keys[0]
	}
	return s
}

// Marshal renders the state as key=value lines.
func (s GossipKeyringState) Marshal() []byte {
	return []byte(fmt.Sprintf("mode=%s\nprimary=%s\nkeys=%s\nrejected=%d\n",
		s.Mode, s.Primary, strings.Join(s.Keys, ","), s.Rejected))
}

// ParseGossipKeyringState reads a state file written by Marshal.
func ParseGossipKeyringState(data []byte) (GossipKeyringState, error) {
	var s GossipKeyringState
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "mode":
			s.Mode = v
		case "primary":
			s.Primary = v
		case "keys":
			if v != "" {
				s.Keys = strings.Split(v, ",")
			}
		case "rejected":
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return s, fmt.Errorf("gossip keyring state: bad rejected count %q", v)
			}
			s.Rejected = n
		}
	}
	if s.Mode == "" {
		return s, fmt.Errorf("gossip keyring state names no mode")
	}
	return s, nil
}
