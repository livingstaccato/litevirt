// Package pooltrust decides which storage_pools rows naming this host the
// host acts on.
//
// storage_pools is replicated, and nothing on apply checks which host wrote a
// row. A row naming this host therefore proves nothing about who made it: any
// cluster member, or anyone able to inject a replicated write, can write one
// that names a directory of the attacker's choosing, and the daemon writes
// there as root. A row that names a place on this host's filesystem (its
// write roots, storage.HostPathsOf) is acted on only when this host itself
// stands behind it:
//
//   - the pool is defined in this host's config.yaml, with the same driver,
//     source and target;
//   - this host created it (CreateStoragePool executed here) or an operator
//     confirmed it here, recorded in the LOCAL ledger <data_dir>/pool-trust.json,
//     which is never replicated; or
//   - it is a local or dir pool whose directory, as written and resolved, is
//     <data_dir>/disks or inside <data_dir>/pools or <data_dir>/mounts, and
//     which passes storage.CheckWriteRoot.
//
// Any other such row is untrusted: it is not a disk root, it is not mounted,
// written, swept or listed, and the pool_row_untrusted condition names it.
package pooltrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/storage"
)

// LedgerFile is the ledger's name in the data directory.
const LedgerFile = "pool-trust.json"

// How a ledger entry came to be.
const (
	HowCreate  = "create"  // CreateStoragePool executed on this host
	HowUpgrade = "upgrade" // adopted on the first start of a build that keeps the ledger
	HowTrust   = "trust"   // an operator confirmed it on this host (`lv pool trust`)
)

// Binding is what trust in a pool row is bound to: a row of the same name
// that names another driver, source or target is another pool, and is not
// trusted on the strength of this one.
type Binding struct {
	Driver string `json:"driver"`
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`
}

// BindingOf normalises a pool's identity: the driver lower-cased ("" is
// "local"), the target cleaned.
func BindingOf(driver, source, target string) Binding {
	d := strings.ToLower(strings.TrimSpace(driver))
	if d == "" {
		d = "local"
	}
	if target != "" {
		target = filepath.Clean(target)
	}
	return Binding{Driver: d, Source: source, Target: target}
}

// Entry is one ledger record.
type Entry struct {
	Binding
	How string `json:"how"`
	At  string `json:"at"`
}

type ledgerFile struct {
	Version int              `json:"version"`
	Pools   map[string]Entry `json:"pools"`
}

// Store is this host's pool trust: the config pools and the ledger.
type Store struct {
	dataDir, pkiDir string
	path            string

	mu          sync.Mutex
	entries     map[string]Entry
	config      map[string]Binding
	initialised bool // the ledger file existed when opened, or has been written since
}

// Open reads the ledger in dataDir. A ledger that cannot be read or parsed
// is reported, and the store trusts none of its entries (fail closed): the
// pools it held are named by pool_row_untrusted until confirmed again. Open
// always returns a usable store.
func Open(dataDir, pkiDir string) (*Store, error) {
	s := &Store{
		dataDir: dataDir,
		pkiDir:  pkiDir,
		path:    filepath.Join(dataDir, LedgerFile),
		entries: map[string]Entry{},
		config:  map[string]Binding{},
	}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		s.initialised = true
		return s, fmt.Errorf("read pool trust ledger %s: %w", s.path, err)
	}
	s.initialised = true
	var lf ledgerFile
	if err := json.Unmarshal(b, &lf); err != nil {
		return s, fmt.Errorf("parse pool trust ledger %s: %w", s.path, err)
	}
	for name, e := range lf.Pools {
		e.Binding = BindingOf(e.Driver, e.Source, e.Target)
		s.entries[name] = e
	}
	return s, nil
}

// Path is the ledger file.
func (s *Store) Path() string { return s.path }

// Initialised reports whether the ledger file exists: a build that keeps it
// has started on this host before, so no upgrade adoption is due.
func (s *Store) Initialised() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initialised
}

// SetConfig records the pools this host's config.yaml defines.
func (s *Store) SetConfig(pools map[string]Binding) {
	m := make(map[string]Binding, len(pools))
	for n, b := range pools {
		m[n] = BindingOf(b.Driver, b.Source, b.Target)
	}
	s.mu.Lock()
	s.config = m
	s.mu.Unlock()
}

// Entry returns the ledger's record of name.
func (s *Store) Entry(name string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[name]
	return e, ok
}

// Record writes name with binding b into the ledger, durably, before it
// returns. A pool create calls it before the pool's row is written, so the
// row is never seen here untrusted.
func (s *Store) Record(name string, b Binding, how string) error {
	b = BindingOf(b.Driver, b.Source, b.Target)
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]Entry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	next[name] = Entry{Binding: b, How: how, At: time.Now().UTC().Format(time.RFC3339)}
	if err := s.writeLocked(next); err != nil {
		return err
	}
	s.entries = next
	return nil
}

// Forget removes name from the ledger: a pool deleted on this host is not
// trusted again if a row of that name comes back.
func (s *Store) Forget(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[name]; !ok {
		return nil
	}
	next := make(map[string]Entry, len(s.entries))
	for k, v := range s.entries {
		if k != name {
			next[k] = v
		}
	}
	if err := s.writeLocked(next); err != nil {
		return err
	}
	s.entries = next
	return nil
}

// writeLocked replaces the ledger file atomically: a 0600 dot-named temp in
// the data directory, synced, renamed over it, and the directory synced.
func (s *Store) writeLocked(entries map[string]Entry) error {
	b, err := json.MarshalIndent(ledgerFile{Version: 1, Pools: entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dataDir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dataDir, ".pool-trust-*.tmp")
	if err != nil {
		return fmt.Errorf("write pool trust ledger: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("write pool trust ledger: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("write pool trust ledger: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("write pool trust ledger: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write pool trust ledger: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("write pool trust ledger: %w", err)
	}
	if d, err := os.Open(s.dataDir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	s.initialised = true
	return nil
}

// Why a row is trusted.
const (
	TrustNoHostPath = "names no host path"
	TrustConfig     = "defined in config.yaml"
	TrustLedger     = "created or confirmed on this host"
	TrustArea       = "in the daemon's own pool area"
)

// Verdict is Judge's answer.
type Verdict struct {
	Trusted bool
	// Why is how a trusted row is trusted, or why an untrusted one is not.
	Why string
}

// NeedsTrust reports whether a pool of binding b names a place on the host's
// own filesystem the daemon writes in or mounts over. A pool that names none
// (ceph, iscsi, zfs, lvm-thin, a local pool on <data_dir>/disks) is not a
// disk root a forged row could aim, and needs no trust.
func NeedsTrust(b Binding) bool {
	return len(storage.HostPathsOf(storage.Config{Driver: b.Driver, Source: b.Source, Target: b.Target}).WriteRoots) > 0
}

// Judge decides whether this host acts on its row of pool name with binding
// b. A nil store trusts everything: a server built without one (a unit test)
// keeps the behaviour from before the ledger.
func (s *Store) Judge(name string, b Binding) Verdict {
	if s == nil {
		return Verdict{Trusted: true, Why: "no trust store"}
	}
	b = BindingOf(b.Driver, b.Source, b.Target)
	if !NeedsTrust(b) {
		return Verdict{Trusted: true, Why: TrustNoHostPath}
	}
	s.mu.Lock()
	cfg, inCfg := s.config[name]
	led, inLedger := s.entries[name]
	s.mu.Unlock()
	if inCfg && cfg == b {
		return Verdict{Trusted: true, Why: TrustConfig}
	}
	if inLedger && led.Binding == b {
		return Verdict{Trusted: true, Why: TrustLedger}
	}
	if ok, _ := s.inOwnArea(b); ok {
		return Verdict{Trusted: true, Why: TrustArea}
	}
	switch {
	case inCfg:
		return Verdict{Why: fmt.Sprintf("config.yaml defines pool %q as %s, not as this row (%s)", name, describe(cfg), describe(b))}
	case inLedger:
		return Verdict{Why: fmt.Sprintf("this host recorded pool %q as %s, not as this row (%s)", name, describe(led.Binding), describe(b))}
	}
	return Verdict{Why: fmt.Sprintf("this host neither created nor confirmed pool %q (%s), it is not in config.yaml, and its directory is outside the daemon's own pool areas", name, describe(b))}
}

// inOwnArea is the area rule: a local or dir pool whose directory is
// <data_dir>/disks or inside <data_dir>/pools or <data_dir>/mounts, as
// written and resolved, and which passes CheckWriteRoot.
func (s *Store) inOwnArea(b Binding) (bool, error) {
	var dir string
	switch b.Driver {
	case "local":
		dir = b.Target
		if dir == "" {
			dir = filepath.Join(s.dataDir, "disks")
		}
	case "dir":
		dir = b.Target
	default:
		return false, nil
	}
	if dir == "" {
		return false, nil
	}
	in, err := storage.InDataDirPoolArea(dir, s.dataDir)
	if err != nil || !in {
		return false, err
	}
	if err := storage.CheckWriteRoot(dir, s.dataDir, s.pkiDir); err != nil {
		return false, err
	}
	return true, nil
}

func describe(b Binding) string {
	parts := []string{"driver " + b.Driver}
	if b.Source != "" {
		parts = append(parts, "source "+b.Source)
	}
	if b.Target != "" {
		parts = append(parts, "target "+b.Target)
	}
	return strings.Join(parts, ", ")
}

// Names returns the ledger's pool names, sorted.
func (s *Store) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.entries))
	for n := range s.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
