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
//   - this host created it (CreateStoragePool executed here, or the daemon's
//     own default pool and ISO library) or an operator confirmed it here,
//     recorded in the LOCAL ledger <data_dir>/pool-trust.json, which is never
//     replicated; or
//   - it is a local or dir pool whose directory is <data_dir>/disks or inside
//     <data_dir>/pools or <data_dir>/mounts — as written, or as those area
//     roots resolve on this host — and which passes storage.CheckWriteRoot.
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

	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// LedgerFile is the ledger's name in the data directory.
const LedgerFile = "pool-trust.json"

// CorruptSuffix starts the name an unreadable ledger is kept under
// (pool-trust.json.corrupt-<unix seconds>) before anything is written.
const CorruptSuffix = ".corrupt-"

// How a ledger entry came to be.
const (
	HowCreate  = "create"  // CreateStoragePool executed on this host
	HowUpgrade = "upgrade" // adopted on the first start of a build that keeps the ledger
	HowTrust   = "trust"   // an operator confirmed it on this host (`lv pool trust`)
	HowDaemon  = "daemon"  // the daemon's own default pool or ISO library
)

// Binding is what trust in a pool row is bound to: a row of the same name
// that names another driver, source, target or (nfs) mount options is
// another pool, and is not trusted on the strength of this one.
type Binding struct {
	Driver       string `json:"driver"`
	Source       string `json:"source,omitempty"`
	Target       string `json:"target,omitempty"`
	MountOptions string `json:"mount_options,omitempty"`
}

// BindingOf normalises a pool's identity: the driver lower-cased ("" is
// "local"), the target cleaned, and for an nfs pool its options["options"]
// mount options normalised (NormalizeMountOptions). No other option is bound:
// the daemon itself rewrites the export keys it records on a row.
func BindingOf(driver, source, target string, opts map[string]string) Binding {
	d := strings.ToLower(strings.TrimSpace(driver))
	if d == "" {
		d = "local"
	}
	if target != "" {
		target = filepath.Clean(target)
	}
	b := Binding{Driver: d, Source: source, Target: target}
	if d == "nfs" {
		b.MountOptions = NormalizeMountOptions(opts["options"])
	}
	return b
}

// normalized re-applies BindingOf's normalisation to a binding as stored.
func (b Binding) normalized() Binding {
	n := BindingOf(b.Driver, b.Source, b.Target, nil)
	if n.Driver == "nfs" {
		n.MountOptions = NormalizeMountOptions(b.MountOptions)
	}
	return n
}

// hardeningOptions are added or removed by every mount whatever a row says
// (storage hardenNFSOptions), so they are not part of what a row chooses.
var hardeningOptions = map[string]bool{
	"nosuid": true, "suid": true, "nodev": true, "dev": true, "noexec": true, "exec": true,
	"nosymfollow": true, "symfollow": true, "nosharecache": true, "sharecache": true,
}

// NormalizeMountOptions is an nfs pool's mount options as mount(8) takes
// them, in the operator's order — of two conflicting options the last wins,
// so "soft,hard" and "hard,soft" are different — split on commas outside
// double quotes (context="a,b" is one option), each trimmed, the hardening
// options every mount sets dropped whatever their case, and an exact repeat
// kept only at its last place, where it takes effect.
func NormalizeMountOptions(s string) string {
	var opts []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case r == ',' && !quoted:
			opts = append(opts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	opts = append(opts, cur.String())
	last := map[string]int{}
	for i, o := range opts {
		opts[i] = strings.TrimSpace(o)
		last[opts[i]] = i
	}
	var out []string
	for i, o := range opts {
		if o == "" || hardeningOptions[strings.ToLower(o)] || last[o] != i {
			continue
		}
		out = append(out, o)
	}
	return strings.Join(out, ",")
}

// samePlace compares what a config definition fixes: driver, source and
// target. A config pool's mount options come from config itself (its row is
// registered without them), so the row's are not compared.
func (b Binding) samePlace(o Binding) bool {
	return b.Driver == o.Driver && b.Source == o.Source && b.Target == o.Target
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
	// Adopted records that the upgrade adoption has run on this host. A
	// ledger written before it ran (the daemon recording its own pools, a
	// create) does not stop it from running.
	Adopted bool `json:"adopted"`
	// A ledger written by an earlier test build may hold "pending_nfs": it is
	// not read, and the next write drops it.
}

// Store is this host's pool trust: the config pools and the ledger.
type Store struct {
	dataDir, pkiDir string
	path            string

	mu          sync.Mutex
	entries     map[string]Entry
	config      map[string]Binding
	initialised bool   // the upgrade adoption ran on this host (or a ledger was lost: it never runs again)
	corrupt     string // why the ledger could not be read, and where it was kept
}

// Open reads the ledger in dataDir. A ledger that cannot be read or parsed
// is kept as pool-trust.json.corrupt-<time> before anything else is written,
// reported (CorruptNote, and pool_row_untrusted), and none of its entries is
// trusted (fail closed): the pools it held are named until confirmed again.
// No upgrade adoption runs over it. Open always returns a usable store.
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
		// A ledger kept aside as corrupt means a ledger existed: not a
		// first start, and no adoption.
		if aside := s.asides(); len(aside) > 0 {
			s.initialised = true
			s.corrupt = fmt.Sprintf("an unreadable ledger was kept as %s", strings.Join(aside, ", "))
		}
		return s, nil
	case err != nil:
		s.initialised = true
		return s, s.setAside(fmt.Errorf("read pool trust ledger %s: %w", s.path, err))
	}
	var lf ledgerFile
	if err := json.Unmarshal(b, &lf); err != nil {
		s.initialised = true
		return s, s.setAside(fmt.Errorf("parse pool trust ledger %s: %w", s.path, err))
	}
	s.initialised = lf.Adopted
	for name, e := range lf.Pools {
		e.Binding = e.Binding.normalized()
		s.entries[name] = e
	}
	if aside := s.asides(); len(aside) > 0 {
		s.initialised = true
		s.corrupt = fmt.Sprintf("an unreadable ledger was kept as %s", strings.Join(aside, ", "))
	}
	return s, nil
}

// setAside keeps the unreadable ledger under a name of its own, so a later
// write does not destroy what it held, and returns cause naming it.
func (s *Store) setAside(cause error) error {
	aside := fmt.Sprintf("%s%s%d", s.path, CorruptSuffix, time.Now().Unix())
	if err := os.Rename(s.path, aside); err != nil {
		s.corrupt = fmt.Sprintf("%v; it could not be kept aside: %v", cause, err)
		return fmt.Errorf("%w; keep it aside: %v", cause, err)
	}
	s.corrupt = fmt.Sprintf("%v; kept as %s", cause, aside)
	return fmt.Errorf("%w; kept as %s", cause, aside)
}

// asides lists the ledgers kept aside as unreadable that are still there.
func (s *Store) asides() []string {
	m, _ := filepath.Glob(s.path + CorruptSuffix + "*")
	sort.Strings(m)
	return m
}

// CorruptNote is why the ledger could not be read and where it was kept, ""
// once no kept ledger remains (an operator reviewed and removed it).
func (s *Store) CorruptNote() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	note := s.corrupt
	s.mu.Unlock()
	if note == "" || (len(s.asides()) == 0 && !strings.Contains(note, "could not be kept aside")) {
		return ""
	}
	return note
}

// Path is the ledger file.
func (s *Store) Path() string { return s.path }

// Initialised reports whether the upgrade adoption has run on this host (or
// a ledger was found unreadable, after which it never runs): no adoption is
// due. A ledger written before the adoption ran does not count.
func (s *Store) Initialised() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initialised
}

// SetConfig records the pools this host's config.yaml defines.
func (s *Store) SetConfig(pools map[string]Binding) {
	m := make(map[string]Binding, len(pools))
	for n, b := range pools {
		m[n] = b.normalized()
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
	b = b.normalized()
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

// Ensure is Record when the ledger does not already hold name with binding
// b: the daemon's own pools are ensured on every registration without
// rewriting the file each time.
func (s *Store) Ensure(name string, b Binding, how string) error {
	if s == nil {
		return nil
	}
	b = b.normalized()
	s.mu.Lock()
	e, ok := s.entries[name]
	s.mu.Unlock()
	if ok && e.Binding == b {
		return nil
	}
	return s.Record(name, b, how)
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
	b, err := json.MarshalIndent(ledgerFile{Version: 1, Pools: entries, Adopted: s.initialised}, "", "  ")
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
//
// An nfs pool always needs it, with or without a target: it is a mount of an
// export, which a forged row would choose, at the host's own mount point.
func NeedsTrust(b Binding) bool {
	if b.Driver == "nfs" {
		return true
	}
	return len(storage.HostPathsOf(storage.Config{Driver: b.Driver, Source: b.Source, Target: b.Target}).WriteRoots) > 0
}

// IsConfigPool reports whether config.yaml defines pool name at the place
// binding b names (driver, source, target): such a pool takes everything
// else — an nfs pool's mount options above all — from config, never from
// its row.
func (s *Store) IsConfigPool(name string, b Binding) bool {
	if s == nil {
		return false
	}
	b = b.normalized()
	s.mu.Lock()
	cfg, ok := s.config[name]
	s.mu.Unlock()
	return ok && cfg.samePlace(b)
}

// Judge decides whether this host acts on its row of pool name with binding
// b. A nil store trusts everything: a server built without one (a unit test)
// keeps the behaviour from before the ledger.
func (s *Store) Judge(name string, b Binding) Verdict {
	if s == nil {
		return Verdict{Trusted: true, Why: "no trust store"}
	}
	b = b.normalized()
	// A replicated row's name is not validated anywhere on its way here, and
	// names reach paths: a row named outside safename.ValidatePoolName ("/",
	// "..", a NUL, a leading "-", over-long) is no pool of this host's,
	// whatever it names. A create, config and the ledger all hold valid
	// names only.
	if err := safename.ValidatePoolName(name); err != nil {
		return Verdict{Why: err.Error()}
	}
	if !NeedsTrust(b) {
		return Verdict{Trusted: true, Why: TrustNoHostPath}
	}
	s.mu.Lock()
	cfg, inCfg := s.config[name]
	led, inLedger := s.entries[name]
	s.mu.Unlock()
	if inCfg && cfg.samePlace(b) {
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
// <data_dir>/disks or inside <data_dir>/pools or <data_dir>/mounts, judged
// against those area roots as written and as they resolve on this host
// (storage.InDataDirPoolArea), and which passes CheckWriteRoot.
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
	in, err := storage.InDataDirPoolArea(dir, s.dataDir, s.pkiDir)
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
	if b.MountOptions != "" {
		parts = append(parts, "mount options "+b.MountOptions)
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
