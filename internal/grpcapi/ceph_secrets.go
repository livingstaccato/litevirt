package grpcapi

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// Ceph secrets on this host. A VM disk on a ceph pool authenticates as the
// pool's client through a libvirt secret holding that client's key (see
// internal/libvirt/secret.go): the daemon defines one per (id, keyring) a ceph
// pool on this host names, from the keyring, and keeps it while a pool or a
// disk recorded on this host uses it.
//
// The secrets are ephemeral, so a libvirtd restart drops them. They are put
// back by ReconcileCephSecrets, which the daemon runs at start and then
// periodically, and synchronously before a VM with a ceph disk is created or
// started here; a pool create defines its secret at once, a pool delete
// removes one nothing else uses.

// cephSecretGrace is how long a secret this daemon (re)defined is kept even
// when nothing seems to use it: a create defines the secret before its disk
// rows exist, and must not lose it to a reconcile that ran in between.
const cephSecretGrace = 10 * time.Minute

// cephSecretMarks remembers, per secret, the digest of the value last set and
// when — so a periodic reconcile re-sets a value only when the keyring changed
// (or libvirt lost the secret), and the grace above can be judged.
type cephSecretMarks struct {
	mu    sync.Mutex
	marks map[string]cephSecretMark
}

type cephSecretMark struct {
	sum [32]byte
	at  time.Time
}

func (m *cephSecretMarks) get(u string) (cephSecretMark, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mk, ok := m.marks[u]
	return mk, ok
}

func (m *cephSecretMarks) put(u string, mk cephSecretMark) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.marks == nil {
		m.marks = map[string]cephSecretMark{}
	}
	m.marks[u] = mk
}

func (m *cephSecretMarks) forget(u string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.marks, u)
}

// ensureCephSecret defines the ceph secret a storage config's disks
// authenticate with, from the keyring it names, and returns its UUID. A config
// that is not ceph, or names no keyring, needs none ("", nil). The key is
// never logged, nor part of an error.
func (s *Server) ensureCephSecret(cfg storage.Config) (string, error) {
	if !strings.EqualFold(cfg.Driver, "ceph") || s.virt == nil {
		return "", nil
	}
	auth, ok := storage.CephAuthOf(cfg.Options)
	if !ok {
		return "", nil
	}
	u := lv.CephSecretUUID(auth.ID, auth.Keyring)
	key, err := storage.CephClientKey(auth.Keyring, auth.ID)
	if err != nil {
		return u, fmt.Errorf("ceph secret for client.%s: %w", auth.ID, err)
	}
	defer clear(key)
	sum := sha256.Sum256(key)
	if mk, seen := s.cephSecrets.get(u); seen && mk.sum == sum {
		if has, herr := s.virt.HasSecret(u); herr == nil && has {
			s.cephSecrets.put(u, cephSecretMark{sum: sum, at: time.Now()})
			return u, nil
		}
	}
	if err := s.virt.DefineCephSecret(u, auth.ID, key); err != nil {
		return u, fmt.Errorf("ceph secret for client.%s: %w", auth.ID, err)
	}
	s.cephSecrets.put(u, cephSecretMark{sum: sum, at: time.Now()})
	slog.Info("ceph secret defined", "uuid", u, "client", auth.ID, "keyring", auth.Keyring)
	return u, nil
}

// ensureCephSecretsForVM defines the secrets a VM's ceph disks on this host
// need, from the pool (or stack volume) each disk was created in. A disk whose
// storage no longer resolves is left to fail at start, as before.
func (s *Server) ensureCephSecretsForVM(ctx context.Context, vm *corrosion.VMRecord) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return nil // the start path reports a missing disk list itself
	}
	for _, d := range disks {
		if _, ok := lv.CephSecretOfLocator(d.Path); !ok || d.StorageVolume == "" {
			continue
		}
		cfg, rerr := s.resolveVolume(ctx, vm.StackName, d.StorageVolume)
		if rerr != nil {
			continue
		}
		if _, err := s.ensureCephSecret(cfg); err != nil {
			return fmt.Errorf("disk %s: %w", d.DiskName, err)
		}
	}
	return nil
}

// ReconcileCephSecrets brings this host's litevirt ceph secrets in line with
// its ceph pools: every pool's secret is defined (and its value re-set when
// the keyring changed or libvirt lost it), and a secret no pool and no disk
// recorded on this host uses any more is removed. Nothing is removed on a
// partial view (a listing that failed), nor within cephSecretGrace of its
// last definition.
func (s *Server) ReconcileCephSecrets(ctx context.Context) {
	if s.virt == nil || s.db == nil {
		return
	}
	pools := map[string]StoragePoolRef{}
	s.storagePoolsMu.RLock()
	for n, p := range s.storagePools {
		pools[n] = p
	}
	s.storagePoolsMu.RUnlock()
	complete := true
	if rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName); err != nil {
		complete = false
	} else {
		for _, r := range rows {
			if _, ok := pools[r.Name]; !ok {
				pools[r.Name] = StoragePoolRef{Driver: r.Driver, Source: r.Source, Target: r.Target, Options: r.Options}
			}
		}
	}

	want := map[string]bool{}
	for name, p := range pools {
		u, err := s.ensureCephSecret(storage.Config{Driver: p.Driver, Source: p.Source, Target: p.Target, Options: p.Options})
		if u != "" {
			want[u] = true
		}
		if err != nil {
			slog.Warn("ceph pool: its VM disks cannot authenticate until this is fixed", "pool", name, "error", err)
		}
	}
	paths, err := corrosion.ListRBDDiskPathsForHost(ctx, s.db, s.hostName)
	if err != nil {
		complete = false
	}
	for _, p := range paths {
		if u, ok := lv.CephSecretOfLocator(p); ok {
			want[u] = true
		}
	}
	if !complete {
		return
	}
	defined, err := s.virt.ListCephSecrets()
	if err != nil {
		return
	}
	for _, u := range defined {
		if want[u] {
			continue
		}
		if mk, ok := s.cephSecrets.get(u); ok && time.Since(mk.at) < cephSecretGrace {
			continue
		}
		if err := s.virt.UndefineSecret(u); err != nil {
			slog.Warn("ceph secret no longer used, but not removed", "uuid", u, "error", err)
			continue
		}
		s.cephSecrets.forget(u)
		slog.Info("ceph secret removed: no pool or disk on this host uses it", "uuid", u)
	}
}
