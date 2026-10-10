package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// Ceph secrets on this host. A VM disk on a ceph pool authenticates as the
// pool's client through a libvirt secret holding that client's key (see
// internal/libvirt/secret.go). The secret is named by the litevirt pool and
// the client (lv.CephSecretUUID), so every host with the pool names the same
// one; this host defines it from the keyring ITS pool names, and keeps it
// while a pool or a disk recorded on this host uses it.
//
// Whether two hosts' keyrings hold the same key is a separate question,
// answered by the key fingerprint each host records on its own pool row
// (storage.CephKeyFPOption): a host whose key differs from the others' raises
// ceph_keyring_mismatch, and refuses to start, or to receive by migration, a
// VM of that pool — with that reason, never libvirt's opaque one.
//
// The secrets are ephemeral, so a libvirtd restart drops them. They are put
// back by ReconcileCephSecrets, which the daemon runs at start and then
// periodically, and synchronously before a VM with a ceph disk is created,
// started, promoted or migrated here; a pool create defines its secret at
// once, a pool delete removes one nothing else uses.

const (
	cephPoolEvaluator       = "ceph_pool"
	condCephKeyringMismatch = "ceph_keyring_mismatch"
)

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

// defineCephSecret sets secret u to client id's key from keyring, unless the
// same value is already there. The key is never logged nor part of an error.
// grace marks the definition as one a create may be about to rely on
// (cephSecretGrace); a definition for disks that already exist needs none.
func (s *Server) defineCephSecret(u, id, keyring string, grace bool) error {
	stamp := time.Time{}
	if grace {
		stamp = time.Now()
	}
	key, err := storage.CephClientKey(keyring, id)
	if err != nil {
		return fmt.Errorf("ceph secret for client.%s: %w", id, err)
	}
	defer clear(key)
	sum := sha256.Sum256(key)
	if mk, seen := s.cephSecrets.get(u); seen && mk.sum == sum {
		if has, herr := s.virt.HasSecret(u); herr == nil && has {
			s.cephSecrets.put(u, cephSecretMark{sum: sum, at: laterOf(mk.at, stamp)})
			return nil
		}
	}
	if err := s.virt.DefineCephSecret(u, id, key); err != nil {
		return fmt.Errorf("ceph secret for client.%s: %w", id, err)
	}
	s.cephSecrets.put(u, cephSecretMark{sum: sum, at: stamp})
	slog.Info("ceph secret defined", "uuid", u, "client", id, "keyring", keyring)
	return nil
}

// ensureCephSecret defines the ceph secret a storage config's disks
// authenticate with, from the keyring it names, and returns its UUID. A config
// that is not ceph, or names no keyring, needs none ("", nil).
func (s *Server) ensureCephSecret(cfg storage.Config) (string, error) {
	if !strings.EqualFold(cfg.Driver, "ceph") || s.virt == nil {
		return "", nil
	}
	auth, ok := storage.CephAuthOf(cfg.Options)
	if !ok {
		return "", nil
	}
	if cfg.Name == "" {
		return "", fmt.Errorf("ceph storage with no pool name has no secret to define")
	}
	u := lv.CephSecretUUID(cfg.Name, auth.ID)
	return u, s.defineCephSecret(u, auth.ID, auth.Keyring, true)
}

// isHostPool reports whether a storage name is a host pool (a row per host)
// rather than a stack's compose volume ("<stack>/<volume>").
func isHostPool(name string) bool { return name != "" && !strings.Contains(name, "/") }

// cephKeyFingerprints returns each host's recorded key fingerprint for pool.
func (s *Server) cephKeyFingerprints(ctx context.Context, pool string) (map[string]string, error) {
	rows, err := corrosion.ListStoragePoolsNamed(ctx, s.db, pool)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		if fp := r.Options[storage.CephKeyFPOption]; fp != "" && strings.EqualFold(r.Driver, "ceph") {
			out[r.HostName] = fp
		}
	}
	return out, nil
}

// cephKeyOddOneOut says whether this host's key (mine) is in a strict
// minority among the hosts' recorded fingerprints of a pool: some other key
// is held by more hosts than this one is. A tie is not decided against this
// host — there is no telling which key is the cluster's.
func cephKeyOddOneOut(mine string, fps map[string]string, self string) (odd bool, differing []string) {
	count := map[string]int{mine: 1}
	for h, fp := range fps {
		if h == self {
			continue
		}
		count[fp]++
		if fp != mine {
			differing = append(differing, h)
		}
	}
	sort.Strings(differing)
	for fp, n := range count {
		if fp != mine && n > count[mine] {
			return true, differing
		}
	}
	return false, differing
}

// refuseOddCephKey refuses a start here of a VM on host pool `pool` when this
// host's key is not the one the pool's other hosts hold.
func (s *Server) refuseOddCephKey(ctx context.Context, pool string, cfg storage.Config) error {
	if !isHostPool(pool) {
		return nil
	}
	mine, ok, err := storage.CephKeyFingerprintOf(cfg.Options)
	if err != nil || !ok {
		return err
	}
	fps, err := s.cephKeyFingerprints(ctx, pool)
	if err != nil {
		return nil // the start's own failure is the clearer answer than a guess
	}
	if odd, differing := cephKeyOddOneOut(mine, fps, s.hostName); odd {
		return fmt.Errorf("the keyring of ceph pool %q on %s holds a different key for client.%s than the pool's other hosts (%s): "+
			"install the cluster's keyring for the client on %s (condition %s)",
			pool, s.hostName, clientOf(cfg), strings.Join(differing, ", "), s.hostName, condCephKeyringMismatch)
	}
	return nil
}

// refuseCephKeyUnlikeSource refuses a migration onto this host of a VM whose
// source host's pool records a different key than this host's keyring holds.
func (s *Server) refuseCephKeyUnlikeSource(ctx context.Context, pool, source string, cfg storage.Config) error {
	if !isHostPool(pool) || source == "" || source == s.hostName {
		return nil
	}
	mine, ok, err := storage.CephKeyFingerprintOf(cfg.Options)
	if err != nil || !ok {
		return err
	}
	fps, err := s.cephKeyFingerprints(ctx, pool)
	if err != nil {
		return nil
	}
	if theirs := fps[source]; theirs != "" && theirs != mine {
		return fmt.Errorf("the keyring of ceph pool %q on %s holds a different key for client.%s than on %s, where the VM runs: "+
			"install the same keyring on %s before migrating to it (condition %s)",
			pool, s.hostName, clientOf(cfg), source, s.hostName, condCephKeyringMismatch)
	}
	return nil
}

func clientOf(cfg storage.Config) string {
	if a, ok := storage.CephAuthOf(cfg.Options); ok {
		return a.ID
	}
	return "admin"
}

// ensureCephSecretsForVM defines, on this host, the secrets a VM's ceph
// disks name, and checks this host can serve them. source is the host the VM
// is migrating from ("" for a start here). Each disk is served by the pool
// (or stack volume) its locator names: its secret is defined from this host's
// keyring for it, and must be the one the disk's domain names; this host's key
// must be the pool's (refuseOddCephKey, refuseCephKeyUnlikeSource). A disk
// whose pool this host does not have is served from its locator's own keyring
// when that is readable here, and refused otherwise.
func (s *Server) ensureCephSecretsForVM(ctx context.Context, vm *corrosion.VMRecord, source string) error {
	if s.virt == nil {
		return nil
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return nil // the start path reports a missing disk list itself
	}
	for _, d := range disks {
		want, ok := lv.CephSecretOfLocator(d.Path)
		if !ok {
			continue
		}
		l, _ := storage.ParseCephLocator(d.Path)
		pool := l.Opts["lvpool"]
		cfg, rerr := s.resolveVolume(ctx, vm.StackName, d.StorageVolume)
		if rerr != nil || !strings.EqualFold(cfg.Driver, "ceph") || cfg.Name != pool {
			// The pool is not on this host (any more): the disk's own locator
			// names its client and keyring.
			id := l.Opts["id"]
			if id == "" {
				id = "admin"
			}
			if derr := s.defineCephSecret(want, id, l.Opts["keyring"], false); derr != nil {
				return fmt.Errorf("disk %s is on ceph pool %q, which %s does not have, and its keyring is not usable here: %w",
					d.DiskName, pool, s.hostName, derr)
			}
			continue
		}
		u, err := s.ensureCephSecret(cfg)
		if err != nil {
			return fmt.Errorf("disk %s: %w", d.DiskName, err)
		}
		if u != want {
			return fmt.Errorf("disk %s authenticates as client.%s of ceph pool %q, but pool %q on %s names client.%s; give the pool the same id on every host",
				d.DiskName, cephLocatorID(l), pool, pool, s.hostName, clientOf(cfg))
		}
		if err := s.refuseOddCephKey(ctx, pool, cfg); err != nil {
			return err
		}
		if err := s.refuseCephKeyUnlikeSource(ctx, pool, source, cfg); err != nil {
			return err
		}
	}
	return nil
}

func cephLocatorID(l storage.CephLocator) string {
	if id := l.Opts["id"]; id != "" {
		return id
	}
	return "admin"
}

// prepareIncomingCephDisks is the migration target's half (EnsureDisks):
// every secret the incoming domain names is defined here, and this host can
// serve the disks, or the migration is refused before libvirt is asked.
func (s *Server) prepareIncomingCephDisks(ctx context.Context, vm *corrosion.VMRecord) error {
	if err := s.ensureCephSecretsForVM(ctx, vm, vm.HostName); err != nil {
		return status.Errorf(codes.FailedPrecondition, "%s cannot receive VM %q: %v", s.hostName, vm.Name, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read disks of %q: %v", vm.Name, err)
	}
	for _, d := range disks {
		u, ok := lv.CephSecretOfLocator(d.Path)
		if !ok {
			continue
		}
		if has, herr := s.virt.HasSecret(u); herr != nil || !has {
			return status.Errorf(codes.FailedPrecondition,
				"%s cannot receive VM %q: its disk %s needs ceph secret %s, which is not defined here (%v)",
				s.hostName, vm.Name, d.DiskName, u, herr)
		}
	}
	return nil
}

// vmHasRBDDisk reports whether any of a VM's disks is an rbd image.
func (s *Server) vmHasRBDDisk(ctx context.Context, vmName string) bool {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return false
	}
	for _, d := range disks {
		if strings.HasPrefix(d.Path, "rbd:") {
			return true
		}
	}
	return false
}

// recordCephKeyFingerprint writes this host's key fingerprint onto its own
// row of a host pool, when it changed.
func (s *Server) recordCephKeyFingerprint(ctx context.Context, pool, fp string) {
	rec, found, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, pool)
	if err != nil || !found || rec.Options[storage.CephKeyFPOption] == fp {
		return
	}
	opts := make(map[string]string, len(rec.Options)+1)
	for k, v := range rec.Options {
		opts[k] = v
	}
	opts[storage.CephKeyFPOption] = fp
	rec.Options = opts
	if err := corrosion.UpsertStoragePool(ctx, s.db, rec); err != nil {
		slog.Warn("ceph pool: record the key fingerprint", "pool", pool, "error", err)
	}
}

// judgeCephKey raises ceph_keyring_mismatch for this host's row of pool when
// another host records a different key, and resolves it when none does.
func (s *Server) judgeCephKey(ctx context.Context, pool, mine string) {
	fps, err := s.cephKeyFingerprints(ctx, pool)
	if err != nil {
		return
	}
	_, differing := cephKeyOddOneOut(mine, fps, s.hostName)
	subject := pool + "@" + s.hostName
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, cephPoolEvaluator, condCephKeyringMismatch, "host", subject)
	if err != nil {
		return
	}
	if len(differing) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("ceph pool: resolve keyring condition", "pool", pool, "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: cephPoolEvaluator, Code: condCephKeyringMismatch,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	ev, _ := json.Marshal(map[string]any{
		"pool": pool, "host": s.hostName, "differs_from": differing,
		"detail": fmt.Sprintf("the keyring of ceph pool %q on %s holds a different key than on %s; VMs of the pool are not started on, or migrated to, the host whose key is in the minority",
			pool, s.hostName, strings.Join(differing, ", ")),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("ceph pool: raise keyring condition", "pool", pool, "error", err)
	}
}

// ReconcileCephSecrets brings this host's litevirt ceph secrets in line with
// its ceph pools: every pool's secret is defined (and its value re-set when
// the keyring changed or libvirt lost it), its key fingerprint recorded and
// compared with the pool's other hosts, a disk whose pool is gone gets its
// secret from its own locator, and a secret no pool and no disk recorded on
// this host uses any more is removed. Nothing is removed on a partial view (a
// listing that failed), nor within cephSecretGrace of its last definition.
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
		cfg := storage.Config{Name: name, Driver: p.Driver, Source: p.Source, Target: p.Target, Options: p.Options}
		u, err := s.ensureCephSecret(cfg)
		if u != "" {
			want[u] = true
		}
		if err != nil {
			slog.Warn("ceph pool: its VM disks cannot authenticate until this is fixed", "pool", name, "error", err)
			continue
		}
		if u == "" {
			continue
		}
		if fp, ok, ferr := storage.CephKeyFingerprintOf(cfg.Options); ferr == nil && ok {
			s.recordCephKeyFingerprint(ctx, name, fp)
			s.judgeCephKey(ctx, name, fp)
		}
	}
	paths, err := corrosion.ListRBDDiskPathsForHost(ctx, s.db, s.hostName)
	if err != nil {
		complete = false
	}
	for _, p := range paths {
		u, ok := lv.CephSecretOfLocator(p)
		if !ok {
			continue
		}
		if !want[u] {
			// No pool here defines it (the pool was deleted under the disk):
			// the disk's own locator names the client and keyring.
			if l, ok := storage.ParseCephLocator(p); ok {
				if err := s.defineCephSecret(u, cephLocatorID(l), l.Opts["keyring"], false); err != nil {
					slog.Warn("ceph secret of a disk whose pool is gone cannot be defined", "uuid", u, "error", err)
				}
			}
		}
		want[u] = true
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

// CephMonitorsForPool is the monitor list a domain's rbd disk on litevirt pool
// `name` is given on this host now (lv.SetCephMonitorResolver): the pool's
// mon_host option, else its conf's mon_host. ok is false when this host has no
// such ceph pool, or its conf cannot be read.
func (s *Server) CephMonitorsForPool(name string) ([]string, bool) {
	ref, ok := s.lookupStoragePool(name)
	if !ok || !strings.EqualFold(ref.Driver, "ceph") {
		return nil, false
	}
	if mh := strings.TrimSpace(ref.Options["mon_host"]); mh != "" {
		return storage.ParseMonHost(mh), true
	}
	conf := ref.Options["conf"]
	if conf == "" {
		conf = storage.DefaultCephConf()
	}
	mons, err := storage.CephMonHosts(conf)
	if err != nil {
		return nil, false
	}
	if len(mons) == 0 && !storage.IsDefaultCephConf(conf) {
		return nil, false
	}
	return mons, true
}

// refuseRBDDisk refuses an operation litevirt does not implement for ceph
// (rbd) disks, with that reason, rather than letting it fail on a path that is
// not a file.
func refuseRBDDisk(d *corrosion.DiskRecord, what string) error {
	return refuseRBDDiskWith(codes.FailedPrecondition, d, what)
}

func refuseRBDDiskWith(code codes.Code, d *corrosion.DiskRecord, what string) error {
	if d == nil || !strings.HasPrefix(d.Path, "rbd:") {
		return nil
	}
	return status.Errorf(code,
		"disk %q of VM %q is a ceph (rbd) disk: %s is not supported on ceph disks yet", d.DiskName, d.VMName, what)
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
