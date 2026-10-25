package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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
// (storage.CephKeyFPOption): a host whose key differs from another's raises
// ceph_keyring_mismatch (a diagnostic), and a live migration between two hosts
// whose keys differ is refused with that reason. A start never trusts other
// hosts' rows: it proves this host's own key opens the disk (`rbd info`).
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
		// A keyring that is missing or names no key for the client: an
		// operator installs it.
		return permanentCeph(fmt.Errorf("ceph secret for client.%s: %w", id, err))
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
		return transientCeph(fmt.Errorf("ceph secret for client.%s: %w", id, err))
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
		return "", permanentCeph(fmt.Errorf("ceph storage with no pool name has no secret to define"))
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

// cephKeyDiffering lists the hosts whose recorded fingerprint of pool's key
// differs from this host's (mine). A diagnostic only: it raises
// ceph_keyring_mismatch, and never refuses a start — rows of hosts that are
// down, removed or mid key rotation cannot vouch for or against this host;
// every start proves this host's key with rbd itself (ProbeDisk).
func cephKeyDiffering(mine string, fps map[string]string, self string) []string {
	var differing []string
	for h, fp := range fps {
		if h != self && fp != mine {
			differing = append(differing, h)
		}
	}
	sort.Strings(differing)
	return differing
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
		return permanentCeph(fmt.Errorf("the keyring of ceph pool %q on %s holds a different key for client.%s than on %s, where the VM runs: "+
			"install the same keyring on %s before migrating to it (condition %s)",
			pool, s.hostName, clientOf(cfg), source, s.hostName, condCephKeyringMismatch))
	}
	return nil
}

func clientOf(cfg storage.Config) string {
	if a, ok := storage.CephAuthOf(cfg.Options); ok {
		return a.ID
	}
	return "admin"
}

// errStorageNotFound is resolveVolume's "this host has no storage of that
// name" — the one answer that lets a disk fall back to its own locator.
var errStorageNotFound = errors.New("no such storage here")

// ensureCephSecretsForVM defines, on this host, the secrets a VM's ceph
// disks name, and proves this host can open them. source is the host the VM
// is migrating from ("" for a start here). Each disk is served by the pool
// (or stack volume) its locator names: its secret is defined from this host's
// keyring for it and must be the one the disk's domain names, a migration's
// target must hold the same key as the source (the pool rows' fingerprints),
// and `rbd info` with this host's credentials must open the image. A disk
// whose pool this host definitely does not have is served from its locator's
// own client and keyring when that is readable here; any other failure to
// resolve its storage refuses.
//
// The probes (cephStartPlan lists the ones a remembered proof does not cover)
// run concurrently under ONE storage.ProbeBound, and whether there is time for
// them is judged once for the VM: a caller with less than that left (the
// reconciler late in its walk) is answered transient — a deferral — before
// any rbd runs. Except for a reconcile walk's FIRST probe (its probe turn,
// health.TakeWalkProbeTurn), which runs on whatever is left, down to
// cephProbeFloor: every pass makes progress on proving a key, however late
// its walk starts.
//
// In a reconcile walk, a probe that got no answer is remembered for about a
// pass (cephKeyFailTTL): the VMs on that storage are then deferred at once,
// without a probe each, and behind the VMs deferred for time (the kind:
// health.ErrStartStorageDown, or ErrStartProbeFailed for the VM whose own
// probe failed). A probe cut short by the walk's own deadline proves nothing
// about the storage and is a deferral for time.
func (s *Server) ensureCephSecretsForVM(ctx context.Context, vm *corrosion.VMRecord, source string) error {
	probes, err := s.cephStartPlan(ctx, vm, source)
	if err != nil || len(probes) == 0 {
		return err
	}
	if health.InReconcilerWalk(ctx) {
		if failed, own := s.cephProofs.failedFor(vm.Name, probes); failed {
			return storageDownCeph(own, fmt.Errorf("Ceph did not answer a probe of VM %s's pool on %s in the last %v; the start is retried",
				vm.Name, s.hostName, cephKeyFailTTL))
		}
	}
	bound, cut := storage.ProbeBound, false
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < storage.ProbeBound {
			if left < cephProbeFloor || !health.TakeWalkProbeTurn(ctx) {
				return transientCeph(fmt.Errorf("proving this host's ceph key for VM %s's disks on %s is deferred: it takes up to %v and the caller has %v left",
					vm.Name, s.hostName, storage.ProbeBound, left.Round(time.Millisecond)))
			}
			bound, cut = left, true
		}
	}
	health.TakeWalkProbeTurn(ctx) // any probe is the walk's progress
	pctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	errs := make([]error, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = p.prober.ProbeDisk(pctx, p.path)
		}()
	}
	wg.Wait()
	for i, p := range probes {
		if errs[i] == nil && p.key != "" {
			s.cephProofs.provedFor(vm.Name, p.key)
		}
	}
	// What an operator must fix is reported first: retrying cannot clear it.
	for i, err := range errs {
		if err != nil && storage.IsPermanentCephError(err) {
			return permanentCeph(fmt.Errorf("disk %s on %s: %w", probes[i].disk, s.hostName, err))
		}
	}
	for i, err := range errs {
		if err == nil {
			continue
		}
		err = fmt.Errorf("disk %s on %s: %w", probes[i].disk, s.hostName, err)
		if cut && pctx.Err() != nil {
			// Cut short by the walk's own deadline: no answer about the
			// storage either way.
			return transientCeph(err)
		}
		for j, perr := range errs {
			if perr != nil && probes[j].key != "" {
				s.cephProofs.fail(probes[j].key, vm.Name)
			}
		}
		return storageDownCeph(true, err)
	}
	return nil
}

// cephProbe is one disk a start must still prove this host's key opens.
type cephProbe struct {
	disk, path string
	prober     storage.DiskProber
	key        string // cephProofKey of its pool and identity ("" → never remembered)
}

// cephStartPlan is ensureCephSecretsForVM up to the probes: each ceph disk's
// secret defined and checked, and the probes still needed — those no proof
// remembered within cephKeyProofTTL covers.
func (s *Server) cephStartPlan(ctx context.Context, vm *corrosion.VMRecord, source string) ([]cephProbe, error) {
	if s.virt == nil {
		return nil, nil
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return nil, nil // the start path reports a missing disk list itself
	}
	var probes []cephProbe
	for _, d := range disks {
		want, ok := lv.CephSecretOfLocator(d.Path)
		if !ok {
			continue
		}
		l, _ := storage.ParseCephLocator(d.Path)
		pool := l.Opts["lvpool"]
		cfg, rerr := s.resolveVolume(ctx, vm.StackName, d.StorageVolume)
		switch {
		case errors.Is(rerr, errStorageNotFound):
			// The pool is not on this host (any more): the disk's own locator
			// names its client and keyring.
			if derr := s.defineCephSecret(want, cephLocatorID(l), l.Opts["keyring"], false); derr != nil {
				return nil, classedCeph(derr, fmt.Errorf("disk %s is on ceph pool %q, which %s does not have, and its keyring is not usable here: %w",
					d.DiskName, pool, s.hostName, derr))
			}
			cfg = storage.Config{Name: pool, Driver: "ceph", Source: l.Pool, Options: rbdPathOptions(d.Path)}
		case rerr != nil:
			// Not "no such pool": this host's pools could not be read. The
			// start is retried, as with any transient failure.
			return nil, transientCeph(fmt.Errorf("disk %s: %w", d.DiskName, rerr))
		case !strings.EqualFold(cfg.Driver, "ceph") || cfg.Name != pool:
			return nil, permanentCeph(fmt.Errorf("disk %s is on ceph pool %q, but storage %q on %s is a %s pool; give the pool the same name and driver on every host",
				d.DiskName, pool, d.StorageVolume, s.hostName, cfg.Driver))
		default:
			u, err := s.ensureCephSecret(cfg)
			if err != nil {
				return nil, classedCeph(err, fmt.Errorf("disk %s: %w", d.DiskName, err))
			}
			if u != want {
				return nil, permanentCeph(fmt.Errorf("disk %s authenticates as client.%s of ceph pool %q, but pool %q on %s names client.%s; give the pool the same id on every host",
					d.DiskName, cephLocatorID(l), pool, pool, s.hostName, clientOf(cfg)))
			}
			if err := s.refuseCephKeyUnlikeSource(ctx, pool, source, cfg); err != nil {
				return nil, err
			}
		}
		drv, err := storage.New(s.dataDir, cfg)
		if err != nil {
			return nil, permanentCeph(fmt.Errorf("disk %s: %w", d.DiskName, err))
		}
		p, ok := drv.(storage.DiskProber)
		if !ok {
			continue
		}
		key := cephProofKey(cfg, l.Pool)
		// A proven key skips the probe — unless this VM's own probe through
		// it got no answer: another VM's proof says nothing about this VM's
		// image (Breaker R-1).
		if key != "" && s.cephProofs.fresh(key) && !s.cephProofs.ownFailed(vm.Name, key) {
			continue
		}
		probes = append(probes, cephProbe{disk: d.DiskName, path: d.Path, prober: p, key: key})
	}
	return probes, nil
}

// rbdLocatorsOf maps each rbd disk of a VM (by its image spec, the domain's
// <source name>) to its recorded locator, for a migration to re-resolve.
func (s *Server) rbdLocatorsOf(ctx context.Context, vmName string) map[string]string {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil
	}
	var out map[string]string
	for _, d := range disks {
		if l, ok := storage.ParseCephLocator(d.Path); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[l.Spec] = d.Path
		}
	}
	return out
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
		return status.Errorf(cephErrCode(err), "%s cannot receive VM %q: %v", s.hostName, vm.Name, err)
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
			return status.Errorf(codes.Unavailable,
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
	if err := corrosion.UpdateStoragePoolOptions(ctx, s.db, rec); err != nil {
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
	differing := cephKeyDiffering(mine, fps, s.hostName)
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
		"detail": fmt.Sprintf("the keyring of ceph pool %q on %s holds a different key than on %s; a live migration between hosts whose keys differ is refused, and a start proves the host's own key with rbd",
			pool, s.hostName, strings.Join(differing, ", ")),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("ceph pool: raise keyring condition", "pool", pool, "error", err)
	}
}

// ReconcileCephSecrets brings this host's litevirt ceph secrets in line with
// its ceph pools (and names, by ceph_trash_leftover, any image in a pool's
// trash this host has failed to purge): every pool's secret is defined (and its value re-set when
// the keyring changed or libvirt lost it), its key fingerprint recorded and
// compared with the pool's other hosts, a disk whose pool is gone gets its
// secret from its own locator, and a secret no pool and no disk recorded on
// this host uses any more is removed. Nothing is removed on a partial view (a
// listing that failed), nor within cephSecretGrace of its last definition.
func (s *Server) ReconcileCephSecrets(ctx context.Context) {
	if s.db != nil {
		s.judgeCephTrash(ctx)
		s.judgeCephImages(ctx)
		s.judgeKeptDisks(ctx)           // disk_kept.go: not a ceph check, but run on the same pass
		s.judgeFirmwareMoveRecords(ctx) // firmware_records_health.go: likewise
		s.sweepCancelledStarts(ctx)     // cancelled_starts.go: likewise; it does not wait for libvirt
	}
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

// cephPoolRef is litevirt pool `name` as this host has it now: one of its
// storage pools (the loaded list, then the table, which holds a pool the list
// has not loaded yet, right after a restart), or, for "<stack>/<volume>" (no
// host pool name has a "/"), that volume of the stored compose stack, as
// resolveVolume gives it to a create and cephStartPlan to a start. found is
// false when there is no such pool or volume here; err is set when whether
// there is cannot be read.
func (s *Server) cephPoolRef(ctx context.Context, name string) (StoragePoolRef, bool, error) {
	if name == "" {
		return StoragePoolRef{}, false, nil
	}
	if stack, vol, isVol := strings.Cut(name, "/"); isVol {
		f, err := s.storedStackFile(ctx, stack)
		if err != nil || f == nil {
			return StoragePoolRef{}, false, err
		}
		v, ok := f.Volumes[vol]
		if !ok {
			return StoragePoolRef{}, false, nil
		}
		return StoragePoolRef{Driver: v.Driver, Source: v.Source, Target: v.Target, Options: v.Options}, true, nil
	}
	return s.resolvePoolErr(ctx, name)
}

// CephMonitorsForPool is the monitor list a domain's rbd disk on litevirt pool
// `name` is given on this host now (lv.SetCephMonitorResolver): the pool's
// mon_host option, else its conf's mon_host. The pool is cephPoolRef's — a
// pool the loaded list does not hold yet, or a compose stack volume, is read
// from the table: its locator's recorded monitors are never given in its
// place. ok is false when this host has no such ceph pool, or it cannot be
// read, or its conf cannot be.
func (s *Server) CephMonitorsForPool(name string) ([]string, bool) {
	ref, ok := s.lookupStoragePool(name)
	if !ok && name != "" && s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cephPoolTableReadTimeout)
		ref, ok, _ = s.cephPoolRef(ctx, name)
		cancel()
	}
	if !ok {
		return nil, false
	}
	return cephRefMonitors(ref)
}

// cephRefMonitors is CephMonitorsForPool for a pool already in hand.
func cephRefMonitors(ref StoragePoolRef) ([]string, bool) {
	if !strings.EqualFold(ref.Driver, "ceph") {
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

// cephPoolTableReadTimeout bounds CephMonitorsForPool's table read of a pool
// the loaded list does not hold. It bounds the query, not the wait for the
// database client's lock, which a running write batch holds: that wait is the
// one every read on the start path makes, and a batch is not left holding it.
const cephPoolTableReadTimeout = 5 * time.Second

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

// cephClassed carries how a ceph start failure is to be answered: a
// FailedPrecondition for one an operator must fix (a key the cluster denies,
// a keyring missing, a pool defined differently here), Unavailable for one a
// retry may clear (Ceph not answering, this host's pools unreadable, libvirt
// failing) — which every start path retries, as main retried a start that
// failed in qemu.
type cephClassed struct {
	code codes.Code
	err  error
	// kind: why a transient one defers a start, for the reconciler's next
	// walk (startDeferredError); nil for want of time.
	kind error
}

func (e *cephClassed) Error() string { return e.err.Error() }
func (e *cephClassed) Unwrap() error { return e.err }

func permanentCeph(err error) error { return &cephClassed{code: codes.FailedPrecondition, err: err} }
func transientCeph(err error) error { return &cephClassed{code: codes.Unavailable, err: err} }

// storageDownCeph is a transient failure because Ceph did not answer a probe:
// this VM's own (own), or one of the same storage another VM's start made.
func storageDownCeph(own bool, err error) error {
	kind := health.ErrStartStorageDown
	if own {
		kind = health.ErrStartProbeFailed
	}
	return &cephClassed{code: codes.Unavailable, err: err, kind: kind}
}

// cephDeferKind is the deferral kind a ceph start failure carries (nil: for
// want of time, or unclassed).
func cephDeferKind(err error) error {
	var c *cephClassed
	if errors.As(err, &c) {
		return c.kind
	}
	return nil
}

// classedCeph wraps err with the class its cause already carries.
func classedCeph(cause, err error) error {
	return &cephClassed{code: cephErrCode(cause), err: err}
}

// cephErrCode is the status code a ceph start failure is answered with; an
// unclassed one is Unavailable (retried), never a terminal refusal.
func cephErrCode(err error) codes.Code {
	var c *cephClassed
	if errors.As(err, &c) {
		return c.code
	}
	return codes.Unavailable
}

// refreshRBDMonitors rewrites the persistent definition of a VM about to
// start with each rbd disk's monitors as its pool resolves them now: a start
// does not otherwise re-resolve them, so a monitor the cluster retired would
// stay in the definition. Best effort: a failure leaves the definition as it
// was (it still names the monitors it started with last time).
//
// Only the disks this branch's locators describe (an identity and the
// litevirt pool that names its secret: lv.CephSecretOfLocator) are refreshed;
// a main-era rbd disk is left as it was defined, as it is everywhere else.
// The definition is rewritten only when some disk's monitors differ from the
// ones it names (lv.RefreshRBDHosts).
func (s *Server) refreshRBDMonitors(ctx context.Context, vmName string) {
	if s.virt == nil {
		return
	}
	locators := s.rbdLocatorsOf(ctx, vmName)
	for spec, loc := range locators {
		if _, ok := lv.CephSecretOfLocator(loc); !ok {
			delete(locators, spec)
		}
	}
	if len(locators) == 0 || !s.virt.DomainExists(vmName) {
		return
	}
	release, err := s.netDevs.acquireTransition(ctx, false)
	if err != nil {
		slog.Warn("rbd monitors not refreshed: network transition unavailable", "vm", vmName, "error", err)
		return
	}
	defer release()
	x, err := s.virt.DumpXMLInactive(vmName)
	if err != nil {
		return
	}
	out, changed, err := lv.RefreshRBDHosts(x, locators)
	if err != nil || !changed {
		return
	}
	if err := s.virt.DefineDomain(out); err != nil {
		slog.Warn("rbd monitors not refreshed in the domain definition", "vm", vmName, "error", err)
		return
	}
	slog.Info("rbd monitors refreshed in the domain definition", "vm", vmName)
}
