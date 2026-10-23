package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// NFS mounts of this host's nfs pools (lab 2 N-1). A pool's export was
// mounted only by its Prepare (pool create, disk create, move, replicate), so
// after a host reboot the mount point was an empty local directory while the
// pool kept reporting active, and a VM start on it failed with "No such
// file". ReconcileNFSMounts, run by the daemon at start and every
// NFSMountReconcileInterval, checks each nfs pool of this host and mounts its
// export when it has been missing since this daemon started — after a reboot
// (storage.MountNFSPool: the options and hardening a pool create uses; never
// over a directory holding anything, never through a symlink). An export this
// daemon has seen mounted and that then disappeared was unmounted on purpose
// (an NFS mount does not vanish on its own: a hard mount of a server that does
// not answer stays in the mount table) and is left unmounted: the pool is
// reported degraded with nfsUnmountedReason, and a daemon restart mounts it
// again. A pool whose export is not mounted is recorded as PoolStateDegraded
// on its own row and raises nfs_mount_missing (evaluator nfs_pool, subject
// host/<pool>@<host>, warning) with the reason; both clear on the pass that
// finds it mounted.
//
// A VM start (every start path runs PrepareHardwareForStart) mounts the export
// of a disk's pool the same way when it has been missing since the daemon
// started, and otherwise refuses the start with the reason: the start would
// fail at qemu's open of the disk ("No such file"), or — with a file of that
// name left in the empty mount point — start the guest on local data instead
// of the export's.

const (
	nfsPoolEvaluator    = "nfs_pool"
	condNFSMountMissing = "nfs_mount_missing"

	// NFSMountReconcileInterval is how often the daemon checks the mounts.
	NFSMountReconcileInterval = 30 * time.Second

	// nfsUnmountedReason is why an export seen mounted earlier in this
	// daemon's life is not mounted, and not mounted back.
	nfsUnmountedReason = "unmounted while the daemon ran, and litevirt leaves it so; a restart of the litevirt daemon on this host mounts it again"

	// nfsStartMountBound bounds a start's own mount attempt.
	nfsStartMountBound = 45 * time.Second
)

// nfsMountMemory is what this daemon has seen of its pools' mounts, keyed by
// mount point: which it has seen mounted (a later absence is a deliberate
// unmount), and when and why a mount last failed (a start does not retry one
// that failed moments ago).
type nfsMountMemory struct {
	mu     sync.Mutex
	seen   map[string]bool
	failed map[string]nfsMountFailure
}

type nfsMountFailure struct {
	at  time.Time
	err error
}

func (m *nfsMountMemory) up(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	m.seen[dir] = true
	delete(m.failed, dir)
}

func (m *nfsMountMemory) wasUp(dir string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[dir]
}

func (m *nfsMountMemory) mountFailed(dir string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed == nil {
		m.failed = map[string]nfsMountFailure{}
	}
	m.failed[dir] = nfsMountFailure{at: time.Now(), err: err}
}

func (m *nfsMountMemory) failedWithin(dir string, d time.Duration) (error, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.failed[dir]
	if !ok || time.Since(f.at) >= d {
		return nil, false
	}
	return f.err, true
}

// nfsPoolConfig is the driver config of one of this host's nfs pool rows: the
// row's options, with a pool from the daemon config taking its options (its
// row is registered without its mount options) from the config definition.
func (s *Server) nfsPoolConfig(r corrosion.StoragePoolRecord) storage.Config {
	cfg := storage.Config{Name: r.Name, Driver: r.Driver, Source: r.Source, Target: r.Target, Options: r.Options}
	if ref, ok := s.lookupStoragePool(r.Name); ok && strings.EqualFold(ref.Driver, "nfs") && ref.Source == r.Source && ref.Target == r.Target && len(ref.Options) > 0 {
		cfg.Options = ref.Options
	}
	return cfg
}

// nfsLock serialises the mounts this daemon makes of nfs pools' exports with
// an nfs pool's create and delete. It is held only across a mount (with the
// re-read of the pool's row and a re-check of the mount table right before
// it, and the row's write after it). A pass's or a start's first check runs
// without it: a check can resolve a path's symlinks, which on an NFS mount
// whose server does not answer can block. The re-check under the lock can
// too, but only up to the resolution's bound (5 s). Lock takes a context, so
// a start or an RPC waiting for it gives up when its own does.
type nfsLock struct {
	once sync.Once
	ch   chan struct{}
}

func (l *nfsLock) init() { l.once.Do(func() { l.ch = make(chan struct{}, 1) }) }

// Lock takes the lock, or returns ctx's error when ctx ends first.
func (l *nfsLock) Lock(ctx context.Context) error {
	l.init()
	select {
	case l.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *nfsLock) Unlock() { <-l.ch }

// Test seams: run after the pass has listed the pools, and before a start
// takes nfsMu to mount.
var (
	nfsPassAfterList   func()
	nfsStartBeforeLock func()
)

// nfsNotMountedError is a start refused because a disk's NFS export is not
// mounted: to a gRPC caller the Unavailable it wraps, to the reconciler and
// the VM checker health.ErrStartStorageNotMounted, which they count under
// their own refusal reason instead of a hardware one.
type nfsNotMountedError struct{ err error }

func (e *nfsNotMountedError) Error() string { return e.err.Error() }
func (e *nfsNotMountedError) Unwrap() []error {
	return []error{e.err, health.ErrStartStorageNotMounted}
}
func (e *nfsNotMountedError) GRPCStatus() *status.Status { return status.Convert(e.err) }

// ReconcileNFSMounts checks the mount of every nfs pool of this host, mounts
// an export missing since this daemon started, and records the outcome on
// the pool's row and in nfs_mount_missing.
func (s *Server) ReconcileNFSMounts(ctx context.Context) {
	if s.db == nil {
		return
	}
	rows, err := s.ownPools(ctx)
	if err != nil {
		slog.Warn("NFS mounts: list this host's pools", "error", err)
		return
	}
	if nfsPassAfterList != nil {
		nfsPassAfterList()
	}
	live := map[string]bool{}
	tried := map[string]error{} // per mount point, within this pass
	for _, r := range rows {
		if !strings.EqualFold(r.Driver, "nfs") {
			continue
		}
		live[r.Name] = true
		s.reconcileNFSPool(ctx, r, tried)
	}
	s.resolveGoneNFSPoolConditions(ctx, live)
}

// reconcileNFSPool checks one pool's mount (once per mount point in a pass:
// tried) with no lock held, mounts it when it has been missing since this
// daemon started, writes the pool's state (active, or degraded while it is
// not mounted) on its row when it changed, and raises or resolves its
// condition. The mount and the writes are made under nfsMu, which a pool
// create and delete of an nfs pool also hold, from a fresh read of the row: a
// pool deleted meanwhile is neither mounted back nor written back.
func (s *Server) reconcileNFSPool(ctx context.Context, listed corrosion.StoragePoolRecord, tried map[string]error) {
	cfg := s.nfsPoolConfig(listed)
	dir := storage.NFSPoolMountDir(s.dataDir, cfg)
	mountErr, done := tried[dir]
	needMount := false
	if !done {
		needMount, mountErr = s.checkNFSMount(cfg, dir)
	}
	if err := s.nfsMu.Lock(ctx); err != nil {
		return
	}
	defer s.nfsMu.Unlock()
	if _, ok := s.currentNFSPoolRow(ctx, listed.Name, listed.Source, listed.Target); !ok {
		return // deleted, or replaced, since the list: the next pass judges it afresh
	}
	if needMount {
		mountErr = s.mountNFSLocked(ctx, listed.Name, cfg, dir)
	}
	if !done {
		tried[dir] = mountErr
	}
	if mountErr != nil {
		slog.Warn("NFS pool's export is not mounted; its disks are not available on this host", "pool", listed.Name, "error", mountErr)
	}
	s.recordNFSPoolOutcome(ctx, listed.Name, listed.Source, listed.Target, mountErr)
}

// currentNFSPoolRow re-reads this host's row of nfs pool name, and reports
// whether it is still the pool with that source and target.
func (s *Server) currentNFSPoolRow(ctx context.Context, name, source, target string) (corrosion.StoragePoolRecord, bool) {
	rec, found, err := s.ownPool(ctx, name)
	if err != nil || !found || !strings.EqualFold(rec.Driver, "nfs") || rec.Source != source || rec.Target != target {
		return rec, false
	}
	return rec, true
}

// recordNFSPoolOutcome writes, from a fresh read of its row, an nfs pool's
// state (degraded while mountErr, active again once it is nil) when it
// changed, and raises or resolves its condition. A pool deleted or replaced
// meanwhile is not written back.
func (s *Server) recordNFSPoolOutcome(ctx context.Context, name, source, target string, mountErr error) {
	rec, ok := s.currentNFSPoolRow(ctx, name, source, target)
	if !ok {
		return
	}
	want := rec.State
	switch {
	case mountErr != nil:
		want = PoolStateDegraded
	case rec.State == PoolStateDegraded:
		want = "active"
	}
	if want != rec.State {
		rec.State = want
		if err := corrosion.UpsertStoragePool(ctx, s.db, rec); err != nil {
			slog.Warn("NFS mounts: record the pool's state", "pool", name, "error", err)
		}
	}
	s.judgeNFSMount(ctx, name, mountErr)
}

// nfsMountSlowAfter is how long a mount of a pool's export may run before
// the pool is reported degraded while it still runs; tests shorten it.
var nfsMountSlowAfter = 5 * time.Second

// nfsOutcomeWriteBound bounds the row and condition writes of a mount's
// outcome, made on a fresh context.
const nfsOutcomeWriteBound = 10 * time.Second

// OverrideNFSMountSlowAfterForTest sets nfsMountSlowAfter, for tests in other
// packages. It returns the restore function.
func OverrideNFSMountSlowAfterForTest(d time.Duration) func() {
	prev := nfsMountSlowAfter
	nfsMountSlowAfter = d
	return func() { nfsMountSlowAfter = prev }
}

// watchNFSMount reports pool degraded, with the reason, once a mount of its
// export has run for nfsMountSlowAfter without finishing (lab 2 F-3: against
// a server that does not answer, a mount runs to its timeout, and the pool
// read active, with no condition, the whole time). The caller records the
// mount's outcome after stop, which ends the watch and waits for a report it
// is writing. A stack volume (pool "") has no row, and is not watched.
func (s *Server) watchNFSMount(ctx context.Context, pool, source, target, dir string) (stop func()) {
	if pool == "" || s.db == nil {
		return func() {}
	}
	after := nfsMountSlowAfter
	started := time.Now().UTC()
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTimer(after)
		defer t.Stop()
		select {
		case <-done:
			return
		case <-t.C:
		}
		err := fmt.Errorf("a mount of export %s at %s has been running since %s without finishing (does its server answer?); it is given up when its command timeout ends, and retried every %v",
			source, dir, started.Format(time.RFC3339), NFSMountReconcileInterval)
		slog.Warn("NFS pool's export is still being mounted; the pool is degraded until it is", "pool", pool, "error", err)
		// A fresh, bounded context: the mount's own may be all but spent
		// (a start waited for nfsMu out of its 45 s).
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), nfsOutcomeWriteBound)
		defer cancel()
		s.recordNFSPoolOutcome(wctx, pool, source, target, err)
	}()
	return func() {
		close(done)
		<-finished
	}
}

// checkNFSMount is a pass's verdict on a pool's mount, made with no lock
// held: nil when an NFS export is mounted at its mount point (or the
// directory lies on another NFS mount), else why it is not; needMount when it
// has been missing since this daemon started, and is to be mounted.
func (s *Server) checkNFSMount(cfg storage.Config, dir string) (needMount bool, err error) {
	st, err := storage.CheckNFSPoolMount(s.dataDir, cfg)
	switch {
	case err != nil:
		return false, err
	case st.Mounted || st.OnNFS:
		if st.Other != "" {
			s.warnOtherNFSMount(dir, cfg.Source, st.Other)
		}
		s.nfsMem.up(dir)
		return false, nil
	case st.Foreign != "":
		return false, fmt.Errorf("mount point %s holds %s, not this pool's export %s; unmount it (umount %s) and litevirt mounts the export there", dir, st.Foreign, cfg.Source, dir)
	case s.nfsMem.wasUp(dir):
		return false, fmt.Errorf("export %s is not mounted at %s: %s", cfg.Source, dir, nfsUnmountedReason)
	}
	return true, nil
}

// warnOtherNFSMount says, once per mount point and source, that a pool's
// mount point holds an NFS mount whose source is not the pool's export as the
// pool spells it (a hand mount, another spelling of it, or another export).
// It counts as mounted, as it did on main at start; the pool's check at use
// still refuses another export.
func (s *Server) warnOtherNFSMount(dir, source, other string) {
	if _, seen := s.nfsOtherWarned.LoadOrStore(dir+"\x00"+other, true); seen {
		return
	}
	slog.Warn("NFS pool's mount point holds an NFS mount of another source; it is used as mounted, and the pool's check at use refuses it if it is not the pool's export",
		"mountpoint", dir, "source", source, "mounted", other)
}

// mountNFSLocked mounts a pool's export, under nfsMu: after a fresh look at
// the mount table (a start, or a disk create's Prepare, may have mounted it
// since the check), and only when it is still missing since this daemon
// started.
func (s *Server) mountNFSLocked(ctx context.Context, pool string, cfg storage.Config, dir string) error {
	if need, err := s.checkNFSMount(cfg, dir); !need {
		return err
	}
	stop := s.watchNFSMount(ctx, pool, cfg.Source, cfg.Target, dir)
	err := storage.MountNFSPool(ctx, s.dataDir, cfg)
	stop()
	if err != nil {
		err = fmt.Errorf("export %s is not mounted at %s: %w; the mount is retried every %v", cfg.Source, dir, err, NFSMountReconcileInterval)
		s.nfsMem.mountFailed(dir, err)
		return err
	}
	s.nfsMem.up(dir)
	slog.Info("NFS pool's export was not mounted since the daemon started; mounted", "pool", pool, "source", cfg.Source, "mountpoint", dir)
	return nil
}

// judgeNFSMount raises nfs_mount_missing for pool on this host while
// mountErr, observed on the first pass and confirmed on the next, and
// resolves it once the export is mounted.
func (s *Server) judgeNFSMount(ctx context.Context, pool string, mountErr error) {
	subject := pool + "@" + s.hostName
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, nfsPoolEvaluator, condNFSMountMissing, "host", subject)
	if err != nil {
		return
	}
	if mountErr == nil {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("NFS mounts: resolve condition", "pool", pool, "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: nfsPoolEvaluator, Code: condNFSMountMissing,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	ev, _ := json.Marshal(map[string]any{
		"pool": pool, "host": s.hostName,
		"detail": fmt.Sprintf("nfs pool %q on %s is not mounted, so a VM disk on it cannot open there (a start of one is refused): %v. "+
			"The pool reports %s until it is mounted",
			pool, s.hostName, mountErr, PoolStateDegraded),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("NFS mounts: raise condition", "pool", pool, "error", err)
	}
}

// resolveGoneNFSPoolConditions resolves this host's open nfs_mount_missing
// conditions whose pool is no longer an nfs pool here.
func (s *Server) resolveGoneNFSPoolConditions(ctx context.Context, live map[string]bool) {
	conds, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		return
	}
	suffix := "@" + s.hostName
	for _, c := range conds {
		if c.Evaluator != nfsPoolEvaluator || c.Code != condNFSMountMissing || c.Lifecycle == corrosion.ConditionResolved ||
			!strings.HasSuffix(c.SubjectID, suffix) || live[strings.TrimSuffix(c.SubjectID, suffix)] {
			continue
		}
		s.judgeNFSMount(ctx, strings.TrimSuffix(c.SubjectID, suffix), nil)
	}
}

// ensureNFSMountsForVM, before a start on this host, mounts the export of
// each of the VM's disks on an nfs pool whose export has not been mounted
// since this daemon started, and refuses the start, with the reason, when a
// disk's export is still not mounted: it was unmounted while the daemon ran,
// its mount failed, or its mount point holds something a mount would hide.
// Such a start failed on main too, at qemu's open of the disk, unless a file
// of the disk's name sat in the empty mount point, which it would have
// started the guest on. Unavailable, as that failure was; the reconciler
// re-drives it, and the VM checker's restarts set the VM to error, as a
// failed start always did there. A mount table that cannot be read refuses
// nothing.
func (s *Server) ensureNFSMountsForVM(ctx context.Context, vm *corrosion.VMRecord) error {
	if s.db == nil {
		return nil
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return nil
	}
	handled := map[string]bool{}
	for _, d := range disks {
		if d.Path == "" || d.StorageVolume == "" {
			continue
		}
		cfg, err := s.resolveVolume(ctx, vm.StackName, d.StorageVolume)
		if err != nil || !strings.EqualFold(cfg.Driver, "nfs") {
			continue
		}
		// The pool's own row (for a config pool, its configured options) —
		// only when the disk's storage resolved to the pool, not to a stack
		// volume of the same name.
		pool := ""
		if cfg.Name == d.StorageVolume {
			if r, ok, gerr := s.ownPool(ctx, d.StorageVolume); gerr == nil && ok && strings.EqualFold(r.Driver, "nfs") {
				cfg, pool = s.nfsPoolConfig(r), r.Name
			}
		}
		dir := storage.NFSPoolMountDir(s.dataDir, cfg)
		if !pathWithin(dir, d.Path) || handled[dir] {
			continue
		}
		handled[dir] = true
		if err := s.ensureNFSMountForStart(ctx, pool, cfg, dir); err != nil {
			slog.Warn("VM start refused: its disk's NFS export is not mounted", "vm", vm.Name, "disk", d.DiskName, "pool", d.StorageVolume, "error", err)
			return &nfsNotMountedError{err: status.Errorf(codes.Unavailable, "start %q: disk %s is on nfs pool %q, whose export is not mounted on this host: %v",
				vm.Name, d.DiskName, d.StorageVolume, err)}
		}
	}
	return nil
}

// ensureNFSMountForStart is one start's mount of a pool's export: nil when an
// NFS export is mounted there (or its directory lies on another NFS mount, or
// the mount table cannot be read), else why it is not. pool names the
// pool's row on this host ("" for a stack volume): a pool deleted while the
// start waited for nfsMu is not mounted back.
func (s *Server) ensureNFSMountForStart(ctx context.Context, pool string, cfg storage.Config, dir string) error {
	judge := func() (bool, error) {
		st, err := storage.CheckNFSPoolMount(s.dataDir, cfg)
		switch {
		case err != nil:
			return false, nil // as before this check: the start goes ahead
		case st.Mounted || st.OnNFS:
			s.nfsMem.up(dir)
			return false, nil
		case st.Foreign != "":
			return false, fmt.Errorf("mount point %s holds %s, not the export %s; unmount it (umount %s) and litevirt mounts the export there", dir, st.Foreign, cfg.Source, dir)
		case s.nfsMem.wasUp(dir):
			return false, fmt.Errorf("export %s at %s was %s", cfg.Source, dir, nfsUnmountedReason)
		}
		if ferr, recent := s.nfsMem.failedWithin(dir, NFSMountReconcileInterval); recent {
			return false, fmt.Errorf("a mount of it failed moments ago, not retried: %v", ferr)
		}
		return true, nil
	}
	need, err := judge()
	if !need {
		return err
	}
	if nfsStartBeforeLock != nil {
		nfsStartBeforeLock()
	}
	mctx, cancel := context.WithTimeout(ctx, nfsStartMountBound)
	defer cancel()
	if err := s.nfsMu.Lock(mctx); err != nil {
		return fmt.Errorf("another NFS mount on this host did not finish in time: %v", err)
	}
	defer s.nfsMu.Unlock()
	// Again, under the lock: a pass, or another start, may have mounted it,
	// failed to, or seen it unmounted meanwhile, and the pool may be gone.
	if need, err = judge(); !need {
		return err
	}
	if pool != "" {
		if r, ok, gerr := s.ownPool(ctx, pool); gerr == nil && (!ok || !strings.EqualFold(r.Driver, "nfs") || r.Source != cfg.Source || r.Target != cfg.Target) {
			return fmt.Errorf("pool %q was deleted or replaced on this host while the start waited", pool)
		}
	}
	stop := s.watchNFSMount(mctx, pool, cfg.Source, cfg.Target, dir)
	err = storage.MountNFSPool(mctx, s.dataDir, cfg)
	stop()
	if pool != "" {
		// The pool's row says so at once, not at the next pass: degraded
		// with the reason, or active again.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), nfsOutcomeWriteBound)
		s.recordNFSPoolOutcome(wctx, pool, cfg.Source, cfg.Target, err)
		cancel()
	}
	if err != nil {
		s.nfsMem.mountFailed(dir, err)
		return err
	}
	s.nfsMem.up(dir)
	slog.Info("VM start: mounted the NFS export of its disk's pool, missing since the daemon started", "source", cfg.Source, "mountpoint", dir)
	return nil
}
