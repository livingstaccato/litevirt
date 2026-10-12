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

// ReconcileNFSMounts checks the mount of every nfs pool of this host, mounts
// an export missing since this daemon started, and records the outcome on
// the pool's row and in nfs_mount_missing.
func (s *Server) ReconcileNFSMounts(ctx context.Context) {
	if s.db == nil {
		return
	}
	rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("NFS mounts: list this host's pools", "error", err)
		return
	}
	live := map[string]bool{}
	tried := map[string]error{} // per mount point, within this pass
	for _, r := range rows {
		if !strings.EqualFold(r.Driver, "nfs") {
			continue
		}
		live[r.Name] = true
		s.reconcileNFSPool(ctx, r.Name, tried)
	}
	s.resolveGoneNFSPoolConditions(ctx, live)
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

// reconcileNFSPool checks one pool's mount (once per mount point in a pass:
// tried), mounts it when it has been missing since this daemon started,
// writes the pool's state (active, or degraded while it is not mounted) on
// its row when it changed, and raises or resolves its condition. All of it
// under nfsMu, which a pool create and delete of an nfs pool also hold, from
// a fresh read of the row: a pool deleted meanwhile is neither mounted back
// nor written back.
func (s *Server) reconcileNFSPool(ctx context.Context, pool string, tried map[string]error) {
	s.nfsMu.Lock()
	defer s.nfsMu.Unlock()
	rec, found, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, pool)
	if err != nil || !found || !strings.EqualFold(rec.Driver, "nfs") {
		return
	}
	cfg := s.nfsPoolConfig(rec)
	dir := storage.NFSPoolMountDir(s.dataDir, cfg)
	mountErr, done := tried[dir]
	if !done {
		mountErr = s.checkNFSMount(ctx, pool, cfg)
		tried[dir] = mountErr
	}
	if mountErr != nil {
		slog.Warn("NFS pool's export is not mounted; its disks are not available on this host", "pool", pool, "error", mountErr)
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
			slog.Warn("NFS mounts: record the pool's state", "pool", pool, "error", err)
		}
	}
	s.judgeNFSMount(ctx, pool, mountErr)
}

// checkNFSMount is one pass's verdict on a pool's mount: nil when its export
// is mounted (now, or after a mount) or its directory lies on another NFS
// mount, else why not. Only an export missing since this daemon started is
// mounted.
func (s *Server) checkNFSMount(ctx context.Context, pool string, cfg storage.Config) error {
	st, err := storage.CheckNFSPoolMount(s.dataDir, cfg)
	switch {
	case err != nil:
		return err
	case st.Mounted || st.OnNFS:
		s.nfsMem.up(st.Dir)
		return nil
	case st.Foreign != "":
		return fmt.Errorf("mount point %s holds %s, not this pool's export %s; unmount it (umount %s) and litevirt mounts the export there", st.Dir, st.Foreign, cfg.Source, st.Dir)
	case s.nfsMem.wasUp(st.Dir):
		return fmt.Errorf("export %s is not mounted at %s: %s", cfg.Source, st.Dir, nfsUnmountedReason)
	}
	if err := storage.MountNFSPool(ctx, s.dataDir, cfg); err != nil {
		err = fmt.Errorf("export %s is not mounted at %s: %w; the mount is retried every %v", cfg.Source, st.Dir, err, NFSMountReconcileInterval)
		s.nfsMem.mountFailed(st.Dir, err)
		return err
	}
	s.nfsMem.up(st.Dir)
	slog.Info("NFS pool's export was not mounted since the daemon started; mounted", "pool", pool, "source", cfg.Source, "mountpoint", st.Dir)
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
// started the guest on. Unavailable, as that failure was: every start path
// retries it. A mount table that cannot be read refuses nothing.
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
		if cfg.Name == d.StorageVolume {
			if r, ok, gerr := corrosion.GetStoragePool(ctx, s.db, s.hostName, d.StorageVolume); gerr == nil && ok && strings.EqualFold(r.Driver, "nfs") {
				cfg = s.nfsPoolConfig(r)
			}
		}
		dir := storage.NFSPoolMountDir(s.dataDir, cfg)
		if !pathWithin(dir, d.Path) || handled[dir] {
			continue
		}
		handled[dir] = true
		if err := s.ensureNFSMountForStart(ctx, cfg, dir); err != nil {
			slog.Warn("VM start refused: its disk's NFS export is not mounted", "vm", vm.Name, "disk", d.DiskName, "pool", d.StorageVolume, "error", err)
			return status.Errorf(codes.Unavailable, "start %q: disk %s is on nfs pool %q, whose export is not mounted on this host: %v",
				vm.Name, d.DiskName, d.StorageVolume, err)
		}
	}
	return nil
}

// ensureNFSMountForStart is one start's mount of a pool's export: nil when it
// is mounted (or its directory lies on another NFS mount, or the mount table
// cannot be read), else why it is not.
func (s *Server) ensureNFSMountForStart(ctx context.Context, cfg storage.Config, dir string) error {
	st, err := storage.CheckNFSPoolMount(s.dataDir, cfg)
	switch {
	case err != nil:
		return nil // as before this check: the start goes ahead
	case st.Mounted || st.OnNFS:
		return nil
	case st.Foreign != "":
		return fmt.Errorf("mount point %s holds %s, not the export %s; unmount it (umount %s) and litevirt mounts the export there", dir, st.Foreign, cfg.Source, dir)
	case s.nfsMem.wasUp(dir):
		return fmt.Errorf("export %s at %s was %s", cfg.Source, dir, nfsUnmountedReason)
	}
	if ferr, recent := s.nfsMem.failedWithin(dir, NFSMountReconcileInterval); recent {
		return fmt.Errorf("a mount of it failed moments ago, not retried: %v", ferr)
	}
	s.nfsMu.Lock()
	defer s.nfsMu.Unlock()
	if st, err := storage.CheckNFSPoolMount(s.dataDir, cfg); err == nil && st.Mounted {
		return nil // a pass mounted it meanwhile
	}
	mctx, cancel := context.WithTimeout(ctx, nfsStartMountBound)
	defer cancel()
	if err := storage.MountNFSPool(mctx, s.dataDir, cfg); err != nil {
		s.nfsMem.mountFailed(dir, err)
		return err
	}
	s.nfsMem.up(dir)
	slog.Info("VM start: mounted the NFS export of its disk's pool, missing since the daemon started", "source", cfg.Source, "mountpoint", dir)
	return nil
}
