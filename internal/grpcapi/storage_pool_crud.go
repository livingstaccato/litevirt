package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// CreateStoragePool registers a new storage pool. The flow:
//
//  1. Validate (non-empty name, supported driver).
//  2. If the caller targeted a different host, forward there — the
//     pool's Prepare() hook (mount NFS, log into iSCSI, …) MUST run on
//     the actual host that's going to serve disks from it.
//  3. Build the driver via storage.New() so unknown drivers fail fast
//     with a useful "supported drivers" hint.
//  4. Call Prepare(). If it fails, do NOT persist the row — we don't
//     want a half-mounted pool advertised cluster-wide.
//  5. Upsert the row via Corrosion. Replication carries it to peers.
//
// Idempotency: re-registering an existing (host,name) returns OK and
// re-runs Prepare — operators expect `lv pool create` to be safe to
// retry after a transient mount failure.
func (s *Server) CreateStoragePool(ctx context.Context, req *pb.CreateStoragePoolRequest) (*pb.CreateStoragePoolResponse, error) {
	// A pool is GLOBAL (req.Project == "" → admin-managed, RBAC-anchored at root) or
	// OWNED by a project (RBAC at /projects/<p>/...). Empty project is NOT normalized
	// to "_default" — that would make it owned, not global.
	// Operator role floor BEFORE any lookup, so a viewer cannot probe pool
	// existence through the authorization checks below. Same order as
	// DeleteStoragePool.
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	project := req.Project
	if project != "" {
		if _, err := safename.CanonicalProjectName(project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid project %q: %v", project, err)
		}
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := safename.ValidatePoolName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if req.Driver == "" {
		return nil, status.Error(codes.InvalidArgument, "driver is required")
	}
	if !slices.Contains(storage.SupportedDrivers, req.Driver) {
		return nil, status.Errorf(codes.InvalidArgument,
			"unknown driver %q (supported: %v)", req.Driver, storage.SupportedDrivers)
	}
	for _, k := range []string{storage.NFSExportOption, storage.DataDisksExportOption} {
		if _, ok := req.Options[k]; ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"option %q is recorded by the daemon, not set in a request", k)
		}
	}

	host := req.Host
	if host == "" {
		host = s.hostName
	}
	// Authorize the project the request CLAIMS — this is where the pool is going.
	if err := s.RequirePerm(ctx, poolRBACPathFor(project, req.Name), "storage.pool.write", "operator"); err != nil {
		return nil, err
	}
	// …and, when a pool of that (host, name) already exists, ALSO authorize its
	// STORED project. The persist below is an INSERT OR REPLACE keyed on
	// (host_name, name), so a create against an existing name is a rewrite of
	// that row: without this, a tenant holding write only in their own project
	// could submit `--project acme` for a global (or another tenant's) pool,
	// pass the claimed-path check, and repoint the stored row at storage they
	// control. DeleteStoragePool authorizes the stored project for the same
	// reason. Fail closed on a read error.
	//
	// When the stored project equals the claim this is the same path that was
	// just checked, so an ordinary re-apply costs nothing.
	existing, found, err := corrosion.GetStoragePool(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if found && existing.Project != project {
		if err := s.RequirePerm(ctx, poolRBACPathFor(existing.Project, req.Name), "storage.pool.write", "operator"); err != nil {
			return nil, err
		}
	}
	// A pool that names a directory or file on the host makes the daemon write
	// there as root, so naming one takes cluster-root authority, and some
	// directories are refused to everyone. Checked here, before the forward,
	// because a forwarded call reaches the owner as a peer; the owner checks the
	// directories again against its own data and PKI dirs.
	if err := s.authorizePoolHostPaths(ctx, fmt.Sprintf("pool %q", req.Name), storage.Config{
		Driver: req.Driver, Source: req.Source, Target: req.Target, Options: req.Options,
	}); err != nil {
		return nil, err
	}
	// The global ISO library's row decides what every project may boot, so
	// creating, replacing or retargeting it is an Admin's (storage.hostpath).
	if req.Name == globalISOLibrary && (project == "" || (found && existing.Project == "")) {
		if err := s.requireISOLibraryRowAuthority(ctx); err != nil {
			return nil, err
		}
		s.pinImplicitISOLibraryMode(ctx)
	}
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "dial %q: %v", host, err)
		}
		defer conn.Close()
		req.Host = host
		return client.CreateStoragePool(ctx, req)
	}

	// A target-less local pool gets a directory of its own, never the shared
	// <data_dir>/disks that holds every VM's local disks across projects.
	if req.Driver == "local" && req.Target == "" {
		req.Target = localPoolDir(s.dataDir, req.Name)
		// A directory left by an earlier pool of this name (in any project)
		// is not handed to this one with its files in it.
		if !(found && existing.Target == req.Target) {
			// The count, never the names: they may be another project's.
			if n := dirEntryCount(req.Target); n > 0 {
				slog.Error("storage pool create refused: its directory holds an earlier pool's files",
					"pool", req.Name, "dir", req.Target, "files", dirEntriesSample(req.Target, 20))
				return nil, status.Errorf(codes.FailedPrecondition,
					"pool %q: its directory already holds %d file(s) from an earlier pool of that name; an admin must remove them first",
					req.Name, n)
			}
		}
	}
	// An NFS export — an nfs pool's, or the one under a directory pool on an
	// NFS mount — is one pool's, cluster-wide and under any spelling of its
	// server, and an NFS pool's mount point is never another pool's
	// directory. Directory pools may share a local directory (their content
	// is confined per file). The other pool is not named: it may be another
	// project's.
	newRef := StoragePoolRef{Driver: req.Driver, Source: req.Source, Target: req.Target}
	other, why, err := s.poolSharedWith(ctx, req.Name, &project, newRef, true)
	if errors.Is(err, errNFSUnresolved) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"pool %q: %v; an NFS server must resolve so its export can be told apart from every other pool's", req.Name, err)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check for a shared directory: %v", err)
	}
	if other != "" {
		slog.Error("storage pool create refused: storage shared with another pool", "pool", req.Name, "other", other, "how", why)
		what := req.Target
		if strings.EqualFold(req.Driver, "nfs") {
			what = req.Source
		}
		return nil, status.Errorf(codes.FailedPrecondition, "pool %q: %s is already another pool's (%s); an NFS export or mount point belongs to one pool", req.Name, what, why)
	}
	if err := checkDirPoolNFSHardened(s.dataDir, newRef); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "pool %q: %v", req.Name, err)
	}
	// A directory pool on an NFS mount records the export it is on, so a
	// pool on another host — which cannot see this host's mounts — compares
	// against it.
	var mt storage.MountTable
	if exp, err := s.poolExportOf(&mt, s.hostName, newRef); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "pool %q: %v", req.Name, err)
	} else if exp != nil && !strings.EqualFold(req.Driver, "nfs") {
		opts := make(map[string]string, len(req.Options)+1)
		for k, v := range req.Options {
			opts[k] = v
		}
		opts[storage.NFSExportOption] = exp.String()
		req.Options = opts
	}
	if err := s.refuseGlobalISOLibraryOverlap(ctx, req); err != nil {
		return nil, err
	}
	if err := s.refuseISOIdentityStoreOverlap(req); err != nil {
		return nil, err
	}

	driver, err := storage.New(s.dataDir, storage.Config{
		Driver:  req.Driver,
		Source:  req.Source,
		Target:  req.Target,
		Options: req.Options,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "build driver: %v", err)
	}
	if err := driver.Prepare(ctx); err != nil {
		// Surface the underlying error verbatim — most "could not
		// mount NFS / could not connect to monitor" diagnostics come
		// from the system itself and operators read them directly.
		return nil, status.Errorf(codes.FailedPrecondition, "prepare: %v", err)
	}

	rec := corrosion.StoragePoolRecord{
		HostName: host,
		Name:     req.Name,
		Driver:   req.Driver,
		Source:   req.Source,
		Target:   req.Target,
		Options:  req.Options,
		Project:  project, // "" = global/shared
		State:    "active",
	}
	// Populate capacity immediately for file-based pools so the UI/inspect and
	// capacity-aware placement don't show 0B until the daemon's next refresh
	// tick. The daemon keeps these current thereafter (refreshDBPoolCapacity).
	if isFileBasedDriver(req.Driver) && req.Target != "" {
		var st syscall.Statfs_t
		if err := syscall.Statfs(req.Target, &st); err == nil {
			rec.TotalBytes = int64(st.Blocks * uint64(st.Bsize))
			rec.UsedBytes = int64((st.Blocks - st.Bavail) * uint64(st.Bsize))
		}
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "persist: %v", err)
	}
	// Make the pool resolvable for move/replicate/compose on this host right
	// away — the daemon's periodic refresh would otherwise be the only thing
	// that loads runtime-created pools into the in-memory map.
	s.addStoragePoolRef(req.Name, StoragePoolRef{
		Driver:  req.Driver,
		Source:  req.Source,
		Target:  req.Target,
		Options: req.Options,
	})
	slog.Info("storage pool created", "host", host, "name", req.Name, "driver", req.Driver)
	return &pb.CreateStoragePoolResponse{Pool: storagePoolRecordToPB(rec)}, nil
}

// DeleteStoragePool soft-deletes a pool row. The driver is given a chance
// to tear down (unmount NFS, log out of iSCSI) but a teardown failure
// does NOT block the row delete — an operator who hit "rm" likely wants
// the pool gone from the inventory even if cleanup is incomplete, and
// can always re-mount manually. The error is logged so it's not silent.
func (s *Server) DeleteStoragePool(ctx context.Context, req *pb.DeleteStoragePoolRequest) (*pb.DeleteStoragePoolResponse, error) {
	// Operator role floor BEFORE any lookup, so a viewer is rejected without being
	// able to probe pool existence; the project-scoped check follows the fetch.
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	// Authorize against the pool's OWNING project (its STORED project, never the
	// request's claim), scoped to the pool's host. storage_pools is replicated, so
	// the entry node can read the record to RBAC-check before forwarding to the
	// owning host. Fail closed on a read error.
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.Name, host)
	}
	if err := s.RequirePerm(ctx, poolRBACPathFor(rec.Project, req.Name), "storage.pool.write", "operator"); err != nil {
		return nil, err
	}
	if rec.Name == globalISOLibrary && rec.Project == "" {
		if err := s.requireISOLibraryRowAuthority(ctx); err != nil {
			return nil, err
		}
		s.pinImplicitISOLibraryMode(ctx)
	}
	if host != s.hostName {
		// Run the reference guard on THIS (entry) node's replicated view BEFORE
		// forwarding, so a NEW entry node enforces the check even when the pool's
		// host runs an OLD daemon that lacks it (mixed-cluster). The target
		// re-checks against its own authoritative view below — a reference
		// visible to EITHER node blocks (unless --force).
		if err := s.poolReferenceGuard(ctx, host, req.Name, req.Force); err != nil {
			return nil, err
		}
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "dial %q: %v", host, err)
		}
		defer conn.Close()
		req.Host = host
		return client.DeleteStoragePool(ctx, req)
	}

	// Target path: re-run the guard against this host's authoritative view.
	if err := s.poolReferenceGuard(ctx, host, req.Name, req.Force); err != nil {
		return nil, err
	}

	// A pool's own <data_dir>/pools/<name> goes with it — but never with files
	// in it: the next pool of this name, in any project, would inherit them.
	// The daemon's own directories in it — the replica area, the upload
	// markers — are not files anyone left there: their empty directories and
	// stale markers are removed. No replica is ever deleted here, with
	// --force or without: --force deletes the pool even with files left, as
	// it always did (main's --force only passed the reference guard), and
	// what is left — replicas included — stays in the directory, which is
	// then kept (and a new pool of this name is refused it while it holds
	// them).
	ownDir := ""
	if (rec.Driver == "local" || rec.Driver == "") && rec.Target == localPoolDir(s.dataDir, rec.Name) {
		ownDir = rec.Target
		kept := s.cleanDaemonPoolDirs(ownDir)
		if left := dirEntriesSample(ownDir, 5); len(left) > 0 {
			if !req.Force {
				return nil, status.Errorf(codes.FailedPrecondition,
					"pool %q still holds files in %s (%s); delete them first, or delete the pool with --force (the files stay)", req.Name, ownDir, strings.Join(append(left, kept...), ", "))
			}
			slog.Warn("storage pool deleted with files left in its directory; the directory and every file in it are kept",
				"pool", req.Name, "dir", ownDir, "files", left, "replicas", kept)
			ownDir = ""
		}
	}

	// Driver teardown (unmount NFS / log out of iSCSI) is best-effort about ERRORS
	// — an operator who hit delete wants the pool gone from inventory even if
	// cleanup is incomplete — but its refcount PREDICATES are hard guards (never
	// tear down a mount/session another pool still uses).
	if err := s.driverTeardownIfPossible(ctx, rec); err != nil {
		slog.Warn("storage pool teardown failed (continuing with row delete)",
			"host", host, "name", req.Name, "error", err)
	}
	// Belt-and-suspenders: drop any libvirt pool object. Idempotent — runtime
	// pools usually have no libvirt handle (Create doesn't EnsureStoragePool), so
	// this is a no-op in the common case and never deletes underlying storage.
	if err := s.virt.PoolDestroyIfDefined(req.Name); err != nil {
		slog.Warn("libvirt pool undefine failed (continuing with row delete)",
			"host", host, "name", req.Name, "error", err)
	}

	if err := corrosion.MarkStoragePoolDeleted(ctx, s.db, host, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	s.removeStoragePoolRef(req.Name)
	if ownDir != "" {
		if err := os.Remove(ownDir); err != nil && !os.IsNotExist(err) {
			slog.Warn("storage pool directory not removed", "pool", req.Name, "dir", ownDir, "error", err)
		}
	}
	s.audit(ctx, "storage.pool.delete", req.Name, fmt.Sprintf("force=%t", req.Force), "ok")
	slog.Info("storage pool deleted", "host", host, "name", req.Name)
	return &pb.DeleteStoragePoolResponse{}, nil
}

// cleanDaemonPoolDirs removes the daemon's own directories in a pool's
// directory before the pool is deleted, as far as they hold nothing:
//
//   - the replica area (.replicas): its empty owner directories, and the area
//     once empty. A replica is never removed here — not with --force either:
//     a replica may be a VM's only copy (its host down, not yet promoted);
//   - the upload markers (.litevirt-uploads): every marker whose upload is no
//     longer there.
//
// Only real directories are entered (a symlink there is never followed), and
// each directory is removed only once empty. It returns the area files kept
// (owner/name, at most a few), for the caller to name.
func (s *Server) cleanDaemonPoolDirs(dir string) (kept []string) {
	realDir := func(p string) bool {
		fi, err := os.Lstat(p)
		return err == nil && fi.IsDir()
	}
	area := filepath.Join(dir, replicaAreaDir)
	if realDir(area) {
		owners, _ := os.ReadDir(area)
		for _, o := range owners {
			od := filepath.Join(area, o.Name())
			if !o.IsDir() || !realDir(od) {
				continue
			}
			for _, f := range dirEntriesSample(od, 5) {
				if len(kept) < 5 && !strings.HasPrefix(f, "and ") {
					kept = append(kept, filepath.Join(replicaAreaDir, o.Name(), f))
				}
			}
			_ = os.Remove(od) // only once empty
		}
		_ = os.Remove(area)
	}
	markers := filepath.Join(dir, uploadMarkerDir)
	if realDir(markers) {
		ents, _ := os.ReadDir(markers)
		for _, e := range ents {
			if _, err := os.Lstat(filepath.Join(dir, e.Name())); errors.Is(err, fs.ErrNotExist) {
				_ = os.Remove(filepath.Join(markers, e.Name()))
			}
		}
		_ = os.Remove(markers)
	}
	return kept
}

// GetStoragePool returns one pool's full details. Used by `lv pool inspect`.
// Read is project-scoped: a global pool is visible to any viewer, an owned one
// only to its project (or root) — previously this required root for ALL pools,
// which both over-restricted a project's own pool and under-scoped reads.
func (s *Server) GetStoragePool(ctx context.Context, req *pb.GetStoragePoolRequest) (*pb.GetStoragePoolResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.Name, host)
	}
	if err := s.authorizeResourceRead(ctx, rec.Project, poolRBACPathFor(rec.Project, rec.Name), "storage.pool.read"); err != nil {
		return nil, err
	}
	return &pb.GetStoragePoolResponse{Pool: storagePoolRecordToPB(rec)}, nil
}

// driverTeardownIfPossible builds the pool's driver and, when it implements the
// optional storage.Teardowner capability (NFS umount / iSCSI logout), invokes it
// — but ONLY after a hard refcount guard: a shared NFS export/mount or iSCSI
// session must never be torn down while another live pool row on this host still
// references the same underlying source. Drivers without a Teardown method
// (local, dir, ceph, zfs, btrfs, lvm-thin) are a no-op. The driver-side hook is
// itself idempotent and skips operator-managed mounts (NFS targetOverride).
func (s *Server) driverTeardownIfPossible(ctx context.Context, rec corrosion.StoragePoolRecord) error {
	if rec.Name == "" {
		return errors.New("missing pool name")
	}
	driver, err := storage.New(s.dataDir, storage.Config{
		Driver:  rec.Driver,
		Source:  rec.Source,
		Target:  rec.Target,
		Options: rec.Options,
	})
	if err != nil {
		// An unknown/unbuildable driver has nothing host-level to undo — the row
		// delete should still proceed.
		return fmt.Errorf("build driver for teardown: %w", err)
	}
	td := storage.AsTeardowner(driver)
	if td == nil {
		return nil // local/dir/ceph/zfs/btrfs/lvm-thin — nothing to tear down
	}
	// Refcount: don't tear down a mount/session another pool on this host still
	// uses. The shared resource is driver-specific (NFS derived mountpoint, iSCSI
	// IQN+portal), not merely the same source string.
	shared, err := corrosion.CountPoolsSharingResource(ctx, s.db, rec)
	if err != nil {
		return fmt.Errorf("count pools sharing resource: %w", err)
	}
	if shared > 0 {
		slog.Info("storage pool teardown skipped: resource shared by another pool",
			"host", rec.HostName, "name", rec.Name, "driver", rec.Driver, "source", rec.Source, "sharing", shared)
		return nil
	}
	return td.Teardown(ctx)
}

// poolReferenceGuard refuses (codes.FailedPrecondition) to delete a pool that is
// still referenced by live VM disks or ENABLED backup/replication schedules,
// unless force. Both counts are HOST-scoped (pools are host-local) and read from
// replicated state, so it runs meaningfully on BOTH the entry node (pre-forward)
// and the target host. Fail CLOSED on a count error — a DB read failure must
// never be read as "no references". Audits the refusal as "blocked".
func (s *Server) poolReferenceGuard(ctx context.Context, host, name string, force bool) error {
	disks, err := corrosion.CountDisksUsingPool(ctx, s.db, host, name)
	if err != nil {
		return status.Errorf(codes.Internal, "count disks using pool: %v", err)
	}
	scheds, err := corrosion.CountActiveSchedulesUsingPool(ctx, s.db, host, name)
	if err != nil {
		return status.Errorf(codes.Internal, "count schedules using pool: %v", err)
	}
	if (disks > 0 || scheds > 0) && !force {
		detail := fmt.Sprintf("disks=%d schedules=%d", disks, scheds)
		s.audit(ctx, "storage.pool.delete", name, detail, "blocked")
		return status.Errorf(codes.FailedPrecondition,
			"pool %q on %q is still referenced (%s); use --force to delete anyway",
			name, host, detail)
	}
	return nil
}

// requireISOLibraryRowAuthority is what touching the global "isos" row takes.
func (s *Server) requireISOLibraryRowAuthority(ctx context.Context) error {
	if err := s.RequirePerm(ctx, "/", verbStorageHostPath, "admin"); err != nil {
		if status.Code(err) == codes.PermissionDenied {
			return status.Errorf(codes.PermissionDenied,
				"the global ISO library pool %q is created, replaced, retargeted or deleted only with %s at / (Admin): every project boots from it",
				globalISOLibrary, verbStorageHostPath)
		}
		return err
	}
	return nil
}

// refuseGlobalISOLibraryOverlap keeps the global ISO library's directory its
// own: no pool may be created in, above or below it, and the library row may
// not be put on a directory another pool maps. A pool sharing it would let its
// writers put files in the library, which only an Admin may write.
func (s *Server) refuseGlobalISOLibraryOverlap(ctx context.Context, req *pb.CreateStoragePoolRequest) error {
	if !isFileBasedDriver(req.Driver) {
		return nil
	}
	dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: req.Driver, Source: req.Source, Target: req.Target})
	if err != nil {
		return nil // the driver reports a pool it cannot place
	}
	var others []corrosion.StoragePoolRecord
	if req.Name == globalISOLibrary && req.Project == "" {
		rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
		if err != nil {
			return status.Errorf(codes.Internal, "list pools: %v", err)
		}
		for _, r := range rows {
			if r.Name != req.Name && isFileBasedDriver(r.Driver) {
				others = append(others, r)
			}
		}
	} else {
		lib, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, globalISOLibrary)
		if err != nil {
			return status.Errorf(codes.Internal, "lookup %s: %v", globalISOLibrary, err)
		}
		if ok && lib.Project == "" && isFileBasedDriver(lib.Driver) {
			others = append(others, lib)
		}
	}
	for _, o := range others {
		odir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: o.Driver, Source: o.Source, Target: o.Target})
		if err != nil {
			continue
		}
		if err := refuseOverlap(dir, odir, o.Name); err != nil {
			return err
		}
	}
	return nil
}

// refuseISOIdentityStoreOverlap refuses a pool at or under the host-local
// store of ISO identity records (<data_dir>/iso-identity): a pool there could
// upload a record that excuses a file for a VM (iso_identity.go).
func (s *Server) refuseISOIdentityStoreOverlap(req *pb.CreateStoragePoolRequest) error {
	if !isFileBasedDriver(req.Driver) {
		return nil
	}
	dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: req.Driver, Source: req.Source, Target: req.Target})
	if err != nil {
		return nil // the driver reports a pool it cannot place
	}
	store := filepath.Join(s.dataDir, isoIdentityDir)
	for _, a := range pathFormsOf(dir) {
		for _, b := range pathFormsOf(store) {
			if pathWithin(b, a) {
				return status.Errorf(codes.InvalidArgument,
					"pool directory %s is in %s, where this host keeps its record of the installer ISOs it judged; choose another directory", dir, store)
			}
		}
	}
	return nil
}

// pathFormsOf is p cleaned, and resolved when that differs (resolving through
// the deepest part that exists, so a link to the place is caught too).
func pathFormsOf(p string) []string {
	clean := filepath.Clean(p)
	out := []string{clean}
	cur, rest := clean, ""
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if r = filepath.Join(r, rest); r != clean {
				out = append(out, r)
			}
			return out
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return out
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func refuseOverlap(dir, libDir, other string) error {
	forms := func(p string) []string {
		out := []string{filepath.Clean(p)}
		if r, err := filepath.EvalSymlinks(p); err == nil && r != out[0] {
			out = append(out, r)
		}
		return out
	}
	for _, a := range forms(dir) {
		for _, b := range forms(libDir) {
			if pathWithin(a, b) || pathWithin(b, a) {
				return status.Errorf(codes.InvalidArgument,
					"pool directory %s overlaps the directory %s of pool %q, and the global ISO library's directory is its own; choose another directory", dir, libDir, other)
			}
		}
	}
	return nil
}

// pathWithin reports whether p is dir or below it.
func pathWithin(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

// pinImplicitISOLibraryMode writes the ISO library mode in force when none was
// ever set, before an Admin creates, replaces or deletes a global isos pool:
// with no row the mode is derived from which isos pools exist, so that change
// would otherwise flip it silently, with no new record generation (stale
// records of the old mode would then count again). The pin does not start a
// new generation: the records made while the mode was implicit keep counting
// (corrosion.PinISOLibraryMode), so no library start is refused while the
// hosts re-record. Best effort: it never refuses the pool change.
func (s *Server) pinImplicitISOLibraryMode(ctx context.Context) {
	m, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil || !m.Implicit || !s.db.MayWriteClusterPolicy() {
		return
	}
	if err := corrosion.PinISOLibraryMode(ctx, s.db, m.Value, callerUsername(ctx)); err != nil {
		slog.Warn("iso library: pin the mode in force before an isos pool change", "mode", m.Value, "error", err)
		return
	}
	slog.Info("iso library: the mode in force is now set explicitly, before an isos pool change", "mode", m.Value)
}
