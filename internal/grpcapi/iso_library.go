package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// ISO libraries. A VM names its installer ISO as <pool>/<file>.iso, never by
// host path (an Admin still may, see vm_iso.go). The host resolves the
// reference to a plain file directly in that pool's directory, at create and
// again at every start.
//
//   - The cluster-global library is the pool "isos" with no project, present
//     on every host. Every project may read it; only an Admin may write it
//     (storage.library.write at /). Its placement is the cluster setting
//     iso_library_mode: "sync" (the default) keeps a local copy on every host,
//     copied between hosts by the daemon and verified by sha256 against the
//     replicated library record, and a VM starts only where its copy matches;
//     "shared" means the operator put the pool on shared storage.
//   - A project library is a file-based pool the project owns with the option
//     content=iso, written by that project's operators
//     (storage.content.write).
//
// The daemon writes every file a library holds (an upload, a pull, a sync), so
// a link has nothing legitimate to be; a file that is a symlink or has a second
// hard link is never an ISO.

const (
	// globalISOLibrary is the name of the cluster-global library pool.
	globalISOLibrary = "isos"
	// verbISOLibraryWrite is what writing the global library takes, at "/".
	verbISOLibraryWrite = "storage.library.write"
	// isoContentOption marks a project pool as an ISO library (content=iso).
	isoContentOption = "content"
)

// GlobalISOLibraryName is the pool name of the cluster-global ISO library,
// which the daemon creates on every host that has none.
const GlobalISOLibraryName = globalISOLibrary

// DataDir is the daemon's data directory.
func (s *Server) DataDir() string { return s.dataDir }

// GlobalISOLibraryOptions are the options the daemon gives the built-in pool.
func GlobalISOLibraryOptions() map[string]string { return map[string]string{isoContentOption: "iso"} }

// parseISORef splits a library reference "<pool>/<file>.iso".
func parseISORef(s string) (pool, file string, ok bool) {
	if s == "" || strings.HasPrefix(s, "/") {
		return "", "", false
	}
	pool, file, found := strings.Cut(s, "/")
	if !found || strings.Contains(file, "/") {
		return "", "", false
	}
	if safename.ValidatePoolName(pool) != nil || safename.ValidateName(file) != nil || !isISOName(file) {
		return "", "", false
	}
	return pool, file, true
}

// The kinds of pool a reference can resolve to, recorded in VMSpec.iso_scope.
const (
	isoScopeGlobal   = "global"   // the global ISO library
	isoScopePool     = "pool"     // another pool with no project
	isoScopeProject  = "project"  // a pool the VM's project owns
	isoScopeHostPath = "hostpath" // an Admin's absolute host path
)

// isGlobalISOLibrary reports whether p is the cluster-global library. It is
// not any row named "isos": in sync mode it is the daemon-made pool at
// <data_dir>/pools/isos; in shared mode it is the global "isos" pool the Admin
// put on shared storage (the setting is the designation, and only an Admin may
// create or retarget that row). An unreadable mode fails closed: no pool is it.
func (s *Server) isGlobalISOLibrary(ctx context.Context, p corrosion.StoragePoolRecord) bool {
	if p.Name != globalISOLibrary || p.Project != "" || !isFileBasedDriver(p.Driver) {
		return false
	}
	mode, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil {
		return false
	}
	if mode.Value == corrosion.ISOLibraryShared {
		return true
	}
	if !corrosion.IsBuiltinISOLibraryRow(p) {
		return false
	}
	if p.HostName == s.hostName {
		return filepath.Clean(p.Target) == filepath.Join(s.dataDir, storage.ISOLibraryDir)
	}
	return true
}

func isProjectISOLibrary(p corrosion.StoragePoolRecord) bool {
	return p.Project != "" && isFileBasedDriver(p.Driver) && strings.EqualFold(p.Options[isoContentOption], "iso")
}

func (s *Server) isISOLibrary(ctx context.Context, p corrosion.StoragePoolRecord) bool {
	return s.isGlobalISOLibrary(ctx, p) || isProjectISOLibrary(p)
}

// poolISOKind is the kind of pool p is, as VMSpec.iso_scope records it.
func (s *Server) poolISOKind(ctx context.Context, p corrosion.StoragePoolRecord) string {
	switch {
	case s.isGlobalISOLibrary(ctx, p):
		return isoScopeGlobal
	case p.Project == "":
		return isoScopePool
	}
	return isoScopeProject
}

// poolsSharingDir returns the pool rows on host whose directory is rec's
// (iso_identity.go, poolsMappingDir).
func (s *Server) poolsSharingDir(ctx context.Context, host string, rec corrosion.StoragePoolRecord) ([]corrosion.StoragePoolRecord, error) {
	dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil {
		return nil, err
	}
	return s.isoPoolFor(ctx, host, filepath.Join(filepath.Clean(dir), "x.iso"))
}

// poolDirResolved is a file-based pool's directory with symlinks resolved.
// The directory is the pool's, set by whoever created the pool; what must not
// be a link is the file in it. It is read under the probe deadline
// (probeDirCtx), so a directory that does not answer fails rather than hangs;
// one that does not exist is an os.ErrNotExist.
func (s *Server) poolDirResolved(ctx context.Context, p corrosion.StoragePoolRecord) (string, error) {
	d, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target})
	if err != nil {
		return "", err
	}
	got, err := probeDirCtx(ctx, d)
	if err != nil {
		return "", err
	}
	if got.path == "" {
		return "", &os.PathError{Op: "resolve", Path: d, Err: os.ErrNotExist}
	}
	return got.path, nil
}

// authorizeISORef is the create-time authority for a library reference, judged
// against the replicated pool rows of host: the VM's project must be allowed
// to use, and the caller to read, every pool row mapping that directory, since
// a file there is in all of them. The global library is a row like any other
// here (no other pool may share its directory). It returns the kind of pool
// the reference names, which the create records.
func (s *Server) authorizeISORef(ctx context.Context, project, host, pool, file string) (string, error) {
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, pool)
	if err != nil {
		return "", status.Errorf(codes.Internal, "iso: look up pool %q on %s: %v", pool, host, err)
	}
	if !ok {
		return "", status.Errorf(codes.FailedPrecondition, "iso %s/%s: there is no pool %q on host %s", pool, file, pool, host)
	}
	if !isFileBasedDriver(rec.Driver) {
		return "", status.Errorf(codes.InvalidArgument, "iso %s/%s: pool %q (%s) holds no files", pool, file, pool, rec.Driver)
	}
	rows, err := s.poolsSharingDir(ctx, host, rec)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "iso %s/%s: %v", pool, file, err)
	}
	for _, p := range rows {
		denied := s.admitPoolAttach(ctx, project, host, p.Name)
		if denied == nil {
			denied = s.authorizeResourceRead(ctx, p.Project, poolRBACPathFor(p.Project, p.Name), "storage.content.read")
		}
		if denied != nil {
			return "", status.Errorf(codes.PermissionDenied,
				"iso %s/%s is in the directory of storage pool %q, which this caller may not read or this VM's project may not use: %v",
				pool, file, p.Name, status.Convert(denied).Message())
		}
	}
	return s.poolISOKind(ctx, rec), nil
}

// isoRefForPath maps an absolute path that names a .iso directly in a
// file-based pool's directory on host to that pool's reference, as earlier
// specs stored it. Pools sharing the directory resolve to the first by name;
// authorizeISORef judges every one of them.
// A directory that did not answer is an error, never "no pool".
func (s *Server) isoRefForPath(ctx context.Context, host, p string) (string, bool, error) {
	base := filepath.Base(p)
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || !isISOName(base) || safename.ValidateName(base) != nil {
		return "", false, nil
	}
	rows, err := s.isoPoolFor(ctx, host, p)
	if err != nil {
		return "", false, err
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows[0].Name + "/" + base, true, nil
}

// resolveISOForVM is a host's own resolution of a reference to the file qemu
// opens for a VM of project, wherever that happens — the create, every start,
// a migration target. In order:
//
//  1. the pool must be on this host (absent: isoAbsent), of the kind recorded
//     at create (scope; empty for a VM created before it was recorded), and,
//     if it has a project, the VM's project's — a same-named pool of another
//     project on another host is not this VM's library, file or no file;
//  2. the file must be on this host (absent: isoAbsent), and a plain file
//     directly in the pool's directory (no symlink, one link, not refused by
//     storage.CheckReadFile);
//  3. the other pools mapping that directory pass isoFileOwnershipAllows;
//  4. with libraryCheck, a global-library file in sync mode must match the
//     library record.
//
// key names the VM's host-local identity record (iso_identity.go); wantSHA,
// on a migration target, is the sha256 of the file the source judged for the
// VM (isoFileOwnershipAllows).
func (s *Server) resolveISOForVM(ctx context.Context, project, scope, pool, file string, libraryCheck bool, key, wantSHA string) (string, error) {
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, pool)
	if err != nil {
		return "", status.Errorf(codes.Internal, "iso: look up pool %q: %v", pool, err)
	}
	if !ok {
		return "", isoAbsent(status.Errorf(codes.FailedPrecondition, "iso %s/%s: this host (%s) has no pool %q", pool, file, s.hostName, pool))
	}
	if !isFileBasedDriver(rec.Driver) {
		return "", status.Errorf(codes.InvalidArgument, "iso %s/%s: pool %q (%s) holds no files", pool, file, pool, rec.Driver)
	}
	if kind := s.poolISOKind(ctx, rec); scope != "" && scope != isoScopeHostPath && kind != scope {
		return "", status.Errorf(codes.FailedPrecondition,
			"iso %s/%s: pool %q on this host (%s) is a %s pool, but the VM was created with a %s one, so it is not the same library",
			pool, file, pool, s.hostName, kind, scope)
	}
	if rec.Project != "" && !tenancy.AdmitAttach(project, rec.Project) {
		return "", status.Errorf(codes.FailedPrecondition,
			"iso %s/%s: on this host (%s) pool %q belongs to project %q, which project %q may not use",
			pool, file, s.hostName, pool, rec.Project, tenancy.NormalizeProject(project))
	}
	dir, err := s.poolDirResolved(ctx, rec)
	if err != nil {
		// Absent, or not answering: either way not attachable here now. A
		// stopped VM's move accepts it with a warning; a start refuses.
		return "", isoAbsent(status.Errorf(codes.FailedPrecondition, "iso %s/%s: pool directory: %v", pool, file, err))
	}
	path := filepath.Join(dir, file)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return "", isoAbsent(status.Errorf(codes.FailedPrecondition, "iso %s/%s: there is no such file on this host (%s)", pool, file, s.hostName))
	}
	if err := s.checkVMISOFile(path); err != nil {
		return "", err
	}
	rows, err := s.poolsMappingDir(ctx, s.hostName, dir)
	if err != nil {
		return "", err
	}
	if err := s.isoFileOwnershipAllows(project, pool, file, path, rows, key, wantSHA); err != nil {
		return "", err
	}
	if libraryCheck {
		if err := s.checkLibraryCopy(ctx, rec, file, path); err != nil {
			return "", err
		}
	}
	return path, nil
}

// isoFileOwnershipAllows is THE ownership rule for an ISO file in a pool
// directory, decided in this one place (the storage branch's per-file
// ownership records belong here after the merge). Every pool mapping the
// directory on this host must be global or the VM's project's; when they all
// are, this host records the file (recordISOIdentity). When another
// project's pool maps it, the file passes only if
//
//   - it is the very file this host recorded for this VM before
//     (isoIdentityHolds): that pool joining the directory since has not made
//     it its file, so a VM that started yesterday still starts; or
//   - on a migration target, its sha256 is wantSHA, the hash of the file the
//     source judged for this VM and is booting it from: the guest gets the
//     bytes it already had, which discloses nothing, and this host then
//     records the file, so a later swap is caught.
//
// A file put there since is refused. The pool the reference names is judged
// before this, by its own project, never excused.
func (s *Server) isoFileOwnershipAllows(project, pool, file, path string, rows []corrosion.StoragePoolRecord, key, wantSHA string) error {
	for _, r := range rows {
		if r.Project != "" && !tenancy.AdmitAttach(project, r.Project) {
			if s.isoIdentityHolds(key, tenancy.NormalizeProject(project), path) {
				return nil
			}
			if wantSHA != "" {
				if sum, fi, err := s.isoFileSHA256Info(path); err == nil && sum == wantSHA {
					s.recordISOIdentityOf(key, tenancy.NormalizeProject(project), path, fi)
					slog.Info("installer ISO: admitted on its first arrival as the very bytes the source judged",
						"pool", pool, "file", file, "host", s.hostName, "sha256", sum)
					return nil
				}
			}
			return status.Errorf(codes.FailedPrecondition,
				"iso %s/%s: on this host (%s) that directory belongs to pool %q of project %q, which project %q may not use",
				pool, file, s.hostName, r.Name, r.Project, tenancy.NormalizeProject(project))
		}
	}
	s.recordISOIdentity(key, tenancy.NormalizeProject(project), path)
	return nil
}

// isoAbsentError marks a refusal because the ISO (its pool, or the file) is
// not on this host — which a stopped VM's move tolerates, since the start
// there judges it again.
type isoAbsentError struct{ error }

func (e isoAbsentError) GRPCStatus() *status.Status { return status.Convert(e.error) }
func (e isoAbsentError) Unwrap() error              { return e.error }

func isoAbsent(err error) error { return isoAbsentError{err} }

func isISOAbsent(err error) bool {
	var a isoAbsentError
	return errors.As(err, &a)
}

// checkLibraryCopy refuses a sync-mode global-library file whose local copy
// does not match the replicated library record (or that has none).
func (s *Server) checkLibraryCopy(ctx context.Context, rec corrosion.StoragePoolRecord, file, path string) error {
	if !s.isGlobalISOLibrary(ctx, rec) {
		return nil
	}
	mode, cur, err := corrosion.CurrentISOCatalog(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "iso %s/%s: cannot read the ISO library: %v", globalISOLibrary, file, err)
	}
	if mode.Value != corrosion.ISOLibrarySync {
		return nil
	}
	e, ok := cur[file]
	if !ok || e.Deleted {
		return status.Errorf(codes.FailedPrecondition,
			"iso %s/%s is not in the cluster's ISO library (iso_library_mode is sync, so every library file is recorded when it is uploaded or pulled); upload or pull it again",
			globalISOLibrary, file)
	}
	sum, err := s.isoFileSHA256(path)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "iso %s/%s: hash this host's copy: %v", globalISOLibrary, file, err)
	}
	if sum != e.SHA256 {
		return status.Errorf(codes.FailedPrecondition,
			"this host's (%s) copy of %s/%s does not match the library yet (it is being synced from another host); start it once `lv iso ls --host %s` shows it ok, or on another host",
			s.hostName, globalISOLibrary, file, s.hostName)
	}
	return nil
}

// ── sha256 cache ──

// isoHashKey names a file's content version: the file (device and inode) and
// its size and mtime. A file replaced by rename gets another inode; one
// rewritten in place another mtime.
type isoHashKey struct {
	dev   uint64
	ino   uint64
	size  int64
	mtime int64
}

type isoLibraryState struct {
	mu sync.Mutex
	// hashes is each content version's sha256, hashed once.
	hashes map[isoHashKey]string
	// keyOf is the version last seen at each path, so a replaced version's
	// hash is dropped.
	keyOf map[string]isoHashKey
	// syncing admits one sync pass at a time.
	syncing sync.Mutex
}

func isoKeyFor(fi os.FileInfo) isoHashKey {
	k := isoHashKey{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	k.ino, _ = fileInode(fi)
	k.dev, _ = fileDevice(fi)
	return k
}

// isoFileSHA256 hashes a file, once per content version (isoHashKey).
func (s *Server) isoFileSHA256(path string) (string, error) {
	sum, _, err := s.isoFileSHA256Info(path)
	return sum, err
}

// isoFileSHA256Info hashes the file at path and returns what it hashed: the
// file is opened without following a link and must be a regular file, and the
// hash is of that open file, cached by its own (dev, ino, size, mtime).
func (s *Server) isoFileSHA256Info(path string) (string, os.FileInfo, error) {
	f, fi, _, err := openNoFollow(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	if !fi.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s is not a regular file", path)
	}
	key := isoKeyFor(fi)
	s.isoLib.mu.Lock()
	sum, ok := s.isoLib.hashes[key]
	s.isoLib.mu.Unlock()
	if ok {
		return sum, fi, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", nil, err
	}
	sum = hex.EncodeToString(h.Sum(nil))
	s.rememberISOHash(path, fi, sum)
	return sum, fi, nil
}

func (s *Server) rememberISOHash(path string, fi os.FileInfo, sum string) {
	s.isoLib.mu.Lock()
	defer s.isoLib.mu.Unlock()
	if s.isoLib.hashes == nil {
		s.isoLib.hashes = map[isoHashKey]string{}
		s.isoLib.keyOf = map[string]isoHashKey{}
	}
	key := isoKeyFor(fi)
	if old, ok := s.isoLib.keyOf[path]; ok && old != key {
		delete(s.isoLib.hashes, old)
	}
	s.isoLib.keyOf[path] = key
	s.isoLib.hashes[key] = sum
}

// errLibraryFileExists is the refusal of a write over a library file.
func errLibraryFileExists(name string) error {
	return status.Errorf(codes.FailedPrecondition,
		"%s is already in the library, and a library file is never replaced (a VM may boot it); remove it first with `lv iso rm`, or use another name", name)
}

// writeLibraryFile writes src into dir/name: through a temp file, at most
// limit bytes, matching wantSHA when given, synced, then put in place. Only
// the daemon's sync (replace) puts a file over an existing name, by rename;
// every other write is no-replace, and a name already taken is refused
// (errLibraryFileExists) — never written through a link there either. It
// returns the sha256 and size.
func (s *Server) writeLibraryFile(dir, name string, src io.Reader, limit int64, wantSHA string, replace bool) (string, int64, error) {
	dest, err := safename.SafeJoin(dir, name)
	if err != nil {
		return "", 0, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if fi, lerr := os.Lstat(dest); lerr == nil {
		if !replace {
			return "", 0, errLibraryFileExists(name)
		}
		if !fi.Mode().IsRegular() {
			return "", 0, status.Errorf(codes.FailedPrecondition, "%s exists and is not a plain file", dest)
		}
	}
	tmp, err := os.CreateTemp(dir, ".iso-*.tmp")
	if err != nil {
		return "", 0, status.Errorf(codes.Internal, "create temp: %v", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op after the rename
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, limit+1))
	if err != nil {
		return "", 0, status.Errorf(codes.Internal, "write: %v", err)
	}
	if n > limit {
		return "", 0, status.Errorf(codes.InvalidArgument, "%s exceeds the %d-byte limit", name, limit)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if want := strings.TrimPrefix(wantSHA, "sha256:"); want != "" && !strings.EqualFold(want, sum) {
		return "", 0, status.Errorf(codes.DataLoss, "%s: sha256 %s does not match the expected %s", name, sum, want)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, status.Errorf(codes.Internal, "close: %v", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return "", 0, status.Errorf(codes.Internal, "chmod: %v", err)
	}
	if err := syncPath(tmpName); err != nil {
		return "", 0, status.Errorf(codes.Internal, "sync: %v", err)
	}
	if err := publishLibraryFile(tmpName, dest, name, replace); err != nil {
		return "", 0, err
	}
	if err := syncPath(dir); err != nil {
		_ = os.Remove(dest)
		return "", 0, status.Errorf(codes.Internal, "sync directory: %v", err)
	}
	if fi, err := os.Lstat(dest); err == nil {
		s.rememberISOHash(dest, fi, sum)
	}
	return sum, n, nil
}

// publishLibraryFile puts a written temp file at dest: by rename when
// replacing, otherwise by a hard link that fails on an existing name (the
// temp name is removed by the caller, leaving the file one link).
func publishLibraryFile(tmpName, dest, name string, replace bool) error {
	if replace {
		if err := os.Rename(tmpName, dest); err != nil {
			return status.Errorf(codes.Internal, "finalize: %v", err)
		}
		return nil
	}
	if err := os.Link(tmpName, dest); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errLibraryFileExists(name)
		}
		return status.Errorf(codes.Internal, "finalize: %v", err)
	}
	if err := os.Remove(tmpName); err != nil {
		_ = os.Remove(dest)
		return status.Errorf(codes.Internal, "finalize: %v", err)
	}
	return nil
}

// recordLibraryFile records a file just written to the global library, when
// the library is in sync mode; on failure the file is withdrawn, so no host
// holds a library file the cluster has no record of.
func (s *Server) recordLibraryFile(ctx context.Context, rec corrosion.StoragePoolRecord, name, path, sum string, size int64) error {
	if !s.isGlobalISOLibrary(ctx, rec) {
		return nil
	}
	mode, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil {
		_ = os.Remove(path)
		return status.Errorf(codes.FailedPrecondition, "read the ISO library mode: %v", err)
	}
	if mode.Value != corrosion.ISOLibrarySync {
		return nil
	}
	if err := corrosion.PutISOCatalogEntry(ctx, s.db, corrosion.ISOCatalogEntry{
		Name: name, SHA256: sum, Size: size, Origin: s.hostName,
	}, callerUsername(ctx)); err != nil {
		_ = os.Remove(path)
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return status.Errorf(codes.FailedPrecondition,
				"the ISO library is in sync mode and cannot record %s until every host runs this release: %v", name, err)
		}
		return status.Errorf(codes.Internal, "record %s in the ISO library: %v", name, err)
	}
	return nil
}

// globalLibraryWritable is the pre-write check for the global library in sync
// mode, so a write that could not be recorded is refused before any byte lands.
func (s *Server) globalLibraryWritable(ctx context.Context, rec corrosion.StoragePoolRecord) error {
	if !s.isGlobalISOLibrary(ctx, rec) {
		return nil
	}
	mode, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "read the ISO library mode: %v", err)
	}
	if mode.Value == corrosion.ISOLibrarySync && !s.db.MayWriteClusterPolicy() {
		return status.Errorf(codes.FailedPrecondition,
			"the ISO library is in sync mode and cannot record new files until every host runs this release (%v)",
			corrosion.ErrClusterPolicyGateClosed)
	}
	return nil
}

// authorizeLibraryWrite is the authority to add or remove a file in pool rec:
// the global library takes storage.library.write at / (Admin), any other pool
// storage.content.write on the pool.
func (s *Server) authorizeLibraryWrite(ctx context.Context, rec corrosion.StoragePoolRecord) error {
	if s.isGlobalISOLibrary(ctx, rec) || (rec.Name == globalISOLibrary && rec.Project == "") {
		if err := s.RequirePerm(ctx, "/", verbISOLibraryWrite, "admin"); err != nil {
			if status.Code(err) == codes.PermissionDenied {
				return status.Errorf(codes.PermissionDenied,
					"the global ISO library %q is written only by an Admin (%s at /); use a project library (a pool your project owns with --option content=iso) instead",
					globalISOLibrary, verbISOLibraryWrite)
			}
			return err
		}
		return nil
	}
	return s.RequirePerm(ctx, poolRBACPathFor(rec.Project, rec.Name), "storage.content.write", "operator")
}

// ── ListISOs ──

// ListISOs lists, for one host, the ISOs a VM may name: the caller's project
// libraries (pools with content=iso it may read), then the global library.
func (s *Server) ListISOs(ctx context.Context, req *pb.ListISOsRequest) (*pb.ListISOsResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	host := req.GetHost()
	if host == "" {
		host = s.hostName
	}
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, host)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list pools: %v", err)
	}
	peer := s.requirePeerCert(ctx) == nil
	allowed := map[string]bool{}
	for _, p := range pools {
		switch {
		case s.isGlobalISOLibrary(ctx, p):
			allowed[p.Name] = true
		case isProjectISOLibrary(p):
			if req.GetProject() != "" && tenancy.NormalizeProject(req.GetProject()) != tenancy.NormalizeProject(p.Project) {
				continue
			}
			if peer || s.authorizeResourceRead(ctx, p.Project, poolRBACPathFor(p.Project, p.Name), "storage.content.read") == nil {
				allowed[p.Name] = true
			}
		}
	}
	var out []*pb.ISOEntry
	if host != s.hostName {
		client, closePeer, err := s.dialPeer(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer closePeer()
		resp, err := client.ListISOs(ctx, &pb.ListISOsRequest{Host: host, Project: req.GetProject()})
		if err != nil {
			return nil, err
		}
		out = resp.GetIsos()
	} else {
		for _, p := range pools {
			if allowed[p.Name] {
				out = append(out, s.listLibrary(ctx, p)...)
			}
		}
	}
	// The forwarded leg answers a peer with every library; the entry filters
	// by what its caller may read.
	kept := out[:0]
	for _, e := range out {
		if allowed[e.GetPool()] {
			kept = append(kept, e)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if a.GetGlobal() != b.GetGlobal() {
			return !a.GetGlobal()
		}
		if a.GetProject() != b.GetProject() {
			return a.GetProject() < b.GetProject()
		}
		if a.GetPool() != b.GetPool() {
			return a.GetPool() < b.GetPool()
		}
		return a.GetName() < b.GetName()
	})
	return &pb.ListISOsResponse{Isos: kept}, nil
}

// listLibrary lists the usable ISOs of one library on this host. Its
// directory is read under the probe deadline: a library whose directory does
// not answer (a dead NFS server) is listed as one "unavailable" entry, never
// waited on.
func (s *Server) listLibrary(ctx context.Context, p corrosion.StoragePoolRecord) []*pb.ISOEntry {
	unavailable := func(err error) []*pb.ISOEntry {
		slog.Warn("iso library: a library directory did not answer", "pool", p.Name, "host", s.hostName, "error", err)
		return []*pb.ISOEntry{{Ref: p.Name + "/", Pool: p.Name, Project: p.Project, Global: s.isGlobalISOLibrary(ctx, p), SyncState: "unavailable"}}
	}
	dir, err := s.poolDirResolved(ctx, p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return unavailable(err)
	}
	// A directory another project's pool also maps holds files that may be
	// that project's: none of them is listed through this library. (The
	// storage branch's per-file ownership refines this once merged.)
	rows, err := s.poolsSharingDir(ctx, s.hostName, p)
	if err != nil {
		return unavailable(err)
	}
	for _, r := range rows {
		if r.Project != "" && r.Project != p.Project {
			return nil
		}
	}
	v, err := deadlined(ctx, "list:"+dir, networkMountOf(dir), dir, func() (any, error) {
		if isoBeforeList != nil {
			isoBeforeList(dir)
		}
		return s.poolContents(context.Background(), p)
	})
	if err != nil {
		return unavailable(err)
	}
	contents, _ := v.([]*pb.StoragePoolContent)
	global := s.isGlobalISOLibrary(ctx, p)
	var catalog map[string]corrosion.ISOCatalogEntry
	if global {
		if mode, cur, merr := corrosion.CurrentISOCatalog(ctx, s.db); merr == nil && mode.Value == corrosion.ISOLibrarySync {
			catalog = cur
		}
	}
	var out []*pb.ISOEntry
	seen := map[string]bool{}
	for _, c := range contents {
		name := c.GetName()
		if !c.GetIsIso() || !isISOName(name) || safename.ValidateName(name) != nil {
			continue
		}
		// What a VM could boot: a plain, singly-linked file in the library.
		path := filepath.Join(dir, name)
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if n, ok := linkCount(fi); ok && n != 1 {
			continue
		}
		e := &pb.ISOEntry{Ref: p.Name + "/" + name, Pool: p.Name, Project: p.Project, Name: name, SizeBytes: fi.Size(), Global: global}
		if catalog != nil {
			c, ok := catalog[name]
			switch {
			case !ok || c.Deleted:
				e.SyncState = "not in library"
			default:
				if sum, herr := s.isoFileSHA256(path); herr == nil && sum == c.SHA256 {
					e.SyncState = "ok"
				} else {
					e.SyncState = "syncing"
				}
			}
		}
		seen[name] = true
		out = append(out, e)
	}
	for name, c := range catalog {
		if !seen[name] && !c.Deleted {
			out = append(out, &pb.ISOEntry{Ref: p.Name + "/" + name, Pool: p.Name, Name: name, SizeBytes: c.Size, Global: true, SyncState: "syncing"})
		}
	}
	return out
}

// libraryDir is a library's directory, resolved, made when it does not exist
// yet; read under the probe deadline (poolDirResolved), so a directory that
// does not answer fails rather than hangs the caller.
func (s *Server) libraryDir(ctx context.Context, rec corrosion.StoragePoolRecord) (string, error) {
	dir, err := s.poolDirResolved(ctx, rec)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return dir, err
	}
	raw, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(raw, 0o755); err != nil {
		return "", err
	}
	return s.poolDirResolved(ctx, rec)
}

// isoBeforeList is a test seam: it runs in the deadlined read of a library's
// directory listing, where an unanswering filesystem would block.
var isoBeforeList func(dir string)

// ── PullISO ──

// PullISO copies an ISO into a library from a URL or a host path.
func (s *Server) PullISO(ctx context.Context, req *pb.PullISORequest) (*pb.PullISOResponse, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	pool, file, ok := parseISORef(req.GetRef())
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "ref %q must be <pool>/<file>.iso", req.GetRef())
	}
	if (req.GetUrl() == "") == (req.GetHostPath() == "") {
		return nil, status.Error(codes.InvalidArgument, "give exactly one source: url or host_path")
	}
	host := req.GetHost()
	if host == "" {
		host = s.hostName
	}
	rec, found, err := corrosion.GetStoragePool(ctx, s.db, host, pool)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", pool, host)
	}
	if !s.isISOLibrary(ctx, rec) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"pool %q is not an ISO library: the global library is %q, and a project library is a file-based pool the project owns with --option content=iso",
			pool, globalISOLibrary)
	}
	if s.requirePeerCert(ctx) != nil {
		if err := s.authorizeLibraryWrite(ctx, rec); err != nil {
			return nil, err
		}
		if req.GetHostPath() != "" {
			if err := s.RequirePerm(ctx, "/", verbISOHostPath, "admin"); err != nil {
				if status.Code(err) == codes.PermissionDenied {
					return nil, status.Errorf(codes.PermissionDenied,
						"copying a host file into a library reads that file, so it needs %s at / (Admin)", verbISOHostPath)
				}
				return nil, err
			}
		}
	}
	if host != s.hostName {
		client, closePeer, err := s.dialPeer(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer closePeer()
		return client.PullISO(ctx, req)
	}
	if err := s.globalLibraryWritable(ctx, rec); err != nil {
		return nil, err
	}
	dir, err := s.libraryDir(ctx, rec)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
	}
	// A library file is never replaced: refuse a taken name before fetching.
	if _, err := os.Lstat(filepath.Join(dir, file)); err == nil {
		return nil, errLibraryFileExists(file)
	}
	var sum string
	var size int64
	if req.GetHostPath() != "" {
		sum, size, err = s.copyHostFileToLibrary(dir, file, req.GetHostPath(), req.GetChecksum())
	} else {
		sum, size, err = s.pullURLToLibrary(dir, file, req.GetUrl(), req.GetChecksum())
	}
	if err != nil {
		return nil, err
	}
	dest := filepath.Join(dir, file)
	if err := s.recordLibraryFile(ctx, rec, file, dest, sum, size); err != nil {
		return nil, err
	}
	src := req.GetUrl()
	if src == "" {
		src = req.GetHostPath()
	}
	s.audit(ctx, "storage.iso.pull", pool+"/"+file, "from "+src+" sha256="+sum, "ok")
	return &pb.PullISOResponse{Ref: pool + "/" + file, Sha256: sum, SizeBytes: size}, nil
}

// copyHostFileToLibrary copies (never links) a host file into a library. The
// source is judged like any file a guest could be given to read.
func (s *Server) copyHostFileToLibrary(dir, name, src, checksum string) (string, int64, error) {
	if err := storage.CheckReadFile(src, s.dataDir, s.pkiDir); err != nil {
		return "", 0, status.Errorf(codes.InvalidArgument, "host_path: %v", err)
	}
	// The link (virtio-win.iso → a versioned file) is resolved once; the file
	// it names is opened without following anything further, and the file
	// actually opened is judged again, so a link swapped in after the check
	// above cannot point the copy at a refused file.
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		return "", 0, status.Errorf(codes.FailedPrecondition, "host_path: %v", err)
	}
	f, fi, openedAs, err := openNoFollow(resolved)
	if err != nil {
		return "", 0, status.Errorf(codes.FailedPrecondition, "host_path: %v", err)
	}
	defer f.Close()
	if !fi.Mode().IsRegular() {
		return "", 0, status.Errorf(codes.InvalidArgument, "host_path %q is not a regular file", src)
	}
	if openedAs == "" {
		openedAs = resolved
	}
	if err := storage.CheckReadFile(openedAs, s.dataDir, s.pkiDir); err != nil {
		return "", 0, status.Errorf(codes.InvalidArgument, "host_path: %v", err)
	}
	// Under /home or /run only an optical disc image may be read: judged on
	// the file opened, which is the file copied.
	if storage.UnderUserDataRoot(src) || storage.UnderUserDataRoot(openedAs) {
		if err := storage.OpticalImageAt(f); err != nil {
			return "", 0, status.Errorf(codes.InvalidArgument, "host_path %q is under a home or runtime directory, where only an ISO image may be read: %v", src, err)
		}
	}
	return s.writeLibraryFile(dir, name, f, maxPoolUploadBytes, checksum, false)
}

// pullURLToLibrary downloads into a library under the image-pull limits
// (scheme allowlist on every redirect, byte ceiling, timeout, network deny
// list), into a temp name, then hands the result to writeLibraryFile's rename.
func (s *Server) pullURLToLibrary(dir, name, url, checksum string) (string, int64, error) {
	if _, err := safename.SafeJoin(dir, name); err != nil {
		return "", 0, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	stage, err := os.MkdirTemp(dir, ".pull-*")
	if err != nil {
		return "", 0, status.Errorf(codes.Internal, "stage: %v", err)
	}
	defer os.RemoveAll(stage)
	staged := filepath.Join(stage, name)
	if _, _, err := image.PullToFile(staged, url, checksum, s.imagePullOptions(), nil); err != nil {
		return "", 0, status.Errorf(codes.FailedPrecondition, "pull %s: %v", url, err)
	}
	f, err := os.Open(staged)
	if err != nil {
		return "", 0, status.Errorf(codes.Internal, "open pulled file: %v", err)
	}
	defer f.Close()
	return s.writeLibraryFile(dir, name, f, maxPoolUploadBytes, checksum, false)
}

// ── library mode ──

func (s *Server) isoLibraryModeStatus(ctx context.Context) (*pb.ISOLibraryMode, error) {
	p, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil && !errors.Is(err, corrosion.ErrUnknownISOLibraryMode) {
		return nil, status.Errorf(codes.Internal, "read the ISO library mode: %v", err)
	}
	setBy := p.SetBy
	if p.Pinned() {
		setBy = p.PinnedBy() + " (pinned the mode in force when an isos pool changed)"
	}
	return &pb.ISOLibraryMode{Mode: p.Value, SetBy: setBy, UpdatedAt: p.UpdatedAt, Settable: s.failoverScopeSettable()}, nil
}

// GetISOLibraryMode reports where the global ISO library lives.
func (s *Server) GetISOLibraryMode(ctx context.Context, _ *emptypb.Empty) (*pb.ISOLibraryMode, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	return s.isoLibraryModeStatus(ctx)
}

// SetISOLibraryMode changes it (admin). Setting it starts a new generation of
// library records (corrosion/iso_library.go): earlier records, tombstones
// included, stop counting, and every host records what its library actually
// holds — this host at once, the others on their next sync pass — so the
// records describe the files as they are.
func (s *Server) SetISOLibraryMode(ctx context.Context, req *pb.SetISOLibraryModeRequest) (*pb.ISOLibraryMode, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	mode := req.GetMode()
	if !corrosion.ValidISOLibraryMode(mode) {
		return nil, status.Errorf(codes.InvalidArgument, "unknown ISO library mode %q (valid: %s, %s)",
			mode, corrosion.ISOLibrarySync, corrosion.ISOLibraryShared)
	}
	if err := corrosion.SetISOLibraryMode(ctx, s.db, mode, callerUsername(ctx)); err != nil {
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"the ISO library mode cannot be changed until every host runs this release: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "set ISO library mode: %v", err)
	}
	if mode == corrosion.ISOLibrarySync {
		if err := s.SyncISOLibrary(ctx); err != nil {
			slog.Warn("iso library: first sync pass after the switch", "error", err)
		}
	}
	s.audit(ctx, "storage.iso_library_mode", "iso_library_mode", "ISO library mode set to "+mode, "ok")
	s.publish("storage.iso_library_mode", mode, "set by "+callerUsername(ctx))
	return s.isoLibraryModeStatus(ctx)
}

// adoptLocalLibraryFiles records every plain .iso in this host's global
// library that the current generation has no record of (a tombstone counts
// as one). It runs on every sync pass: a tombstone is collected only once
// every library host has removed the file, so a local file with no current
// record is one added again, never one the library removed.
func (s *Server) adoptLocalLibraryFiles(ctx context.Context, rec corrosion.StoragePoolRecord, dir string, cur map[string]corrosion.ISOCatalogEntry) error {
	for _, e := range s.listLibrary(ctx, rec) {
		if _, known := cur[e.GetName()]; known || e.GetName() == "" || e.GetSyncState() == "syncing" {
			continue
		}
		sum, err := s.isoFileSHA256(filepath.Join(dir, e.GetName()))
		if err != nil {
			continue
		}
		if err := corrosion.PutISOCatalogEntry(ctx, s.db, corrosion.ISOCatalogEntry{
			Name: e.GetName(), SHA256: sum, Size: e.GetSizeBytes(), Origin: s.hostName,
		}, "system:"+s.hostName); err != nil {
			return fmt.Errorf("record %s: %w", e.GetName(), err)
		}
	}
	return nil
}

// ── sync ──

// FetchISOLibraryFile streams this host's copy of a global-library file to a
// peer, only when it matches the sha256 asked for.
func (s *Server) FetchISOLibraryFile(req *pb.FetchISOLibraryFileRequest, stream grpc.ServerStreamingServer[pb.FetchISOLibraryFileChunk]) error {
	ctx := stream.Context()
	if err := s.requirePeerCert(ctx); err != nil {
		return err
	}
	name := req.GetName()
	if safename.ValidateName(name) != nil || !isISOName(name) {
		return status.Errorf(codes.InvalidArgument, "invalid library file name %q", name)
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, globalISOLibrary)
	if err != nil || !ok || !s.isGlobalISOLibrary(ctx, rec) {
		return status.Errorf(codes.NotFound, "no global ISO library on %s", s.hostName)
	}
	dir, err := s.poolDirResolved(ctx, rec)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "library directory: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := s.checkVMISOFile(path); err != nil {
		return err
	}
	sum, err := s.isoFileSHA256(path)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "hash %s: %v", name, err)
	}
	if sum != req.GetSha256() {
		return status.Errorf(codes.FailedPrecondition, "%s on %s is not the requested version", name, s.hostName)
	}
	f, err := os.Open(path)
	if err != nil {
		return status.Errorf(codes.Internal, "open: %v", err)
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := stream.Send(&pb.FetchISOLibraryFileChunk{Chunk: buf[:n]}); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return status.Errorf(codes.Internal, "read: %v", rerr)
		}
	}
}

type fetchReader struct {
	stream grpc.ServerStreamingClient[pb.FetchISOLibraryFileChunk]
	buf    []byte
}

func (r *fetchReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		c, err := r.stream.Recv()
		if err != nil {
			return 0, err
		}
		r.buf = c.GetChunk()
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// SyncISOLibrary is one pass of a sync-mode global library on this host:
//
//  1. record the files this host holds that the generation has no record of
//     (adoptLocalLibraryFiles);
//  2. bring every recorded file to its recorded sha256 (fetched from a host
//     whose copy matches), and remove every file recorded as removed; a file
//     with no record is left alone;
//  3. after a pass with no failures, record what this host has applied
//     (its ack), and collect the records this host wrote that no longer count:
//     those of an earlier generation, and tombstones every library host has
//     applied.
//
// The daemon runs it periodically.
func (s *Server) SyncISOLibrary(ctx context.Context) error {
	if !s.isoLib.syncing.TryLock() {
		return nil
	}
	defer s.isoLib.syncing.Unlock()
	mode, cur, err := corrosion.CurrentISOCatalog(ctx, s.db)
	if err != nil || mode.Value != corrosion.ISOLibrarySync {
		return err
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, globalISOLibrary)
	if err != nil || !ok || !s.isGlobalISOLibrary(ctx, rec) {
		return err
	}
	dir, err := s.libraryDir(ctx, rec)
	if err != nil {
		return err
	}
	acks, err := corrosion.ListISOLibraryHostAcks(ctx, s.db)
	if err != nil {
		return err
	}
	mine, acked := acks[s.hostName]
	if err := s.adoptLocalLibraryFiles(ctx, rec, dir, cur); err != nil {
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil // nothing can be recorded yet; try again next pass
		}
		return err
	}
	if mode, cur, err = corrosion.CurrentISOCatalog(ctx, s.db); err != nil {
		return err
	}
	var errs []error
	applied := map[string]string{}
	for _, e := range cur {
		if safename.ValidateName(e.Name) != nil || !isISOName(e.Name) {
			continue
		}
		path := filepath.Join(dir, e.Name)
		if e.Deleted {
			if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode().IsRegular() {
				if rerr := os.Remove(path); rerr != nil {
					errs = append(errs, rerr)
					continue
				}
			}
			applied[e.Name] = e.UpdatedAt
			continue
		}
		if sum, herr := s.isoFileSHA256(path); herr == nil && sum == e.SHA256 {
			applied[e.Name] = e.UpdatedAt
			continue
		}
		if ferr := s.fetchLibraryFile(ctx, dir, e); ferr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name, ferr))
			continue
		}
		applied[e.Name] = e.UpdatedAt
	}
	ack := corrosion.ISOLibraryHostAck{Host: s.hostName, Gen: mode.UpdatedAt, Applied: applied}
	if !acked || mine.Gen != ack.Gen || !sameApplied(mine.Applied, applied) {
		if err := corrosion.PutISOLibraryHostAck(ctx, s.db, ack); err != nil && !errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			errs = append(errs, err)
		} else {
			acks[s.hostName] = ack
		}
	}
	if err := s.collectLibraryRecords(ctx, mode, acks); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func sameApplied(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// collectLibraryRecords empties the records this host wrote that no longer
// count: an earlier generation's, and tombstones every host holding a global
// library has applied — that exact version, by its own per-record ack. The
// key is read again just before it is emptied, and left alone if it changed
// (a file added again since writes a new version, which must not be lost).
func (s *Server) collectLibraryRecords(ctx context.Context, mode corrosion.ISOLibraryModePolicy, acks map[string]corrosion.ISOLibraryHostAck) error {
	all, err := corrosion.ListISOCatalog(ctx, s.db)
	if err != nil {
		return err
	}
	pools, err := corrosion.ListAllStoragePools(ctx, s.db)
	if err != nil {
		return err
	}
	var hosts []string
	for _, p := range pools {
		if corrosion.IsBuiltinISOLibraryRow(p) {
			hosts = append(hosts, p.HostName)
		}
	}
	appliedEverywhere := func(e corrosion.ISOCatalogEntry) bool {
		for _, h := range hosts {
			a, ok := acks[h]
			if !ok || a.Gen != mode.UpdatedAt || a.Applied[e.Name] != e.UpdatedAt {
				return false
			}
		}
		return true
	}
	for _, e := range all {
		if e.Origin != s.hostName || e.Collected() {
			continue
		}
		if mode.CurrentGen(e.Gen) && !(e.Deleted && appliedEverywhere(e)) {
			continue
		}
		if !s.catalogEntryUnchanged(ctx, e) {
			continue
		}
		if err := corrosion.CollectISOCatalogEntry(ctx, s.db, e.Name, "system:"+s.hostName); err != nil {
			if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
				return nil
			}
			return err
		}
	}
	return nil
}

// catalogEntryUnchanged re-reads e's key and reports whether it is still the
// version e is.
func (s *Server) catalogEntryUnchanged(ctx context.Context, e corrosion.ISOCatalogEntry) bool {
	if isoBeforeCollect != nil {
		isoBeforeCollect(e.Name)
	}
	all, err := corrosion.ListISOCatalog(ctx, s.db)
	if err != nil {
		return false
	}
	for _, now := range all {
		if now.Name == e.Name {
			return now.UpdatedAt == e.UpdatedAt
		}
	}
	return false
}

// isoBeforeCollect is a test seam: it runs just before a record is re-read for
// collection, where a concurrent re-add would land.
var isoBeforeCollect func(name string)

func (s *Server) fetchLibraryFile(ctx context.Context, dir string, e corrosion.ISOCatalogEntry) error {
	peers, err := corrosion.HostsWithPool(ctx, s.db, globalISOLibrary, s.hostName)
	if err != nil {
		return err
	}
	// The host that wrote it first: it is the one sure to hold it.
	sort.SliceStable(peers, func(i, j int) bool { return peers[i] == e.Origin && peers[j] != e.Origin })
	var last error = fmt.Errorf("no other host holds a matching copy")
	for _, peer := range peers {
		client, closePeer, err := s.dialPeer(ctx, peer)
		if err != nil {
			last = err
			continue
		}
		st, err := client.FetchISOLibraryFile(ctx, &pb.FetchISOLibraryFileRequest{Name: e.Name, Sha256: e.SHA256})
		if err == nil {
			_, _, err = s.writeLibraryFile(dir, e.Name, &fetchReader{stream: st}, e.Size, e.SHA256, true)
		}
		closePeer()
		if err == nil {
			slog.Info("iso library: synced", "file", e.Name, "from", peer, "sha256", e.SHA256)
			return nil
		}
		last = err
	}
	return last
}
