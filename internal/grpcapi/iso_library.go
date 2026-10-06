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

func isGlobalISOLibrary(p corrosion.StoragePoolRecord) bool {
	return p.Name == globalISOLibrary && p.Project == "" && isFileBasedDriver(p.Driver)
}

func isProjectISOLibrary(p corrosion.StoragePoolRecord) bool {
	return p.Project != "" && isFileBasedDriver(p.Driver) && strings.EqualFold(p.Options[isoContentOption], "iso")
}

func isISOLibrary(p corrosion.StoragePoolRecord) bool {
	return isGlobalISOLibrary(p) || isProjectISOLibrary(p)
}

// poolDirResolved is a file-based pool's directory with symlinks resolved.
// The directory is the pool's, set by whoever created the pool; what must not
// be a link is the file in it.
func (s *Server) poolDirResolved(p corrosion.StoragePoolRecord) (string, error) {
	d, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target})
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(d)
}

// authorizeISORef is the create-time authority for a library reference, judged
// against the replicated pool rows of host. The global library is open to every
// VM; any other pool must be one the VM's project may use and the caller may
// read — every pool row mapping that directory, since a file there is in all of
// them.
func (s *Server) authorizeISORef(ctx context.Context, project, host, pool, file string) error {
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, pool)
	if err != nil {
		return status.Errorf(codes.Internal, "iso: look up pool %q on %s: %v", pool, host, err)
	}
	if !ok {
		return status.Errorf(codes.FailedPrecondition, "iso %s/%s: there is no pool %q on host %s", pool, file, pool, host)
	}
	if !isFileBasedDriver(rec.Driver) {
		return status.Errorf(codes.InvalidArgument, "iso %s/%s: pool %q (%s) holds no files", pool, file, pool, rec.Driver)
	}
	if isGlobalISOLibrary(rec) {
		return nil
	}
	dir, derr := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if derr != nil {
		return status.Errorf(codes.FailedPrecondition, "iso %s/%s: %v", pool, file, derr)
	}
	rows, err := s.isoPoolFor(ctx, host, filepath.Join(filepath.Clean(dir), file))
	if err != nil {
		return status.Errorf(codes.Internal, "iso: look up storage pools on %s: %v", host, err)
	}
	for _, p := range rows {
		if isGlobalISOLibrary(p) {
			continue
		}
		denied := s.admitPoolAttach(ctx, project, host, p.Name)
		if denied == nil {
			denied = s.authorizeResourceRead(ctx, p.Project, poolRBACPathFor(p.Project, p.Name), "storage.content.read")
		}
		if denied != nil {
			return status.Errorf(codes.PermissionDenied,
				"iso %s/%s is in the directory of storage pool %q, which this caller may not read or this VM's project may not use: %v",
				pool, file, p.Name, status.Convert(denied).Message())
		}
	}
	return nil
}

// isoRefForPath maps an absolute path that names a .iso directly in a
// file-based pool's directory on host to that pool's reference, as earlier
// specs stored it. Pools sharing the directory resolve to the first by name;
// authorizeISORef judges every one of them.
func (s *Server) isoRefForPath(ctx context.Context, host, p string) (string, bool) {
	base := filepath.Base(p)
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || !isISOName(base) || safename.ValidateName(base) != nil {
		return "", false
	}
	rows, err := s.isoPoolFor(ctx, host, p)
	if err != nil || len(rows) == 0 {
		return "", false
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows[0].Name + "/" + base, true
}

// resolveISORef is the host's own resolution of a reference to the file qemu
// opens: a plain file directly in the pool's directory (no symlink, one link,
// not refused by storage.CheckReadFile), and — for the global library in sync
// mode — a copy matching the library record.
func (s *Server) resolveISORef(ctx context.Context, pool, file string) (string, error) {
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, pool)
	if err != nil {
		return "", status.Errorf(codes.Internal, "iso: look up pool %q: %v", pool, err)
	}
	if !ok {
		return "", status.Errorf(codes.FailedPrecondition, "iso %s/%s: this host (%s) has no pool %q", pool, file, s.hostName, pool)
	}
	if !isFileBasedDriver(rec.Driver) {
		return "", status.Errorf(codes.InvalidArgument, "iso %s/%s: pool %q (%s) holds no files", pool, file, pool, rec.Driver)
	}
	dir, err := s.poolDirResolved(rec)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "iso %s/%s: pool directory: %v", pool, file, err)
	}
	path := filepath.Join(dir, file)
	if err := s.checkVMISOFile(path); err != nil {
		return "", err
	}
	if err := s.checkLibraryCopy(ctx, rec, file, path); err != nil {
		return "", err
	}
	return path, nil
}

// checkLibraryCopy refuses a sync-mode global-library file whose local copy
// does not match the replicated library record (or that has none).
func (s *Server) checkLibraryCopy(ctx context.Context, rec corrosion.StoragePoolRecord, file, path string) error {
	if !isGlobalISOLibrary(rec) {
		return nil
	}
	mode, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "iso %s/%s: cannot read the ISO library mode: %v", globalISOLibrary, file, err)
	}
	if mode.Value != corrosion.ISOLibrarySync {
		return nil
	}
	e, ok, err := corrosion.GetISOCatalogEntry(ctx, s.db, file)
	if err != nil {
		return status.Errorf(codes.Internal, "iso: read the ISO library record: %v", err)
	}
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

type isoHashKey struct {
	size  int64
	mtime int64
	ino   uint64
}

type isoLibraryState struct {
	mu     sync.Mutex
	hashes map[string]isoHashEntry
	// syncing admits one sync pass at a time.
	syncing sync.Mutex
}

type isoHashEntry struct {
	key isoHashKey
	sum string
}

func isoKeyFor(fi os.FileInfo) isoHashKey {
	k := isoHashKey{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if ino, ok := fileInode(fi); ok {
		k.ino = ino
	}
	return k
}

// isoFileSHA256 hashes a library file, reusing the last hash while its size,
// mtime and inode are unchanged (the daemon replaces a library file by rename,
// which changes the inode).
func (s *Server) isoFileSHA256(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	key := isoKeyFor(fi)
	s.isoLib.mu.Lock()
	if e, ok := s.isoLib.hashes[path]; ok && e.key == key {
		s.isoLib.mu.Unlock()
		return e.sum, nil
	}
	s.isoLib.mu.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.rememberISOHash(path, fi, sum)
	return sum, nil
}

func (s *Server) rememberISOHash(path string, fi os.FileInfo, sum string) {
	s.isoLib.mu.Lock()
	defer s.isoLib.mu.Unlock()
	if s.isoLib.hashes == nil {
		s.isoLib.hashes = map[string]isoHashEntry{}
	}
	s.isoLib.hashes[path] = isoHashEntry{key: isoKeyFor(fi), sum: sum}
}

// writeLibraryFile writes src into dir/name: through a temp file, at most
// limit bytes, matching wantSHA when given, synced, then renamed over the old
// name (never written through a link there). It returns the sha256 and size.
func (s *Server) writeLibraryFile(dir, name string, src io.Reader, limit int64, wantSHA string) (string, int64, error) {
	dest, err := safename.SafeJoin(dir, name)
	if err != nil {
		return "", 0, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if fi, lerr := os.Lstat(dest); lerr == nil && !fi.Mode().IsRegular() {
		return "", 0, status.Errorf(codes.FailedPrecondition, "%s exists and is not a plain file", dest)
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
	if err := os.Rename(tmpName, dest); err != nil {
		return "", 0, status.Errorf(codes.Internal, "finalize: %v", err)
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

// recordLibraryFile records a file just written to the global library, when
// the library is in sync mode; on failure the file is withdrawn, so no host
// holds a library file the cluster has no record of.
func (s *Server) recordLibraryFile(ctx context.Context, rec corrosion.StoragePoolRecord, name, path, sum string, size int64) error {
	if !isGlobalISOLibrary(rec) {
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
	if !isGlobalISOLibrary(rec) {
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
	if isGlobalISOLibrary(rec) {
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
		case isGlobalISOLibrary(p):
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

// listLibrary lists the usable ISOs of one library on this host.
func (s *Server) listLibrary(ctx context.Context, p corrosion.StoragePoolRecord) []*pb.ISOEntry {
	dir, err := s.poolDirResolved(p)
	if err != nil {
		return nil
	}
	global := isGlobalISOLibrary(p)
	var catalog map[string]corrosion.ISOCatalogEntry
	if global {
		if mode, merr := corrosion.GetISOLibraryMode(ctx, s.db); merr == nil && mode.Value == corrosion.ISOLibrarySync {
			catalog = map[string]corrosion.ISOCatalogEntry{}
			if all, cerr := corrosion.ListISOCatalog(ctx, s.db); cerr == nil {
				for _, e := range all {
					catalog[e.Name] = e
				}
			}
		}
	}
	var out []*pb.ISOEntry
	seen := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, de := range entries {
		name := de.Name()
		if !isISOName(name) || safename.ValidateName(name) != nil {
			continue
		}
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
	if !isISOLibrary(rec) {
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
	raw, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
	}
	if err := os.MkdirAll(raw, 0o755); err != nil {
		return nil, status.Errorf(codes.Internal, "mkdir: %v", err)
	}
	dir, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
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
	f, err := os.Open(src)
	if err != nil {
		return "", 0, status.Errorf(codes.FailedPrecondition, "host_path: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return "", 0, status.Errorf(codes.InvalidArgument, "host_path %q is not a regular file", src)
	}
	return s.writeLibraryFile(dir, name, f, maxPoolUploadBytes, checksum)
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
	return s.writeLibraryFile(dir, name, f, maxPoolUploadBytes, checksum)
}

// ── library mode ──

func (s *Server) isoLibraryModeStatus(ctx context.Context) (*pb.ISOLibraryMode, error) {
	p, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil && !errors.Is(err, corrosion.ErrUnknownISOLibraryMode) {
		return nil, status.Errorf(codes.Internal, "read the ISO library mode: %v", err)
	}
	return &pb.ISOLibraryMode{Mode: p.Value, SetBy: p.SetBy, UpdatedAt: p.UpdatedAt, Settable: s.failoverScopeSettable()}, nil
}

// GetISOLibraryMode reports where the global ISO library lives.
func (s *Server) GetISOLibraryMode(ctx context.Context, _ *emptypb.Empty) (*pb.ISOLibraryMode, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	return s.isoLibraryModeStatus(ctx)
}

// SetISOLibraryMode changes it (admin). Switching to sync records the files
// this host's global library holds that the library has no record of yet, so
// they reach every other host.
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
		s.adoptLocalLibraryFiles(ctx)
	}
	s.audit(ctx, "storage.iso_library_mode", "iso_library_mode", "ISO library mode set to "+mode, "ok")
	s.publish("storage.iso_library_mode", mode, "set by "+callerUsername(ctx))
	return s.isoLibraryModeStatus(ctx)
}

// adoptLocalLibraryFiles records every plain .iso in this host's global
// library that the library has no record of.
func (s *Server) adoptLocalLibraryFiles(ctx context.Context) {
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, globalISOLibrary)
	if err != nil || !ok || !isGlobalISOLibrary(rec) {
		return
	}
	known := map[string]bool{}
	if all, err := corrosion.ListISOCatalog(ctx, s.db); err == nil {
		for _, e := range all {
			known[e.Name] = true
		}
	}
	for _, e := range s.listLibrary(ctx, rec) {
		if known[e.GetName()] {
			continue
		}
		dir, err := s.poolDirResolved(rec)
		if err != nil {
			return
		}
		sum, err := s.isoFileSHA256(filepath.Join(dir, e.GetName()))
		if err != nil {
			continue
		}
		if err := corrosion.PutISOCatalogEntry(ctx, s.db, corrosion.ISOCatalogEntry{
			Name: e.GetName(), SHA256: sum, Size: e.GetSizeBytes(), Origin: s.hostName,
		}, callerUsername(ctx)); err != nil {
			slog.Warn("iso library: record an existing file", "file", e.GetName(), "error", err)
		}
	}
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
	if err != nil || !ok || !isGlobalISOLibrary(rec) {
		return status.Errorf(codes.NotFound, "no global ISO library on %s", s.hostName)
	}
	dir, err := s.poolDirResolved(rec)
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

// SyncISOLibrary is one pass of a sync-mode global library on this host: every
// recorded file is brought to the recorded sha256 (fetched from a host whose
// copy matches), and every file recorded as removed is removed. A file the
// library has no record of is left alone. The daemon runs it periodically.
func (s *Server) SyncISOLibrary(ctx context.Context) error {
	if !s.isoLib.syncing.TryLock() {
		return nil
	}
	defer s.isoLib.syncing.Unlock()
	mode, err := corrosion.GetISOLibraryMode(ctx, s.db)
	if err != nil || mode.Value != corrosion.ISOLibrarySync {
		return err
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, globalISOLibrary)
	if err != nil || !ok || !isGlobalISOLibrary(rec) {
		return err
	}
	raw, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(raw, 0o755); err != nil {
		return err
	}
	dir, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return err
	}
	entries, err := corrosion.ListISOCatalog(ctx, s.db)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if safename.ValidateName(e.Name) != nil || !isISOName(e.Name) {
			continue
		}
		path := filepath.Join(dir, e.Name)
		if e.Deleted {
			if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode().IsRegular() {
				if rerr := os.Remove(path); rerr != nil {
					errs = append(errs, rerr)
				}
			}
			continue
		}
		if sum, herr := s.isoFileSHA256(path); herr == nil && sum == e.SHA256 {
			continue
		}
		if ferr := s.fetchLibraryFile(ctx, dir, e); ferr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name, ferr))
		}
	}
	return errors.Join(errs...)
}

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
			_, _, err = s.writeLibraryFile(dir, e.Name, &fetchReader{stream: st}, e.Size, e.SHA256)
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
