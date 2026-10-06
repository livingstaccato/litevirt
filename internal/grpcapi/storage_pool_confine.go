package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"google.golang.org/grpc/metadata"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// A pool directory that is not the pool's own — <data_dir>/disks, where every
// VM's local disks live and where an older cluster's built-in default pool
// still is, or a directory another pool on the host also uses — keeps working
// for VM disks, moves, replicas and the rest. What its content operations
// (listing, upload, delete) show and touch is confined per file to what the
// caller's project owns by record:
//
//   - a VM disk (as its file or as a backing file), live or kept after its VM
//     was deleted, whose row on this host is a VM the caller may read;
//   - a replica of such a VM's disk, by an exact replica record (replicaOwner);
//   - a file uploaded into this pool while it belonged to its current
//     project (a global pool's uploads are everyone's who may use the pool).
//
// Installer media (an ISO) no record refers to is library content, visible
// to everyone who may read the pool. Any other file no record refers to is
// visible only to a caller with storage.hostpath at the cluster root, or to
// the daemon's own content calls: it may be a failover's set-aside copy, a
// restore, or a replica.
//
// The caller is the user who made the call, wherever it entered the cluster
// (poolContentCallerOf): a call forwarded from another node is judged as the
// user whose identity it carries, never as the peer that relayed it.

// poolUploadsFile records, per host, which pool and project each uploaded file
// belongs to. It is host-local, as the files are, and only the daemon writes
// it: nothing in a pool directory is trusted to say whose a file is.
const poolUploadsFile = "pool-uploads.json"

// poolUpload is one upload's record, bound to the file — its device and
// inode, size and modification time — so a file deleted and recreated under
// the same name, rewritten, or put at a reused inode number is not the
// upload. A published upload is never written again.
type poolUpload struct {
	Pool    string `json:"pool"`
	Project string `json:"project"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
}

// fileID is what binds an upload record to one file.
type fileID struct {
	dev, ino uint64
	size     int64
	mtimeNs  int64
}

func fileIdentity(path string) (fileID, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() {
		return fileID{}, fmt.Errorf("%s is not a regular file", path)
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino), size: fi.Size(), mtimeNs: fi.ModTime().UnixNano()}, nil
}

func (s *Server) readPoolUploads() (map[string]poolUpload, error) {
	b, err := os.ReadFile(filepath.Join(s.dataDir, poolUploadsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]poolUpload{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]poolUpload{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", poolUploadsFile, err)
	}
	return m, nil
}

func (s *Server) writePoolUploads(m map[string]poolUpload) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	dst := filepath.Join(s.dataDir, poolUploadsFile)
	tmp, err := os.CreateTemp(s.dataDir, "."+poolUploadsFile+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// recordPoolUpload records path as uploaded into pool for project.
func (s *Server) recordPoolUpload(pool, project, path string) error {
	id, err := fileIdentity(path)
	if err != nil {
		return err
	}
	s.poolUploadsMu.Lock()
	defer s.poolUploadsMu.Unlock()
	m, err := s.readPoolUploads()
	if err != nil {
		return err
	}
	m[filepath.Clean(path)] = poolUpload{Pool: pool, Project: project, Dev: id.dev, Ino: id.ino, Size: id.size, MtimeNs: id.mtimeNs}
	return s.writePoolUploads(m)
}

// forgetPoolUpload drops path's record, if any.
func (s *Server) forgetPoolUpload(path string) error {
	s.poolUploadsMu.Lock()
	defer s.poolUploadsMu.Unlock()
	m, err := s.readPoolUploads()
	if err != nil {
		return err
	}
	if _, ok := m[filepath.Clean(path)]; !ok {
		return nil
	}
	delete(m, filepath.Clean(path))
	return s.writePoolUploads(m)
}

// poolUploadOf returns path's upload record when it still describes the file
// there now.
func (s *Server) poolUploadOf(uploads map[string]poolUpload, path string) (poolUpload, bool) {
	u, ok := uploads[filepath.Clean(path)]
	if !ok {
		return poolUpload{}, false
	}
	id, err := fileIdentity(path)
	if err != nil || id.dev != u.Dev || id.ino != u.Ino || id.size != u.Size || id.mtimeNs != u.MtimeNs {
		return poolUpload{}, false
	}
	return u, true
}

// isRecordedUpload reports whether path is an upload any pool recorded and
// that still describes the file there. The VM-disk debris sweep keeps these.
func (s *Server) isRecordedUpload(path string) bool {
	s.poolUploadsMu.Lock()
	m, err := s.readPoolUploads()
	s.poolUploadsMu.Unlock()
	if err != nil {
		return true // unreadable records protect, never expose to a sweep
	}
	_, ok := s.poolUploadOf(m, path)
	return ok
}

// poolUploadsSubdir is where uploads into a pool on <data_dir>/disks land:
// never beside the VM disks, whose names (<vm>-<disk>.qcow2) the debris sweep
// and migrations own.
const poolUploadsSubdir = "uploads"

// poolContentDirs are the directories a file pool's content is in: its own
// directory, and for a pool on <data_dir>/disks also disks/uploads.
func (s *Server) poolContentDirs(dir string) []string {
	if storage.IsDataDirDisks(dir, s.dataDir) {
		return []string{dir, filepath.Join(dir, poolUploadsSubdir)}
	}
	return []string{dir}
}

// poolUploadDir is where an upload into a pool whose directory is dir lands.
func (s *Server) poolUploadDir(dir string) string {
	ds := s.poolContentDirs(dir)
	return ds[len(ds)-1]
}

// poolDirShared reports whether a file pool's directory is not its own: it is
// <data_dir>/disks, or another live pool on this host uses the same
// directory, an alias of it, one inside it or one containing it. A lookup
// error counts as shared (content stays confined).
func (s *Server) poolDirShared(ctx context.Context, rec corrosion.StoragePoolRecord) bool {
	ref := StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options}
	dir, err := fileBasedPoolDir(s.dataDir, ref)
	if err != nil {
		return true
	}
	if storage.IsDataDirDisks(dir, s.dataDir) {
		return true
	}
	rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return true
	}
	for _, r := range rows {
		if r.Name == rec.Name || !isFileBasedDriver(r.Driver) {
			continue
		}
		d, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: r.Driver, Source: r.Source, Target: r.Target})
		if err == nil && storage.DirsOverlap(dir, d) {
			return true
		}
	}
	return false
}

// poolContentViewMDKey marks a content call (list, upload, delete) the daemon
// makes for itself — replication's upload and pruning, promote's listing — or
// one an entry node forwards for a caller with storage.hostpath at the root
// who has no bearer to forward. Value "all": every file. It is honoured only
// from a cluster peer; a user cannot set a peer call's metadata.
const poolContentViewMDKey = "x-litevirt-pool-content-view"

// withPoolContentViewAll marks an outgoing content call as the daemon's own.
func withPoolContentViewAll(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, poolContentViewMDKey, "all")
}

// poolContentView is how much of a shared pool directory a content caller sees.
type poolContentView int

const (
	viewCaller    poolContentView = iota // a user: their project's files and library media
	viewAll                              // storage.hostpath at the root, or the daemon itself
	viewNoProject                        // a peer carrying no identity: library media only
)

// poolContentCaller is who a content call is for.
type poolContentCaller struct {
	ctx    context.Context // the user's identity, for RBAC (viewCaller, viewAll)
	view   poolContentView
	record bool // an upload by this caller is recorded as its pool's project's
}

// poolContentCallerOf resolves who a content call is for. A direct caller is
// itself. A call relayed by a peer is the user whose bearer it carries
// (pki.FwdBearerMDKey), authenticated here whether or not forwarded identity
// is enforced cluster-wide; a peer call that carries none is the daemon's own
// when it says so (poolContentViewMDKey), and otherwise nobody's.
func (s *Server) poolContentCallerOf(ctx context.Context) (poolContentCaller, error) {
	userView := func(uctx context.Context) poolContentCaller {
		if s.RequirePerm(uctx, "/", verbStorageHostPath, "admin") == nil {
			return poolContentCaller{ctx: uctx, view: viewAll, record: true}
		}
		return poolContentCaller{ctx: uctx, view: viewCaller, record: true}
	}
	if s.requirePeerCert(ctx) != nil {
		return userView(ctx), nil
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(poolContentViewMDKey); len(v) > 0 && v[0] == "all" {
			return poolContentCaller{ctx: ctx, view: viewAll}, nil
		}
	}
	if callerAuthMethod(ctx) != authMethodMTLS {
		return userView(ctx), nil // already promoted to the forwarded user
	}
	if fwd := fwdBearerFromCtx(ctx); fwd != "" {
		uctx, err := s.authenticateForwardedBearer(ctx, fwd)
		if err != nil {
			return poolContentCaller{}, err
		}
		return userView(uctx), nil
	}
	return poolContentCaller{ctx: ctx, view: viewNoProject}, nil
}

// forwardContentCall prepares ctx for forwarding a content call to the pool's
// host. A bearer is relayed by PeerDial; a caller with none (a bearerless
// admin certificate, on-node root) who holds storage.hostpath is marked as
// seeing every file, as it would on the pool's host itself.
func (s *Server) forwardContentCall(ctx context.Context) context.Context {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if a := md.Get("authorization"); len(a) > 0 && a[0] != "" {
			return ctx
		}
	}
	if c, err := s.poolContentCallerOf(ctx); err == nil && c.view == viewAll {
		return withPoolContentViewAll(ctx)
	}
	return ctx
}

// poolFileConfinement decides, for one content operation on one pool, which
// files the caller may see and change. nil means everything: the caller sees
// every file, or the pool's directory is its own and the caller is a user.
type poolFileConfinement struct {
	s       *Server
	rec     corrosion.StoragePoolRecord
	caller  poolContentCaller
	uploads map[string]poolUpload
	vmOK    map[string]bool // VM name → caller may read it
}

// poolConfinementFor returns the confinement of rec's content for caller, or
// nil. A peer with no identity is confined everywhere: it is nobody.
func (s *Server) poolConfinementFor(ctx context.Context, rec corrosion.StoragePoolRecord, caller poolContentCaller) (*poolFileConfinement, error) {
	switch {
	case caller.view == viewAll:
		return nil, nil
	case caller.view == viewCaller && !s.poolDirShared(ctx, rec):
		return nil, nil
	}
	s.poolUploadsMu.Lock()
	uploads, err := s.readPoolUploads()
	s.poolUploadsMu.Unlock()
	if err != nil {
		return nil, err
	}
	return &poolFileConfinement{s: s, rec: rec, caller: caller, uploads: uploads, vmOK: map[string]bool{}}, nil
}

func (c *poolFileConfinement) callerReadsVM(ctx context.Context, name string) bool {
	if c.caller.view == viewNoProject {
		return false
	}
	if ok, seen := c.vmOK[name]; seen {
		return ok
	}
	// A deleted VM's row still says whose its kept disks are.
	vm, err := corrosion.GetVMIncludingDeleted(ctx, c.s.db, name)
	ok := err == nil && vm != nil && c.s.RequirePerm(c.caller.ctx, vmRBACPath(vm), "vm.read", "viewer") == nil
	c.vmOK[name] = ok
	return ok
}

// fileOwnership is what the records say about one file in a shared pool
// directory.
type fileOwnership struct {
	owned      bool // some record refers to it
	callerOwns bool // one of those records is the caller's project's
	deletable  bool // the caller may delete it: its own upload or replica
}

// replicaOwner returns the project an exact replica record gives path to.
// There are no replica records on this branch yet, so none: a file named like
// a replica is owned by no one through its name — the name is not a record,
// and "<vm>-<disk>-<ts>" splits more than one way. The replica records of
// fix/disk-files-project-isolation are wired in here, and only here.
func (c *poolFileConfinement) replicaOwner(ctx context.Context, path string) (project string, ok bool) {
	return "", false
}

// ownership reads the records for path: an upload recorded for it (to any
// pool), a VM disk row (live or tombstoned) using it as its file or backing
// file, and an exact replica record. A disk row on another host describes
// that host's file at the same path: it marks this one owned (so it is not
// library content) but gives it to no one.
func (c *poolFileConfinement) ownership(ctx context.Context, path string) (fileOwnership, error) {
	var o fileOwnership
	if u, ok := c.s.poolUploadOf(c.uploads, path); ok {
		o.owned = true
		if c.caller.view != viewNoProject && u.Pool == c.rec.Name && u.Project == c.rec.Project {
			o.callerOwns, o.deletable = true, true
		}
	}
	refs, err := corrosion.DisksReferencingPath(ctx, c.s.db, path)
	if err != nil {
		return o, err
	}
	// A detached disk, or one kept when its VM was deleted, is still its
	// VM's project's: its tombstoned row says so.
	kept, err := corrosion.TombstonedDisksReferencingPath(ctx, c.s.db, path)
	if err != nil {
		return o, err
	}
	for _, d := range append(refs, kept...) {
		o.owned = true
		if (d.HostName == "" || d.HostName == c.s.hostName) && c.callerReadsVM(ctx, d.VMName) {
			o.callerOwns = true
		}
	}
	if project, ok := c.replicaOwner(ctx, path); ok {
		o.owned = true
		if c.caller.view != viewNoProject && project == c.rec.Project {
			o.callerOwns, o.deletable = true, true
		}
	}
	return o, nil
}

// visible reports whether the caller sees path: a file its project owns by
// record, or installer media (an ISO) no record refers to — library content,
// which everyone who may read the pool sees. An unowned disk image is not:
// it may be any project's. A lookup error hides the file.
func (c *poolFileConfinement) visible(ctx context.Context, path string) bool {
	if c == nil {
		return true
	}
	o, err := c.ownership(ctx, path)
	if err != nil {
		return false
	}
	if o.owned {
		return o.callerOwns
	}
	return isLibraryMediaName(filepath.Base(path))
}

// deletable reports whether the caller may delete path: only its own upload
// or replica (the RPC has already required storage.content.write on the
// pool). Unowned library content is an admin's to delete.
func (c *poolFileConfinement) deletable(ctx context.Context, path string) bool {
	if c == nil {
		return true
	}
	o, err := c.ownership(ctx, path)
	return err == nil && o.deletable
}

// isLibraryMediaName reports whether name is installer media: a name an
// upload may take (validatePoolUploadName) that is an ISO, plain or
// compressed (x.iso, x.iso.xz). Disk images (.qcow2, .raw, .img, .vmdk, …)
// are not library media.
func isLibraryMediaName(name string) bool {
	if validatePoolUploadName(name) != nil {
		return false
	}
	lower := strings.ToLower(name)
	for _, c := range []string{"", ".gz", ".xz", ".zst", ".bz2"} {
		if strings.HasSuffix(lower, ".iso"+c) {
			return true
		}
	}
	return false
}
