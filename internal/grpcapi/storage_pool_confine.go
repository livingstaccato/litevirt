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
//   - a live VM disk (as its file or as a backing file) of a VM the caller
//     may read;
//   - a replica of such a VM's disk made by a replication schedule into this
//     pool;
//   - a file uploaded into this pool while it belonged to its current
//     project (a global pool's uploads are everyone's who may use the pool).
//
// A file with no owner record is visible only to a caller with
// storage.hostpath at the cluster root (or a cluster peer): it may be a
// failover's set-aside copy, a restore, or a deleted VM's kept disk.

// poolUploadsFile records, per host, which pool and project each uploaded file
// belongs to. It is host-local, as the files are, and only the daemon writes
// it: nothing in a pool directory is trusted to say whose a file is.
const poolUploadsFile = "pool-uploads.json"

// poolUpload is one upload's record, bound to the file by device and inode so
// a file deleted and recreated under the same name is not the upload.
type poolUpload struct {
	Pool    string `json:"pool"`
	Project string `json:"project"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
}

func fileIdentity(path string) (dev, ino uint64, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() {
		return 0, 0, fmt.Errorf("%s is not a regular file", path)
	}
	return uint64(st.Dev), uint64(st.Ino), nil
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
	dev, ino, err := fileIdentity(path)
	if err != nil {
		return err
	}
	s.poolUploadsMu.Lock()
	defer s.poolUploadsMu.Unlock()
	m, err := s.readPoolUploads()
	if err != nil {
		return err
	}
	m[filepath.Clean(path)] = poolUpload{Pool: pool, Project: project, Dev: dev, Ino: ino}
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
	dev, ino, err := fileIdentity(path)
	if err != nil || dev != u.Dev || ino != u.Ino {
		return poolUpload{}, false
	}
	return u, true
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

// seesUnownedPoolFiles reports whether the caller sees every file in a shared
// pool directory, owned by record or not: a cluster peer (a forward,
// replication pruning, promote) or a caller with storage.hostpath at the
// cluster root, who could name the directory itself.
func (s *Server) seesUnownedPoolFiles(ctx context.Context) bool {
	return s.requirePeerCert(ctx) == nil || s.RequirePerm(ctx, "/", verbStorageHostPath, "admin") == nil
}

// poolFileConfinement decides, for one content operation on one pool, which
// files the caller may see and change. nil means everything (the pool's
// directory is its own, or the caller sees unowned files).
type poolFileConfinement struct {
	s       *Server
	rec     corrosion.StoragePoolRecord
	uploads map[string]poolUpload
	scheds  []corrosion.BackupScheduleRecord
	vmOK    map[string]bool // VM name → caller may read it
}

// poolConfinementFor returns the confinement for rec's content, or nil.
func (s *Server) poolConfinementFor(ctx context.Context, rec corrosion.StoragePoolRecord) (*poolFileConfinement, error) {
	if !s.poolDirShared(ctx, rec) || s.seesUnownedPoolFiles(ctx) {
		return nil, nil
	}
	s.poolUploadsMu.Lock()
	uploads, err := s.readPoolUploads()
	s.poolUploadsMu.Unlock()
	if err != nil {
		return nil, err
	}
	scheds, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, err
	}
	return &poolFileConfinement{s: s, rec: rec, uploads: uploads, scheds: scheds, vmOK: map[string]bool{}}, nil
}

func (c *poolFileConfinement) callerReadsVM(ctx context.Context, name string) bool {
	if ok, seen := c.vmOK[name]; seen {
		return ok
	}
	// A deleted VM's row still says whose its kept disks are.
	vm, err := corrosion.GetVMIncludingDeleted(ctx, c.s.db, name)
	ok := err == nil && vm != nil && c.s.RequirePerm(ctx, vmRBACPath(vm), "vm.read", "viewer") == nil
	c.vmOK[name] = ok
	return ok
}

// fileOwnership is what the records say about one file in a shared pool
// directory.
type fileOwnership struct {
	owned      bool // some record refers to it
	callerOwns bool // one of those records is the caller's project's
	deletable  bool // the caller may delete it (an upload or replica of theirs)
}

// ownership reads the records for path: an upload recorded for it (to any
// pool), a VM disk row on any host using it as its file or backing file, and
// a replication schedule whose replicas it is named as.
func (c *poolFileConfinement) ownership(ctx context.Context, path string) (fileOwnership, error) {
	var o fileOwnership
	if u, ok := c.s.poolUploadOf(c.uploads, path); ok {
		o.owned = true
		if u.Pool == c.rec.Name && u.Project == c.rec.Project {
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
		if c.callerReadsVM(ctx, d.VMName) {
			o.callerOwns = true
		}
	}
	base := filepath.Base(path)
	for _, sc := range c.scheds {
		if sc.Type != "replication" || sc.VMName == "" || !strings.HasPrefix(base, sc.VMName+"-") {
			continue
		}
		disks, err := corrosion.GetVMDisks(ctx, c.s.db, sc.VMName)
		if err != nil {
			return o, err
		}
		for _, d := range disks {
			if !isReplicaOf(base, sc.VMName, d.DiskName) {
				continue
			}
			o.owned = true
			if c.callerReadsVM(ctx, sc.VMName) {
				o.callerOwns, o.deletable = true, true
			}
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
// or its own VM's replica. Unowned library content is an admin's to delete.
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
