package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// ── which pools map a directory ──
//
// The pools that "share" an ISO's directory are those whose directory is the
// same directory on this host: the same path once symlinks are resolved (a
// pool aimed through a link or /proc/self/root), or the same directory by
// identity (a bind mount of it elsewhere). Reading another pool's directory
// can block (an unanswering NFS server on a hard mount), so:
//
//   - a daemon-made NFS mount directory (an nfs pool with no target,
//     <data_dir>/mounts/<source>) is never stat'ed: it is a real directory the
//     daemon created, never a link, and is compared as written;
//   - every other directory is read under a deadline, and one that does not
//     answer fails the question CLOSED — the caller refuses, saying which pool
//     did not answer — rather than hanging or guessing it does not share.
//
// Another host's rows are compared as written; that host judges them again
// itself when it resolves the ISO.

// isoDirProbe resolves a directory and stats it. A variable so a test can make
// it block or alias.
var isoDirProbe = func(p string) (string, os.FileInfo, error) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", nil, err
	}
	fi, err := os.Stat(r)
	return r, fi, err
}

// isoDirProbeTimeout bounds one directory probe.
var isoDirProbeTimeout = 3 * time.Second

type dirProbe struct {
	path string
	info os.FileInfo
}

// errDirProbeTimeout is the fail-closed answer for a directory that did not
// answer in time.
type errDirProbeTimeout struct{ dir string }

func (e errDirProbeTimeout) Error() string {
	return fmt.Sprintf("directory %s did not answer within %s", e.dir, isoDirProbeTimeout)
}

// probeDir runs isoDirProbe under isoDirProbeTimeout. A missing directory is
// (zero, nil): it maps nothing.
func probeDir(p string) (dirProbe, error) {
	type res struct {
		r   string
		fi  os.FileInfo
		err error
	}
	ch := make(chan res, 1)
	go func() {
		r, fi, err := isoDirProbe(p)
		ch <- res{r, fi, err}
	}()
	t := time.NewTimer(isoDirProbeTimeout)
	defer t.Stop()
	select {
	case v := <-ch:
		if v.err != nil {
			if os.IsNotExist(v.err) {
				return dirProbe{}, nil
			}
			return dirProbe{path: filepath.Clean(p)}, nil
		}
		return dirProbe{path: v.r, info: v.fi}, nil
	case <-t.C:
		return dirProbe{}, errDirProbeTimeout{dir: p}
	}
}

// isDaemonNFSMount reports whether a pool's directory is the mount directory
// the daemon makes for an nfs pool with no target.
func isDaemonNFSMount(p corrosion.StoragePoolRecord) bool {
	return p.Driver == "nfs" && p.Target == ""
}

// poolsMappingDir returns the file-based pools on host whose directory is dir.
// On this host dir must already be resolved (the directory the file is opened
// through), and its identity is probed too.
func (s *Server) poolsMappingDir(ctx context.Context, host, dir string) ([]corrosion.StoragePoolRecord, error) {
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, host)
	if err != nil {
		return nil, err
	}
	dir = filepath.Clean(dir)
	local := host == s.hostName
	var target dirProbe
	if local {
		if target, err = probeDir(dir); err != nil {
			return nil, status.Errorf(codes.Unavailable, "which pools share %s cannot be told: %v; refusing until it answers", dir, err)
		}
	}
	var out []corrosion.StoragePoolRecord
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) {
			continue
		}
		pd, perr := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target})
		if perr != nil || pd == "" {
			continue
		}
		pd = filepath.Clean(pd)
		if !local || isDaemonNFSMount(p) {
			if pd == dir || (local && pd == target.path) {
				out = append(out, p)
			}
			continue
		}
		got, err := probeDir(pd)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable,
				"the directory of pool %q (%s) on %s did not answer within %s, so whether it shares %s cannot be told; refusing until it answers",
				p.Name, pd, s.hostName, isoDirProbeTimeout, dir)
		}
		if got.path == dir || (got.info != nil && target.info != nil && os.SameFile(got.info, target.info)) {
			out = append(out, p)
		}
	}
	return out, nil
}

// ── the file each host judged ──
//
// When a host judges a VM's ISO by the full ownership rule and it passes (at
// the create, at a start, as a migration target), it records which file that
// was: the resolved path, inode, size and mtime, in <data_dir>/iso-identity,
// keyed by the VM's uuid and naming its project. A later start of that
// unchanged file on this host passes even if another project's pool has come
// to share the directory since. The record is this host's own (no replication,
// so nothing another host says can excuse a file here), and it ignores the
// device number, which a ZFS, btrfs, NFS or LVM mount can renumber across a
// reboot; on one host the path, the inode, the size and the mtime name the
// file, its link count being one.

type isoIdentityRecord struct {
	Project string `json:"project"`
	Path    string `json:"path"`
	Ino     uint64 `json:"ino"`
	Dev     uint64 `json:"dev,omitempty"` // informational only: never compared
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
}

// isoIdentityKey names a VM's record: its uuid, or its name for a VM without
// one (made before uuids). A name reused by another VM is caught by the
// project and the file having to match too.
func isoIdentityKey(vmName string, spec *pb.VMSpec) string {
	if u := spec.GetUuid(); u != "" && safename.ValidateName(u) == nil {
		return "uuid-" + u
	}
	return "name-" + vmName
}

func (s *Server) isoIdentityPath(key string) string {
	return filepath.Join(s.dataDir, "iso-identity", key+".json")
}

func isoIdentityOfFile(project, path string) (isoIdentityRecord, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return isoIdentityRecord{}, false
	}
	r := isoIdentityRecord{Project: project, Path: path, Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano()}
	r.Ino, _ = fileInode(fi)
	r.Dev, _ = fileDevice(fi)
	return r, true
}

// recordISOIdentity records that path passed the full rule for the VM (best
// effort: a failed write only means a later start judges the file in full).
func (s *Server) recordISOIdentity(key, project, path string) {
	r, ok := isoIdentityOfFile(project, path)
	if !ok || key == "" {
		return
	}
	if old, ok := s.readISOIdentity(key); ok && old == r {
		return
	}
	b, _ := json.Marshal(r)
	p := s.isoIdentityPath(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

func (s *Server) readISOIdentity(key string) (isoIdentityRecord, bool) {
	b, err := os.ReadFile(s.isoIdentityPath(key))
	if err != nil {
		return isoIdentityRecord{}, false
	}
	var r isoIdentityRecord
	if json.Unmarshal(b, &r) != nil {
		return isoIdentityRecord{}, false
	}
	return r, true
}

// isoIdentityHolds reports whether path is, for this VM and project, the very
// file this host recorded as passing the full rule.
func (s *Server) isoIdentityHolds(key, project, path string) bool {
	if key == "" {
		return false
	}
	rec, ok := s.readISOIdentity(key)
	if !ok {
		return false
	}
	now, ok := isoIdentityOfFile(project, path)
	return ok && rec.Project == now.Project && rec.Path == now.Path && rec.Ino == now.Ino &&
		rec.Size == now.Size && rec.MtimeNs == now.MtimeNs
}

// forgetISOIdentity drops a VM's record on this host.
func (s *Server) forgetISOIdentity(key string) {
	if key != "" {
		_ = os.Remove(s.isoIdentityPath(key))
	}
}
