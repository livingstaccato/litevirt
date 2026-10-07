package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
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
//   - a directory on a network filesystem other than the one the ISO's
//     directory is on (by /proc/self/mountinfo, which never touches the mount)
//     is not the same directory, and is not read either — as long as no link
//     above its mount point leads somewhere else;
//   - every other directory is read under a deadline, one probe per directory
//     at a time. One that does not answer, or answers with an error other
//     than "no such directory", fails the question CLOSED — the caller
//     refuses, saying which pool did not answer — rather than hanging or
//     guessing it does not share. Until a probe that timed out returns, the
//     next question about that directory is answered "did not answer" at
//     once, so a dead directory holds at most one blocked thread.
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

// isoDirProbeTimeout bounds one directory probe, and any other read of a
// library directory (deadlined).
var isoDirProbeTimeout = 3 * time.Second

type dirProbe struct {
	path string
	info os.FileInfo
}

// errDirProbeTimeout is the fail-closed answer for a directory that did not
// answer in time (or whose earlier probe has not returned yet).
type errDirProbeTimeout struct{ dir string }

func (e errDirProbeTimeout) Error() string {
	return fmt.Sprintf("directory %s did not answer within %s", e.dir, isoDirProbeTimeout)
}

// errDirProbeFailed is the fail-closed answer for a directory that answered
// with an error (EIO, ESTALE, EACCES, ELOOP …): what it is cannot be told.
type errDirProbeFailed struct {
	dir string
	err error
}

func (e errDirProbeFailed) Error() string {
	return fmt.Sprintf("directory %s could not be read: %v", e.dir, e.err)
}

// deadlineFlight is one in-flight deadlined read, shared by every caller
// asking the same question while it runs.
type deadlineFlight struct {
	done     chan struct{}
	val      any
	err      error
	group    string // the network mount it reads, if any
	project  string // the project whose budget it counts against
	timedOut bool   // a caller gave up on it: answer "did not answer" until it returns (under deadlineFlights)
}

// The deadlined reads that can be running at once. Each one that blocks in the
// kernel holds an OS thread until the filesystem answers, and the Go runtime
// aborts at 10,000; past a bound a new read is refused at once (fail closed).
// The bounds are layered so that no project can spend another's:
//
//   - isoMaxReadsInFlight in all;
//   - of which isoReservedLocalReads only for reads not on a network mount
//     (where nearly every library and pool directory is), which a network
//     mount that stops answering can never take;
//   - isoMaxReadsPerMount on one network mount, counted from the moment each
//     read starts (not once one has timed out);
//   - isoMaxReadsPerProject for one project (the caller's, or the VM's;
//     readProject), and the same for reads no project asked for (the sync
//     loop).
var (
	isoMaxReadsInFlight   = 64
	isoReservedLocalReads = 16
	isoMaxReadsPerMount   = 4
	isoMaxReadsPerProject = 16
)

var deadlineFlights = struct {
	sync.Mutex
	m        map[string]*deadlineFlight
	inFlight int
	network  int            // flights on a network mount
	perMount map[string]int // flights per network mount
	perProj  map[string]int // flights per project
	// stuck counts, per network mount, the reads that timed out and have not
	// returned: while one has, every new read on that mount is answered "did
	// not answer" at once.
	stuck map[string]int
}{m: map[string]*deadlineFlight{}, stuck: map[string]int{}, perMount: map[string]int{}, perProj: map[string]int{}}

// readProjectKey carries, in a context, the project a read is done for.
type readProjectKey struct{}

// withReadProject marks ctx's reads as done for project.
func withReadProject(ctx context.Context, project string) context.Context {
	return context.WithValue(ctx, readProjectKey{}, "project:"+tenancy.NormalizeProject(project))
}

// readProject is the budget a read counts against: its project, or "system".
func readProject(ctx context.Context) string {
	if p, ok := ctx.Value(readProjectKey{}).(string); ok && p != "" {
		return p
	}
	return "system"
}

// errTooManyReads is the fail-closed answer once a bound on waiting reads is
// reached.
type errTooManyReads struct{ dir, what string }

func (e errTooManyReads) Error() string {
	return fmt.Sprintf("directory %s was not read: %s are already waiting on filesystems that do not answer", e.dir, e.what)
}

// errMountNotAnswering is the fail-closed answer for a directory on a network
// mount another read of which has timed out and not returned.
type errMountNotAnswering struct{ dir, mount string }

func (e errMountNotAnswering) Error() string {
	return fmt.Sprintf("directory %s is on %s, which did not answer within %s", e.dir, e.mount, isoDirProbeTimeout)
}

// deadlined runs fn for key under isoDirProbeTimeout, at most one at a time
// per key: a caller asking while one runs waits on that one. Once a caller has
// given up on it, every later caller is answered errDirProbeTimeout at once
// until fn returns — and, with group (the network mount the read is on), so is
// every new read on that mount. No more than isoMaxReadsInFlight run at once.
// A blocked fn holds its goroutine (in the kernel, an OS thread) until the
// filesystem answers; together these bound them.
func deadlined(ctx context.Context, key, group, what string, fn func() (any, error)) (any, error) {
	deadlineFlights.Lock()
	f, ok := deadlineFlights.m[key]
	switch {
	case ok && f.timedOut:
		deadlineFlights.Unlock()
		return nil, errDirProbeTimeout{dir: what}
	case !ok && group != "" && deadlineFlights.stuck[group] > 0:
		deadlineFlights.Unlock()
		return nil, errMountNotAnswering{dir: what, mount: group}
	case !ok && deadlineFlights.inFlight >= isoMaxReadsInFlight:
		deadlineFlights.Unlock()
		return nil, errTooManyReads{dir: what, what: fmt.Sprintf("%d reads", isoMaxReadsInFlight)}
	case !ok && group != "" && deadlineFlights.network >= isoMaxReadsInFlight-isoReservedLocalReads:
		deadlineFlights.Unlock()
		return nil, errTooManyReads{dir: what, what: fmt.Sprintf("%d reads on network filesystems", isoMaxReadsInFlight-isoReservedLocalReads)}
	case !ok && group != "" && deadlineFlights.perMount[group] >= isoMaxReadsPerMount:
		deadlineFlights.Unlock()
		return nil, errTooManyReads{dir: what, what: fmt.Sprintf("%d reads on %s", isoMaxReadsPerMount, group)}
	case !ok && deadlineFlights.perProj[readProject(ctx)] >= isoMaxReadsPerProject:
		deadlineFlights.Unlock()
		return nil, errTooManyReads{dir: what, what: fmt.Sprintf("%d reads for %s", isoMaxReadsPerProject, readProject(ctx))}
	case !ok:
		f = &deadlineFlight{done: make(chan struct{}), group: group, project: readProject(ctx)}
		deadlineFlights.m[key] = f
		deadlineFlights.inFlight++
		deadlineFlights.perProj[f.project]++
		if group != "" {
			deadlineFlights.network++
			deadlineFlights.perMount[group]++
		}
		go func() {
			var v any
			var err error
			defer func() {
				if r := recover(); r != nil {
					v, err = nil, fmt.Errorf("reading %s failed: %v", what, r)
				}
				f.val, f.err = v, err
				deadlineFlights.Lock()
				if deadlineFlights.m[key] == f {
					delete(deadlineFlights.m, key)
				}
				deadlineFlights.inFlight--
				if deadlineFlights.perProj[f.project]--; deadlineFlights.perProj[f.project] <= 0 {
					delete(deadlineFlights.perProj, f.project)
				}
				if f.group != "" {
					deadlineFlights.network--
					if deadlineFlights.perMount[f.group]--; deadlineFlights.perMount[f.group] <= 0 {
						delete(deadlineFlights.perMount, f.group)
					}
				}
				if f.timedOut && f.group != "" {
					if deadlineFlights.stuck[f.group]--; deadlineFlights.stuck[f.group] <= 0 {
						delete(deadlineFlights.stuck, f.group)
					}
				}
				deadlineFlights.Unlock()
				close(f.done)
			}()
			v, err = fn()
		}()
	}
	deadlineFlights.Unlock()
	t := time.NewTimer(isoDirProbeTimeout)
	defer t.Stop()
	select {
	case <-f.done:
		return f.val, f.err
	case <-t.C:
		deadlineFlights.Lock()
		select {
		case <-f.done: // returned meanwhile
			deadlineFlights.Unlock()
			return f.val, f.err
		default:
		}
		if !f.timedOut {
			f.timedOut = true
			if f.group != "" {
				deadlineFlights.stuck[f.group]++
			}
		}
		deadlineFlights.Unlock()
		return nil, errDirProbeTimeout{dir: what}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// probeDir is probeDirCtx with no caller context.
func probeDir(p string) (dirProbe, error) { return probeDirCtx(context.Background(), p) }

// networkMountOf is the mount point of the network (or FUSE) filesystem a
// lexical path is on, by the mount table; "" for any other.
func networkMountOf(p string) string {
	mounts, err := isoMountInfo()
	if err != nil {
		return ""
	}
	if m, ok := mountOf(mounts, filepath.Clean(p)); ok && isNetworkFS(m.fstype) {
		return m.point
	}
	return ""
}

// probeDirCtx resolves and stats p under the deadline (deadlined), grouped by
// the network mount it is on. A missing directory is (zero, nil): it maps
// nothing. Any other error fails closed.
func probeDirCtx(ctx context.Context, p string) (dirProbe, error) {
	v, err := deadlined(ctx, "probe:"+p, networkMountOf(p), p, func() (any, error) {
		r, fi, err := isoDirProbe(p)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				return dirProbe{}, nil
			}
			return nil, errDirProbeFailed{dir: p, err: err}
		}
		return dirProbe{path: r, info: fi}, nil
	})
	if err != nil {
		return dirProbe{}, err
	}
	return v.(dirProbe), nil
}

// isDaemonNFSMount reports whether a pool's directory is the mount directory
// the daemon makes for an nfs pool with no target.
func isDaemonNFSMount(p corrosion.StoragePoolRecord) bool {
	return p.Driver == "nfs" && p.Target == ""
}

// mountEntry is one line of /proc/self/mountinfo.
type mountEntry struct {
	point   string // mount point
	dev     string // major:minor of the filesystem
	fstype  string
	options string // per-mount options (nosymfollow …)
}

// noSymfollow reports a mount that follows no symlink in it (nosymfollow).
func (m mountEntry) noSymfollow() bool {
	for _, o := range strings.Split(m.options, ",") {
		if o == "nosymfollow" {
			return true
		}
	}
	return false
}

// isoMountInfo reads this process's mount table (cached for a second: every
// directory read consults it). A variable so a test can add a mount. Reading
// /proc/self/mountinfo never touches a mounted filesystem.
var isoMountInfo = cachedMountInfo

var mountInfoCache struct {
	sync.Mutex
	at     time.Time
	mounts []mountEntry
	err    error
}

func cachedMountInfo() ([]mountEntry, error) {
	mountInfoCache.Lock()
	defer mountInfoCache.Unlock()
	if time.Since(mountInfoCache.at) < time.Second {
		return mountInfoCache.mounts, mountInfoCache.err
	}
	b, err := os.ReadFile("/proc/self/mountinfo")
	mountInfoCache.at, mountInfoCache.mounts, mountInfoCache.err = time.Now(), nil, err
	if err == nil {
		mountInfoCache.mounts = parseMountInfo(string(b))
	}
	return mountInfoCache.mounts, mountInfoCache.err
}

// parseMountInfo parses mountinfo lines: "id parent major:minor root point
// options [optional...] - fstype source superoptions".
func parseMountInfo(s string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(f) {
			continue
		}
		out = append(out, mountEntry{point: unescapeMountField(f[4]), dev: f[2], fstype: f[sep+1], options: f[5]})
	}
	return out
}

// unescapeMountField undoes mountinfo's octal escapes (\040 for a space …).
func unescapeMountField(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountOf returns the mount a lexical path is on: the last-mounted entry with
// the longest mount point that is the path or above it.
func mountOf(mounts []mountEntry, p string) (mountEntry, bool) {
	var best mountEntry
	found := false
	for _, m := range mounts {
		if !pathWithin(m.point, p) {
			continue
		}
		if !found || len(m.point) >= len(best.point) {
			best, found = m, true
		}
	}
	return best, found
}

// isNetworkFS reports a filesystem type that can stop answering: a network
// filesystem, or a FUSE one.
func isNetworkFS(fstype string) bool {
	switch fstype {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "9p", "afs", "lustre", "gpfs", "beegfs", "fuse":
		return true
	}
	return strings.HasPrefix(fstype, "fuse.")
}

// onAnotherNetworkFS reports, without touching it, that pool directory pd is
// on a network filesystem other than the one target (a resolved directory) is
// on, reached with no link — so it cannot be target, and need not be read:
// no link above that filesystem's mount point, and either pd is the mount
// point itself (a mount point is never a link) or the mount follows no link
// (nosymfollow). A link inside a network export could otherwise name a local
// directory. Anything it cannot tell is false (read it).
func onAnotherNetworkFS(ctx context.Context, mounts []mountEntry, target, pd string) bool {
	if len(mounts) == 0 || target == "" {
		return false
	}
	tm, ok := mountOf(mounts, target)
	if !ok {
		return false
	}
	pm, ok := mountOf(mounts, pd)
	if !ok || !isNetworkFS(pm.fstype) || pm.dev == tm.dev || pm.point == "/" {
		return false
	}
	if filepath.Clean(pd) != pm.point && !pm.noSymfollow() {
		return false
	}
	parent := filepath.Dir(pm.point)
	got, err := probeDirCtx(ctx, parent)
	return err == nil && got.path == parent
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
	var mounts []mountEntry
	if local {
		if target, err = probeDirCtx(ctx, dir); err != nil {
			return nil, status.Errorf(codes.Unavailable, "which pools share %s cannot be told: %v; refusing until it answers", dir, err)
		}
		mounts, _ = isoMountInfo()
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
		if pd == dir || (local && pd == target.path) {
			out = append(out, p)
			continue
		}
		if !local || isDaemonNFSMount(p) {
			continue
		}
		if onAnotherNetworkFS(ctx, mounts, target.path, pd) {
			continue
		}
		got, err := probeDirCtx(ctx, pd)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable,
				"the directory of pool %q (%s) on %s did not answer (%v), so whether it shares %s cannot be told; refusing until it answers",
				p.Name, pd, s.hostName, err, dir)
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

// isoIdentityDir is the host-local store of the records, under the data
// directory. No pool may be created at or under it
// (refuseISOIdentityStoreOverlap): a pool there could write a record.
const isoIdentityDir = "iso-identity"

func (s *Server) isoIdentityPath(key string) string {
	return filepath.Join(s.dataDir, isoIdentityDir, key+".json")
}

func isoIdentityOfFile(project, path string) (isoIdentityRecord, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return isoIdentityRecord{}, false
	}
	return isoIdentityOfInfo(project, path, fi)
}

func isoIdentityOfInfo(project, path string, fi os.FileInfo) (isoIdentityRecord, bool) {
	if fi == nil || !fi.Mode().IsRegular() {
		return isoIdentityRecord{}, false
	}
	r := isoIdentityRecord{Project: project, Path: path, Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano()}
	r.Ino, _ = fileInode(fi)
	r.Dev, _ = fileDevice(fi)
	return r, true
}

// isoIdentityMu serializes the writers of the store (a start racing a
// migration target's judgement of the same VM, a sweep).
var isoIdentityMu sync.Mutex

// recordISOIdentity records that path passed the full rule for the VM (best
// effort: a failed write only means a later start judges the file in full).
// It is written durably: a temp file of its own in the store, synced, renamed
// over the record, and the directory synced.
func (s *Server) recordISOIdentity(key, project, path string) {
	fi, err := os.Lstat(path)
	if err != nil {
		return
	}
	s.recordISOIdentityOf(key, project, path, fi)
}

// recordISOIdentityOf records the file fi describes (one the caller opened and
// judged) as the VM's file at path.
func (s *Server) recordISOIdentityOf(key, project, path string, fi os.FileInfo) {
	r, ok := isoIdentityOfInfo(project, path, fi)
	if !ok || key == "" {
		return
	}
	isoIdentityMu.Lock()
	defer isoIdentityMu.Unlock()
	if old, ok := s.readISOIdentity(key); ok && old == r {
		return
	}
	b, _ := json.Marshal(r)
	p := s.isoIdentityPath(key)
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op after the rename
	if _, err := f.Write(b); err != nil {
		f.Close()
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return
	}
	if err := f.Close(); err != nil {
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		return
	}
	_ = syncPath(dir)
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
	if key == "" {
		return
	}
	isoIdentityMu.Lock()
	defer isoIdentityMu.Unlock()
	if err := os.Remove(s.isoIdentityPath(key)); err == nil {
		_ = syncPath(filepath.Dir(s.isoIdentityPath(key)))
	}
}

// forgetVMISOIdentity drops every record this host keeps for a VM: under its
// uuid and under its name.
func (s *Server) forgetVMISOIdentity(vmName, specJSON string) {
	var sp struct {
		Uuid string `json:"uuid"`
	}
	_ = json.Unmarshal([]byte(specJSON), &sp)
	if sp.Uuid != "" {
		s.forgetISOIdentity(isoIdentityKey(vmName, &pb.VMSpec{Uuid: sp.Uuid}))
	}
	s.forgetISOIdentity("name-" + vmName)
}

// isoIdentitySweepGrace keeps a record younger than this out of the sweep: a
// create writes its record before the VM row exists.
var isoIdentitySweepGrace = 10 * time.Minute

// SweepISOIdentities removes this host's records of VMs that no longer exist
// (a uuid no VM row carries, a name no VM row has), and temp files a crash
// left. It keeps everything when the VM rows cannot be read.
func (s *Server) SweepISOIdentities(ctx context.Context) error {
	dir := filepath.Join(s.dataDir, isoIdentityDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return err
	}
	names, uuids := map[string]bool{}, map[string]bool{}
	for _, vm := range vms {
		names[vm.Name] = true
		var sp struct {
			Uuid string `json:"uuid"`
		}
		if json.Unmarshal([]byte(vm.Spec), &sp) == nil && sp.Uuid != "" {
			uuids[sp.Uuid] = true
		}
	}
	isoIdentityMu.Lock()
	defer isoIdentityMu.Unlock()
	removed := 0
	for _, e := range ents {
		n := e.Name()
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || time.Since(info.ModTime()) < isoIdentitySweepGrace {
			continue
		}
		orphan := false
		switch {
		case strings.HasPrefix(n, ".tmp-"):
			orphan = true
		case strings.HasPrefix(n, "uuid-") && strings.HasSuffix(n, ".json"):
			orphan = !uuids[strings.TrimSuffix(strings.TrimPrefix(n, "uuid-"), ".json")]
		case strings.HasPrefix(n, "name-") && strings.HasSuffix(n, ".json"):
			orphan = !names[strings.TrimSuffix(strings.TrimPrefix(n, "name-"), ".json")]
		}
		if orphan && os.Remove(filepath.Join(dir, n)) == nil {
			removed++
		}
	}
	if removed > 0 {
		_ = syncPath(dir)
	}
	return nil
}
