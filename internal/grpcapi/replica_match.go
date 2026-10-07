package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Which files are a VM's replicas.
//
// Promotion boots a replica and replication's pruning deletes old ones, so
// both must take only the files that are this VM's: never by a name prefix,
// which another project's VM can share ("bvm" + "root-20261006" and
// "bvm-root" + "20261006" both write "bvm-root-20261006-…"). A replica the
// daemon places is recorded with the VM, disk and project it is of
// (recordPoolReplica; on shared storage cluster-wide), and that record
// decides. A file with no record is a replica only if it can be one made
// before records (isLegacyUnrecorded), its name is exactly
// <vm>-<disk>-<YYYYMMDD-HHMMSS>.<qcow2|raw> with a stamp not in the future,
// no VM of another project has a disk that writes the same name, and no disk
// of another project's VM uses the file.
//
// A file whose records all went stale (the file changed since) is matched by
// its name in the same way: a record only ever adds proof.
//
// A replicate-volume copy is recorded as the operator's copy of the disk, not
// as a replica: pruning, the newest replica and an increment's base never
// take it. Replicas are ordered by the run time their names carry.
//
// A replica an operator names for a manual promotion (explicitReplicaOK) may
// also be such a copy, an upload the VM's project owns, or a pre-records file
// named <vm>-<disk>-<anything>; an admin may name any file in the pool.

// replicaKey names one VM's disk, in its project, whose replicas a call is
// about.
type replicaKey struct {
	VM, Disk, Project string
	// UUID is the VM's incarnation uuid when known. It keys the replicated
	// record of the replicas (pool_records.go), never their matching.
	UUID string
}

func replicaKeyOf(vm *corrosion.VMRecord, disk string) replicaKey {
	uuid, _ := vmSpecUUID(vm.Spec)
	return replicaKey{VM: vm.Name, Disk: disk, Project: tenancy.NormalizeProject(vm.Project), UUID: uuid}
}

// sameProject compares projects as stored ("" is the default project).
func sameProject(a, b string) bool {
	return tenancy.NormalizeProject(a) == tenancy.NormalizeProject(b)
}

// replicaStampLayout is the run time the replication runner writes into a
// replica's name.
const replicaStampLayout = "20060102-150405"

// replicaStampSkew is how far in the future a replica's stamp may be (clock
// skew between hosts). A later one was not written by a replication run.
const replicaStampSkew = 10 * time.Minute

// replicaStem is name without its .qcow2 or .raw extension.
func replicaStem(name string) (string, bool) {
	if base, ok := strings.CutSuffix(name, ".qcow2"); ok {
		return base, true
	}
	return strings.CutSuffix(name, ".raw")
}

// replicaNamePrefix parses name as the replication runner writes it,
// <prefix>-<YYYYMMDD-HHMMSS>.<qcow2|raw>, from the right, and returns
// <prefix> ("<vm>-<disk>"). A stamp beyond now plus replicaStampSkew does not
// parse.
func replicaNamePrefix(name string) (string, bool) {
	p, _, future, ok := parseReplicaName(name)
	return p, ok && !future
}

// parseReplicaName parses <prefix>-<YYYYMMDD-HHMMSS>.<qcow2|raw> from the
// right, whenever the stamp is (future: beyond now plus replicaStampSkew).
func parseReplicaName(name string) (prefix string, ts time.Time, future, ok bool) {
	base, ok := replicaStem(name)
	if !ok {
		return "", time.Time{}, false, false
	}
	n := len(base) - len(replicaStampLayout)
	if n < 4 || base[n-1] != '-' {
		return "", time.Time{}, false, false
	}
	ts, err := time.Parse(replicaStampLayout, base[n:])
	if err != nil {
		return "", time.Time{}, false, false
	}
	return base[:n-1], ts, ts.After(time.Now().Add(replicaStampSkew)), true
}

// notAReplicaName is the refusal of a replica upload or push whose name is not
// one of k's disk's, saying so when only its stamp is wrong: beyond this
// host's clock, which is the replicating host's clock being ahead.
func notAReplicaName(name string, k replicaKey) error {
	if p, ts, future, ok := parseReplicaName(name); ok && future && p == k.VM+"-"+k.Disk {
		return status.Errorf(codes.InvalidArgument,
			"%q is stamped %s, in the future by more than %s of this host's clock: the replicating host's clock is ahead",
			name, ts.Format(time.RFC3339), replicaStampSkew)
	}
	return status.Errorf(codes.InvalidArgument, "%q is not a replica name of vm %q disk %q", name, k.VM, k.Disk)
}

// replicaOlder orders replicas by the run time their names carry (a name
// with none first, then by name): replicas of one disk by age.
func replicaOlder(a, b string) bool {
	ta, oka := replicaTimestamp(a)
	tb, okb := replicaTimestamp(b)
	switch {
	case oka && okb && !ta.Equal(tb):
		return ta.Before(tb)
	case oka != okb:
		return okb
	}
	return a < b
}

func sortReplicasOldestFirst(names []string) {
	sort.SliceStable(names, func(i, j int) bool { return replicaOlder(names[i], names[j]) })
}

// replicaNameIs reports whether name is exactly a replica name of k's disk.
func replicaNameIs(name string, k replicaKey) bool {
	p, ok := replicaNamePrefix(name)
	return ok && p == k.VM+"-"+k.Disk
}

// replicaNameClaimedElsewhere reports whether a VM of another project than
// k's could have written replica name: some other split of its stem into
// <vm>-<disk>-<rest> names a VM outside k's project (live or deleted) that
// has, or had, that disk. A lookup error claims it, and so does a deleted VM
// whose disk rows are gone (what its disks were cannot be known).
func (s *Server) replicaNameClaimedElsewhere(ctx context.Context, name string, k replicaKey) bool {
	stem, ok := replicaStem(name)
	if !ok {
		return true
	}
	disksOf := map[string]map[string]bool{} // vm → its disks (nil: claim everything)
	for i := 1; i < len(stem)-1; i++ {
		if stem[i] != '-' {
			continue
		}
		vmName := stem[:i]
		disks, seen := disksOf[vmName]
		if !seen {
			var claim bool
			disks, claim = s.otherProjectDisks(ctx, vmName, k)
			if claim {
				return true
			}
			disksOf[vmName] = disks
		}
		if disks == nil {
			continue
		}
		for j := i + 2; j < len(stem); j++ {
			if stem[j] == '-' && disks[stem[i+1:j]] {
				return true
			}
		}
	}
	return false
}

// otherProjectDisks returns the disk names of vmName when it is a VM of
// another project than k's (nil when it is k's project's or no VM), and true
// when what it has cannot be known.
func (s *Server) otherProjectDisks(ctx context.Context, vmName string, k replicaKey) (map[string]bool, bool) {
	vm, err := corrosion.GetVMIncludingDeleted(ctx, s.db, vmName)
	if err != nil {
		return nil, true
	}
	if vm == nil || sameProject(vm.Project, k.Project) {
		return nil, false
	}
	live, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, true
	}
	kept, err := corrosion.GetSoftDeletedVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, true
	}
	disks := map[string]bool{}
	for _, d := range live {
		disks[d.DiskName] = true
	}
	for _, d := range kept {
		disks[d.DiskName] = true
	}
	if len(disks) == 0 {
		if cur, err := corrosion.GetVM(ctx, s.db, vmName); err != nil || cur == nil {
			return nil, true // deleted, disks unknown: fail closed
		}
	}
	return disks, false
}

// usedByOtherProject reports whether a disk row (live or kept) of a VM of
// another project uses path, or that cannot be read.
func (s *Server) usedByOtherProject(ctx context.Context, path string, k replicaKey) bool {
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return true
	}
	kept, err := corrosion.TombstonedDisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return true
	}
	for _, d := range append(refs, kept...) {
		vm, err := corrosion.GetVMIncludingDeleted(ctx, s.db, d.VMName)
		if err != nil || (vm != nil && !sameProject(vm.Project, k.Project)) {
			return true
		}
	}
	return false
}

// isReplicaFor reports whether the file at path is a replica a replication
// run made of k's disk: by its record when one still describes it (a copy is
// not), and otherwise by its exact name, as a replica made before records
// (see the comment at the top of this file). An older node's upload (a Peer
// record) was placed by a node, not a user, and a file whose records are all
// stale was changed since: both are matched by name like a file from before
// records, whenever they were made.
func (s *Server) isReplicaFor(ctx context.Context, uploads poolRecords, path string, k replicaKey) bool {
	u, st := s.recordState(uploads, path)
	switch {
	case st == recMatched && !u.Peer:
		return !u.Copy && u.VM == k.VM && u.Disk == k.Disk && sameProject(u.Project, k.Project)
	case st == recNone && !s.isLegacyUnrecorded(ctx, path) && !s.lateReplicaOK(ctx, path, k):
		return false
	}
	name := filepath.Base(path)
	return replicaNameIs(name, k) && !s.replicaNameClaimedElsewhere(ctx, name, k) && !s.usedByOtherProject(ctx, path, k)
}

// lateReplicaOK reports whether an unrecorded file on shared storage, made
// after its records epoch, is a replica of k's disk whose record has not
// arrived: its writer, the VM's host, stopped answering (a partition: it kept
// writing to the store, its records did not reach this side) before the
// record could replicate. All of: the name is exactly k's runner name (the
// caller then applies the claimed-elsewhere and other-project checks), no
// record of any host names the file (the caller's recNone), the VM's host is
// not live, that host has a replica row for this VM disk on this store, and
// the file is newer — by stamp and modification time — than every entry of
// that row and no newer than the host was last seen answering, and the upload
// API did not place it (no upload marker on the store).
func (s *Server) lateReplicaOK(ctx context.Context, path string, k replicaKey) bool {
	name := filepath.Base(path)
	_, ts, future, ok := parseReplicaName(name)
	if !ok || future || !replicaNameIs(name, k) {
		return false
	}
	// The upload API placed it (its record may be on the other side of the
	// partition; its marker is on the store, with the file).
	if hasUploadMarker(path) {
		return false
	}
	vm, err := corrosion.GetVM(ctx, s.db, k.VM)
	if err != nil || vm == nil || !sameProject(vm.Project, k.Project) || vm.HostName == "" || vm.HostName == s.hostName {
		return false
	}
	writer := vm.HostName
	last, healthy, err := corrosion.HostLastSeen(ctx, s.db, writer)
	if err != nil || last.IsZero() {
		return false
	}
	if hr, err := corrosion.GetHost(ctx, s.db, writer); err != nil || (healthy && (hr == nil || hr.State != "fenced")) {
		return false // live, or unknown
	}
	st := sharedStoreOf(filepath.Dir(path))
	if st.ID == "" {
		return false
	}
	rows, err := corrosion.ListPoolRecords(ctx, s.db, replicaRowPrefix(st.ID, writer))
	if err != nil {
		return false
	}
	found := false
	var newestStamp time.Time
	var newestMtime int64
	for _, v := range rows {
		var row replicaRow
		if json.Unmarshal([]byte(v), &row) != nil || row.VM != k.VM || row.Disk != k.Disk || !sameProject(row.Project, k.Project) {
			continue
		}
		found = true
		for n, f := range row.Files {
			if f.Copy {
				continue
			}
			if t, ok := replicaTimestamp(n); ok && t.After(newestStamp) {
				newestStamp = t
			}
			newestMtime = max(newestMtime, f.MtimeNs)
		}
	}
	fi, err := os.Lstat(path)
	if !found || err != nil || !ts.After(newestStamp) || fi.ModTime().UnixNano() <= newestMtime {
		return false
	}
	limit := last.Add(replicaStampSkew)
	return !fi.ModTime().After(limit) && !ts.After(limit)
}

// explicitReplicaOK reports whether a manual promotion may use the file at
// path, named by the operator, as k's disk: for an admin (storage.hostpath
// at the root) any regular file, as on main; otherwise a replica of it (isReplicaFor), a
// replicate-volume copy of it, an upload its project owns
// (uploadIsProjects), or a file from before records (or whose records are
// stale) named <vm>-<disk>-<anything>.<qcow2|raw> that no other project's VM
// and disk could have written. Never another project's upload.
func (s *Server) explicitReplicaOK(ctx context.Context, uploads poolRecords, path string, k replicaKey, admin bool) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	if s.isReplicaFor(ctx, uploads, path, k) {
		return true
	}
	if admin {
		// As on main, an admin's named replica is any file — another
		// project's included; doPromoteLocal warns of that
		// (anotherProjectsOwner).
		return true
	}
	u, st := s.recordState(uploads, path)
	switch {
	case st == recMatched && u.VM != "":
		// k's disk's copy; never another disk's replica or copy.
		return u.Copy && u.VM == k.VM && u.Disk == k.Disk && sameProject(u.Project, k.Project)
	case st == recMatched && !u.Peer:
		return s.uploadIsProjects(ctx, u, k)
	case st == recNone && !s.isLegacyUnrecorded(ctx, path):
		return false
	}
	name := filepath.Base(path)
	stem, ok := replicaStem(name)
	return ok && strings.HasPrefix(stem, k.VM+"-"+k.Disk+"-") &&
		!s.replicaNameClaimedElsewhere(ctx, name, k) && !s.usedByOtherProject(ctx, path, k)
}

// uploadIsProjects reports whether a user's upload is k's project's: made
// into a pool of that project, or into a global pool by a user who may create
// k's VM (and so could have promoted it themselves).
func (s *Server) uploadIsProjects(ctx context.Context, u poolUpload, k replicaKey) bool {
	if u.Project != "" {
		return sameProject(u.Project, k.Project)
	}
	name, realm, ok := strings.Cut(u.Uploader, "@")
	if !ok || name == "" {
		return false
	}
	user, err := corrosion.GetUser(ctx, s.db, name)
	if err != nil || user == nil {
		return false
	}
	vm, err := corrosion.GetVM(ctx, s.db, k.VM)
	if err != nil || vm == nil || !sameProject(vm.Project, k.Project) {
		return false
	}
	uctx := context.WithValue(context.WithValue(context.WithValue(context.Background(),
		ctxKeyUsername, user.Username), ctxKeyRole, user.Role), ctxKeyRealm, realm)
	return s.RequirePerm(uctx, vmRBACPath(vm), "vm.create", "operator") == nil
}

// namedReplicaPath is where a replica an operator names is in a pool whose
// directory is dir: the pool directory, or — for a pool on <data_dir>/disks,
// where users' uploads land in disks/uploads — there.
func (s *Server) namedReplicaPath(dir, named string) string {
	for _, d := range []string{dir, s.poolUploadDir(dir)} {
		if p := filepath.Join(d, named); lexists(p) {
			return p
		}
	}
	return filepath.Join(dir, named)
}

func lexists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// localReplicaNames lists the replicas of k's disk in dir, oldest first (by
// the run time in their names). With named, it is that one file when a manual
// promotion may use it (explicitReplicaOK), or none.
func (s *Server) localReplicaNames(ctx context.Context, dir string, k replicaKey, named string, admin bool) []string {
	uploads, err := s.loadPoolUploads(ctx, s.poolContentDirs(dir)...)
	if err != nil {
		return nil
	}
	if named != "" {
		if filepath.Base(named) != named || !s.explicitReplicaOK(ctx, uploads, s.namedReplicaPath(dir, named), k, admin) {
			return nil
		}
		return []string{named}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if s.isReplicaFor(ctx, uploads, filepath.Join(dir, e.Name()), k) {
			names = append(names, e.Name())
		}
	}
	sortReplicasOldestFirst(names)
	return names
}

// replicaNames lists the replicas of k's disk in pool on host, oldest first,
// WITHOUT the RBAC gate, so it is safe from unauthenticated internal contexts
// (scheduler, failover coordinator). Locally it reads the pool directory; on
// a peer it asks the pool's host as the daemon, for this VM's replicas only.
// named and admin are a manual promotion's named replica (localReplicaNames).
// Any error yields none.
func (s *Server) replicaNames(ctx context.Context, pool, host string, k replicaKey, named string, admin bool) []string {
	if host == "" || host == s.hostName {
		poolRef, ok := s.resolvePool(ctx, pool)
		if !ok {
			return nil
		}
		// A refused pool's directory is not listed, here or anywhere.
		if !s.poolUsableForWrite(ctx, pool, poolRef) {
			return nil
		}
		dir, err := fileBasedPoolDir(s.dataDir, poolRef)
		if err != nil {
			return nil
		}
		return s.localReplicaNames(ctx, dir, k, named, admin)
	}
	client, closeFn, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil
	}
	defer closeFn()
	return s.remoteReplicaNames(ctx, client, pool, host, k, named, admin)
}

// remoteReplicaNames asks a peer for the replicas of k's disk in its pool (or
// whether a manual promotion may use the named one). A host that matched them
// by record says so (replicaListingMDKey). An older host's listing is every
// file, none recorded, and is matched here by name.
func (s *Server) remoteReplicaNames(ctx context.Context, client pb.LiteVirtClient, pool, host string, k replicaKey, named string, admin bool) []string {
	var hdr metadata.MD
	resp, err := client.ListStoragePoolContents(withReplicaContentView(ctx, k, named, admin),
		&pb.ListStoragePoolContentsRequest{PoolName: pool, Host: host}, grpc.Header(&hdr))
	if err != nil {
		return nil
	}
	matched := len(hdr.Get(replicaListingMDKey)) > 0
	var names []string
	for _, c := range resp.GetContents() {
		n := c.GetName()
		ok := matched
		switch {
		case ok:
		case named != "":
			stem, isImg := replicaStem(n)
			ok = n == named && (admin || isImg && strings.HasPrefix(stem, k.VM+"-"+k.Disk+"-") && !s.replicaNameClaimedElsewhere(ctx, n, k))
		default:
			ok = replicaNameIs(n, k) && !s.replicaNameClaimedElsewhere(ctx, n, k)
		}
		if ok && (named == "" || n == named) {
			names = append(names, n)
		}
	}
	sortReplicasOldestFirst(names)
	return names
}

// replicaReadable reports why the replica at path cannot be promoted: it is
// gone, not a regular file (a symlink is never followed), empty, or cannot be
// read. A replica is published only once written and non-empty, so any of
// these means it was lost or damaged afterwards.
func replicaReadable(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if fi.Size() == 0 {
		return fmt.Errorf("%s is empty", filepath.Base(path))
	}
	f, err := storage.OpenPoolFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.ReadAt(make([]byte, 1), 0); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// errReplicaUnavailable prefixes the refusal of a chosen replica that is
// missing or unreadable on its host; promotion then tries the next-older one.
const errReplicaUnavailable = "replica unavailable"

// replicaUnavailable reports whether err refused a promotion only because the
// chosen replica is not there to use: this build's refusal, or an older
// host's ("not present on", or its listing not holding it).
func replicaUnavailable(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		return false
	}
	m := st.Message()
	return strings.Contains(m, errReplicaUnavailable) || strings.Contains(m, "not present on") ||
		(strings.HasPrefix(m, "replica ") && strings.Contains(m, "not found in pool"))
}

// anotherProjectsOwner reports whether the file at path is another
// project's and never k's, and names that project: another project's upload
// or replica by record, a disk of another project's VM, or a file named
// exactly as only another project's VM disk's replication names its replicas
// (<vm>-<disk>-<stamp>, a VM and disk of another project) where k's disk's
// never is. An admin may still promote such a file by naming it; it is
// warned of, never refused.
func (s *Server) anotherProjectsOwner(ctx context.Context, uploads poolRecords, path string, k replicaKey) (string, bool) {
	if u, st := s.recordState(uploads, path); st == recMatched && !u.Peer {
		switch {
		case u.VM != "" && !sameProject(u.Project, k.Project):
			return displayProject(u.Project), true
		case u.VM == "" && u.Project != "" && !sameProject(u.Project, k.Project):
			return displayProject(u.Project), true
		}
	}
	refs, _ := corrosion.DisksReferencingPath(ctx, s.db, path)
	kept, _ := corrosion.TombstonedDisksReferencingPath(ctx, s.db, path)
	for _, d := range append(refs, kept...) {
		if vm, err := corrosion.GetVMIncludingDeleted(ctx, s.db, d.VMName); err == nil && vm != nil && !sameProject(vm.Project, k.Project) {
			return displayProject(vm.Project), true
		}
	}
	p, ok := replicaNamePrefix(filepath.Base(path))
	if !ok || p == k.VM+"-"+k.Disk {
		return "", false
	}
	for i := 1; i < len(p)-1; i++ {
		if p[i] != '-' {
			continue
		}
		disks, _ := s.otherProjectDisks(ctx, p[:i], k)
		if disks[p[i+1:]] {
			if vm, err := corrosion.GetVMIncludingDeleted(ctx, s.db, p[:i]); err == nil && vm != nil {
				return displayProject(vm.Project), true
			}
			return "another project", true
		}
	}
	return "", false
}
