package grpcapi

import (
	"context"
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
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Which files are a VM's replicas.
//
// Promotion boots a replica and replication's pruning deletes old ones, so
// both must take only the files that are this VM's: never by a name prefix,
// which another project's VM can share ("bvm" + "root-20261006" and
// "bvm-root" + "20261006" both write "bvm-root-20261006-…"). A replica the
// daemon places is recorded on the pool's host (recordPoolReplica) with the
// VM, disk and project it is of, and that record decides. A file with no
// record — a replica made before this build, or on a host that predates
// records — is the VM's only when its name is exactly
// <vm>-<disk>-<YYYYMMDD-HHMMSS>.<qcow2|raw> and no VM of another project could
// have written the same name.

// replicaKey names one VM's disk, in its project, whose replicas a call is
// about.
type replicaKey struct {
	VM, Disk, Project string
}

func replicaKeyOf(vm *corrosion.VMRecord, disk string) replicaKey {
	return replicaKey{VM: vm.Name, Disk: disk, Project: tenancy.NormalizeProject(vm.Project)}
}

// sameProject compares projects as stored ("" is the default project).
func sameProject(a, b string) bool {
	return tenancy.NormalizeProject(a) == tenancy.NormalizeProject(b)
}

// replicaStampLayout is the run time the replication runner writes into a
// replica's name.
const replicaStampLayout = "20060102-150405"

// replicaNamePrefix parses name as the replication runner writes it,
// <prefix>-<YYYYMMDD-HHMMSS>.<qcow2|raw>, from the right, and returns
// <prefix> ("<vm>-<disk>").
func replicaNamePrefix(name string) (string, bool) {
	base, ok := strings.CutSuffix(name, ".qcow2")
	if !ok {
		if base, ok = strings.CutSuffix(name, ".raw"); !ok {
			return "", false
		}
	}
	n := len(base) - len(replicaStampLayout)
	if n < 4 || base[n-1] != '-' {
		return "", false
	}
	if _, err := time.Parse(replicaStampLayout, base[n:]); err != nil {
		return "", false
	}
	return base[:n-1], true
}

// replicaNameIs reports whether name is exactly a replica name of k's disk.
func replicaNameIs(name string, k replicaKey) bool {
	p, ok := replicaNamePrefix(name)
	return ok && p == k.VM+"-"+k.Disk
}

// replicaNameClaimedElsewhere reports whether a VM of another project than
// k's could have written replica name: some other split of its prefix names a
// VM (live or deleted) outside k's project. A lookup error claims it.
func (s *Server) replicaNameClaimedElsewhere(ctx context.Context, name string, k replicaKey) bool {
	prefix, ok := replicaNamePrefix(name)
	if !ok {
		return true
	}
	for i := 1; i < len(prefix)-1; i++ {
		if prefix[i] != '-' || prefix[:i] == k.VM {
			continue
		}
		vm, err := corrosion.GetVMIncludingDeleted(ctx, s.db, prefix[:i])
		if err != nil {
			return true
		}
		if vm != nil && !sameProject(vm.Project, k.Project) {
			return true
		}
	}
	return false
}

// isReplicaFor reports whether the file at path is a replica of k's disk: by
// its record when it has one, and otherwise by its exact name, provided no VM
// of another project could own that name and no disk row of another
// project's VM uses the file.
func (s *Server) isReplicaFor(ctx context.Context, uploads map[string]poolUpload, path string, k replicaKey) bool {
	if u, ok := s.poolUploadOf(uploads, path); ok {
		return u.VM == k.VM && u.Disk == k.Disk && sameProject(u.Project, k.Project)
	}
	if !replicaNameIs(filepath.Base(path), k) || s.replicaNameClaimedElsewhere(ctx, filepath.Base(path), k) {
		return false
	}
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return false
	}
	kept, err := corrosion.TombstonedDisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return false
	}
	for _, d := range append(refs, kept...) {
		vm, err := corrosion.GetVMIncludingDeleted(ctx, s.db, d.VMName)
		if err != nil || (vm != nil && !sameProject(vm.Project, k.Project)) {
			return false
		}
	}
	return true
}

// localReplicaNames lists the replicas of k's disk in dir, oldest first (the
// stamp sorts lexically).
func (s *Server) localReplicaNames(ctx context.Context, dir string, k replicaKey) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	uploads, err := s.loadPoolUploads()
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
	sort.Strings(names)
	return names
}

// replicaNames lists the replicas of k's disk in pool on host, oldest first,
// WITHOUT the RBAC gate, so it is safe from unauthenticated internal contexts
// (scheduler, failover coordinator). Locally it reads the pool directory; on
// a peer it asks the pool's host as the daemon, for this VM's replicas only.
// Any error yields none.
func (s *Server) replicaNames(ctx context.Context, pool, host string, k replicaKey) []string {
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
		return s.localReplicaNames(ctx, dir, k)
	}
	client, closeFn, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil
	}
	defer closeFn()
	return s.remoteReplicaNames(ctx, client, pool, host, k)
}

// remoteReplicaNames asks a peer for the replicas of k's disk in its pool. A
// host that matched them by record says so (replicaListingMDKey). An older
// host's listing is every file, none recorded, and is matched here by exact
// name.
func (s *Server) remoteReplicaNames(ctx context.Context, client pb.LiteVirtClient, pool, host string, k replicaKey) []string {
	var hdr metadata.MD
	resp, err := client.ListStoragePoolContents(withReplicaContentView(ctx, k),
		&pb.ListStoragePoolContentsRequest{PoolName: pool, Host: host}, grpc.Header(&hdr))
	if err != nil {
		return nil
	}
	matched := len(hdr.Get(replicaListingMDKey)) > 0
	var names []string
	for _, c := range resp.GetContents() {
		n := c.GetName()
		if matched || (replicaNameIs(n, k) && !s.replicaNameClaimedElsewhere(ctx, n, k)) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
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
	f, err := os.Open(path)
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
