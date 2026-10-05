package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A deleted VM's leftovers on the hosts it LEFT.
//
// DeleteVM runs on the VM's owner and frees what is there. Two things a VM
// leaves on a host it migrated away from were freed nowhere:
//
//   - a disk DETACHED while the VM ran on that host. Detach keeps the file by
//     design (executeDiskDetach: storage is preserved) and soft-deletes the row;
//     a migration repoints only live rows, so the file stays on the old host
//     and the delete on the new owner never sees it.
//   - the owner-epoch marker, <dataDir>/vms/<name>/owner_epoch. A migration
//     deliberately leaves the source's marker (cleanupPostMigration), and only
//     the owner's copy went with the delete.
//
// So after the tombstone the owner asks every other active host to remove
// them, through CleanupMigrationArtifacts with vm_deleted set. The owner sends
// only what its rows prove: a detached row naming that host, written by THIS
// incarnation. The receiving host decides by its OWN replica and keeps
// anything it cannot prove unused (removeDeletedVMLeftoversHere).

// deletedVMLeftovers is what a delete asks the hosts the VM left to remove.
type deletedVMLeftovers struct {
	vm string
	// hosts are the other active workload hosts — the ones that may hold the
	// marker. Every one is asked; the marker is name-keyed and inert once the
	// row is gone, which is exactly what the receiving host checks.
	hosts []string
	// detached maps a host to the detached disk files the VM left on it.
	detached map[string][]string
}

// deletedVMCleanupAttempts / deletedVMCleanupBackoff bound the retry while a
// receiving host's replica has not yet seen the tombstone (it answers ABORTED).
// Variables so a test can shorten them.
var (
	deletedVMCleanupAttempts = 6
	deletedVMCleanupBackoff  = 500 * time.Millisecond
	deletedVMCleanupTimeout  = 30 * time.Second
)

// departedDetachedDisks picks, from a live VM's soft-deleted disk rows, the
// detached files it left on OTHER hosts, keyed by host. A row qualifies only
// when every one of these holds — anything else is kept:
//
//   - it names a host other than self (self's files are the local delete's);
//   - it is a host-local file (local/dir): a shared-pool path is the same file
//     everywhere and may be some other host's live disk;
//   - delete_with_vm is set: an adopted or foreign disk is never freed by a
//     VM delete;
//   - it was soft-deleted STRICTLY AFTER this incarnation was created
//     (detachedAfterCreate). A row left by a PREVIOUS VM of the same name —
//     one deleted with --keep-disks, whose files were kept on purpose — can
//     still be here: InsertVMWithHardware purges a name's tombstoned rows,
//     but BeginVMCreateOperation instead re-stamps them with deleted_at set to
//     the new VM's created_at, to the nanosecond. Equal is therefore the
//     predecessor's signature and is kept.
func departedDetachedDisks(self, createdAt string, rows []corrosion.SoftDeletedDisk) map[string][]string {
	out := map[string][]string{}
	for _, r := range rows {
		if r.HostName == "" || r.HostName == self || r.Path == "" {
			continue
		}
		if !isHostLocalDiskDriver(r.StorageType) || !r.DeleteWithVM {
			continue
		}
		if !detachedAfterCreate(r.DeletedAt, createdAt) {
			continue
		}
		out[r.HostName] = append(out[r.HostName], r.Path)
	}
	return out
}

// detachedAfterCreate reports whether a soft-delete stamp is strictly after an
// incarnation's created_at, both compared untruncated. deleted_at from a
// detach has second precision, so a detach in the create's own second reads
// as no later than it and the file is kept; so is anything unparseable.
func detachedAfterCreate(deletedAt, createdAt string) bool {
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return false
	}
	deleted, err := time.Parse(time.RFC3339Nano, deletedAt)
	if err != nil {
		return false
	}
	return deleted.After(created)
}

// planDeletedVMLeftovers reads, BEFORE the tombstone, what the delete will ask
// the hosts the VM left to remove. It has to run first: the tombstone
// re-stamps every disk row of the VM, after which a detached row and a row that
// was live a moment ago look the same.
//
// withDisks is false for a --keep-disks delete: the markers are still planned,
// the detached disks are not.
//
// Best-effort: a read that fails plans nothing for that part, which leaves the
// files where they are.
func (s *Server) planDeletedVMLeftovers(ctx context.Context, vm *corrosion.VMRecord, withDisks bool) deletedVMLeftovers {
	plan := deletedVMLeftovers{vm: vm.Name}
	if withDisks {
		rows, err := corrosion.GetSoftDeletedVMDisks(ctx, s.db, vm.Name)
		if err != nil {
			slog.Warn("delete: cannot read detached disks; any left on other hosts are kept",
				"vm", vm.Name, "error", err)
		} else {
			plan.detached = departedDetachedDisks(s.hostName, vm.CreatedAt, rows)
		}
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		slog.Warn("delete: cannot list hosts; the VM's leftovers on other hosts are kept",
			"vm", vm.Name, "error", err)
		plan.detached = nil
		return plan
	}
	active := map[string]bool{}
	for _, h := range hosts {
		if h.Name == s.hostName || h.State != "active" || h.IsWitness() {
			continue
		}
		active[h.Name] = true
		plan.hosts = append(plan.hosts, h.Name)
	}
	for h, paths := range plan.detached {
		if !active[h] {
			slog.Warn("delete: detached disks are left on a host that is not active",
				"vm", vm.Name, "host", h, "paths", paths)
		}
	}
	sort.Strings(plan.hosts)
	return plan
}

// cleanupDeletedVMLeftovers asks each host in the plan to remove the VM's
// leftovers. It runs after the tombstone, on a context detached from the
// caller's (a peer call, so the receiving host authorises it as the system),
// and never fails the delete: the VM is gone, and a host that is unreachable or
// declines keeps its files, which is the safe direction.
func (s *Server) cleanupDeletedVMLeftovers(ctx context.Context, plan deletedVMLeftovers) {
	for _, host := range plan.hosts {
		s.cleanupDeletedVMLeftoversOn(ctx, host, plan.vm, plan.detached[host])
	}
}

func (s *Server) cleanupDeletedVMLeftoversOn(ctx context.Context, host, vmName string, paths []string) {
	req := &pb.CleanupMigrationArtifactsRequest{VmName: vmName, DiskPaths: paths, VmDeleted: true}
	for attempt := 0; attempt < deletedVMCleanupAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(deletedVMCleanupBackoff << (attempt - 1))
		}
		cctx, cancel := notifyDetachedContext(ctx, deletedVMCleanupTimeout)
		client, closeConn, err := s.dialPeer(cctx, host)
		if err != nil {
			cancel()
			slog.Warn("delete: cannot reach a host the VM may have left; its leftovers there are kept",
				"vm", vmName, "host", host, "error", err)
			return
		}
		_, err = client.CleanupMigrationArtifacts(cctx, req)
		closeConn()
		cancel()
		switch status.Code(err) {
		case codes.OK:
			return
		case codes.Aborted:
			// That host's replica has not seen the tombstone yet.
			continue
		default:
			slog.Warn("delete: a host the VM may have left declined to remove its leftovers",
				"vm", vmName, "host", host, "paths", paths, "error", err)
			return
		}
	}
	slog.Warn("delete: a host still holds a live record of the deleted VM; its leftovers there are kept",
		"vm", vmName, "host", host, "paths", paths)
}

// removeDeletedVMLeftoversHere is the receiving side: remove a deleted VM's
// owner-epoch marker and the detached disks the deleting host named — judged
// entirely by this host's own replica and runtime, never by the request.
//
// Nothing is removed while:
//
//   - this host's replica holds a LIVE row for the name. Either the tombstone
//     has not arrived (ABORTED; the caller retries) or the name has been taken
//     again. A marker is a fence only while a row exists: removing one under a
//     live row turns a refused self-heal restart into a permitted one
//     (runtimeSuperseded reads an absent marker as "not superseded").
//   - a domain of that name is defined here. Whatever it is, its marker and its
//     disks are not a deleted VM's leftovers.
//
// and a disk path is removed only when, in addition:
//
//   - it lies in a disk-artifact root on this host;
//   - this host's replica has a soft-deleted row of THIS VM naming THIS host at
//     exactly that path, host-local and delete_with_vm — the deleting host's
//     list is a request, not evidence;
//   - it is THIS incarnation's, by this host's own replica: the tombstoned
//     row's created_at is readable, the disk row's deleted_at is strictly
//     after it, and so is the file's modification time. The row check alone
//     cannot see a predecessor once the tombstone has re-stamped every disk
//     row of the name; the file can — what a --keep-disks predecessor kept was
//     last written before this VM existed, while a disk attached to this VM
//     was made, and written, after. This holds however the request arrives,
//     an admin calling CleanupMigrationArtifacts directly included;
//   - the VM has no live snapshot row (its snapshot chain may run through it);
//   - no live disk row of any VM uses it as its file, backing image or
//     linked-clone base;
//   - no domain defined on this host uses it as a disk or anywhere in that
//     disk's qcow2 backing chain.
//
// An unreadable answer to any of these keeps the file.
func (s *Server) removeDeletedVMLeftoversHere(ctx context.Context, req *pb.CleanupMigrationArtifactsRequest, vm *corrosion.VMRecord) (*emptypb.Empty, error) {
	name := req.VmName
	// The lock serializes with this host's other lockVM holders (delete,
	// hotplug, migration out). It does NOT hold off a create of the same name —
	// createVM does not take it — or a migration in (EnsureDisks does not
	// either). Those are refused by the live-row and domain checks below, read
	// as late as possible; a create that lands between those reads and the
	// removals is the residual window, and it needs a row first, which is what
	// both checks see.
	unlock := s.lockVM(name)
	defer unlock()
	if cur, err := corrosion.GetVM(ctx, s.db, name); err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the record of %q: %v", name, err)
	} else if cur != nil {
		vm = cur
	}
	if vm != nil {
		return nil, status.Errorf(codes.Aborted,
			"VM %q still has a live record on %s; its leftovers here are kept until the delete reaches it", name, s.hostName)
	}
	if s.virt != nil && s.virt.DomainExists(name) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"a domain named %q is defined on %s; nothing of it is removed", name, s.hostName)
	}

	if err := health.RemoveVMOwnerEpochMarker(s.dataDir, name); err != nil {
		slog.Warn("deleted VM leftovers: owner-epoch marker not removed", "vm", name, "error", err)
	}

	if len(req.DiskPaths) == 0 {
		return &emptypb.Empty{}, nil
	}
	rows, err := corrosion.GetSoftDeletedVMDisks(ctx, s.db, name)
	if err != nil {
		slog.Warn("deleted VM leftovers: cannot read the VM's disk rows; keeping its detached disks",
			"vm", name, "error", err)
		return &emptypb.Empty{}, nil
	}
	if snaps, serr := corrosion.ListSnapshots(ctx, s.db, name); serr != nil || len(snaps) > 0 {
		slog.Warn("deleted VM leftovers: the VM still has snapshot records (or they are unreadable); keeping its detached disks",
			"vm", name, "snapshots", len(snaps), "error", serr)
		return &emptypb.Empty{}, nil
	}
	createdAt, cerr := corrosion.GetTombstonedVMCreatedAt(ctx, s.db, name)
	if cerr != nil || createdAt == "" {
		slog.Warn("deleted VM leftovers: cannot tell which incarnation was deleted; keeping its detached disks",
			"vm", name, "error", cerr)
		return &emptypb.Empty{}, nil
	}
	created, _ := time.Parse(time.RFC3339Nano, createdAt)
	recorded := map[string]bool{}
	for _, r := range rows {
		if r.HostName == s.hostName && isHostLocalDiskDriver(r.StorageType) && r.DeleteWithVM && r.Path != "" &&
			detachedAfterCreate(r.DeletedAt, createdAt) {
			recorded[r.Path] = true
		}
	}
	for _, p := range req.DiskPaths {
		if p == "" {
			continue
		}
		keep := func(why string) {
			slog.Warn("deleted VM leftovers: keeping a detached disk", "vm", name, "path", p, "reason", why)
		}
		switch {
		case !s.withinDiskArtifactRoot(p):
			keep("outside a disk-artifact root")
		case !recorded[p]:
			keep("this host's replica does not record it as a disk detached from this incarnation here")
		case !modifiedAfter(p, created):
			keep("the file was last written before this incarnation was created (or cannot be read)")
		default:
			// Exempting no VM: this one has no live rows left to exempt.
			if referenced, why, _ := s.pathStillReferenced(ctx, p, "", ""); referenced {
				keep("still referenced by " + why)
				continue
			}
			if used, why := s.localDomainUsesPath(p); used {
				keep(why)
				continue
			}
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				slog.Warn("deleted VM leftovers: remove detached disk", "vm", name, "path", p, "error", err)
				continue
			}
			slog.Info("deleted VM leftovers: removed a disk detached from the VM on this host", "vm", name, "path", p)
		}
	}
	return &emptypb.Empty{}, nil
}

// localDomainUsesPath reports whether any domain defined on this host uses p
// as a disk source or anywhere in a disk's qcow2 backing chain. A listing or
// source read that fails answers yes. A chain link that cannot be read as
// qcow2 (a raw image, a missing file) ends that chain: it has no further
// backing to follow.
func (s *Server) localDomainUsesPath(p string) (bool, string) {
	if s.virt == nil {
		return false, ""
	}
	names, err := s.virt.ListDomains()
	if err != nil {
		return true, "cannot list this host's domains: " + err.Error()
	}
	for _, d := range names {
		srcs, serr := s.virt.DomainDiskSources(d)
		if serr != nil {
			return true, "cannot read the disks of domain " + d + ": " + serr.Error()
		}
		for _, src := range srcs {
			cur := src
			for depth := 0; cur != "" && depth < 32; depth++ {
				if filepath.Clean(cur) == filepath.Clean(p) {
					return true, "domain " + d + " uses it"
				}
				info, ierr := qcow2.Info(cur)
				if ierr != nil || info.BackingFile == "" {
					break
				}
				next := info.BackingFile
				if !filepath.IsAbs(next) {
					next = filepath.Join(filepath.Dir(cur), next)
				}
				cur = next
			}
		}
	}
	return false, ""
}

// modifiedAfter reports whether p's modification time is strictly after t.
// An unreadable file answers no.
func modifiedAfter(p string, t time.Time) bool {
	fi, err := os.Stat(p)
	return err == nil && !t.IsZero() && fi.ModTime().After(t)
}
