package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/notify"
)

// Replica sets (colonelpanik/litevirt#258).
//
// Replication used to copy one disk of a VM, its root, and promotion built a
// one-disk VM from it with a note that N data disks were "not recovered": a
// guest booted against a root disk whose data volumes were silently absent.
//
// Now a run replicates every disk of the VM with one run time, so the replicas
// of one run are a set: each disk keeps its own replica and record, in the
// format it always had (replica_records.go), and a run's set is the records
// that carry its time. The root disk goes first and exactly as before — its
// incremental chain and its fallback — then each other disk as a full point-in-time copy (copyVMDiskConsistent).
//
// A promotion, manual or automatic, recovers every disk that has a replica:
// the replica of the root's run, or, for a disk that run did not copy, its
// newest replica from before it. It never refuses for a disk it cannot
// recover — main promoted the root alone, and automatic recovery still does
// at least that, retrying with the root alone when the domain fails with the
// other disks. A promotion whose set is incomplete marks the VM partial:
// `lv inspect` shows promoted_partial, and a vm.promoted_partial event and a
// replication.promoted_partial notification name each missing disk and where
// its real data is. The vm.promoted event lists the whole set, disk by disk:
// the recovery manifest.
//
// A disk on shared storage (nfs, ceph, rbd, iscsi, a shared pool) is never
// copied and never rebuilt from a replica: it is reachable from another host
// as it is, and a takeover promotion reattaches it as-is, its row untouched.
// Not copied either: a host-local disk that is not file-based (zfs, lvm),
// reported as skipped on every run, and a cdrom.
//
// The VM lock is held for the root's run as before, and for each other disk
// only during its point-in-time step (otherDiskCopy). The partial marker is
// a durable health condition (replica_set / vm.promoted_partial).

// replicaSetOthers is every disk of the VM besides src that a replication run
// replicates and a promotion recovers: not a cdrom. In a fixed order, so a
// run's events and a promotion's manifest read the same every time.
func replicaSetOthers(disks []corrosion.DiskRecord, src *corrosion.DiskRecord) []corrosion.DiskRecord {
	var out []corrosion.DiskRecord
	for _, d := range disks {
		if src != nil && d.DiskName == src.DiskName {
			continue
		}
		if d.DeviceKind == "cdrom" {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetDev != out[j].TargetDev {
			return out[i].TargetDev < out[j].TargetDev
		}
		return out[i].DiskName < out[j].DiskName
	})
	return out
}

// diskOnSharedStorage reports whether d lives on cluster-shared storage: its
// storage type says so (corrosion.DiskIsShared: nfs, ceph, rbd, iscsi), or the
// pool it names is one with a shared driver. Such a disk is reachable from
// another host as it is, so it is never copied into a replica and never
// rebuilt from one: a promotion reattaches it as-is (plan §5.1 "reattach").
func (s *Server) diskOnSharedStorage(ctx context.Context, d corrosion.DiskRecord) bool {
	if corrosion.DiskOnSharedStorage(ctx, s.db, d, s.hostName) {
		return true
	}
	// This host's pool configuration, which may not be a row yet.
	if d.StorageVolume != "" {
		if ref, ok := s.resolvePool(ctx, d.StorageVolume); ok && isSharedDriver(ref.Driver) {
			return true
		}
	}
	return false
}

// vmHasSharedDisk is diskOnSharedStorage over a VM's disks: the one test the
// executor's shared-disk fence gate and the promotion's reattach agree on.
func (s *Server) vmHasSharedDisk(ctx context.Context, disks []corrosion.DiskRecord) bool {
	for _, d := range disks {
		if s.diskOnSharedStorage(ctx, d) {
			return true
		}
	}
	return false
}

// refuseRebuildOverPromotedDisks refuses a same-name promotion of vm, already
// this host's, while any of its disk rows here names a live disk an earlier
// promotion built (`<vm>-promoted-<run>…`) that is still there. The promoted
// VM has run from those disks, so they hold writes no replica on this host
// has — the replicas here are of the host the VM left — and rebuilding them
// from replica would discard those writes, as re-running a promotion over a
// partial one with --force used to. A shared disk is never rebuilt, so its
// row is not looked at. A file that cannot be examined refuses too: it may be
// one. The remedy keeps both: a promotion under another name.
func (s *Server) refuseRebuildOverPromotedDisks(ctx context.Context, vm *corrosion.VMRecord, replica string) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable, "list the disks of %s: %v", vm.Name, err)
	}
	var promoted []string
	for _, d := range disks {
		if d.HostName != s.hostName || d.Path == "" ||
			!strings.HasPrefix(filepath.Base(d.Path), vm.Name+"-promoted-") || s.diskOnSharedStorage(ctx, d) {
			continue
		}
		_, err := os.Lstat(d.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue // nothing there to lose
		case err != nil:
			return status.Errorf(codes.Unavailable, "examine %s's live disk %s at %s: %v", vm.Name, d.DiskName, d.Path, err)
		}
		promoted = append(promoted, fmt.Sprintf("%s at %s", d.DiskName, d.Path))
	}
	if len(promoted) == 0 {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"vm %q already runs on %s from live disks an earlier promotion built (%s), and holds what it has written to them "+
			"since; no replica on %s has those writes, so rebuilding them from replica %s would discard them, and a "+
			"promotion over it is refused, --force or not. To keep both, promote the replica under another name: "+
			"`lv replication promote %s --replica %s --new-name <name>`",
		vm.Name, s.hostName, strings.Join(promoted, ", "), s.hostName, replica, vm.Name, replica)
}

// sharedDiskOwners are the hosts a shared disk is judged by (review R3-I1):
// the host its own row names AND the VM's owner, each unless it is this host.
// After a partial promotion the VM is this host's while the disk's row still
// names the old owner, so the VM's owner alone says nothing; and a row left
// naming a host the VM has since left (a migration whose ownership commit
// declined) leaves the VM's owner as the host that may be writing it. Every
// host returned must pass the verdict. The disk's row naming this host, with
// the VM's owner this host or none, returns none: the same-host rebuild. ok
// is false when there is no one to judge it by — its row names no host and
// the VM is already this host's (or no one's) — and the verdict refuses.
func sharedDiskOwners(diskHost, vmHost, self string) (owners []string, ok bool) {
	if diskHost == "" && (vmHost == "" || vmHost == self) {
		return nil, false
	}
	for _, h := range []string{diskHost, vmHost} {
		if h != "" && h != self && !slices.Contains(owners, h) {
			owners = append(owners, h)
		}
	}
	return owners, true
}

// sharedReattachVerdict decides whether a promotion may reattach a disk on
// shared storage as-is, where main attached nothing — so every doubt leaves
// it unattached (main's outcome), never refuses the promotion. It judges one
// owner: each of sharedDiskOwners in turn (the disk's own row's host and the
// VM's, review R3-I1), self when there is none, "" when there is no one to
// judge by:
//
//   - a renamed promotion never: the original VM owns the disk;
//   - fenceProven — THIS executor verified a proof-grade fence of the VM's
//     old owner fencedHost for this promotion (a carried proof, the
//     shared-storage fence enforced, requireProofGradeFence passed) —
//     reattaches a disk that host, or this one, owns; it proves nothing
//     about any other host;
//   - an automated promotion (the coordinator's, in-process or relayed with
//     the automated mark) without that never: its old owner may have been
//     fenced best-effort only, and may still be writing the disk;
//   - every other promotion — an operator's, through any node or local-root
//     lv, or an older coordinator's relay that carries neither a proof nor
//     the mark — gets the manual rule: only when the disk's row names this
//     host, or its owner is fenced, removed or no longer a member AND proven
//     off (ownerProvedOff: the newest fence on record for it is
//     proof-grade, an IPMI power-off or `lv host fence-confirm` —
//     corrosion.FenceRecordProvesOff; for a host no longer a member, the
//     newest of its LAST life, corrosion.RemovedHostProvedOff, review
//     R4-I1). A `fenced` state over an SSH,
//     watchdog or best-effort fence, or none, proves nothing, and neither
//     does a removal (review R3-I2): `lv host rm --force` asks for no fence,
//     and a host whose daemon died may still be running its qemu. --force
//     never bypasses it;
//   - an owner whose host row or fence record cannot be read, or a disk with
//     no owner to judge: never (fail closed).
func sharedReattachVerdict(renamed, automated, fenceProven bool, fencedHost, owner, self string, ownerHost *corrosion.HostRecord, ownerProvedOff bool, ownerErr error) (bool, string) {
	switch {
	case renamed:
		return false, "renamed"
	case fenceProven && owner != "" && (owner == fencedHost || owner == self):
		return true, ""
	case automated:
		return false, fmt.Sprintf("no proof-grade fence of %s was verified by this host for this promotion", owner)
	case owner == "":
		return false, "its row names no host, so who may still be writing it cannot be judged"
	case owner == self:
		return true, ""
	default:
		return corrosion.SharedDiskOwnerVerdict(owner, ownerHost, ownerProvedOff, ownerErr)
	}
}

// sharedDiskStatTimeout bounds the look at a shared disk's path: a hard NFS
// mount whose server is gone blocks a stat forever, and main never looked.
var sharedDiskStatTimeout = 5 * time.Second

// statShared is os.Stat; a var so a test can make it block.
var statShared = os.Stat

// statWithin stats path, giving up after timeout (review N2). The stat left
// running when it times out is abandoned; it ends when the mount answers.
func statWithin(path string, timeout time.Duration) error {
	_, err := statInfoWithin(path, timeout)
	return err
}

// statInfoWithin is statWithin with what the stat found.
func statInfoWithin(path string, timeout time.Duration) (os.FileInfo, error) {
	type res struct {
		fi  os.FileInfo
		err error
	}
	done := make(chan res, 1)
	stat := statShared // read here, not in the goroutine that may outlive the call
	go func() {
		fi, err := stat(path)
		done <- res{fi, err}
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-done:
		return r.fi, r.err
	case <-t.C:
		return nil, fmt.Errorf("not reachable (timed out after %s)", timeout)
	}
}

// replicateOtherDisks replicates each of disks with the root's run time ts,
// after the root succeeded. Every disk is tried; the run fails if any copy
// did, so the schedule reports an incomplete set rather than a success. A disk
// on shared storage, or on storage replication cannot copy, is skipped with
// an event, every run, and does not fail it: main never copied it either.
//
// The VM's lock is not held here: it is taken only for each disk's brief
// point-in-time step (otherDiskCopy), never for the bulk copy, so a VM's stop,
// migrate or hotplug never waits behind a data disk's copy. relock takes it.
func (s *Server) replicateOtherDisks(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, disks []corrosion.DiskRecord, targetHost, ts string, allowForceShare bool, relock func() func()) error {
	if len(disks) == 0 {
		return nil
	}
	ctx = withOtherDiskLock(ctx, relock)
	var copyable []corrosion.DiskRecord
	for _, d := range disks {
		switch {
		case s.diskOnSharedStorage(ctx, d):
			s.recordVMEvent(ctx, vm.Name, "disk.replicated", "skipped", fmt.Sprintf(
				"%s: not replicated; it is on shared storage (%s), reachable from another host as it is, so a promotion reattaches it as-is",
				d.DiskName, d.StorageType))
		case !isFileBasedDriver(d.StorageType):
			s.recordVMEvent(ctx, vm.Name, "disk.replicated", "skipped", fmt.Sprintf(
				"%s: not replicated; its storage (%s) is not file-based, so a promotion cannot recover it from a replica",
				d.DiskName, d.StorageType))
		default:
			copyable = append(copyable, d)
		}
	}
	if len(copyable) == 0 {
		return nil
	}
	var errs []error
	for i := range copyable {
		d := &copyable[i]
		var err error
		if targetHost == s.hostName {
			err = s.replicateLocal(ctx, sched, vm, d, ts, allowForceShare)
		} else {
			err = s.replicateCrossHost(ctx, sched, vm, d, targetHost, ts, allowForceShare)
		}
		if err != nil {
			slog.Warn("replication: a disk of the set was not replicated; the set of this run is incomplete",
				"vm", vm.Name, "disk", d.DiskName, "error", err)
			errs = append(errs, err)
			if errors.Is(err, errVMNoLongerHere) {
				break // the rest would be copies of a VM this host no longer runs
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("replica set of %s at %s is incomplete: %w", vm.Name, ts, errors.Join(errs...))
	}
	return nil
}

// otherDiskLockKey carries the VM lock's taker into another disk's copy.
type otherDiskLockKey struct{}

func withOtherDiskLock(ctx context.Context, relock func() func()) context.Context {
	if relock == nil {
		return ctx
	}
	return context.WithValue(ctx, otherDiskLockKey{}, relock)
}

func otherDiskLockFrom(ctx context.Context) func() func() {
	f, _ := ctx.Value(otherDiskLockKey{}).(func() func())
	return f
}

// heldLock is the VM lock, taken and dropped around each step that needs it.
type heldLock struct {
	take    func() func()
	release func()
}

func (h *heldLock) acquire() {
	if h.release == nil {
		h.release = h.take()
	}
}

func (h *heldLock) drop() {
	if h.release != nil {
		h.release()
		h.release = nil
	}
}

// afterPITPointKey carries a callback a backup session calls once its point
// in time is fixed (BeginBackup returned), so another disk's copy drops the
// VM lock before reading the export.
type afterPITPointKey struct{}

func afterPITPoint(ctx context.Context) {
	if f, ok := ctx.Value(afterPITPointKey{}).(func()); ok {
		f()
	}
}

// diskFileIdentity is what changes when a closed disk file is written or
// replaced while it is copied without the VM lock.
type diskFileIdentity struct {
	size  int64
	mtime time.Time
	ino   uint64
}

func identityOf(path string) (diskFileIdentity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return diskFileIdentity{}, err
	}
	id := diskFileIdentity{size: fi.Size(), mtime: fi.ModTime()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		id.ino = uint64(st.Ino)
	}
	return id, nil
}

// errOtherDiskChanged refuses a copy of a shut-off disk that was written,
// replaced, or opened by a started VM while it was copied without the lock.
var errOtherDiskChanged = errors.New("the disk changed or its VM started while it was copied; the copy is not point-in-time and was discarded")

// otherDiskCopy is copyVMDiskConsistent for a disk other than the root, with
// the VM lock taken only for each disk's brief point-in-time step:
//
//   - shut off: the disk's identity (size, mtime, inode) and the domain state
//     are read under the lock; the copy runs without it, with -U so a VM
//     started meanwhile is not refused; then, under the lock again, the copy
//     stands only if the domain is still shut off and the file unchanged —
//     else it is discarded (errOtherDiskChanged), never published;
//   - running: a backup session is opened under the lock, which is dropped as
//     soon as its point in time is fixed; the export is read without it (a
//     stop aborts the job and the copy fails; nothing is published);
//   - the external snapshot (layer 2) runs under the lock throughout — its
//     window is the point-in-time step, and its overlay must not meet a move
//     mid-copy. It is skipped until the pit_overlay release feature, as for
//     the root;
//   - main's -U copy, the last resort, needs no lock: it is not point-in-time
//     and is recorded so.
func (s *Server) otherDiskCopy(ctx context.Context, take func() func(), vm *corrosion.VMRecord, d *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error, allowForceShare bool) (copyResult, error) {
	lk := &heldLock{take: take}
	defer lk.drop()
	// Each time the lock is taken again, the VM may have moved or gone while
	// it was dropped: then nothing more is copied of it here (review N7).
	acquireHere := func() error {
		lk.acquire()
		return s.vmStillHere(ctx, vm.Name)
	}
	if err := acquireHere(); err != nil {
		return copyResult{}, err
	}
	if err := s.healPITOverlay(ctx, vm, d); err != nil {
		return copyResult{}, err
	}
	src := s.hostDiskFile(d.Path)
	if s.sourceClosedForPlainCopy(vm) {
		before, err := identityOf(src)
		if err != nil {
			return copyResult{}, err
		}
		lk.drop()
		if err := convertImageForceShare(ctx, src, "qcow2", s.diskChainRule(ctx, *d), dst, emit); err != nil {
			return copyResult{}, err
		}
		if err := acquireHere(); err != nil {
			return copyResult{}, err
		}
		after, aerr := identityOf(src)
		if aerr != nil || after != before || !s.sourceClosedForPlainCopy(vm) {
			return copyResult{}, errOtherDiskChanged
		}
		return copyResult{method: copyPlain}, nil
	}
	var why []string
	err := s.copyViaBackupSession(context.WithValue(ctx, afterPITPointKey{}, lk.drop), vm, d, dst, emit)
	if err == nil {
		return copyResult{method: copyBackupSession}, nil
	}
	why = append(why, "backup session: "+err.Error())
	if err := acquireHere(); err != nil {
		return copyResult{}, err
	}
	m, err := s.copyViaExternalSnapshot(ctx, vm, d, dst, emit)
	if err == nil {
		return copyResult{method: m}, nil
	}
	lk.drop()
	why = append(why, "external snapshot: "+err.Error())
	reason := strings.Join(why, "; ")
	if !allowForceShare {
		return copyResult{}, fmt.Errorf("%w (%s)", errNoPointInTimeCopy, reason)
	}
	slog.Warn("copy: no point-in-time copy of a running disk could be made; copying it with qemu-img convert -U, NOT point-in-time",
		"vm", vm.Name, "disk", d.DiskName, "state", vm.State, "why", reason)
	if err := convertImageForceShare(ctx, src, "qcow2", s.diskChainRule(ctx, *d), dst, emit); err != nil {
		return copyResult{}, err
	}
	return copyResult{method: copyForceShare, why: reason}, nil
}

// errVMNoLongerHere stops a run's copies of the other disks: while the VM
// lock was dropped, the VM moved to another host, was deleted, or its domain
// went from this host. Nothing more of it is copied here, and never by the
// -U last resort.
var errVMNoLongerHere = errors.New("the VM is no longer owned and defined on this host")

// vmStillHere checks, under the VM lock, that vm is still this host's and its
// domain still defined here.
func (s *Server) vmStillHere(ctx context.Context, vm string) error {
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return fmt.Errorf("%w: read the VM: %v", errVMNoLongerHere, err)
	}
	if rec == nil || rec.HostName != s.hostName {
		return errVMNoLongerHere
	}
	if s.virt != nil && !s.virt.DomainExists(vm) {
		return errVMNoLongerHere
	}
	return nil
}

// promotedSetDisk is one disk of a promotion besides the one promoted from the
// chosen replica: its row, and the replica it is recovered from, or — on
// shared storage — that it is reattached as-is, or why neither.
type promotedSetDisk struct {
	row         corrosion.DiskRecord
	replica     replicaRecord // File "" when not recovered from a replica
	replicaPath string
	livePath    string // the built live disk, or a shared disk's own path
	shared      bool   // on shared storage: never copied, never rebuilt
	missing     string // why it is not attached; "" when it is
	// unproven is the host a shared disk was left unattached for — the one
	// that failed the reattach verdict — named by the partial report's
	// remedy; "" when no host did.
	unproven string
	// Where it is attached in the promoted domain.
	bus, ctrl, dev string
}

// recovered reports whether the disk is attached to the promoted VM: rebuilt
// from a replica, or, on shared storage, reattached as-is.
func (d promotedSetDisk) recovered() bool { return d.missing == "" }

// built reports whether the promotion built a live disk for it.
func (d promotedSetDisk) built() bool { return d.recovered() && !d.shared && d.livePath != "" }

// chooseSetReplicas picks, on this host, the replica each of others is
// recovered from: the one of the root's run (rootTaken), else the newest from
// before it. A replica newer than the root's run is never taken (an operator
// who named an older root replica chose a point in time), nor one recorded as
// not point-in-time unless acceptNotPIT, nor — ageLimit > 0, an automatic
// promotion — one older than the bound the root's replica passed. With no
// root run time nothing can be matched to it, and none is taken. A disk with
// none is missing, with the reason. A disk on shared storage (shared) is never
// matched to a replica: the caller reattaches it.
func chooseSetReplicas(poolDir, project, vm, rootTaken string, others []corrosion.DiskRecord, shared func(corrosion.DiskRecord) bool, acceptNotPIT bool, ageLimit time.Duration, now time.Time) []promotedSetDisk {
	recs, _ := listReplicaRecords(poolDir, project, vm)
	out := make([]promotedSetDisk, 0, len(others))
	for _, row := range others {
		pd := promotedSetDisk{row: row}
		if shared(row) {
			pd.shared = true
			out = append(out, pd)
			continue
		}
		skippedNotPIT, skippedOld := false, ""
		for _, r := range recs { // oldest first
			if r.Disk != row.DiskName {
				continue
			}
			if rootTaken == "" || r.Taken > rootTaken {
				continue
			}
			if r.NotPointInTime && !acceptNotPIT {
				skippedNotPIT = true
				continue
			}
			if ageLimit > 0 {
				if err := checkAutoPromoteReplicaAge(r.File, now, ageLimit); err != nil {
					skippedOld = r.File
					continue
				}
			}
			path := filepath.Join(replicaOwnerDir(poolDir, project, vm), r.File)
			if replicaReadable(path) != nil {
				continue
			}
			pd.replica, pd.replicaPath = r, path
		}
		switch {
		case pd.replica.File != "":
		case rootTaken == "":
			pd.missing = "the root replica's run time is unknown, so no replica of this disk can be matched to it"
		case !isFileBasedDriver(row.StorageType):
			pd.missing = fmt.Sprintf("its storage (%s) is not file-based, so it is never replicated", row.StorageType)
		case skippedOld != "":
			pd.missing = fmt.Sprintf("its newest replica %s is older than automatic promotion's bound (%s); promote by hand to take it", skippedOld, ageLimit)
		case skippedNotPIT:
			pd.missing = "its only replicas are not point-in-time (promote with --accept-not-point-in-time to take one)"
		default:
			pd.missing = "it has no replica from this run or before"
		}
		out = append(out, pd)
	}
	return out
}

// assignTargetDevs gives every attached other disk a target device that
// collides with neither the root's nor another's: each keeps its stored name
// when it has one no earlier disk took; a disk with none, or with a taken one,
// gets the next free name on its bus, in order.
func assignTargetDevs(rootDev string, others []promotedSetDisk) {
	used := map[string]bool{rootDev: true}
	for i := range others {
		d := &others[i]
		d.dev = ""
		if !d.recovered() || d.row.TargetDev == "" || used[d.row.TargetDev] {
			continue
		}
		d.dev = d.row.TargetDev
		used[d.dev] = true
	}
	for i := range others {
		d := &others[i]
		if !d.recovered() || d.dev != "" {
			continue
		}
		for k := 1; ; k++ {
			if n := lv.DiskDevName(d.bus, k); !used[n] {
				d.dev = n
				used[n] = true
				break
			}
		}
	}
}

// promotionManifest is the vm.promoted event's detail: the root's replica,
// then every other disk and the replica it was recovered from, that it was
// reattached as-is, or why not. partial lists what makes the set incomplete,
// "" when nothing does.
func promotionManifest(rootDisk, rootReplica, rootTaken, host, origVM, newVM string, others []promotedSetDisk) (manifest, partial string) {
	// The remedy for a shared disk left unattached (review R3-m2). A second
	// promotion over this one is not a remedy: it is refused
	// (refuseRebuildOverPromotedDisks), because rebuilding the promoted VM's
	// disks from their replicas would discard what it has written. A start
	// is (review R4-I2): it judges the disk's owner again, and attaches the
	// disk once that host is proven off (rejudgeSharedDisksForStart).
	rerun := fmt.Sprintf("Re-running `lv replication promote %s --force` over this promotion does not attach it: it is "+
		"refused, because rebuilding the promoted VM's disks from their replicas would discard what it has written", origVM)
	sharedAdvice := func(owner string) string {
		if newVM != "" && newVM != origVM {
			return fmt.Sprintf("it belongs to the original VM %s and must not be attached to %s", origVM, newVM)
		}
		if owner == "" || owner == host {
			// No host failed the verdict, or the one that did is the
			// promoting host itself: confirming a fence would not attach it,
			// and the promoting host is never the one to power off.
			return "confirming a host powered off would not attach it. " + rerun
		}
		// The confirmation is not only for this disk (review PB-m3): with
		// recovery claims enforced it may let the failover coordinator
		// recover every workload still recorded on the owner, which the
		// operator should know before confirming.
		return fmt.Sprintf("it is attached as-is only once its owner is proven off: once %s is powered off, "+
			"`lv host fence-confirm %s`, then `lv restart %s`, whose start attaches it. The confirmation may also let "+
			"the failover coordinator recover every workload still recorded on %s. %s", owner, owner, origVM, owner, rerun)
	}
	parts := []string{fmt.Sprintf("%s ← %s", rootDisk, rootReplica)}
	var missing, earlier []string
	for _, d := range others {
		switch {
		case d.shared && d.recovered():
			parts = append(parts, fmt.Sprintf("%s: shared (%s) — reattached as-is at %s", d.row.DiskName, d.row.StorageType, d.row.Path))
		case d.shared:
			parts = append(parts, fmt.Sprintf("%s: shared (%s) — NOT attached (%s)", d.row.DiskName, d.row.StorageType, d.missing))
			missing = append(missing, fmt.Sprintf("%s (shared (%s) at %s, not attached: %s; %s)",
				d.row.DiskName, d.row.StorageType, d.row.Path, d.missing, sharedAdvice(d.unproven)))
		case !d.recovered():
			parts = append(parts, fmt.Sprintf("%s: NOT recovered (%s)", d.row.DiskName, d.missing))
			where := ""
			if d.row.HostName != "" && d.row.Path != "" {
				where = fmt.Sprintf("; its real disk is on %s at %s", d.row.HostName, d.row.Path)
			}
			missing = append(missing, fmt.Sprintf("%s (%s%s)", d.row.DiskName, d.missing, where))
		case d.replica.Taken != rootTaken:
			parts = append(parts, fmt.Sprintf("%s ← %s (an earlier run than the root's %s)", d.row.DiskName, d.replica.File, rootTaken))
			earlier = append(earlier, fmt.Sprintf("%s (from the run of %s, not the root's %s)", d.row.DiskName, d.replica.Taken, rootTaken))
		default:
			parts = append(parts, fmt.Sprintf("%s ← %s", d.row.DiskName, d.replica.File))
		}
	}
	manifest = fmt.Sprintf("from replica %s on %s; disks: %s", rootReplica, host, strings.Join(parts, "; "))
	var why []string
	if len(missing) > 0 {
		why = append(why, "not recovered: "+strings.Join(missing, ", "))
	}
	if len(earlier) > 0 {
		why = append(why, "recovered from an earlier run, so not consistent with the root disk: "+strings.Join(earlier, ", "))
	}
	if len(why) > 0 {
		partial = "partial recovery: " + strings.Join(why, "; ")
	}
	return manifest, partial
}

// vmEventPromotedPartial is the event of a promotion whose replica set was
// incomplete.
const vmEventPromotedPartial = "vm.promoted_partial"

// The promoted-partial marker is a durable condition on the VM, one per VM,
// like a held failover: raised by a partial promotion, resolved by a later
// complete one. InspectVM shows it as promoted_partial however many events
// the VM has recorded since.
const (
	promotedPartialEvaluator = "replica_set"
	promotedPartialCode      = "vm.promoted_partial"
	promotedPartialKind      = "vm"
)

type promotedPartialEvidence struct {
	VM     string `json:"vm"`
	Host   string `json:"host"`
	Detail string `json:"detail"`
	// CreatedAt is the VM row's created_at when the marker was raised: a VM
	// re-created under the name later is another VM, and never inherits it.
	CreatedAt string `json:"created_at,omitempty"`
}

// reportPromotedPartial is the event, notification and durable marker of a
// promotion that recovered the VM without its whole replica set.
func (s *Server) reportPromotedPartial(ctx context.Context, vm, host, partial string) {
	detail := fmt.Sprintf("VM %s promoted on %s with a %s. The guest runs without the disks named, or with disks not consistent with its root", vm, host, partial)
	slog.Error("promote: the VM was recovered without its whole replica set", "vm", vm, "host", host, "detail", partial)
	s.recordVMEventSeverity(ctx, vm, vmEventPromotedPartial, "warning", "error", detail)
	s.notify(ctx, notify.Notification{
		Kind: "replication.promoted_partial", Severity: notify.SevError, Subject: vm, Detail: detail,
	})
	if s.db == nil {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	ev := promotedPartialEvidence{VM: vm, Host: host, Detail: detail}
	if rec, err := corrosion.GetVM(ctx, s.db, vm); err == nil && rec != nil {
		ev.CreatedAt = rec.CreatedAt
	}
	b, _ := json.Marshal(ev)
	row := corrosion.HealthCondition{
		Evaluator: promotedPartialEvaluator, Code: promotedPartialCode, SubjectKind: promotedPartialKind, SubjectID: vm,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning, Hosts: []string{host},
		Evidence: string(b), ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: s.hostName,
	}
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("promote: persist the partial-recovery marker", "vm", vm, "error", err)
	}
}

// clearPromotedPartial resolves vm's partial-recovery marker, if one is open:
// a later promotion recovered the whole set, or the VM was deleted. There is
// no generic "resolve a health condition by hand" command to clear it with.
func (s *Server) clearPromotedPartial(ctx context.Context, vm string) {
	if s.db == nil {
		return
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, promotedPartialEvaluator, promotedPartialCode, promotedPartialKind, vm)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, s.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("promote: resolve the partial-recovery marker", "vm", vm, "error", err)
	}
}

// promotedPartialReason is vm's open partial-recovery marker's detail, "" when
// none is open.
func (s *Server) promotedPartialReason(ctx context.Context, vmName string) string {
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, promotedPartialEvaluator, promotedPartialCode, promotedPartialKind, vmName)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return ""
	}
	var ev promotedPartialEvidence
	if json.Unmarshal([]byte(row.Evidence), &ev) != nil || ev.Detail == "" {
		return "promoted without its whole replica set"
	}
	if ev.CreatedAt != "" {
		if rec, err := corrosion.GetVM(ctx, s.db, vmName); err == nil && rec != nil && rec.CreatedAt != ev.CreatedAt {
			return "" // raised for an earlier VM of this name
		}
	}
	return ev.Detail
}
