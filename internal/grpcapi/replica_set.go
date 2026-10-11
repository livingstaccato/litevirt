package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

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
// incremental chain, its fallback, its top-level mirror for a main-build host —
// then each other disk as a full point-in-time copy (copyVMDiskConsistent).
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
// reported as skipped on every run, and a cdrom. To a receiver on an older
// build, which promotes only the root, the other disks are not sent.
//
// The VM lock is held for the root's run as before, and for each other disk
// only during its point-in-time step (otherDiskCopy). The partial marker is
// a durable health condition (replica_set / vm.promoted_partial).

// otherSetDiskKey marks a context replicating a disk other than the root.
type otherSetDiskKey struct{}

func withOtherSetDisk(ctx context.Context) context.Context {
	return context.WithValue(ctx, otherSetDiskKey{}, true)
}

// isOtherSetDisk reports whether ctx replicates a disk other than the root,
// which is never mirrored to a pool's top level: a main-build host promotes
// the root disk alone.
func isOtherSetDisk(ctx context.Context) bool {
	v, _ := ctx.Value(otherSetDiskKey{}).(bool)
	return v
}

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
	if corrosion.DiskIsShared(d) {
		return true
	}
	if d.StorageVolume == "" {
		return false
	}
	ref, ok := s.resolvePool(ctx, d.StorageVolume)
	return ok && isSharedDriver(ref.Driver)
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
	ctx = withOtherSetDisk(ctx)
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
	if targetHost != s.hostName {
		// A receiver on an older build keeps replicas at its pool's top level
		// and promotes the root disk alone: another disk sent there is never
		// read.
		legacy, err := s.replicaReceiverLegacy(ctx, targetHost, sched.TargetPool, vm.Project, vm.Name)
		if err != nil {
			return fmt.Errorf("replicate the other disks of %s: %w", vm.Name, err)
		}
		if legacy {
			names := make([]string, 0, len(copyable))
			for _, d := range copyable {
				names = append(names, d.DiskName)
			}
			s.recordVMEvent(ctx, vm.Name, "disk.replicated", "skipped", fmt.Sprintf(
				"%s → %s@%s: not replicated; %s runs an older build that promotes the root disk only",
				strings.Join(names, ", "), sched.TargetPool, targetHost, targetHost))
			return nil
		}
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
	lk.acquire()
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
		lk.acquire()
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
	lk.acquire()
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
func promotionManifest(rootDisk, rootReplica, rootTaken, host string, others []promotedSetDisk) (manifest, partial string) {
	parts := []string{fmt.Sprintf("%s ← %s", rootDisk, rootReplica)}
	var missing, earlier []string
	for _, d := range others {
		switch {
		case d.shared && d.recovered():
			parts = append(parts, fmt.Sprintf("%s: shared (%s) — reattached as-is at %s", d.row.DiskName, d.row.StorageType, d.row.Path))
		case d.shared:
			parts = append(parts, fmt.Sprintf("%s: shared (%s) — NOT attached (%s)", d.row.DiskName, d.row.StorageType, d.missing))
			missing = append(missing, fmt.Sprintf("%s (shared (%s) at %s, not attached: %s; attach it as-is once the old host's fence is confirmed)",
				d.row.DiskName, d.row.StorageType, d.row.Path, d.missing))
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
	b, _ := json.Marshal(promotedPartialEvidence{VM: vm, Host: host, Detail: detail})
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
// a later promotion recovered the whole set.
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
	return ev.Detail
}
