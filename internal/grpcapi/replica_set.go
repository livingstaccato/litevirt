package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
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
// at least that. A promotion whose set is incomplete marks the VM partial:
// `lv inspect` shows promoted_partial, and a vm.promoted_partial event and a
// replication.promoted_partial notification name each missing disk and where
// its real data is. The vm.promoted event lists the whole set, disk by disk:
// the recovery manifest.
//
// Not copied, and so never recovered from a replica: a disk on storage that is
// not file-based (ceph, iscsi, zfs, lvm), which the run reports as skipped on
// every run, and a cdrom. To a receiver on an older build, which promotes only
// the root, the other disks are not sent.

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

// replicateOtherDisks replicates each of disks with the root's run time ts,
// after the root succeeded. Every disk is tried; the run fails if any copy
// did, so the schedule reports an incomplete set rather than a success. A disk
// replication cannot copy is skipped with an event, every run, and does not
// fail it: main never copied it either.
func (s *Server) replicateOtherDisks(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, disks []corrosion.DiskRecord, targetHost, ts string, allowForceShare bool) error {
	if len(disks) == 0 {
		return nil
	}
	ctx = withOtherSetDisk(ctx)
	if targetHost != s.hostName {
		// A receiver on an older build keeps replicas at its pool's top level
		// and promotes the root disk alone: another disk sent there is never
		// read.
		legacy, err := s.replicaReceiverLegacy(ctx, targetHost, sched.TargetPool, vm.Project, vm.Name)
		if err != nil {
			return fmt.Errorf("replicate the other disks of %s: %w", vm.Name, err)
		}
		if legacy {
			names := make([]string, 0, len(disks))
			for _, d := range disks {
				names = append(names, d.DiskName)
			}
			s.recordVMEvent(ctx, vm.Name, "disk.replicated", "skipped", fmt.Sprintf(
				"%s → %s@%s: not replicated; %s runs an older build that promotes the root disk only",
				strings.Join(names, ", "), sched.TargetPool, targetHost, targetHost))
			return nil
		}
	}
	var errs []error
	for i := range disks {
		d := &disks[i]
		if !isFileBasedDriver(d.StorageType) {
			s.recordVMEvent(ctx, vm.Name, "disk.replicated", "skipped", fmt.Sprintf(
				"%s: not replicated; its storage (%s) is not file-based, so a promotion cannot recover it from a replica",
				d.DiskName, d.StorageType))
			continue
		}
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

// promotedSetDisk is one disk of a promotion besides the one promoted from the
// chosen replica: its row, and the replica it is recovered from or why it is
// not.
type promotedSetDisk struct {
	row         corrosion.DiskRecord
	replica     replicaRecord // File "" when not recovered
	replicaPath string
	livePath    string
	missing     string // why it is not recovered; "" when it is
}

// recovered reports whether the disk is recovered from a replica.
func (d promotedSetDisk) recovered() bool { return d.missing == "" }

// chooseSetReplicas picks, on this host, the replica each of others is
// recovered from: the one of the root's run (rootTaken), else the newest from
// before it. A replica newer than the root's run is never taken (an operator
// who named an older root replica chose a point in time), nor one recorded as
// not point-in-time unless acceptNotPIT. A disk with none is missing, with the
// reason.
func chooseSetReplicas(poolDir, project, vm, rootTaken string, others []corrosion.DiskRecord, acceptNotPIT bool) []promotedSetDisk {
	recs, _ := listReplicaRecords(poolDir, project, vm)
	out := make([]promotedSetDisk, 0, len(others))
	for _, row := range others {
		pd := promotedSetDisk{row: row}
		skippedNotPIT := false
		for _, r := range recs { // oldest first
			if r.Disk != row.DiskName {
				continue
			}
			if rootTaken != "" && r.Taken > rootTaken {
				continue
			}
			if r.NotPointInTime && !acceptNotPIT {
				skippedNotPIT = true
				continue
			}
			path := filepath.Join(replicaOwnerDir(poolDir, project, vm), r.File)
			if replicaReadable(path) != nil {
				continue
			}
			pd.replica, pd.replicaPath = r, path
		}
		switch {
		case pd.replica.File != "":
		case !isFileBasedDriver(row.StorageType):
			pd.missing = fmt.Sprintf("its storage (%s) is not file-based, so it is never replicated", row.StorageType)
		case skippedNotPIT:
			pd.missing = "its only replicas are not point-in-time (promote with --accept-not-point-in-time to take one)"
		default:
			pd.missing = "it has no replica"
			if rootTaken != "" {
				pd.missing += " from this run or before"
			}
		}
		out = append(out, pd)
	}
	return out
}

// promotionManifest is the vm.promoted event's detail: the root's replica,
// then every other disk and the replica it was recovered from, or why not.
// partial lists what makes the set incomplete, "" when nothing does.
func promotionManifest(rootDisk, rootReplica, rootTaken, host string, others []promotedSetDisk) (manifest, partial string) {
	parts := []string{fmt.Sprintf("%s ← %s", rootDisk, rootReplica)}
	var missing, earlier []string
	for _, d := range others {
		switch {
		case !d.recovered():
			parts = append(parts, fmt.Sprintf("%s: NOT recovered (%s)", d.row.DiskName, d.missing))
			where := ""
			if d.row.HostName != "" && d.row.Path != "" {
				where = fmt.Sprintf("; its real disk is on %s at %s", d.row.HostName, d.row.Path)
			}
			missing = append(missing, fmt.Sprintf("%s (%s%s)", d.row.DiskName, d.missing, where))
		case rootTaken != "" && d.replica.Taken != rootTaken:
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
// incomplete; InspectVM shows the newest one as promoted_partial.
const vmEventPromotedPartial = "vm.promoted_partial"

// reportPromotedPartial is the event and notification of a promotion that
// recovered the VM without its whole replica set.
func (s *Server) reportPromotedPartial(ctx context.Context, vm, host, partial string) {
	detail := fmt.Sprintf("VM %s promoted on %s with a %s. The guest runs without the disks named, or with disks not consistent with its root", vm, host, partial)
	slog.Error("promote: the VM was recovered without its whole replica set", "vm", vm, "host", host, "detail", partial)
	s.recordVMEventSeverity(ctx, vm, vmEventPromotedPartial, "warning", "error", detail)
	s.notify(ctx, notify.Notification{
		Kind: "replication.promoted_partial", Severity: notify.SevError, Subject: vm, Detail: detail,
	})
}

// promotedPartialReason is the newest promotion's partial-recovery detail when
// that promotion was partial, "" otherwise. A partial promotion records its
// vm.promoted_partial after its vm.promoted (event times have nanosecond
// order), so the newest of the two says which the newest promotion was.
func (s *Server) promotedPartialReason(ctx context.Context, vmName string) string {
	evs, err := corrosion.ListVMEvents(ctx, s.db, vmName, 100, "")
	if err != nil {
		return ""
	}
	for _, e := range evs { // newest first
		switch e.Type {
		case vmEventPromotedPartial:
			return e.Detail
		case "vm.promoted":
			return ""
		}
	}
	return ""
}
