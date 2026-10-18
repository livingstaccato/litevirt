package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Incremental replication of a disk other than the root.
//
// An --incremental schedule copies each other disk of a running VM the way it
// copies the root: a backup session reads the extents dirty since the disk's
// own checkpoint and applies them to a raw replica forked from the replica
// that checkpoint's run wrote. Each disk has a chain of its own: its own
// libvirt checkpoint (replCheckpointName names the disk) and its own anchor
// row, so one disk's break never touches another's.
//
// The anchor of another disk is a replication_checkpoints row keyed
// (vm, diskChainRepo(pool, disk)). The root keeps (vm, pool), the row every
// build reads; a pool name cannot hold "/", so the two never meet, and no
// older build reads the new rows. The row's value is a diskChainAnchor: the
// checkpoint, and what the chain is valid for. A run forks from it only when
// all of it still holds:
//
//   - the host is this one and the VM's owner epoch is unchanged: a VM that
//     moved away and back has had writes no bitmap here saw;
//   - the disk's path and file (inode) are unchanged: a swapped disk, or one
//     restored in place (a restore places a new file), has none of the old
//     file's content;
//   - the guest-visible size is unchanged: a resize starts a new chain;
//   - the base replica is the one the checkpoint's run wrote, from this host,
//     at the anchor's size.
//
// Anything else is a full copy of that disk: the run opens a session with no
// parent, which reads every allocated extent into a new raw replica and
// starts the chain again. A session that cannot open (a stopped VM, a
// checkpoint libvirt no longer has, a bitmap the disk file does not carry)
// falls back to the disk's full point-in-time copy, as before, and the chain
// is reset.

// diskChainRepo is the replication_checkpoints repo key of disk's chain in
// pool, for a disk other than the root.
func diskChainRepo(pool, disk string) string { return pool + "/" + disk }

// diskChainAnchor is the stored anchor of a disk's chain.
type diskChainAnchor struct {
	Checkpoint string `json:"checkpoint"`
	Host       string `json:"host"`
	OwnerEpoch int64  `json:"owner_epoch"`
	Path       string `json:"path"`
	Inode      uint64 `json:"inode"`
	Size       int64  `json:"size"`
}

func (a diskChainAnchor) encode() string {
	b, _ := json.Marshal(a)
	return string(b)
}

func decodeDiskChainAnchor(s string) (diskChainAnchor, bool) {
	var a diskChainAnchor
	if s == "" || json.Unmarshal([]byte(s), &a) != nil || a.Checkpoint == "" {
		return diskChainAnchor{}, false
	}
	return a, true
}

// diskChainBreak says why a disk's stored anchor cannot be continued, "" when
// it can.
func diskChainBreak(a diskChainAnchor, host string, epoch int64, path string, inode uint64) string {
	switch {
	case a.Host != host:
		return fmt.Sprintf("its checkpoint was taken on %s", a.Host)
	case a.OwnerEpoch != epoch:
		return "the VM changed owner since its checkpoint"
	case a.Path != path:
		return "the disk's file changed since its checkpoint"
	case a.Inode != inode:
		return "the disk's file was replaced since its checkpoint"
	}
	return ""
}

// resetDiskChain drops disk's anchor, and its checkpoint when it was taken
// here. Best effort: a leftover anchor is never continued (diskChainBreak), and
// a leftover checkpoint only holds a bitmap.
func (s *Server) resetDiskChain(ctx context.Context, vm, pool, disk string) {
	repo := diskChainRepo(pool, disk)
	raw, _ := corrosion.GetReplicationCheckpoint(ctx, s.db, vm, repo)
	if raw == "" {
		return
	}
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, vm, repo, ""); err != nil {
		slog.Error("incremental replication: chain reset write failed", "vm", vm, "disk", disk, "pool", pool, "error", err)
	}
	if a, ok := decodeDiskChainAnchor(raw); ok && a.Host == s.hostName && s.backupSource != nil {
		_ = s.backupSource.DeleteCheckpoint(vm, a.Checkpoint)
	}
}

// replicateDiskIncremental is replicateIncremental for a disk other than the
// root. The VM lock (take) is held only while the session's point in time is
// fixed, as for that disk's full copy (otherDiskCopy). An error other than
// errVMNoLongerHere or errCheckpointCommit lets the caller fall back to the
// full copy.
func (s *Server) replicateDiskIncremental(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, d *corrosion.DiskRecord, targetHost, ts string, take func() func()) error {
	ctx = s.withReplicaOwner(ctx, vm)
	key := replicaScheduleKey(sched)
	repo := diskChainRepo(sched.TargetPool, d.DiskName)

	lk := &heldLock{take: take}
	defer lk.drop()
	lk.acquire()
	if err := s.vmStillHere(ctx, vm.Name); err != nil {
		return err
	}
	cur, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil || cur == nil {
		return fmt.Errorf("%w: read the VM: %v", errVMNoLongerHere, err)
	}
	id, err := identityOf(s.hostDiskFile(d.Path))
	if err != nil {
		return fmt.Errorf("examine the disk's file: %w", err)
	}

	raw, _ := corrosion.GetReplicationCheckpoint(ctx, s.db, vm.Name, repo)
	parent, haveParent := decodeDiskChainAnchor(raw)
	base, parentCP, why := "", "", "no checkpoint yet"
	if haveParent {
		why = diskChainBreak(parent, s.hostName, cur.OwnerEpoch, d.Path, id.ino)
		if why == "" {
			why = "the target holds no replica its checkpoint continues"
			if taken, ok := checkpointTaken(d.DiskName, parent.Checkpoint); ok {
				for _, r := range s.replicaRecordsOn(ctx, sched.TargetPool, targetHost, vm.Project, vm.Name) {
					if r.Disk == d.DiskName && r.Schedule == key && r.Format == "raw" && r.Taken == taken &&
						(r.SizeBytes == 0 || r.SizeBytes == parent.Size) {
						base, parentCP, why = r.File, parent.Checkpoint, ""
						break
					}
				}
			}
		}
		if why != "" && parent.Host == s.hostName {
			// A chain that cannot be continued is never forked from again.
			_ = s.backupSource.DeleteCheckpoint(vm.Name, parent.Checkpoint)
		}
	}

	newCP := replCheckpointName(d.DiskName, ts)
	committed := false
	defer func() {
		if !committed {
			_ = s.backupSource.DeleteCheckpoint(vm.Name, newCP)
		}
	}()
	session, err := s.backupSource.BeginBackup(vm.Name, d.Path, parentCP, newCP)
	if err != nil {
		return fmt.Errorf("begin backup session: %w", err)
	}
	if !session.Incremental() {
		base = ""
	}
	if base != "" && session.Size() != parent.Size {
		// Resized since its checkpoint: the increment would be laid over a
		// base of another size. Read it whole instead, at a new point in time.
		why = fmt.Sprintf("the disk was resized since its checkpoint (%d → %d bytes)", parent.Size, session.Size())
		_ = session.Close()
		_ = s.backupSource.DeleteCheckpoint(vm.Name, newCP)
		_ = s.backupSource.DeleteCheckpoint(vm.Name, parentCP)
		base, parentCP = "", ""
		if err := s.vmStillHere(ctx, vm.Name); err != nil {
			return err
		}
		if session, err = s.backupSource.BeginBackup(vm.Name, d.Path, "", newCP); err != nil {
			return fmt.Errorf("begin backup session: %w", err)
		}
	}
	// The point in time is fixed: the export is read without the lock.
	lk.drop()
	defer session.Close()
	totalSize := session.Size()
	extents, err := session.ChangedExtents()
	if err != nil {
		return fmt.Errorf("changed extents: %w", err)
	}
	rec := newReplicaRecord(vm.Project, vm.Name, d.DiskName, key, ts, "raw")
	rec.Source = s.hostName
	if targetHost == s.hostName {
		err = s.applyIncrementLocal(ctx, sched.TargetPool, rec, base, totalSize, session, extents)
	} else {
		err = s.applyIncrementRemote(ctx, targetHost, sched.TargetPool, rec, base, totalSize, session, extents)
	}
	if err != nil {
		return err
	}

	next := diskChainAnchor{
		Checkpoint: newCP, Host: s.hostName, OwnerEpoch: cur.OwnerEpoch,
		Path: d.Path, Inode: id.ino, Size: totalSize,
	}
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, vm.Name, repo, next.encode()); err != nil {
		return fmt.Errorf("%w: record %q for %s/%s: %v", errCheckpointCommit, newCP, vm.Name, repo, err)
	}
	committed = true
	if parentCP != "" && parentCP != newCP {
		if err := s.backupSource.DeleteCheckpoint(vm.Name, parentCP); err != nil {
			slog.Warn("replication: dropping superseded parent checkpoint failed (bitmap leak; not fatal)",
				"vm", vm.Name, "disk", d.DiskName, "parent", parentCP, "error", err)
		}
	}

	pruned := s.pruneReplicasAnywhere(ctx, sched.TargetPool, targetHost, vm.Project, vm.Name, d.DiskName, key, sched.KeepReplicas)
	pruned += s.pruneEarlierReplicasAnywhere(ctx, sched.TargetPool, targetHost, vm, d.DiskName, sched.KeepReplicas)
	mode := "incremental"
	if base == "" {
		mode = "full (" + why + ")"
	}
	detail := fmt.Sprintf("%s → %s@%s (%s, %s, %d extent(s))", d.DiskName, sched.TargetPool, targetHost, ts, mode, len(extents))
	if pruned > 0 {
		detail += fmt.Sprintf(", pruned %d old", pruned)
	}
	s.recordVMEvent(ctx, vm.Name, "disk.replicated", "ok", detail)
	return nil
}

// replicateOtherDiskIncrementalOr runs d's incremental copy on an
// --incremental schedule and, when it cannot be made, resets d's chain and
// runs full (the disk's full point-in-time copy). The VM leaving this host
// and a failed anchor write are returned as they are: neither falls back.
func (s *Server) replicateOtherDiskIncrementalOr(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, d *corrosion.DiskRecord, targetHost, ts string, take func() func(), full func() error) error {
	err := s.replicateDiskIncremental(ctx, sched, vm, d, targetHost, ts, take)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errVMNoLongerHere):
		return err
	case errors.Is(err, errCheckpointCommit):
		slog.Error("incremental replication: checkpoint commit failed; the parent anchor is kept for the next run",
			"vm", vm.Name, "disk", d.DiskName, "pool", sched.TargetPool, "error", err)
		return err
	}
	s.resetDiskChain(ctx, vm.Name, sched.TargetPool, d.DiskName)
	slog.Warn("incremental replication of a disk fell back to a full copy",
		"vm", vm.Name, "disk", d.DiskName, "pool", sched.TargetPool, "error", err)
	return full()
}
