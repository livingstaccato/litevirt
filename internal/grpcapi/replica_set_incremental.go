package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

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
//   - the VM is the same incarnation (its created_at): a VM deleted and
//     created again under the name, whose disk may even reuse the path and
//     inode, is another VM;
//   - the disk's path and file (inode) are unchanged: a swapped disk, or one
//     restored in place (a restore places a new file), has none of the old
//     file's content;
//   - the guest-visible size is unchanged: a resize starts a new chain;
//   - the base replica is the one the checkpoint's run wrote, from this host
//     (a peer's listing does not carry the writer; the anchor's host stands
//     for it), at the anchor's size.
//
// A target whose replicas cannot be listed (unreachable for a moment) breaks
// nothing: the disk is not copied in that run (errChainListing), its chain is
// kept, and the next run continues it. After chainListingEscalateAfter such
// runs in a row the condition replica.chain_unlistable names the VM and disk,
// and the first run that can list the target again copies the disk in full
// and starts its chain again (a new target pool is a new chain anyway).
//
// Anything else is a full copy of that disk: the run opens a session with no
// parent, which reads every allocated extent into a new raw replica and
// starts the chain again. A session that cannot open (a stopped VM, a
// checkpoint libvirt no longer has, a bitmap the disk file does not carry)
// falls back to the disk's full point-in-time copy, as before, and the chain
// is reset.

// diskChainRepo is the replication_checkpoints repo key of disk's chain in
// pool, for a disk other than the root; for the root, of its chain's
// identity guard (rootChainGuard), beside the bare (vm, pool) row every
// build reads.
func diskChainRepo(pool, disk string) string { return pool + "/" + disk }

// diskChainAnchor is the stored anchor of a disk's chain.
type diskChainAnchor struct {
	Checkpoint string `json:"checkpoint"`
	Host       string `json:"host"`
	OwnerEpoch int64  `json:"owner_epoch"`
	Path       string `json:"path"`
	Inode      uint64 `json:"inode"`
	Size       int64  `json:"size"`
	// Incarnation is the VM's created_at.
	Incarnation string `json:"incarnation"`
}

// diskIdentity is what a disk's chain is valid for, read now.
type diskIdentity struct {
	host, incarnation, path string
	epoch                   int64
	inode                   uint64
}

// errChainListing: the target's replicas could not be listed, so whether the
// chain's base is there is unknown. The disk is not copied in this run and
// its chain is kept for the next.
var errChainListing = errors.New("the target's replicas could not be listed; the disk's chain is kept for the next run")

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
func diskChainBreak(a diskChainAnchor, id diskIdentity) string {
	switch {
	case a.Host != id.host:
		return fmt.Sprintf("its checkpoint was taken on %s", a.Host)
	case a.Incarnation != id.incarnation:
		return "the VM was created again since its checkpoint"
	case a.OwnerEpoch != id.epoch:
		return "the VM changed owner since its checkpoint"
	case a.Path != id.path:
		return "the disk's file changed since its checkpoint"
	case a.Inode != id.inode:
		return "the disk's file was replaced since its checkpoint"
	}
	return ""
}

// diskIdentityOf is d's identity now, in vm (read under the VM lock).
func (s *Server) diskIdentityOf(vm *corrosion.VMRecord, d *corrosion.DiskRecord) (diskIdentity, error) {
	fid, err := identityOf(s.hostDiskFile(d.Path))
	if err != nil {
		return diskIdentity{}, err
	}
	return diskIdentity{host: s.hostName, incarnation: vm.CreatedAt, path: d.Path, epoch: vm.OwnerEpoch, inode: fid.ino}, nil
}

// anchorFor is the anchor a run that took checkpoint cp of a disk of
// guest-visible size writes.
func anchorFor(cp string, id diskIdentity, size int64) diskChainAnchor {
	return diskChainAnchor{Checkpoint: cp, Host: id.host, OwnerEpoch: id.epoch, Path: id.path, Inode: id.inode,
		Size: size, Incarnation: id.incarnation}
}

// chainBase is the raw replica the run at taken wrote of disk for schedule key
// on the target, written from this host at size; "" when there is none.
// errChainListing when the target's replicas cannot be listed.
func (s *Server) chainBase(ctx context.Context, pool, targetHost, project, vm, disk, key, taken string, size int64) (string, error) {
	recs, err := s.replicaRecordsOnChecked(ctx, pool, targetHost, project, vm)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errChainListing, err)
	}
	local := targetHost == "" || targetHost == s.hostName
	for _, r := range recs {
		if r.Disk != disk || r.Schedule != key || r.Format != "raw" || r.Taken != taken {
			continue
		}
		// A local record says who wrote it; a peer's listing does not.
		if local && r.Source != s.hostName {
			continue
		}
		if r.SizeBytes != 0 && r.SizeBytes != size {
			continue
		}
		return r.File, nil
	}
	return "", nil
}

// chainListingEscalateAfter is how many runs in a row may fail to list a
// disk's target before replica.chain_unlistable names it.
const chainListingEscalateAfter = 3

// The replica.chain_unlistable condition, one per VM.
const (
	chainUnlistableEvaluator = "replica_set"
	chainUnlistableCode      = "replica.chain_unlistable"
	chainUnlistableKind      = "vm"
)

// chainListFailures counts, in memory, the consecutive runs whose target's
// replicas could not be listed, per VM, pool and disk. A restart of the
// daemon starts the count again.
type chainListFailures struct {
	mu sync.Mutex
	m  map[string]chainListFailure // vm \x00 pool \x00 disk
}

type chainListFailure struct {
	vm, pool, disk, target, err string
	runs                        int
}

// noteChainListing records whether a run could list disk's target (err nil)
// or not, and raises or resolves replica.chain_unlistable for the VM. It
// returns true when the target is listable again after the condition was
// raised for this disk: its chain is then started again.
func (s *Server) noteChainListing(ctx context.Context, vm, pool, disk, target string, err error) bool {
	k := vm + "\x00" + pool + "\x00" + disk
	c := &s.chainListing
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]chainListFailure{}
	}
	prev := c.m[k]
	escalatedBefore := prev.runs >= chainListingEscalateAfter
	if err != nil {
		c.m[k] = chainListFailure{vm: vm, pool: pool, disk: disk, target: target, err: err.Error(), runs: prev.runs + 1}
	} else {
		delete(c.m, k)
	}
	var open []chainListFailure
	for _, f := range c.m {
		if f.vm == vm && f.runs >= chainListingEscalateAfter {
			open = append(open, f)
		}
	}
	c.mu.Unlock()
	if len(open) > 0 || escalatedBefore {
		s.judgeChainUnlistable(ctx, vm, open)
	}
	return err == nil && escalatedBefore
}

// judgeChainUnlistable raises replica.chain_unlistable for vm while open
// names a disk, and resolves it once none.
func (s *Server) judgeChainUnlistable(ctx context.Context, vm string, open []chainListFailure) {
	if s.db == nil {
		return
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, chainUnlistableEvaluator, chainUnlistableCode, chainUnlistableKind, vm)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if len(open) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("replication: resolve the unlistable-chain condition", "vm", vm, "error", err)
		}
		return
	}
	sort.Slice(open, func(i, j int) bool { return open[i].pool+open[i].disk < open[j].pool+open[j].disk })
	type disk struct {
		Disk   string `json:"disk"`
		Pool   string `json:"pool"`
		Target string `json:"target_host"`
		Runs   int    `json:"runs"`
		Error  string `json:"error"`
	}
	var list []disk
	for _, f := range open {
		list = append(list, disk{Disk: f.disk, Pool: f.pool, Target: f.target, Runs: f.runs, Error: f.err})
	}
	ev, _ := json.Marshal(map[string]any{
		"vm": vm, "host": s.hostName, "disks": list,
		"detail": fmt.Sprintf("the replicas of %d disk(s) of %s on their target could not be listed in %d or more replication runs in a row, so those disks were not replicated; "+
			"their chains are kept, and the first run that can list the target again copies each in full", len(list), vm, chainListingEscalateAfter),
	})
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: chainUnlistableEvaluator, Code: chainUnlistableCode,
			SubjectKind: chainUnlistableKind, SubjectID: vm, Lifecycle: corrosion.ConditionConfirmed, FirstSeen: now, ConfirmedAt: now}
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("replication: raise the unlistable-chain condition", "vm", vm, "error", err)
	}
}

// rootChainGuard is the identity guard of vm's root chain in pool.
func (s *Server) rootChainGuard(ctx context.Context, vm, pool, root string) (diskChainAnchor, bool) {
	raw, _ := corrosion.GetReplicationCheckpoint(ctx, s.db, vm, diskChainRepo(pool, root))
	return decodeDiskChainAnchor(raw)
}

// dropDiskChains tombstones a deleted VM's per-disk anchors and root
// guards (every row keyed diskChainRepo), through the reset statement each
// row already has. The bare (vm, pool) rows older builds read are left as
// they always were. Best effort: a row left behind is never continued, its
// incarnation being another VM's.
func (s *Server) dropDiskChains(ctx context.Context, vm string) {
	repos, err := corrosion.ReplicationCheckpointRepos(ctx, s.db, vm)
	if err != nil {
		slog.Warn("delete: could not read the deleted VM's replication chains", "vm", vm, "error", err)
		return
	}
	for _, repo := range repos {
		if !strings.Contains(repo, "/") {
			continue
		}
		if err := corrosion.SetReplicationCheckpoint(ctx, s.db, vm, repo, ""); err != nil {
			slog.Warn("delete: could not drop a deleted VM's replication chain", "vm", vm, "repo", repo, "error", err)
		}
	}
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
	id, err := s.diskIdentityOf(cur, d)
	if err != nil {
		return fmt.Errorf("examine the disk's file: %w", err)
	}

	raw, _ := corrosion.GetReplicationCheckpoint(ctx, s.db, vm.Name, repo)
	parent, haveParent := decodeDiskChainAnchor(raw)
	base, parentCP, why := "", "", "no checkpoint yet"
	if haveParent {
		why = diskChainBreak(parent, id)
		if why == "" {
			why = "the target holds no replica its checkpoint continues"
			if taken, ok := checkpointTaken(d.DiskName, parent.Checkpoint); ok {
				b, err := s.chainBase(ctx, sched.TargetPool, targetHost, vm.Project, vm.Name, d.DiskName, key, taken, parent.Size)
				escalated := s.noteChainListing(ctx, vm.Name, sched.TargetPool, d.DiskName, targetHost, err)
				switch {
				case err != nil:
					return err // nothing touched: the chain is kept
				case escalated:
					why = fmt.Sprintf("the target's replicas could not be listed in %d runs or more in a row, so its chain is started again", chainListingEscalateAfter)
				case b != "":
					base, parentCP, why = b, parent.Checkpoint, ""
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

	next := anchorFor(newCP, id, totalSize)
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
	case errors.Is(err, errChainListing):
		slog.Warn("incremental replication: the target's replicas could not be listed; the disk is copied next run, its chain kept",
			"vm", vm.Name, "disk", d.DiskName, "pool", sched.TargetPool, "error", err)
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
