package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/scheduler"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// errCheckpointCommit marks a failure to durably record the NEW replication
// checkpoint anchor after a transfer. It is distinct from a transfer failure: the
// parent anchor (DB row + libvirt bitmap) is left intact, so RunReplication must
// NOT reset the chain and fall back to a full copy (that would erase the retryable
// parent). The next run retries from the preserved parent.
var errCheckpointCommit = errors.New("replication checkpoint commit failed")

// RunReplication is the scheduler's replication dispatch (scheduler.Replication
// Runner). It replicates the VM's disk to the schedule's target pool, keeping
// the newest keep_replicas copies. A full copy is copyVMDiskConsistent's
// (pit_copy.go), as ReplicateVolume's: point-in-time — a plain copy of a
// shut-off disk, else a backup session, else an external snapshot (quiesced
// when the guest agent answers) — and, only when none of those can be made,
// main's -U copy, recorded and reported as NOT point-in-time. It's a
// fast-recovery layer, not a backup replacement.
//
// Target model: an explicit target_host or a shared pool (nfs/ceph/iscsi) makes
// the replica usable cluster-wide; for a non-shared pool a cross-host target is
// rejected with guidance (true cross-host transport of local-only storage is a
// planned follow-up).
func (s *Server) RunReplication(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error {
	if sched.Scope == "container" {
		return s.runContainerReplication(ctx, sched, runAt)
	}
	if sched.TargetPool == "" {
		return fmt.Errorf("replication schedule for %q missing target_pool", sched.VMName)
	}
	vm, err := corrosion.GetVM(ctx, s.db, sched.VMName)
	if err != nil || vm == nil {
		return fmt.Errorf("vm %q not found", sched.VMName)
	}
	if vm.HostName != s.hostName {
		return nil // not ours; the owning host's scheduler handles it
	}
	// The schedule's bandwidth limit, read once per run, paces every leg
	// that sends this run's data to a peer.
	ctx = withReplicationLimiter(ctx, s.scheduleLimiter(ctx, sched))
	err = s.runVMReplication(ctx, sched, vm, runAt)
	if errors.Is(err, errFirmwareMoveSkipped) {
		// A VM in a live firmware move: this run is skipped, with a log
		// line, and reported as neither a success nor a failure (spec §6.9).
		return nil
	}
	var notOwner *notOwnerNowError
	if errors.As(err, &notOwner) {
		// A host back from a fence or partition still sees the VM's row on
		// itself until it catches up, and the VM may have moved: skipped,
		// neither a failure nor an outcome, and the schedule row is the
		// owner's to record.
		return fmt.Errorf("%w: %v", scheduler.ErrRunSkipped, err)
	}
	s.replicationOutcome(ctx, sched, "vm", vm.Name, tenancy.NormalizeProject(vm.Project), sched.TargetHost, sched.TargetPool, "", err)
	return err
}

// runVMReplication is one run of a VM's replication schedule on the VM's host.
// Its outcome is reported by replicationOutcome (transitions only).
func (s *Server) runVMReplication(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, runAt time.Time) (err error) {
	if err := s.mayReplicateVMAsOwner(ctx, vm); err != nil {
		return err
	}
	// The lock is held for the root disk's run, as always, and released
	// before the other disks: each of those takes it only for its brief
	// point-in-time step (replica_set.go).
	var unlockOnce sync.Once
	vmUnlock := s.lockVMAs(sched.VMName, "replication")
	unlock := func() { unlockOnce.Do(vmUnlock) }
	defer unlock()
	if err := s.firmwareMoveSkip("scheduled replication", vm); err != nil {
		return err
	}
	// A volume move left unresolved: the rows name the file holding the
	// guest's writes before one is copied (move_unresolved.go).
	if err := s.resolveUnresolvedMovesFor(ctx, sched.VMName, health.MoveUseReadsRunning); err != nil {
		return err
	}

	disks, err := corrosion.GetVMDisks(ctx, s.db, sched.VMName)
	if err != nil {
		return fmt.Errorf("list disks: %w", err)
	}
	src := pickReplicaSource(disks)
	if src == nil {
		return fmt.Errorf("vm %q has no disks to replicate", sched.VMName)
	}
	if !isFileBasedDriver(src.StorageType) {
		return fmt.Errorf("replication supports file-based disks only (disk %q is %q)", src.DiskName, src.StorageType)
	}

	// Resolve where the replica lands per the target model: explicit host, or a
	// shared pool (usable cluster-wide so write locally), otherwise a healthy
	// peer that has the pool — falling back to a same-host copy only if the pool
	// is local-only and no peer has it.
	poolLocal, haveLocal := s.resolvePool(ctx, sched.TargetPool)
	shared := haveLocal && isSharedDriver(poolLocal.Driver)
	targetHost := sched.TargetHost
	switch {
	case shared:
		targetHost = s.hostName
	case targetHost == s.hostName:
		// An explicit target that is the host the VM runs on: a same-host
		// copy, as an operator may choose (as on main). But when the VM moved
		// here from the host that replicated INTO this host (its replicas
		// here were written by another host), the schedule is the move's
		// leftover: replicating beside the disk it protects would protect
		// nothing. The move switches it to the host it left; until then it
		// is suspended, never reported as a success.
		if s.vmMovedOntoItsTarget(ctx, sched, vm, src.DiskName) {
			return s.suspendedOnOwnTarget(sched, "vm", vm.Name)
		}
	case targetHost != "":
		// explicit peer → cross-host below
	default:
		peers, _ := corrosion.HostsWithPool(ctx, s.db, sched.TargetPool, s.hostName)
		switch {
		case len(peers) > 0:
			targetHost = peers[0]
		case haveLocal:
			targetHost = s.hostName
		default:
			return fmt.Errorf("no active host has pool %q (and it isn't local); set target_host or use a shared pool", sched.TargetPool)
		}
	}

	// Project isolation (day-2): the VM's project may replicate only into a pool
	// that is global or its own — enforced at RUN time (against the resolved target
	// host) so a schedule created before v37, or any path, can't copy data into
	// another project's pool. Promotion runs through this path too.
	if err := s.admitVMPoolUse(ctx, vm, targetHost, sched.TargetPool); err != nil {
		return fmt.Errorf("replication target pool admission: %w", err)
	}

	ts := runAt.UTC().Format("20060102-150405")

	// The scheduler's point-in-time retry (the last copy was qemu-img -U,
	// pit_retry.go) makes a point-in-time copy or none: it never takes the -U
	// copy again. Any run settles the retry owed; a cron run that again
	// takes the -U copy owes a new one.
	owed := s.pitRetry.take(pitRetryKey(sched))
	defer func() {
		// A run that failed before its copy (a peer, a pool, a session)
		// keeps the retry owed; a point-in-time retry that could not make
		// one does not — the cron runs next.
		if err != nil && owed && !errors.Is(err, errNoPointInTimeCopy) && !s.pitRetry.has(pitRetryKey(sched)) {
			s.pitRetry.set(pitRetryKey(sched))
		}
	}()
	allowForceShare := !scheduler.IsPointInTimeRetry(ctx)

	// The root disk first, exactly as before: its incremental chain, its
	// fallback to a full copy, its mirror for main-build hosts.
	replicateRoot := func() error {
		// Incremental path (opt-in): transfer only dirty extents into a raw replica
		// via the libvirt backup session. Falls back to the full qcow2 copy below
		// when the session can't open (stopped VM / old libvirt) or the transfer
		// fails — resetting the chain so the next run re-bases cleanly.
		if sched.Incremental && s.backupSource != nil {
			err := s.replicateIncremental(ctx, sched, vm, src, targetHost, ts)
			switch {
			case err == nil:
				return nil
			case errors.Is(err, errCheckpointCommit):
				// The transfer succeeded but the new anchor couldn't be recorded. The
				// parent anchor (DB row + bitmap) is intact — do NOT reset the chain or
				// fall back (that would erase the retryable parent). Retry next run.
				slog.Error("incremental replication: checkpoint commit failed; parent anchor preserved for retry",
					"vm", sched.VMName, "pool", sched.TargetPool, "error", err)
				return err
			default:
				// Genuine transfer/session failure: reset the chain so the next run
				// re-bases cleanly, then fall through to the full qcow2 copy.
				if rerr := corrosion.SetReplicationCheckpoint(ctx, s.db, sched.VMName, sched.Repo, ""); rerr != nil {
					slog.Error("incremental replication: chain reset write failed",
						"vm", sched.VMName, "pool", sched.TargetPool, "error", rerr)
				}
				// The full copy below is point-in-time for a running source too
				// (copyVMDiskConsistent: a backup session, else an external
				// snapshot). Only when neither can be made is it main's -U copy,
				// and that replica is recorded and reported as not point-in-time,
				// so the downgrade is never silent.
				slog.Warn("incremental replication fell back to full copy",
					"vm", sched.VMName, "pool", sched.TargetPool, "error", err)
			}
		}

		if targetHost == s.hostName {
			return s.replicateLocal(ctx, sched, vm, src, ts, allowForceShare)
		}
		return s.replicateCrossHost(ctx, sched, vm, src, targetHost, ts, allowForceShare)
	}
	if err := replicateRoot(); err != nil {
		return err
	}
	// Then every other disk, with the same run time, so the run leaves one
	// replica set a promotion recovers whole (replica_set.go).
	unlock()
	return s.replicateOtherDisks(ctx, sched, vm, replicaSetOthers(disks, src), targetHost, ts, allowForceShare,
		func() func() { return s.lockVMAs(sched.VMName, "replication") })
}

// replicateLocal writes the replica into a file-based pool on this host (the
// shared-storage / same-host path), then prunes locally. The copy is
// copyVMDiskConsistent's: point-in-time unless every point-in-time layer
// failed (then, if allowForceShare, main's -U copy, marked).
func (s *Server) replicateLocal(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, src *corrosion.DiskRecord, ts string, allowForceShare bool) error {
	noop := func(*pb.MoveVolumeProgress) error { return nil }
	return s.replicateLocalCopy(ctx, sched, vm, src, ts, func(ctx context.Context, dst string) (copyResult, error) {
		return s.copyVMDiskConsistent(ctx, vm, src, dst, noop, allowForceShare)
	})
}

// notPointInTimeReplica reports a replica the -U copy made and owes the run a
// point-in-time retry at the next scheduler tick.
func (s *Server) notPointInTimeReplica(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, src *corrosion.DiskRecord, what, why string) {
	s.reportNotPointInTime(ctx, vm, src, what, why)
	s.pitRetry.set(pitRetryKey(sched))
}

// replicaCopier copies a disk image to dst. convertQcow2 in production; the
// parameter exists so the publication contract around it can be tested without
// a real qemu-img failure, which is not something a test can stage.
type replicaCopier func(ctx context.Context, src, dst string, emit func(*pb.MoveVolumeProgress) error) error

func (s *Server) replicateLocalWith(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, src *corrosion.DiskRecord, ts string, convert replicaCopier) error {
	noop := func(*pb.MoveVolumeProgress) error { return nil }
	return s.replicateLocalCopy(ctx, sched, vm, src, ts, func(ctx context.Context, dst string) (copyResult, error) {
		return copyResult{method: copyPlain}, convert(ctx, src.Path, dst, noop)
	})
}

// replicateLocalCopy is replicateLocal with the copy given: it writes into
// dst and says how it did, and a copy that is not point-in-time is recorded
// (NotPointInTime) and reported as such.
func (s *Server) replicateLocalCopy(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, src *corrosion.DiskRecord, ts string, copyTo func(ctx context.Context, dst string) (copyResult, error)) error {
	dstPool, ok := s.resolvePool(ctx, sched.TargetPool)
	if !ok {
		return fmt.Errorf("target pool %q not configured on host %q", sched.TargetPool, s.hostName)
	}
	if !isFileBasedDriver(dstPool.Driver) {
		return fmt.Errorf("target pool %q driver %q is not file-based", sched.TargetPool, dstPool.Driver)
	}
	if err := s.checkPoolForWrite(ctx, sched.TargetPool, dstPool); err != nil {
		return err
	}
	drv, err := storage.New(s.dataDir, storage.Config{
		Driver: dstPool.Driver, Source: dstPool.Source, Target: dstPool.Target, Options: dstPool.Options,
	})
	if err != nil {
		return fmt.Errorf("construct target driver: %w", err)
	}
	dstDir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: dstPool.Driver, Source: dstPool.Source, Target: dstPool.Target})
	if err != nil {
		return fmt.Errorf("resolve target dir: %w", err)
	}
	if err := prepareTargetPool(ctx, drv, dstDir); err != nil {
		return fmt.Errorf("prepare target pool: %w", err)
	}
	// The replica goes into the VM's own directory of the replica area, with a
	// record naming its project, VM, disk and schedule (replica_records.go).
	key := replicaScheduleKey(sched)
	rec := newReplicaRecord(vm.Project, sched.VMName, src.DiskName, key, ts, "qcow2")
	rec.Source = s.hostName
	if filepath.Join(replicaOwnerDir(dstDir, rec.Project, rec.VM), rec.File) == src.Path {
		return fmt.Errorf("source and destination resolve to the same path")
	}
	var res copyResult
	areaPath, err := publishRecordedReplicaRec(ctx, dstDir, &rec, func(tmp string) error {
		r, err := copyTo(ctx, tmp)
		res = r
		rec.NotPointInTime = err == nil && !r.method.pointInTime()
		return err
	})
	if err != nil {
		s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "error", fmt.Sprintf("%s → %s: %v", src.DiskName, sched.TargetPool, err))
		return fmt.Errorf("replicate %s: %w", src.DiskName, err)
	}
	// A main-build host promotes only top-level replicas (replica_mirror.go),
	// and of the root disk only: another disk's mirror is never read there.
	if !isOtherSetDisk(ctx) && s.mirrorReplicasToTopLevel(ctx) {
		if err := s.mirrorFullLocal(ctx, sched.TargetPool, replicaKeyOf(vm, src.DiskName), areaPath,
			legacyReplicaName(rec.VM, rec.Disk, rec.Taken, rec.Format)); err != nil {
			s.mirrorFailed(ctx, sched.VMName, src.DiskName, sched.TargetPool, s.hostName, err)
		}
	}
	pruned, perr := s.pruneRecordedReplicas(ctx, sched.TargetPool, vm.Project, sched.VMName, src.DiskName, key, sched.KeepReplicas)
	if perr != nil {
		slog.Warn("replication: prune skipped", "vm", sched.VMName, "pool", sched.TargetPool, "error", perr)
	}
	pruned += s.pruneEarlierReplicasAnywhere(ctx, sched.TargetPool, s.hostName, vm, src.DiskName, sched.KeepReplicas)
	detail := fmt.Sprintf("%s → %s (%s)", src.DiskName, sched.TargetPool, rec.File)
	if res.method != "" && res.method != copyPlain {
		detail += "; " + string(res.method)
	}
	if pruned > 0 {
		detail += fmt.Sprintf(", pruned %d old", pruned)
	}
	s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "ok", detail)
	if rec.NotPointInTime {
		s.notPointInTimeReplica(ctx, sched, vm, src, fmt.Sprintf("replica %s in pool %s", rec.File, sched.TargetPool), res.why)
	}
	return nil
}

// replicateCrossHost replicates to a local scratch file, streams it to the
// target host's pool as a recorded replica (UploadStoragePoolContent with a
// replica header), removes the scratch, then prunes that schedule's old
// replicas on the peer.
func (s *Server) replicateCrossHost(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, src *corrosion.DiskRecord, targetHost, ts string, allowForceShare bool) error {
	ctx = s.withReplicaOwner(ctx, vm)
	key := replicaScheduleKey(sched)
	rec := newReplicaRecord(vm.Project, sched.VMName, src.DiskName, key, ts, "qcow2")
	rec.Source = s.hostName
	// The receiver proves it records replicas BEFORE anything is spent on
	// it: no full local copy for a host that would refuse it.
	client, closeConn, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		return fmt.Errorf("reach target host %q: %w", targetHost, err)
	}
	defer closeConn()

	legacy, err := proveReplicaRecords(ctx, client, sched.TargetPool, targetHost, rec.Project, rec.VM)
	if err != nil {
		s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "error", fmt.Sprintf("%s → %s@%s: %v", src.DiskName, sched.TargetPool, targetHost, err))
		return err
	}

	scratchDir := filepath.Join(s.dataDir, "replicate-scratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return fmt.Errorf("scratch dir: %w", err)
	}
	f, err := os.CreateTemp(scratchDir, ".repl-*.tmp")
	if err != nil {
		return fmt.Errorf("scratch file: %w", err)
	}
	scratch := f.Name()
	_ = f.Close()
	defer os.Remove(scratch)

	noop := func(*pb.MoveVolumeProgress) error { return nil }
	res, err := s.copyVMDiskConsistent(ctx, vm, src, scratch, noop, allowForceShare)
	if err != nil {
		s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "error", fmt.Sprintf("%s → %s@%s: local copy: %v", src.DiskName, sched.TargetPool, targetHost, err))
		return fmt.Errorf("local scratch replicate: %w", err)
	}
	rec.NotPointInTime = !res.method.pointInTime()

	sent := rec.File
	markKept := true
	if legacy {
		// A receiver on an older build: main's upload of a runner-named file
		// to its pool's top level, which it keeps and promotes as main did.
		// It has no record to carry the not-point-in-time mark.
		sent = legacyReplicaName(rec.VM, rec.Disk, rec.Taken, rec.Format)
		err = streamLegacyReplica(ctx, client, scratch, sched.TargetPool, targetHost, replicaKeyOf(vm, src.DiskName), sent)
		markKept = !rec.NotPointInTime
	} else {
		var resp *pb.PushReplicaResponse
		resp, err = streamReplicaToPool(ctx, client, scratch, sched.TargetPool, targetHost, rec)
		// A receiver that records replicas but predates the mark drops it.
		markKept = err != nil || !rec.NotPointInTime || resp.GetNotPointInTimeRecorded()
	}
	if err != nil {
		s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "error", fmt.Sprintf("%s → %s@%s: upload: %v", src.DiskName, sched.TargetPool, targetHost, err))
		return fmt.Errorf("stream to %q: %w", targetHost, err)
	}
	// A main-build host promotes only top-level replicas (replica_mirror.go):
	// the same data again, under main's name at the top level.
	if !legacy && !isOtherSetDisk(ctx) && s.mirrorReplicasToTopLevel(ctx) {
		if err := streamLegacyReplica(ctx, client, scratch, sched.TargetPool, targetHost, replicaKeyOf(vm, src.DiskName),
			legacyReplicaName(rec.VM, rec.Disk, rec.Taken, rec.Format)); err != nil {
			s.mirrorFailed(ctx, sched.VMName, src.DiskName, sched.TargetPool, targetHost, err)
		}
	}

	pruned := 0
	if !legacy {
		pruned = s.pruneReplicasAnywhere(ctx, sched.TargetPool, targetHost, vm.Project, sched.VMName, src.DiskName, key, sched.KeepReplicas)
	}
	pruned += s.pruneEarlierReplicasAnywhere(ctx, sched.TargetPool, targetHost, vm, src.DiskName, sched.KeepReplicas)
	detail := fmt.Sprintf("%s → %s@%s (%s)", src.DiskName, sched.TargetPool, targetHost, sent)
	if res.method != copyPlain {
		detail += "; " + string(res.method)
	}
	if pruned > 0 {
		detail += fmt.Sprintf(", pruned %d old", pruned)
	}
	s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "ok", detail)
	if rec.NotPointInTime {
		why := res.why
		if !markKept {
			why += fmt.Sprintf("; host %s runs an older build that cannot record the not-point-in-time mark, so its record does not carry it", targetHost)
		}
		s.notPointInTimeReplica(ctx, sched, vm, src, fmt.Sprintf("replica %s in pool %s on %s", sent, sched.TargetPool, targetHost), why)
	}
	return nil
}

// streamReplicaToPool sends a local file to a peer's pool as the recorded
// replica rec, over the peer-only PushReplica, charging each chunk to the
// run's limiter.
func streamReplicaToPool(ctx context.Context, client pb.LiteVirtClient, path, pool, host string, rec replicaRecord) (*pb.PushReplicaResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	up, err := client.PushReplica(ctx)
	if err != nil {
		return nil, err
	}
	if err := up.Send(&pb.PushReplicaRequest{PoolName: pool, Host: host, Replica: rec.toPB()}); err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := chargeReplication(ctx, n); err != nil {
				return nil, err
			}
			if err := up.Send(&pb.PushReplicaRequest{Chunk: buf[:n]}); err != nil {
				return nil, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	return up.CloseAndRecv()
}

// streamLegacyReplica sends a local file to an older build's pool as main's
// runner did: an upload of the runner name to the pool's top level. The
// content call says it is the daemon's, about k's replicas, so a receiver
// that knows the marker records it as k's replica. Each chunk is charged to
// the run's limiter.
func streamLegacyReplica(ctx context.Context, client pb.LiteVirtClient, path, pool, host string, k replicaKey, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	up, err := client.UploadStoragePoolContent(withReplicaContentView(ctx, k, "", false))
	if err != nil {
		return err
	}
	if err := up.Send(&pb.UploadStoragePoolContentRequest{PoolName: pool, Host: host, Filename: name}); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := chargeReplication(ctx, n); err != nil {
				return err
			}
			if err := up.Send(&pb.UploadStoragePoolContentRequest{Chunk: buf[:n]}); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	_, err = up.CloseAndRecv()
	return err
}

// pruneReplicasRemote keeps the newest keepN pool-recorded (or legacy
// unrecorded) replicas of k's disk at the top level of a peer's pool — those
// written before replicas moved into the replica area (replica_records.go),
// which replication runs no longer write — deleting older ones via DeleteStoragePoolContent. It lists and
// deletes as the daemon, for this VM's replicas only (remoteReplicaNames), so
// the peer refuses any other file. Returns the count deleted (best-effort;
// errors are logged by the caller's event).
func (s *Server) pruneReplicasRemote(ctx context.Context, client pb.LiteVirtClient, pool, host string, k replicaKey, keepN int) int {
	if keepN <= 0 {
		return 0
	}
	return s.pruneTopLevelReplicasRemote(ctx, client, pool, host, k, keepN)
}

// pruneTopLevelReplicasRemote is pruneReplicasRemote keeping exactly keep (0:
// none).
func (s *Server) pruneTopLevelReplicasRemote(ctx context.Context, client pb.LiteVirtClient, pool, host string, k replicaKey, keep int) int {
	names := s.remoteReplicaNames(ctx, client, pool, host, k, "", false)
	if len(names) <= keep {
		return 0
	}
	ctx = withReplicaContentView(ctx, k, "", false)
	deleted := 0
	for _, n := range names[:len(names)-keep] {
		if _, err := client.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: pool, Host: host, Filename: n}); err == nil {
			deleted++
		}
	}
	return deleted
}

// replicateIncremental transfers only the disk's dirty extents into a new raw
// replica, forked from the previous one. It opens a libvirt backup session
// (pull-mode NBD) to read guest-visible changed extents since the schedule's
// last checkpoint; a session that opens non-incrementally (no parent, or parent
// gone) produces a full raw push. On success it advances the schedule's
// checkpoint chain and prunes old replicas. Returns an error to let the caller
// fall back to a full qcow2 copy.
func (s *Server) replicateIncremental(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, src *corrosion.DiskRecord, targetHost, ts string) error {
	ctx = s.withReplicaOwner(ctx, vm)
	key := replicaScheduleKey(sched)
	// A receiver on an older build keeps main's top-level replicas: the
	// fork base is the newest of those, and the push is main's.
	legacy := false
	if targetHost != s.hostName {
		l, err := s.replicaReceiverLegacy(ctx, targetHost, sched.TargetPool, vm.Project, sched.VMName)
		if err != nil {
			return err
		}
		legacy = l
	}
	// Read the anchor from the per-VM replication_checkpoints table keyed by the
	// REAL vm (sched.VMName), NOT sched.LastCheckpoint — for fan-out scopes the
	// schedule row's vm_name is a sentinel, so sched.LastCheckpoint is always
	// empty and incremental silently degraded to full copies (bug-sweep #6).
	parentCP, _ := corrosion.GetReplicationCheckpoint(ctx, s.db, sched.VMName, sched.Repo)
	// The fork base is the replica the run that created parentCP wrote, and no
	// other: the dirty extents since parentCP applied to any other file graft
	// increments onto a base they do not continue, a silently wrong replica.
	// A checkpoint names its run (replCheckpointName of the run's time), and so
	// does the replica that run wrote, so the base is chosen by that identity:
	// not "the newest", which after a reversal or a re-targeted run can be a
	// replica from another period or another source. No such replica on the
	// target: a full push.
	var base string
	if anchor, ok := checkpointTaken(src.DiskName, parentCP); ok {
		if legacy {
			base = s.legacyRawReplicaTakenAt(ctx, sched.TargetPool, targetHost, replicaKeyOf(vm, src.DiskName), legacyReplicaName(sched.VMName, src.DiskName, anchor, "raw"))
		} else {
			base = s.rawReplicaTakenAt(ctx, sched.TargetPool, targetHost, vm.Project, sched.VMName, src.DiskName, key, anchor)
		}
	}
	incrCP := ""
	if base != "" {
		incrCP = parentCP // the base its own checkpoint continues → real incremental
	}

	newCP := replCheckpointName(src.DiskName, ts)
	session, err := s.backupSource.BeginBackup(sched.VMName, src.Path, incrCP, newCP)
	if err != nil {
		return fmt.Errorf("begin backup session: %w", err)
	}
	defer session.Close()
	// BeginBackup creates newCP durably (independent of the backup job). If the
	// transfer below fails, newCP would never be recorded and never cleaned up —
	// an unbounded checkpoint/bitmap leak on a flaky link (bug-sweep #7). Delete
	// it on any failure; the parent anchor (incrCP) is preserved for a retry.
	committed := false
	defer func() {
		if !committed {
			_ = s.backupSource.DeleteCheckpoint(sched.VMName, newCP)
		}
	}()
	if !session.Incremental() {
		base = "" // session decided full (e.g. parent checkpoint vanished)
	}
	extents, err := session.ChangedExtents()
	if err != nil {
		return fmt.Errorf("changed extents: %w", err)
	}
	totalSize := session.Size()
	rec := newReplicaRecord(vm.Project, sched.VMName, src.DiskName, key, ts, "raw")
	rec.Source = s.hostName

	if targetHost == s.hostName {
		if err := s.applyIncrementLocal(ctx, sched.TargetPool, rec, base, totalSize, session, extents); err != nil {
			return err
		}
	} else {
		if err := s.applyIncrementRemote(ctx, targetHost, sched.TargetPool, rec, base, totalSize, session, extents); err != nil {
			return err
		}
	}
	// A main-build host promotes only top-level replicas (replica_mirror.go).
	// To an older receiver the push above already was main's.
	if !legacy && s.mirrorReplicasToTopLevel(ctx) {
		if err := s.mirrorIncrement(ctx, targetHost, sched.TargetPool, replicaKeyOf(vm, src.DiskName), rec, base, totalSize, session, extents); err != nil {
			s.mirrorFailed(ctx, sched.VMName, src.DiskName, sched.TargetPool, targetHost, err)
		}
	}

	// Advance the chain: record the new anchor, then drop the old one. On failure
	// this returns errCheckpointCommit and leaves the parent anchor intact.
	if err := s.advanceReplicationCheckpoint(ctx, sched.VMName, sched.Repo, parentCP, newCP); err != nil {
		return err
	}
	committed = true // newCP is now the recorded anchor — keep it

	pruned := 0
	if !legacy {
		pruned = s.pruneReplicasAnywhere(ctx, sched.TargetPool, targetHost, vm.Project, sched.VMName, src.DiskName, key, sched.KeepReplicas)
	}
	pruned += s.pruneEarlierReplicasAnywhere(ctx, sched.TargetPool, targetHost, vm, src.DiskName, sched.KeepReplicas)
	mode := "full"
	if base != "" {
		mode = "incremental"
	}
	detail := fmt.Sprintf("%s → %s@%s (%s, %s, %d extent(s))", src.DiskName, sched.TargetPool, targetHost, ts, mode, len(extents))
	if pruned > 0 {
		detail += fmt.Sprintf(", pruned %d old", pruned)
	}
	s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "ok", detail)
	return nil
}

// advanceReplicationCheckpoint commits the checkpoint chain forward. It records
// newCP as the schedule's anchor FIRST — checked — and only after that write lands
// does it drop the superseded parent bitmap. If the anchor write fails it returns
// errCheckpointCommit WITHOUT touching the parent, so the caller preserves a fully
// retryable state (parent bitmap + parent DB anchor both intact) and the just-
// created newCP is cleaned up by replicateIncremental's deferred rollback.
func (s *Server) advanceReplicationCheckpoint(ctx context.Context, vmName, repo, parentCP, newCP string) error {
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, vmName, repo, newCP); err != nil {
		return fmt.Errorf("%w: record %q for %s/%s: %v", errCheckpointCommit, newCP, vmName, repo, err)
	}
	// Anchor is durable; the parent is now superseded. Dropping its bitmap is
	// best-effort — a failure only leaks a bitmap, it can't break the chain.
	if parentCP != "" && parentCP != newCP {
		if err := s.backupSource.DeleteCheckpoint(vmName, parentCP); err != nil {
			slog.Warn("replication: dropping superseded parent checkpoint failed (bitmap leak; not fatal)",
				"vm", vmName, "parent", parentCP, "error", err)
		}
	}
	return nil
}

// rawReplicaTakenAt returns the file of the raw replica this schedule recorded
// for (project, vm, disk) in pool on host at taken, or "" if there is none. It
// is the fork base for an incremental push, so it is chosen from the VM's own
// records only — never a file that merely shares a name prefix — and only the
// one its checkpoint continues.
func (s *Server) rawReplicaTakenAt(ctx context.Context, pool, host, project, vm, disk, schedule, taken string) string {
	for _, r := range s.replicaRecordsOn(ctx, pool, host, project, vm) {
		if r.Disk == disk && r.Schedule == schedule && r.Format == "raw" && r.Taken == taken {
			return r.File
		}
	}
	return ""
}

// checkpointTaken is the run time a replication checkpoint names
// (replCheckpointName), when it is one.
func checkpointTaken(disk, cp string) (string, bool) {
	taken, ok := strings.CutPrefix(cp, "lvrepl-"+sanitizeName(disk)+"-")
	if !ok || !replicaTakenRE.MatchString(taken) {
		return "", false
	}
	return taken, true
}

// replicaReceiverLegacy reports whether host is on a build that predates
// replica records (proveReplicaRecords).
func (s *Server) replicaReceiverLegacy(ctx context.Context, host, pool, project, vm string) (bool, error) {
	client, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return false, fmt.Errorf("reach host %q: %w", host, err)
	}
	defer closeConn()
	return proveReplicaRecords(ctx, client, pool, host, project, vm)
}

// legacyRawReplicaTakenAt is want when it is a raw top-level replica of k's disk
// in pool on host (an older build's: remoteReplicaNames matches it by its exact
// runner name, never one another project's VM could have written), or "".
func (s *Server) legacyRawReplicaTakenAt(ctx context.Context, pool, host string, k replicaKey, want string) string {
	client, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return ""
	}
	defer closeConn()
	for _, n := range s.remoteReplicaNames(ctx, client, pool, host, k, "", false) {
		if n == want {
			return n
		}
	}
	return ""
}

// applyIncrementLocal writes the new raw replica into a same-host pool.
func (s *Server) applyIncrementLocal(ctx context.Context, pool string, rec replicaRecord, base string, totalSize int64, r io.ReaderAt, extents [][2]int64) error {
	apply := func(f *os.File) error {
		return forEachExtentChunk(r, extents, totalSize, func(off int64, data []byte) error {
			_, werr := f.WriteAt(data, off)
			return werr
		})
	}
	_, err := s.receiveRawReplica(ctx, pool, rec, base, totalSize, apply)
	return err
}

// receiveRawReplica materializes the raw replica rec in pool on this host —
// forked from base, a recorded raw replica of the same disk and schedule, when
// set — and records it. Shared by the local incremental path and the
// PushReplicaIncrement receiver.
func (s *Server) receiveRawReplica(ctx context.Context, pool string, rec replicaRecord, base string, totalSize int64, apply func(*os.File) error) (string, error) {
	if err := rec.validate(); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "%v", err)
	}
	poolDir, err := s.replicaPoolDir(ctx, pool)
	if err != nil {
		return "", err
	}
	if base != "" {
		b, _, ok := recordedReplica(poolDir, rec.Project, rec.VM, base)
		if !ok || b.Disk != rec.Disk || b.Schedule != rec.Schedule || b.Format != "raw" {
			return "", status.Errorf(codes.FailedPrecondition,
				"base %q is not a recorded raw replica of vm %q disk %q for this schedule", base, rec.VM, rec.Disk)
		}
	}
	dir, err := ownerDirChecked(poolDir, rec.Project, rec.VM, true)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "replica directory: %v", err)
	}
	dest, err := forkRawAndApply(dir, rec.File, base, totalSize, apply)
	if err != nil {
		return "", err
	}
	if err := writeReplicaRecord(dir, rec); err != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("record replica: %w", err)
	}
	return dest, nil
}

// applyIncrementRemote streams the new raw replica to a peer's pool via
// PushReplicaIncrement (dirty extents only; the peer forks from base),
// charging each extent chunk to the run's limiter.
func (s *Server) applyIncrementRemote(ctx context.Context, host, pool string, rec replicaRecord, base string, totalSize int64, r io.ReaderAt, extents [][2]int64) error {
	client, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return fmt.Errorf("reach host %q: %w", host, err)
	}
	defer closeConn()
	// An older receiver's PushReplicaIncrement ignores the record and writes
	// the bytes as a bare name in its pool: to one, the push is main's — the
	// runner name at the top level, forked from base, a top-level replica
	// there (replicateIncremental chose it so).
	legacy, err := proveReplicaRecords(ctx, client, pool, host, rec.Project, rec.VM)
	if err != nil {
		return err
	}
	up, err := client.PushReplicaIncrement(ctx)
	if err != nil {
		return err
	}
	hdr := &pb.PushReplicaIncrementRequest{
		PoolName: pool, Host: host, Filename: rec.File, Base: base, TotalSize: totalSize,
		Replica: rec.toPB(),
	}
	if legacy {
		hdr.Filename, hdr.Replica = legacyReplicaName(rec.VM, rec.Disk, rec.Taken, rec.Format), nil
	}
	if err := up.Send(hdr); err != nil {
		return err
	}
	if err := forEachExtentChunk(r, extents, totalSize, func(off int64, data []byte) error {
		if err := chargeReplication(ctx, len(data)); err != nil {
			return err
		}
		return up.Send(&pb.PushReplicaIncrementRequest{Offset: off, Data: data})
	}); err != nil {
		return err
	}
	resp, err := up.CloseAndRecv()
	if err != nil {
		return err
	}
	if !legacy && !resp.GetReplicaRecorded() {
		return fmt.Errorf("host %q wrote the increment without recording it as a replica", host)
	}
	return nil
}

// pruneReplicasAnywhere prunes this schedule's old recorded replicas of
// (project, vm, disk) in the target pool, local or remote.
func (s *Server) pruneReplicasAnywhere(ctx context.Context, pool, host, project, vm, disk, schedule string, keepN int) int {
	if keepN <= 0 {
		return 0
	}
	if host == s.hostName {
		n, err := s.pruneRecordedReplicas(ctx, pool, project, vm, disk, schedule, keepN)
		if err != nil {
			slog.Warn("replication: prune skipped", "vm", vm, "pool", pool, "error", err)
		}
		return n
	}
	client, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return 0
	}
	defer closeConn()
	resp, err := client.PruneReplicas(ctx, &pb.PruneReplicasRequest{
		PoolName: pool, Host: host, Project: tenancy.NormalizeProject(project), Vm: vm,
		Disk: disk, Schedule: schedule, Keep: int32(keepN),
	})
	if err != nil {
		slog.Warn("replication: remote prune failed", "vm", vm, "pool", pool, "host", host, "error", err)
		return 0
	}
	return int(resp.GetDeleted())
}

// pruneEarlierReplicasAnywhere keeps a schedule's keep_replicas across both
// places a VM disk's replicas live. Replicas written before replicas moved
// into the replica area sit at the pool's top level (pool-recorded, or
// unrecorded under their exact runner name: replica_match.go); runs never
// write there now, so they are always older than the area's. Of them, the
// newest keepN minus the disk's replicas in the area stay — none once the
// area holds keepN — and never one a live disk uses. keepN <= 0 keeps all.
// Best-effort: the count deleted.
func (s *Server) pruneEarlierReplicasAnywhere(ctx context.Context, pool, host string, vm *corrosion.VMRecord, disk string, keepN int) int {
	if keepN <= 0 {
		return 0
	}
	if host == "" {
		host = s.hostName
	}
	inArea := 0
	for _, r := range s.replicaRecordsOn(ctx, pool, host, vm.Project, vm.Name) {
		if r.Disk == disk {
			inArea++
		}
	}
	keep := max(keepN-inArea, 0)
	// A host on an older build cannot see the replica area: if it coordinates
	// a failover, the top-level replicas are all it can promote. While any
	// host may be one, they are kept as main kept them (keepN), never cut for
	// the area's.
	if keep < keepN && !s.everyHostListsReplicas(ctx) {
		keep = keepN
	}
	k := replicaKeyOf(vm, disk)
	if host == s.hostName {
		dir, err := s.replicaPoolDir(ctx, pool)
		if err != nil {
			return 0
		}
		return s.pruneTopLevelReplicas(ctx, dir, k, keep)
	}
	client, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return 0
	}
	defer closeConn()
	return s.pruneTopLevelReplicasRemote(ctx, client, pool, host, k, keep)
}

// forEachExtentChunk reads each extent from r in ≤1 MiB pieces and hands each
// (offset,data) to fn — the sink is either a local WriteAt or a gRPC Send. A
// reusable buffer is safe: both sinks consume the bytes synchronously.
func forEachExtentChunk(r io.ReaderAt, extents [][2]int64, totalSize int64, fn func(off int64, data []byte) error) error {
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	for _, e := range extents {
		off, length := e[0], e[1]
		if off < 0 || length <= 0 {
			continue
		}
		if off+length > totalSize {
			length = totalSize - off
		}
		end := off + length
		for pos := off; pos < end; {
			n := int64(chunk)
			if end-pos < n {
				n = end - pos
			}
			got, rerr := readFullAt(r, buf[:n], pos)
			if got > 0 {
				if err := fn(pos, buf[:got]); err != nil {
					return err
				}
			}
			if rerr != nil {
				return rerr
			}
			pos += int64(got)
		}
	}
	return nil
}

// readFullAt fills p from r at off, looping over short reads. A short read that
// ends in io.EOF before filling p is a real error for our bounded extents.
func readFullAt(r io.ReaderAt, p []byte, off int64) (int, error) {
	total := 0
	for total < len(p) {
		n, err := r.ReadAt(p[total:], off+int64(total))
		total += n
		if err != nil {
			if err == io.EOF && total == len(p) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

// pickReplicaSource chooses the disk to replicate: the root disk if present,
// else the first disk.
func pickReplicaSource(disks []corrosion.DiskRecord) *corrosion.DiskRecord {
	for i := range disks {
		if disks[i].DiskName == "root" {
			return &disks[i]
		}
	}
	if len(disks) > 0 {
		return &disks[0]
	}
	return nil
}

// isSharedDriver reports whether a pool driver is reachable from multiple hosts
// (so a replica written by the source is usable by a peer on failover).
func isSharedDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "nfs", "ceph", "iscsi":
		return true
	}
	return false
}

// pruneLocalReplicas keeps the newest keepN top-level replicas of k's disk in
// dir — pool-recorded or legacy ones, written before replicas moved into the
// replica area (replica_records.go)
// (localReplicaNames: by record, or an unrecorded file by its exact name;
// never an operator's copy), deleting older ones — never one a live disk uses
// (a promotion that kept the replica as its backing file; on shared storage,
// on any host), as a remote prune's delete refuses too. keepN <= 0 keeps
// all. Returns the count deleted.
func (s *Server) pruneLocalReplicas(ctx context.Context, dir string, k replicaKey, keepN int) int {
	if keepN <= 0 {
		return 0
	}
	return s.pruneTopLevelReplicas(ctx, dir, k, keepN)
}

// pruneTopLevelReplicas is pruneLocalReplicas keeping exactly keep (0: none).
func (s *Server) pruneTopLevelReplicas(ctx context.Context, dir string, k replicaKey, keep int) int {
	names := s.localReplicaNames(ctx, dir, k, "", false) // oldest first
	if len(names) <= keep {
		return 0
	}
	backing, berr := s.supersededBacking(ctx)
	if berr != nil {
		return 0 // cannot tell what a set-aside copy is layered on: prune nothing
	}
	deleted := 0
	for _, n := range names[:len(names)-keep] {
		p := filepath.Join(dir, n)
		if backing.has(p) {
			continue
		}
		if owners, err := s.replicaUsers(ctx, p); err != nil || len(owners) > 0 {
			continue
		}
		if held, why := s.keptHolds(ctx, p); held {
			slog.Warn("replication: a replica a kept disk holds is not pruned", "replica", p, "why", why)
			continue
		}
		if os.Remove(p) == nil {
			deleted++
			if err := s.forgetPoolUpload(ctx, p); err != nil {
				slog.Warn("replication: pruned replica's record not dropped", "replica", p, "error", err)
			}
		}
	}
	return deleted
}

// replicaUsers returns the live disks that use the replica at path: this
// host's, and on shared storage every host's. Another host may mount the
// store elsewhere, where the same file has another path; this host cannot see
// its mounts, so any live disk on another host whose file or backing file has
// this file's name counts (replica names carry their VM, disk and run time,
// so this keeps more, never fewer).
func (s *Server) replicaUsers(ctx context.Context, path string) ([]corrosion.DiskRecord, error) {
	if !sharedStoreOf(filepath.Dir(path)).Shared {
		return s.liveDiskOwners(ctx, s.hostName, path)
	}
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return nil, err
	}
	named, err := corrosion.DisksReferencingName(ctx, s.db, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	for _, d := range named {
		if d.HostName != s.hostName {
			refs = append(refs, d)
		}
	}
	return refs, nil
}

// replicaKeyFor is the replica key of vmName's disk, in the VM's project;
// false when the VM's row cannot be read.
func (s *Server) replicaKeyFor(ctx context.Context, vmName, disk string) (replicaKey, bool) {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return replicaKey{VM: vmName, Disk: disk}, false
	}
	return replicaKeyOf(vm, disk), true
}

// publishReplica runs write against a temporary sibling of dst and renames it
// into place only once it has succeeded and produced something.
//
// The local replication path used to hand the FINAL name to the converter. A
// crash, a cancellation or a conversion error therefore left a truncated file
// called `<vm>-<disk>-<ts>.qcow2`, which is exactly the name promotion looks
// for — and promotion picks the lexically newest match, so the freshest
// candidate on a failing schedule was the broken one. On a failure the file was
// not even removed, so it stayed the newest until the next successful run.
//
// The temp name is dotted and has no record, so nothing selects it: a run that
// dies between the two steps leaves litter, not a promotable lie. The
// cross-host path already worked this way — its upload lands in an
// os.CreateTemp file and is renamed by the receiver — so this makes the two
// paths agree. The placement is no-clobber: an existing dst is refused.
//
// The emptiness check is the floor, not a validation: it catches a converter
// that reported success and wrote nothing. A deeper check (qemu-img check,
// format and size against the source) belongs with the replica record
// (replica_records.go), which is what promotion now selects on.
// syncPath flushes a file or directory to stable storage. A var so a test can
// observe the order publishReplica syncs in.
var syncPath = func(path string) error {
	f, err := storage.OpenPoolFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func publishReplica(ctx context.Context, dst string, write func(tmp string) error) error {
	_ = ctx
	// A ".repl-*.tmp" name in the destination directory: the rename stays on
	// one filesystem, no record names it, and a copy a crash left
	// half-written is collected by sweepStaleStagingTemps. The earlier
	// ".<name>.partial" matched no sweep pattern, and the next run's new
	// timestamp never reused it, so each crash leaked a full-size image.
	f, err := storage.CreatePoolTemp(filepath.Dir(dst), ".repl-*.tmp")
	if err != nil {
		return fmt.Errorf("create replica temp: %w", err)
	}
	tmp := f.Name()
	_ = f.Close()
	if err := write(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	fi, err := os.Stat(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replica was not written: %w", err)
	}
	if fi.Size() == 0 {
		_ = os.Remove(tmp)
		return fmt.Errorf("replica is empty; refusing to publish %s", filepath.Base(dst))
	}
	// Durable before promotable. qemu-img convert does not flush its output by
	// default and a rename is metadata only, so without these a power loss
	// could leave the final, promotable name on a file whose data never
	// reached the disk. The data is synced before the rename, the directory
	// after it so the rename itself survives.
	if err := syncPath(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("sync replica before publishing: %w", err)
	}
	// Never over a file already there.
	if err := placeNoClobber(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("publish replica: %w", err)
	}
	if err := syncPath(filepath.Dir(dst)); err != nil {
		// The rename happened but may not survive a crash. Withdraw it rather
		// than leave a promotable name the storage would not vouch for.
		_ = os.Remove(dst)
		return fmt.Errorf("sync replica directory after publishing: %w", err)
	}
	return nil
}

// sourceIsShutOff reports whether a VM's disks are definitely closed, which is
// the only case where the full-copy fallback is a consistent copy.
//
// The store's "stopped" is not enough. The coarse libvirt state folds paused
// and pm-suspended domains into "stopped", and qemu still holds their images
// open — a guest resumed mid-copy smears it exactly as a running one does. So
// this asks libvirt for the state reason, as recoveryDomainDisposition does,
// and answers true only for a genuine shut-off. Anything it cannot establish —
// no libvirt connection, an error, a state it does not recognise — is false.
func (s *Server) sourceIsShutOff(vm *corrosion.VMRecord) bool {
	if vm.State != "stopped" || s.virt == nil {
		return false
	}
	st, err := s.virt.DomainStateReason(vm.Name)
	if err != nil {
		slog.Warn("replication: live domain state indeterminate; treating the source as open",
			"vm", vm.Name, "error", err)
		return false
	}
	return st.State == "stopped" && st.Reason != "paused" && st.Reason != "pmsuspended"
}

// vmMovedOntoItsTarget reports whether vm's schedule targets the host the VM
// now runs on because the VM moved onto its replica target: the newest replica
// this schedule recorded here was written by another host. A schedule that has
// only ever replicated here from here (an operator's same-host copy), or none
// yet, is not.
//
// Only a per-VM schedule: a shared (pool, project, cluster) schedule is never
// switched for one of its VMs, so a VM that moves onto its explicit target
// keeps replicating into the pool there, as on main, rather than being
// suspended with no way out.
func (s *Server) vmMovedOntoItsTarget(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, disk string) bool {
	if sched.Origin != "" {
		return false
	}
	key := replicaScheduleKey(sched)
	newest := replicaRecord{}
	for _, r := range s.replicaRecordsOn(ctx, sched.TargetPool, s.hostName, vm.Project, vm.Name) { // oldest first
		if r.Disk == disk && r.Schedule == key {
			newest = r
		}
	}
	return newest.Source != "" && newest.Source != s.hostName
}
