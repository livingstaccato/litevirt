package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/storage"
)

// Main's top-level replica, written beside the replica area during a rolling
// upgrade.
//
// A host on main's build (3e4ba50b) cannot see the replica area. If it
// coordinates a failover, it lists the replica host's pool with its host
// certificate and promotes the lexically newest top-level file named
// <vm>-<disk>-<ts>.qcow2 or .raw (findReplicaHost, promote.go:444-489 at
// 3e4ba50b). A replica written only into the area is invisible to it, so it
// would promote the last replica written before the upgrade, where main
// promoted the latest.
//
// While any host cannot answer ListReplicas — the signal that also holds the
// top-level prune (everyHostListsReplicas) — every run that writes a replica
// into the area also writes main's: the runner name at the pool's top level,
// in main's format (replication_runner.go:194 and :222 for a full copy,
// :365 for an incremental raw one, at 3e4ba50b), with the same data. Once
// every host answers, the runs stop writing it, and the prune rule cuts the
// top-level copies away (never one a disk uses).

// mirrorReplicasToTopLevel reports whether a run must also write main's
// top-level replica: some host may be one that promotes only those.
func (s *Server) mirrorReplicasToTopLevel(ctx context.Context) bool {
	return !s.everyHostListsReplicas(ctx)
}

// mirrorFailed reports a top-level copy that could not be written. The
// replica in the area stands; a main-build coordinator would promote an
// older one until a later run writes it.
func (s *Server) mirrorFailed(ctx context.Context, vm, disk, pool, host string, err error) {
	slog.Error("replication: main's top-level replica was not written; a main-build host would promote an older replica",
		"vm", vm, "disk", disk, "pool", pool, "host", host, "error", err)
	s.recordVMEvent(ctx, vm, "disk.replicated", "error",
		fmt.Sprintf("%s → %s@%s: the top-level replica a main-build host promotes was not written (%v); it would promote an older one", disk, pool, host, err))
}

// mirrorFullLocal writes main's top-level copy of the area replica at
// areaPath into pool on this host, as k's replica, under name.
func (s *Server) mirrorFullLocal(ctx context.Context, pool string, k replicaKey, areaPath, name string) error {
	dir, err := s.replicaPoolDir(ctx, pool)
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, name)
	if err := publishReplica(ctx, dst, func(tmp string) error { return sparseCopyFile(areaPath, tmp) }); err != nil {
		return err
	}
	if err := s.recordPoolReplica(ctx, pool, k, dst); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("record replica: %w", err)
	}
	return nil
}

// sparseCopyFile copies src over dst (which exists), keeping holes.
func sparseCopyFile(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	f, err := storage.OpenPoolFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(fi.Size()); err != nil {
		return err
	}
	if err := sparseCopyInto(f, src); err != nil {
		return err
	}
	return f.Close()
}

// mirrorIncrement writes main's top-level raw replica of the run that wrote
// rec into the area, forked from base there. It forks the top-level copy
// from main's name for the same base run only when that file is there, so
// both hold the same data; otherwise it writes the whole disk from r (the
// run's point-in-time image), skipping zeros.
func (s *Server) mirrorIncrement(ctx context.Context, host, pool string, k replicaKey, rec replicaRecord, base string, totalSize int64, r io.ReaderAt, extents [][2]int64) error {
	name := legacyReplicaName(rec.VM, rec.Disk, rec.Taken, "raw")
	var (
		client    pb.LiteVirtClient
		dir       string
		topLevels []string
	)
	if host == s.hostName {
		d, err := s.replicaPoolDir(ctx, pool)
		if err != nil {
			return err
		}
		dir = d
		topLevels = s.localReplicaNames(ctx, dir, k, "", false)
	} else {
		cl, closeConn, err := s.dialPeer(ctx, host)
		if err != nil {
			return fmt.Errorf("reach host %q: %w", host, err)
		}
		defer closeConn()
		client = cl
		topLevels = s.remoteReplicaNames(ctx, client, pool, host, k, "", false)
	}
	topBase := ""
	if base != "" {
		if want, ok := legacyNameOfAreaReplica(rec.VM, rec.Disk, base); ok && slices.Contains(topLevels, want) {
			topBase = want
		}
	}
	if topBase == "" {
		extents = [][2]int64{{0, totalSize}}
	}
	each := func(fn func(off int64, data []byte) error) error {
		return forEachExtentChunk(r, extents, totalSize, func(off int64, data []byte) error {
			if topBase == "" && allZero(data) {
				return nil // a fresh file is all holes
			}
			return fn(off, data)
		})
	}

	if client == nil {
		dest, err := forkRawAndApply(dir, name, topBase, totalSize, func(f *os.File) error {
			return each(func(off int64, data []byte) error {
				_, werr := f.WriteAt(data, off)
				return werr
			})
		})
		if err != nil {
			return err
		}
		if err := s.recordPoolReplica(ctx, pool, k, dest); err != nil {
			_ = os.Remove(dest)
			return fmt.Errorf("record replica: %w", err)
		}
		return nil
	}
	up, err := client.PushReplicaIncrement(ctx)
	if err != nil {
		return err
	}
	if err := up.Send(&pb.PushReplicaIncrementRequest{
		PoolName: pool, Host: host, Filename: name, Base: topBase, TotalSize: totalSize,
	}); err != nil {
		return err
	}
	if err := each(func(off int64, data []byte) error {
		return up.Send(&pb.PushReplicaIncrementRequest{Offset: off, Data: data})
	}); err != nil {
		return err
	}
	_, err = up.CloseAndRecv()
	return err
}

// legacyNameOfAreaReplica is main's top-level name for the run that wrote the
// area's raw replica file of (vm, disk) (replicaFileName: <disk>-<taken>.raw).
func legacyNameOfAreaReplica(vm, disk, file string) (string, bool) {
	taken, ok := strings.CutPrefix(file, disk+"-")
	if !ok {
		return "", false
	}
	taken, ok = strings.CutSuffix(taken, ".raw")
	if !ok || !replicaTakenRE.MatchString(taken) {
		return "", false
	}
	return legacyReplicaName(vm, disk, taken, "raw"), true
}
