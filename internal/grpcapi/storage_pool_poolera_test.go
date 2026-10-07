package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// poolEraReplicate writes a replica of sched's VM's disk as replication runs
// did before replicas moved into the pool's replica area
// (replica_records.go): a top-level <vm>-<disk>-<stamp>.qcow2 in the target
// pool, recorded by recordPoolReplica (on shared storage in the replicated
// rows too), withdrawn where an unrecorded file would not be matched by its
// name, and the disk's top-level replicas pruned to sched's keep. An upgraded
// cluster's pools hold these, and promotion, failover and pruning still match
// them: the tests built on it are about that matching.
func poolEraReplicate(t *testing.T, s *Server, sched corrosion.BackupScheduleRecord, at time.Time) error {
	t.Helper()
	ctx := context.Background()
	vm, err := corrosion.GetVM(ctx, s.db, sched.VMName)
	if err != nil || vm == nil {
		return fmt.Errorf("vm %q: %v", sched.VMName, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, sched.VMName)
	if err != nil {
		return err
	}
	src := pickReplicaSource(disks)
	if src == nil {
		return fmt.Errorf("vm %q has no disk", sched.VMName)
	}
	dir, err := s.replicaPoolDir(ctx, sched.TargetPool)
	if err != nil {
		return err
	}
	p := filepath.Join(dir, fmt.Sprintf("%s-%s-%s.qcow2", sched.VMName, src.DiskName, at.UTC().Format("20060102-150405")))
	writeQcow2(t, p)
	k := replicaKeyOf(vm, src.DiskName)
	if err := s.recordPoolReplica(ctx, sched.TargetPool, k, p); err != nil && !s.isLegacyUnrecorded(ctx, p) {
		_ = os.Remove(p)
		return fmt.Errorf("record the replica: %w", err)
	}
	s.pruneLocalReplicas(ctx, dir, k, sched.KeepReplicas)
	return nil
}
