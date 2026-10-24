package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestSnapshotScheduler_PoolModeFansOut confirms a single
// pool-level backup_schedules row dispatches one backup per VM
// whose disks live on the pool — only for VMs owned by THIS host.
func TestSnapshotScheduler_PoolModeFansOut(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)

	// Two VMs owned by host-a on pool "fast"; one VM owned by
	// host-b also on "fast". A's scheduler should fire 2 (its own
	// pair) and skip host-b's VM.
	for _, vm := range []struct{ name, host string }{
		{"vm-a1", "host-a"},
		{"vm-a2", "host-a"},
		{"vm-b1", "host-b"},
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm.name, HostName: vm.host, Spec: "{}", State: "running",
		}, nil, []corrosion.DiskRecord{
			{VMName: vm.name, DiskName: "root", Path: "/tmp/" + vm.name, StorageVolume: "fast", SizeBytes: 1},
		}); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
	}

	// Single pool-level schedule.
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: corrosion.ScheduleKey("pool", "", "fast", ""), Scope: "pool",
		PoolName: "fast", Repo: "main", Cron: "* * * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert pool schedule: %v", err)
	}

	var fired atomic.Int32
	var firedNames []string
	s := NewSnapshotScheduler(db, "host-a", schedRunnerFn(func(rec corrosion.BackupScheduleRecord) error {
		fired.Add(1)
		firedNames = append(firedNames, rec.VMName)
		return nil
	}))
	s.Now = func() time.Time { return time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC) }
	s.Tick(ctx)

	if got := fired.Load(); got != 2 {
		t.Errorf("expected 2 fires (host-a's two VMs), got %d (%v)", got, firedNames)
	}
	for _, n := range firedNames {
		if n == "vm-b1" {
			t.Errorf("scheduler fired for foreign-host VM %q", n)
		}
	}
}

// TestSnapshotScheduler_VMScopeIgnoresPoolName: only the scope makes a row a
// fan-out. CreateBackupSchedule stores the request's pool_name whatever the
// scope, so a vm-scoped schedule can carry one; it backs up its own VM and
// nothing else on the pool.
//
// Mutation: treat a row with a pool_name as a pool row in expandScope — red
// (vm-a1 and vm-a2 both fire).
func TestSnapshotScheduler_VMScopeIgnoresPoolName(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	for _, vm := range []string{"vm-a1", "vm-a2"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm, HostName: "host-a", Spec: "{}", State: "running",
		}, nil, []corrosion.DiskRecord{
			{VMName: vm, DiskName: "root", Path: "/tmp/" + vm, StorageVolume: "fast", SizeBytes: 1},
		}); err != nil {
			t.Fatalf("InsertVM %s: %v", vm, err)
		}
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm-a1", Scope: "vm", PoolName: "fast", Repo: "main", Cron: "* * * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert vm schedule: %v", err)
	}

	var firedNames []string
	s := NewSnapshotScheduler(db, "host-a", schedRunnerFn(func(rec corrosion.BackupScheduleRecord) error {
		firedNames = append(firedNames, rec.VMName)
		return nil
	}))
	s.Now = func() time.Time { return time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC) }
	s.Tick(ctx)

	if len(firedNames) != 1 || firedNames[0] != "vm-a1" {
		t.Fatalf("a vm-scoped schedule with a pool_name fired for %v, want [vm-a1]", firedNames)
	}
}
