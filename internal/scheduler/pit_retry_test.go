package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// retryingReplRunner owes a point-in-time retry to the VMs in due, and
// records whether each run came as a retry.
type retryingReplRunner struct {
	recordingReplRunner
	due     map[string]bool
	retries []bool
}

func (r *retryingReplRunner) RunReplication(ctx context.Context, s corrosion.BackupScheduleRecord, at time.Time) error {
	r.mu.Lock()
	r.retries = append(r.retries, IsPointInTimeRetry(ctx))
	r.mu.Unlock()
	return r.recordingReplRunner.RunReplication(ctx, s, at)
}

func (r *retryingReplRunner) PointInTimeRetryDue(s corrosion.BackupScheduleRecord) bool {
	return r.due[s.VMName]
}
func (r *retryingReplRunner) AnyPointInTimeRetryDue() bool { return len(r.due) > 0 }

// A replication run whose copy was not point-in-time is retried at the next
// tick, not a full interval later: the schedule runs although its cron does
// not match. Others do not.
//
// Mutation "no retry dispatch": Tick ignores PointInTimeRetrier — red.
func TestScheduler_RetriesANotPointInTimeRunAtTheNextTick(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	seedVM(t, db, "vm2")
	for _, vm := range []string{"vm1", "vm2"} {
		if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
			VMName: vm, Repo: "dr-pool", Cron: "0 2 * * *", Enabled: true,
			Type: "replication", TargetPool: "dr-pool", KeepReplicas: 3,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	repl := &retryingReplRunner{due: map[string]bool{"vm1": true}}
	s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 1, 0, 0, time.UTC) } // cron does not match

	s.Tick(ctx)
	repl.mu.Lock()
	defer repl.mu.Unlock()
	if len(repl.calls) != 1 || repl.calls[0].VMName != "vm1" {
		t.Fatalf("runs %+v, want vm1's retry only", repl.calls)
	}
	if !repl.retries[0] {
		t.Error("the retry did not come as one; the runner would take the -U copy again")
	}
}

// A cron run is not a retry, even for a VM owed one.
func TestScheduler_ACronRunIsNotARetry(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr-pool", Cron: "0 2 * * *", Enabled: true,
		Type: "replication", TargetPool: "dr-pool", KeepReplicas: 3,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	repl := &retryingReplRunner{due: map[string]bool{"vm1": true}}
	s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) } // cron matches
	s.Tick(ctx)
	repl.mu.Lock()
	defer repl.mu.Unlock()
	if len(repl.retries) != 1 || repl.retries[0] {
		t.Fatalf("runs as retries %v, want one cron run", repl.retries)
	}
}

// The retry reaches a fan-out schedule's VM too, as that VM's run.
func TestScheduler_RetriesAFanoutVMsRun(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "__cluster__", Scope: "cluster", Repo: "dr-pool", Cron: "0 2 * * *", Enabled: true,
		Type: "replication", TargetPool: "dr-pool", KeepReplicas: 3,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	repl := &retryingReplRunner{due: map[string]bool{"vm1": true}}
	s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 1, 0, 0, time.UTC) }

	s.Tick(ctx)
	repl.mu.Lock()
	defer repl.mu.Unlock()
	if len(repl.calls) != 1 || repl.calls[0].VMName != "vm1" || repl.calls[0].Origin != "__cluster__" {
		t.Fatalf("runs %+v, want vm1's run of the cluster schedule", repl.calls)
	}
}
