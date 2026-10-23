package scheduler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

type pausedReplRunner struct{}

func (pausedReplRunner) RunReplication(context.Context, corrosion.BackupScheduleRecord, time.Time) error {
	return fmt.Errorf("%w: vm vm1 is on host-a, a witness", ErrRunPaused)
}

// A run the runner reports as paused (a witness cannot act for its VM) is
// recorded with the reason as the schedule's last error, never as a clean run:
// the schedule must not read as healthy, and the host that takes the VM over
// then starts from a failing state and reports replication.recovered.
//
// Mutation: treat ErrRunPaused as a success in runAndRecord - last_run_err is
// cleared and this goes red.
func TestScheduler_APausedReplicationRunIsRecordedWithItsReasonNotAsOK(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr-pool", Cron: "0 2 * * *", Enabled: true,
		Type: "replication", TargetPool: "dr-pool", KeepReplicas: 3,
	}); err != nil {
		t.Fatal(err)
	}
	s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
	s.ReplRunner = pausedReplRunner{}
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
	s.Tick(ctx)

	scheds, err := corrosion.ListBackupSchedules(ctx, db)
	if err != nil || len(scheds) != 1 {
		t.Fatalf("schedules = %v, %v", scheds, err)
	}
	if scheds[0].LastRunAt == "" || scheds[0].LastRunErr == "" {
		t.Errorf("the paused run was recorded as last_run_at=%q last_run_err=%q, want the run recorded with its reason", scheds[0].LastRunAt, scheds[0].LastRunErr)
	}
}
