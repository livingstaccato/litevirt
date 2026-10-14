package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// stuckReplRunner is a replication runner whose runs for one VM do not
// return until release is closed (a copy to an NFS server that died
// mid-write). calls counts the runs per VM.
type stuckReplRunner struct {
	stuckVM string
	release chan struct{}

	mu    sync.Mutex
	calls map[string]int
}

func (r *stuckReplRunner) RunReplication(_ context.Context, s corrosion.BackupScheduleRecord, _ time.Time) error {
	r.mu.Lock()
	r.calls[s.VMName]++
	r.mu.Unlock()
	if s.VMName == r.stuckVM {
		<-r.release
	}
	return nil
}

func (r *stuckReplRunner) count(vm string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[vm]
}

func scheduleRow(t *testing.T, db *corrosion.Client, vm string) corrosion.BackupScheduleRecord {
	t.Helper()
	rows, err := corrosion.ListBackupSchedules(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.VMName == vm {
			return r
		}
	}
	t.Fatalf("no schedule row for %s", vm)
	return corrosion.BackupScheduleRecord{}
}

// Lab 2 (nfsplace, m-a): a replication copy whose NFS server died mid-copy
// held the scheduler for the whole outage, because runs are made one after
// another and the copy's write waits in the kernel. A run now holds the pass
// at most its hold bound and goes on by itself; the other schedules run on
// time; the stuck run is not started again while it has not returned; and
// its outcome is recorded once, when it does.
//
// Mutations: the run waited for in place (no hold bound) — the tick does not
// return: red. The running mark dropped — the stuck run is started again at
// the next tick: red. The outcome recorded at the bound instead of by the
// run — last_run_at is set while the run has not returned: red.
func TestSnapshotScheduler_AStuckRunDoesNotHoldTheOtherSchedules(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm-nfs")
	seedVM(t, db, "vm-local")
	for _, row := range []corrosion.BackupScheduleRecord{
		{VMName: "vm-nfs", Repo: "nfs", Cron: "* * * * *", Enabled: true, Type: "replication", TargetPool: "nfs", KeepReplicas: 1},
		{VMName: "vm-local", Repo: "local", Cron: "* * * * *", Enabled: true, Type: "replication", TargetPool: "local", KeepReplicas: 1},
	} {
		if err := corrosion.UpsertBackupSchedule(ctx, db, row); err != nil {
			t.Fatal(err)
		}
	}
	repl := &stuckReplRunner{stuckVM: "vm-nfs", release: make(chan struct{}), calls: map[string]int{}}
	defer func() {
		select {
		case <-repl.release:
		default:
			close(repl.release)
		}
	}()
	s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
	s.ReplRunner = repl
	s.RunHoldBound = 200 * time.Millisecond
	first := time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC)
	now := first
	s.Now = func() time.Time { return now }

	tick := func(what string) {
		t.Helper()
		done := make(chan struct{})
		go func() { s.Tick(ctx); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the tick did not return within 5s, held by a run that does not return", what)
		}
	}

	tick("first tick")
	if n := repl.count("vm-local"); n != 1 {
		t.Fatalf("vm-local ran %d times on the first tick, want 1", n)
	}
	if r := scheduleRow(t, db, "vm-local"); r.LastRunAt == "" {
		t.Fatal("vm-local's run was not recorded")
	}
	if r := scheduleRow(t, db, "vm-nfs"); r.LastRunAt != "" {
		t.Fatalf("vm-nfs's run, which has not returned, was recorded: last_run_at %q", r.LastRunAt)
	}

	now = first.Add(time.Minute)
	tick("second tick")
	if n := repl.count("vm-local"); n != 2 {
		t.Fatalf("vm-local ran %d times by the second tick, want 2", n)
	}
	if n := repl.count("vm-nfs"); n != 1 {
		t.Fatalf("vm-nfs was started %d times while its first run had not returned, want 1", n)
	}

	close(repl.release)
	deadline := time.Now().Add(5 * time.Second)
	for scheduleRow(t, db, "vm-nfs").LastRunAt == "" {
		if time.Now().After(deadline) {
			t.Fatal("vm-nfs's run returned and its outcome was never recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got, want := scheduleRow(t, db, "vm-nfs").LastRunAt, first.Format(time.RFC3339); got != want {
		t.Fatalf("vm-nfs's recorded run: last_run_at %q, want the run that returned (%q)", got, want)
	}

	// Once it has returned, it runs again at its next match.
	for {
		s.runningMu.Lock()
		_, busy := s.running[runKey(corrosion.BackupScheduleRecord{Type: "replication", VMName: "vm-nfs", Repo: "nfs"})]
		s.runningMu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("vm-nfs is still marked running after its run returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	now = first.Add(2 * time.Minute)
	tick("third tick")
	if n := repl.count("vm-nfs"); n != 2 {
		t.Fatalf("vm-nfs ran %d times after its stuck run returned, want 2", n)
	}
}
