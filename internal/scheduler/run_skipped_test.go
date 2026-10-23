package scheduler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// errReplRunner fails every run with err.
type errReplRunner struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (r *errReplRunner) RunReplication(context.Context, corrosion.BackupScheduleRecord, time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.err
}

// captureLog sends slog's default logger to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	var mu sync.Mutex
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Lab 4 finding 7: a host back from an IPMI fence still saw a replicated VM
// on itself during warmup, ran its schedule, and logged ERROR "schedule run
// failed ... this host may not act as the VM's owner now (warmup)", for a VM
// that had already been promoted on another host; it also wrote that error,
// and a last_run_at, onto the schedule row the owner keeps. A run the runner
// skips for that reason (ErrRunSkipped) is logged at info and records
// nothing. Any other error is still a failure, logged and recorded.
//
// Mutation: drop the ErrRunSkipped case in runAndRecord — "skipped" logs an
// ERROR and marks the row.
func TestScheduler_ARunSkippedAsNotOwnerIsNotAFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		failure bool
	}{
		{"skipped", fmt.Errorf("%w: this host may not act as the VM's owner now (warmup)", ErrRunSkipped), false},
		{"failed", errors.New("copy failed"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := newSchedTestDB(t)
			seedVM(t, db, "ipmi-f")
			if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
				VMName: "ipmi-f", Repo: "default", Cron: "* * * * *", Enabled: true,
				Type: "replication", TargetPool: "default", KeepReplicas: 2,
			}); err != nil {
				t.Fatal(err)
			}
			logs := captureLog(t)
			repl := &errReplRunner{err: tc.err}
			s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
			s.ReplRunner = repl
			s.Now = func() time.Time { return time.Date(2026, 10, 23, 16, 58, 0, 0, time.UTC) }
			s.Tick(ctx)
			if repl.calls != 1 {
				t.Fatalf("runner called %d times, want 1", repl.calls)
			}
			scheds, err := corrosion.ListBackupSchedules(ctx, db)
			if err != nil || len(scheds) != 1 {
				t.Fatalf("schedules %v, %v", scheds, err)
			}
			marked := scheds[0].LastRunAt != "" || scheds[0].LastRunErr != ""
			loggedError := strings.Contains(logs.String(), "level=ERROR")
			if marked != tc.failure || loggedError != tc.failure {
				t.Errorf("row marked %v (%q at %q), ERROR logged %v; want both %v\nlog: %s",
					marked, scheds[0].LastRunErr, scheds[0].LastRunAt, loggedError, tc.failure, logs.String())
			}
			if !tc.failure && !strings.Contains(logs.String(), "schedule run skipped") {
				t.Errorf("the skip is not logged: %s", logs.String())
			}
		})
	}
}
