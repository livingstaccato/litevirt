package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

type recordingReplRunner struct {
	mu    sync.Mutex
	calls []corrosion.BackupScheduleRecord
}

func (r *recordingReplRunner) RunReplication(_ context.Context, s corrosion.BackupScheduleRecord, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, s)
	return nil
}

// TestScheduler_ReplicationDispatch: a type='replication' row goes to the
// ReplRunner, and the backup runner is NOT called for it.
func TestScheduler_ReplicationDispatch(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr-pool", Cron: "0 2 * * *", Enabled: true,
		Type: "replication", TargetPool: "dr-pool", KeepReplicas: 3,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	backup := &recordingRunner{}
	repl := &recordingReplRunner{}
	s := NewSnapshotScheduler(db, "host-a", backup)
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }

	s.Tick(ctx)
	repl.mu.Lock()
	n := len(repl.calls)
	var tp string
	if n > 0 {
		tp = repl.calls[0].TargetPool
	}
	repl.mu.Unlock()
	if n != 1 {
		t.Fatalf("ReplRunner fired %d times, want 1", n)
	}
	if tp != "dr-pool" {
		t.Errorf("replicated to %q, want dr-pool", tp)
	}
	if got := backup.callCount(); got != 0 {
		t.Errorf("backup runner fired %d times for a replication row, want 0", got)
	}
}

// A fan-out schedule's per-VM run carries the row it came from (Origin), so
// the runner can tell it from a vm-scoped schedule of the same VM into the same
// pool — each prunes only the replicas it recorded.
func TestScheduler_FanoutRunCarriesItsOrigin(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "__cluster__", Scope: "cluster", Repo: "dr-pool", Cron: "0 2 * * *", Enabled: true,
		Type: "replication", TargetPool: "dr-pool", KeepReplicas: 3,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	repl := &recordingReplRunner{}
	s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }

	s.Tick(ctx)
	repl.mu.Lock()
	defer repl.mu.Unlock()
	if len(repl.calls) != 1 {
		t.Fatalf("ReplRunner fired %d times, want 1", len(repl.calls))
	}
	if got := repl.calls[0]; got.VMName != "vm1" || got.Origin != "__cluster__" {
		t.Errorf("fan-out run = vm %q origin %q, want vm1 from __cluster__", got.VMName, got.Origin)
	}
}

func seedContainerRow(t *testing.T, db *corrosion.Client, host, name, project string) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), db, corrosion.ContainerRecord{
		HostName: host, Name: name, State: "running", Image: "alpine", Project: project,
	}); err != nil {
		t.Fatalf("seed container %s on %s: %v", name, host, err)
	}
}

func containerReplSchedule(t *testing.T, db *corrosion.Client, name, project string) {
	t.Helper()
	if err := corrosion.UpsertBackupSchedule(context.Background(), db, corrosion.BackupScheduleRecord{
		VMName: corrosion.ScheduleKey("container", name, "", project), Scope: "container", ProjectName: project,
		Repo: "dr-repo", Cron: "0 2 * * *", Enabled: true, Type: "replication", TargetPool: "dr-repo",
		TargetHost: "host-b", KeepReplicas: 2,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
}

// A container-scoped replication schedule runs on the host that holds the
// container, once, and only there.
func TestScheduler_ContainerReplicationRoutesToTheContainersHost(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedContainerRow(t, db, "host-a", "web", "_default")
	containerReplSchedule(t, db, "web", "_default")

	for _, tc := range []struct {
		host string
		want int
	}{{"host-a", 1}, {"host-b", 0}} {
		repl := &recordingReplRunner{}
		s := NewSnapshotScheduler(db, tc.host, &recordingRunner{})
		s.ReplRunner = repl
		s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
		s.Tick(ctx)
		repl.mu.Lock()
		got := len(repl.calls)
		repl.mu.Unlock()
		if got != tc.want {
			t.Errorf("%s: ReplRunner fired %d times, want %d", tc.host, got, tc.want)
		}
	}
}

// The same container name in two projects on two hosts is ambiguous without the
// project; the schedule's project picks the one it is about.
func TestScheduler_ContainerReplicationHonoursTheScheduleProject(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedContainerRow(t, db, "host-a", "web", "_default")
	seedContainerRow(t, db, "host-c", "web", "prod")
	containerReplSchedule(t, db, "web", "prod")

	run := func(host string) int {
		repl := &recordingReplRunner{}
		s := NewSnapshotScheduler(db, host, &recordingRunner{})
		s.ReplRunner = repl
		s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
		s.Tick(ctx)
		repl.mu.Lock()
		defer repl.mu.Unlock()
		return len(repl.calls)
	}
	if got := run("host-c"); got != 1 {
		t.Errorf("the prod container's host ran it %d times, want 1", got)
	}
	if got := run("host-a"); got != 0 {
		t.Errorf("the other project's same-named container ran it %d times, want 0", got)
	}
}

// A container schedule is never mistaken for a VM of the same name.
func TestScheduler_ContainerScheduleIsNotAVMSchedule(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "web") // a VM named like the container, on this host
	seedContainerRow(t, db, "host-b", "web", "_default")
	containerReplSchedule(t, db, "web", "_default")

	repl := &recordingReplRunner{}
	s := NewSnapshotScheduler(db, "host-a", &recordingRunner{})
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
	s.Tick(ctx)
	repl.mu.Lock()
	defer repl.mu.Unlock()
	if len(repl.calls) != 0 {
		t.Fatalf("the container's schedule ran on the host of a same-named VM: %+v", repl.calls)
	}
}

// A shared (pool, project, cluster) replication schedule whose explicit target
// is this host does not replicate this host's own VMs: the replica would sit
// beside the disk it protects.
func TestScheduler_ASharedReplicationScheduleSkipsItsOwnTarget(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm-on-b", HostName: "host-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "@cluster", Scope: "cluster", Repo: "dr", Cron: "0 2 * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "host-b",
	}); err != nil {
		t.Fatal(err)
	}
	repl := &recordingReplRunner{}
	s := NewSnapshotScheduler(db, "host-b", &recordingRunner{})
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
	s.Tick(ctx)
	repl.mu.Lock()
	defer repl.mu.Unlock()
	if len(repl.calls) != 0 {
		t.Fatalf("the target host ran its own VMs into its own pool: %d run(s)", len(repl.calls))
	}
}
