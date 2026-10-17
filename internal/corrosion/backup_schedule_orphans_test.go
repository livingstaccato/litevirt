package corrosion

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// orphanFixture is a replica holding a schedule of each kind the orphan rule
// tells apart, every one naming repo "r":
//
//   - gone:      its VM was deleted two days ago, the schedule written before;
//   - recent:    its VM was deleted just now (inside the grace);
//   - unborn:    no row of its VM at all (not replicated yet, or never made);
//   - live:      its VM is live;
//   - rewritten: its VM was deleted two days ago, the schedule written after
//     the tombstone (a re-create of the name);
//   - @cluster:  a cluster-scoped schedule.
func orphanFixture(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	c := testClient(t)
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	for _, vm := range []string{"gone", "recent", "live", "rewritten"} {
		if err := InsertVM(ctx, c, VMRecord{Name: vm, HostName: "h1", Spec: "{}", State: "stopped"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, vm := range []string{"gone", "recent", "unborn", "live", "rewritten"} {
		if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: vm, Repo: "r", Cron: "0 4 * * *", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: "@cluster", Scope: "cluster", Repo: "r", Cron: "0 4 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, vm := range []string{"gone", "recent", "rewritten"} {
		if err := DeleteVM(ctx, c, vm); err != nil {
			t.Fatal(err)
		}
	}
	for _, vm := range []string{"gone", "rewritten"} {
		if err := c.Execute(ctx, `UPDATE vms SET deleted_at = ? WHERE name = ?`, old, vm); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: "rewritten", Repo: "r", Cron: "0 5 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return c
}

func orphanNames(t *testing.T, c *Client, now time.Time) string {
	t.Helper()
	got, err := OrphanedVMSchedules(context.Background(), c, now, VMScheduleOrphanGrace)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range got {
		names = append(names, s.VMName+"/"+s.Repo)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// Only a schedule whose VM row is a tombstone older than the grace, and which
// was written no later than that tombstone, is an orphan. A schedule of a VM
// with no row, of a live VM, of a VM deleted inside the grace, one written
// after the tombstone, and a fan-out scope's are not.
//
// Mutations: drop the grace — "recent" turns up; drop the LWW tie-break —
// "rewritten" turns up; treat a missing VM row as an orphan — "unborn" turns
// up.
func TestOrphanedVMSchedules(t *testing.T) {
	c := orphanFixture(t)
	if got := orphanNames(t, c, time.Now()); got != "gone/r" {
		t.Fatalf("orphans now = %q, want gone/r", got)
	}
	// Past the grace the recently deleted VM's schedule is one too.
	if got := orphanNames(t, c, time.Now().Add(VMScheduleOrphanGrace+time.Hour)); got != "gone/r,recent/r" {
		t.Fatalf("orphans past the grace = %q, want gone/r,recent/r", got)
	}
}

// A schedule of a deleted VM does not keep a torn-down stack's repo
// registered (lab 2, e2e-brepo-59201-1: the warning repeated at every daemon
// start), while a schedule of a VM with no row yet still does.
//
// Mutation: count every live schedule in scheduledBackupRepos — red.
func TestDeleteStackBackupRepos_AnOrphanedScheduleDoesNotKeepTheRepo(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	if err := UpsertBackupRepo(ctx, c, BackupRepo{Name: "e2erepo", Path: "/tmp/e2erepo", StackName: "s1"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "gone", HostName: "h1", Spec: "{}", State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: "gone", Repo: "e2erepo", Cron: "0 4 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteVM(ctx, c, "gone"); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, `UPDATE vms SET deleted_at = ? WHERE name = ?`, old, "gone"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteStackBackupRepos(ctx, c, "s1", nil); err != nil {
		t.Fatal(err)
	}
	if repos, _ := ListBackupRepos(ctx, c); len(repos) != 0 {
		t.Fatalf("a deleted VM's schedule kept the repo registered: %+v", repos)
	}

	// A schedule of a VM this replica holds no row of still keeps it.
	c2 := testClient(t)
	if err := UpsertBackupRepo(ctx, c2, BackupRepo{Name: "e2erepo", Path: "/tmp/e2erepo", StackName: "s1"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, c2, BackupScheduleRecord{VMName: "unborn", Repo: "e2erepo", Cron: "0 4 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteStackBackupRepos(ctx, c2, "s1", nil); err != nil {
		t.Fatal(err)
	}
	if repos, _ := ListBackupRepos(ctx, c2); len(repos) != 1 {
		t.Fatalf("a schedule of a VM with no row yet did not keep the repo: %+v", repos)
	}
}
