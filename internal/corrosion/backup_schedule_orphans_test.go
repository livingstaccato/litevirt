package corrosion

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// backdate sets a tombstone's display deletion two days back, locally.
func backdate(t *testing.T, c *Client, table, name string) {
	t.Helper()
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := c.DB().ExecContext(context.Background(), `UPDATE `+table+` SET deleted_at = ? WHERE name = ?`, old, name); err != nil {
		t.Fatal(err)
	}
}

// tornDownStack records stack name and tombstones it.
func tornDownStack(t *testing.T, c *Client, name string) {
	t.Helper()
	ctx := context.Background()
	if err := UpsertStack(ctx, c, StackRecord{Name: name, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteStackRecord(ctx, c, name); err != nil {
		t.Fatal(err)
	}
}

// orphanFixture is a replica holding a schedule of each kind the orphan rule
// tells apart. Stack "down" was torn down; stack "up" is live.
//
// VMs (each with a schedule into repo "r"):
//   - gone:      down's, deleted two days ago, the schedule written before;
//   - tie:       as gone, the schedule's stamp equal to the tombstone's;
//   - recent:    down's, deleted just now (inside the grace);
//   - unborn:    no row of its VM at all;
//   - live:      down's, still live;
//   - rewritten: down's, deleted two days ago, the schedule written after;
//   - plain:     no stack's, deleted two days ago (a failed rebuild leaves this);
//   - upvm:      live stack up's, deleted two days ago (a blue-green blue);
//   - ran:       down's, deleted two days ago, then stamped by a run that
//     finished after the delete (MarkBackupScheduleRun, now);
//   - rdvm:      stack rd's, deleted two days ago; rd was torn down and
//     deployed again (its record is live);
//   - @cluster:  a cluster-scoped schedule.
//
// Containers (each with a replication schedule into "r"):
//   - ctgone:  down's, deleted two days ago;
//   - ctplain: no stack's, deleted two days ago;
//   - ctup:    live stack up's, deleted two days ago;
//   - ctran:   down's, deleted two days ago, then stamped by a late run;
//   - ctmoved: down's tombstone on h1 two days ago, but live on h2.
func orphanFixture(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	c := testClient(t)
	tornDownStack(t, c, "down")
	if err := UpsertStack(ctx, c, StackRecord{Name: "up", State: "active"}); err != nil {
		t.Fatal(err)
	}
	// rd: torn down, then deployed again.
	tornDownStack(t, c, "rd")
	if err := UpsertStack(ctx, c, StackRecord{Name: "rd", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := GetStack(ctx, c, "rd"); st == nil {
		t.Fatal("premise: the redeployed stack's record is not live")
	}
	stackOf := map[string]string{"gone": "down", "tie": "down", "recent": "down", "live": "down", "rewritten": "down", "upvm": "up", "ran": "down", "rdvm": "rd"}
	for _, vm := range []string{"gone", "tie", "recent", "live", "rewritten", "plain", "upvm", "ran", "rdvm"} {
		if err := InsertVM(ctx, c, VMRecord{Name: vm, StackName: stackOf[vm], HostName: "h1", Spec: "{}", State: "stopped"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, vm := range []string{"gone", "tie", "recent", "unborn", "live", "rewritten", "plain", "upvm", "ran", "rdvm"} {
		if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: vm, Repo: "r", Cron: "0 4 * * *", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: "@cluster", Scope: "cluster", Repo: "r", Cron: "0 4 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, vm := range []string{"gone", "tie", "recent", "rewritten", "plain", "upvm", "ran", "rdvm"} {
		if err := DeleteVM(ctx, c, vm); err != nil {
			t.Fatal(err)
		}
	}
	for _, vm := range []string{"gone", "tie", "rewritten", "plain", "upvm", "ran", "rdvm"} {
		backdate(t, c, "vms", vm)
	}
	if err := MarkBackupScheduleRun(ctx, c, "ran", "r", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: "rewritten", Repo: "r", Cron: "0 5 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// The equal stamp: the schedule last written at the tombstone's own key.
	if _, err := c.DB().ExecContext(ctx,
		`UPDATE backup_schedules SET updated_at = (SELECT updated_at FROM vms WHERE name = 'tie') WHERE vm_name = 'tie'`); err != nil {
		t.Fatal(err)
	}

	mkCT := func(host, name, stack string) {
		r := ContainerRecord{HostName: host, Name: name, State: "stopped"}
		if stack != "" {
			r.Labels = map[string]string{LabelStack: stack}
		}
		if err := UpsertContainer(ctx, c, r); err != nil {
			t.Fatal(err)
		}
	}
	mkCT("h1", "ctgone", "down")
	mkCT("h1", "ctplain", "")
	mkCT("h1", "ctmoved", "down")
	mkCT("h1", "ctup", "up")
	mkCT("h1", "ctran", "down")
	for _, ct := range []string{"ctgone", "ctplain", "ctmoved", "ctup", "ctran"} {
		if err := upsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: ContainerScheduleKey("", ct), Scope: "container",
			Type: "replication", Repo: "r", TargetPool: "r", Cron: "0 4 * * *", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := DeleteContainer(ctx, c, "h1", ct); err != nil {
			t.Fatal(err)
		}
		backdate(t, c, "containers", ct)
	}
	if err := MarkBackupScheduleRun(ctx, c, ContainerScheduleKey("", "ctran"), "r", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	mkCT("h2", "ctmoved", "down")
	return c
}

func orphanNames(t *testing.T, c *Client, now time.Time) string {
	t.Helper()
	got, err := OrphanedStackSchedules(context.Background(), c, now, ScheduleOrphanGrace)
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

// Only a schedule of a workload of a torn-down stack, whose tombstone is
// older than the grace, and which is not newer than the tombstone or has not
// been written for a full grace (a run that finished after the delete), is an
// orphan. A redeployed stack's workload is never one. A
// schedule of a workload that is no stack's or a live stack's (a failed
// rebuild, a blue-green blue) stays dormant, as it always has.
//
// Mutations: drop the grace — "recent" turns up; drop the LWW tie-break —
// "rewritten" turns up; make an equal stamp not an orphan (> 0 to >= 0) —
// "tie" goes; treat a missing VM row as an orphan — "unborn" turns up; drop
// the torn-down-stack clause — "plain", "upvm" and "rdvm" turn up; drop the
// quiet clause — "ran", "ctran" and "rewritten" never turn up; drop the
// container stack checks — "ctplain" or "ctup" turns up; drop the live-row check —
// "ctmoved" turns up.
func TestOrphanedStackSchedules(t *testing.T) {
	c := orphanFixture(t)
	want := "@ct:_default/ctgone/r,gone/r,tie/r"
	if got := orphanNames(t, c, time.Now()); got != want {
		t.Fatalf("orphans now = %q, want %q", got, want)
	}
	// Past the grace the recently deleted VM's schedule is one too.
	// So are the ones a late run (or a write after the tombstone) stamped,
	// once nothing has written them for a full grace.
	want = "@ct:_default/ctgone/r,@ct:_default/ctran/r,gone/r,ran/r,recent/r,rewritten/r,tie/r"
	if got := orphanNames(t, c, time.Now().Add(ScheduleOrphanGrace+time.Hour)); got != want {
		t.Fatalf("orphans past the grace = %q, want %q", got, want)
	}
}

// A schedule of a torn-down stack's deleted VM does not keep that stack's
// repo registered (lab 2, e2e-brepo-59201-1: the warning repeated at every
// daemon start), while a schedule of a VM with no row yet still does.
//
// Mutation: count every live schedule in scheduledBackupRepos — red.
func TestDeleteStackBackupRepos_AnOrphanedScheduleDoesNotKeepTheRepo(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	tornDownStack(t, c, "s1")
	if err := UpsertBackupRepo(ctx, c, BackupRepo{Name: "e2erepo", Path: "/tmp/e2erepo", StackName: "s1"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "gone", StackName: "s1", HostName: "h1", Spec: "{}", State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: "gone", Repo: "e2erepo", Cron: "0 4 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteVM(ctx, c, "gone"); err != nil {
		t.Fatal(err)
	}
	backdate(t, c, "vms", "gone")
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
