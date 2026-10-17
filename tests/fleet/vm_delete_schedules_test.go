// Fleet scenarios: a VM's own backup schedules end with the VM, and only
// with it.
//
// Observed on lab 2, 2026-10-15 (lab2-n5-schedule.md): `lv compose down` of
// stack e2e-brepo-59201-1 deleted its VM, whose compose `backup:` block had
// made a schedule naming the stack's repo e2erepo. Nothing removed the
// schedule, so the teardown kept e2erepo registered for it, and every daemon
// start retried and warned "the stack's backup repos stay registered" for a
// schedule of a VM that no longer existed. `lv rm` of any VM left its
// schedules the same way, firing for nothing.
package fleet

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const scheduledStackYAML = `name: brs

backup-repos:
  brrepo:
    path: /tmp/fleet-brs-repo

images:
  test:
    source: file:///dev/null

vms:
  web:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
    cloud-init:
      userdata: |
        #cloud-config
        hostname: USERDATA
    backup:
      repo: brrepo
      schedule: "0 4 * * *"
`

func scheduledStack(userdata string) string {
	return strings.ReplaceAll(scheduledStackYAML, "USERDATA", userdata)
}

// newScheduledStackFleet is three independent replicas with stack brs
// deployed through node-1 onto node-0: web, its compose schedule into brrepo,
// and an operator's schedule into repo "ops" added through node-2.
func newScheduledStackFleet(t *testing.T) (*Cluster, *corrosion.VMRecord) {
	t.Helper()
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, c.Nodes[0].DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
		SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatal(err)
		}
	}
	c.WaitConverged(t, 20*time.Second)
	deployClean(t, ctx, c.SelfClient(c.Nodes[1]), scheduledStack("first"))
	waitHistoryApplied(t, c, 20*time.Second)
	if _, err := c.SelfClient(c.Nodes[2]).CreateBackupSchedule(ctx, &pb.CreateBackupScheduleRequest{
		VmName: "web", Repo: "ops", Cron: "0 2 * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("operator's schedule: %v", err)
	}
	waitHistoryApplied(t, c, 20*time.Second)
	before, err := corrosion.GetVM(ctx, c.Nodes[0].DB, "web")
	if err != nil || before == nil || before.HostName != "node-0" {
		t.Fatalf("web after the deploy: %+v (%v), want it on node-0", before, err)
	}
	assertSchedulesEverywhere(t, c, "web/brrepo,web/ops")
	return c, before
}

// schedulesOn is every live schedule in n's replica as vm_name/repo, sorted.
func schedulesOn(t *testing.T, n *Node) string {
	t.Helper()
	rows, err := corrosion.ListBackupSchedules(context.Background(), n.DB)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.VMName+"/"+r.Repo)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// assertSchedulesEverywhere waits for every replica to have applied every
// write, then checks each holds exactly want.
func assertSchedulesEverywhere(t *testing.T, c *Cluster, want string) {
	t.Helper()
	c.ClearLinkFaults()
	waitHistoryApplied(t, c, 30*time.Second)
	for _, n := range c.Nodes {
		if got := schedulesOn(t, n); got != want {
			t.Errorf("live schedules on %s = %q, want %q", n.Name, got, want)
		}
	}
}

// compose down entered on node-1, a node that does not host web: the delete
// is forwarded to node-0, and the entry removes web's schedules — the compose
// one and the operator's — on every replica, so the teardown unregisters the
// stack's repo there and then.
//
// Red before the fix: both schedules stay live everywhere, and brrepo stays
// registered (lab 2, e2e-brepo-59201-1).
func TestFleet_ComposeDownTakesTheVMsSchedulesAndTheStacksRepo(t *testing.T) {
	c, _ := newScheduledStackFleet(t)
	ctx := context.Background()
	for _, p := range deleteStackCollect(t, ctx, c.SelfClient(c.Nodes[1]), "brs") {
		if p.Status == "error" {
			t.Fatalf("compose down: %s: %s", p.VmName, p.Error)
		}
	}
	assertSchedulesEverywhere(t, c, "")
	for _, n := range c.Nodes {
		if r, err := corrosion.GetBackupRepo(ctx, n.DB, "brrepo"); err != nil || r != nil {
			t.Errorf("brrepo on %s after compose down: %+v (%v), want it unregistered", n.Name, r, err)
		}
	}
}

// A compose re-create of web entered on node-1 (its delete forwarded to
// node-0, as recreateInline does), and then a rebuild entered on node-1,
// both bring the VM back, and keep both schedules on every replica. Only
// lv rm, entered on node-2, ends them.
//
// Mutation: drop hasDeletedVMSink from DeleteVM's schedule predicate — the
// re-create drops "web/ops" (the compose hook writes "web/brrepo" back).
func TestFleet_ReCreateAndRebuildKeepTheVMsSchedulesAndRmEndsThem(t *testing.T) {
	c, before := newScheduledStackFleet(t)
	ctx := context.Background()
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	lagFrom(c, n0, n1, n2)
	msgs := deployCollect(t, ctx, c.SelfClient(n1), scheduledStack("second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("compose re-create: %s; %s", p.Error, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n0)
	assertSchedulesEverywhere(t, c, "web/brrepo,web/ops")

	recreated, _ := corrosion.GetVM(ctx, n0.DB, "web")
	if _, err := c.SelfClient(n1).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", recreated, n0)
	assertSchedulesEverywhere(t, c, "web/brrepo,web/ops")

	if _, err := c.SelfClient(n2).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("lv rm: %v", err)
	}
	assertSchedulesEverywhere(t, c, "")
}

// A blue-green update creates web-green, then deletes the blue web through
// the cutover's own delete: web's schedules stay live on every replica, as
// they did before (the operator's "ops" included).
//
// Mutation: drop withSchedulesKept from serverOps.DeleteVM — red.
func TestFleet_ABlueGreenCutoverKeepsTheBluesSchedules(t *testing.T) {
	c, _ := newScheduledStackFleet(t)
	ctx := context.Background()
	blueGreen := func(userdata string) string {
		return strings.Replace(scheduledStack(userdata), "    backup:\n", "    update:\n      strategy: blue-green\n    backup:\n", 1)
	}
	// The strategy itself is a field the VM keeps.
	deployClean(t, ctx, c.SelfClient(c.Nodes[1]), blueGreen("first"))
	waitHistoryApplied(t, c, 20*time.Second)
	msgs := deployCollect(t, ctx, c.SelfClient(c.Nodes[1]), blueGreen("second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("blue-green update: %s; %s", p.Error, whereIs(c, "web"))
	}
	if green, _ := corrosion.GetVM(ctx, c.Nodes[0].DB, "web-green"); green == nil {
		t.Fatalf("premise: no web-green after the blue-green update; %v", msgs)
	}
	if blue, _ := corrosion.GetVM(ctx, c.Nodes[0].DB, "web"); blue != nil {
		t.Fatalf("premise: the blue web was not deleted; %v", msgs)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	for _, n := range c.Nodes {
		if got := schedulesOn(t, n); !strings.Contains(got, "web/brrepo") || !strings.Contains(got, "web/ops") {
			t.Errorf("live schedules on %s after the cutover = %q, want web/brrepo and web/ops kept", n.Name, got)
		}
	}
}

// A cluster that already holds a schedule of a VM deleted long ago — left by
// a delete on an older build — heals with no migration: the schedule no
// longer keeps the torn-down stack's repo registered, and the failover lease
// holder's sweep removes it on every replica. A schedule of a VM whose row
// has not arrived is kept.
//
// Red before the fix: the repo stays registered and the schedule live.
func TestFleet_ALeftoverScheduleOfADeletedVMHeals(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	ctx := context.Background()
	n0, holder := c.Nodes[0], c.Nodes[1]
	if err := corrosion.UpsertBackupRepo(ctx, n0.DB, corrosion.BackupRepo{Name: "e2erepo", Path: "/tmp/e2erepo", StackName: "gone-stack"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, n0.DB, corrosion.VMRecord{Name: "e2e-br", StackName: "gone-stack", HostName: n0.Name, Spec: "{}", State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range []corrosion.BackupScheduleRecord{
		{VMName: "e2e-br", Repo: "e2erepo", Cron: "0 4 * * *", Enabled: true},
		{VMName: "unborn", Repo: "other", Cron: "0 4 * * *", Enabled: true},
	} {
		if err := corrosion.UpsertBackupSchedule(ctx, n0.DB, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.DeleteVM(ctx, n0.DB, "e2e-br"); err != nil {
		t.Fatal(err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	// The delete was two days ago: its tombstone is past the grace.
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	for _, n := range c.Nodes {
		if _, err := n.DB.DB().ExecContext(ctx, `UPDATE vms SET deleted_at = ? WHERE name = ?`, old, "e2e-br"); err != nil {
			t.Fatal(err)
		}
	}

	// The stack's teardown, as the sweep of torn-down stacks' rows retries
	// it on any node, no longer keeps the repo for the leftover.
	if err := corrosion.DeleteStackBackupRepos(ctx, holder.DB, "gone-stack", nil); err != nil {
		t.Fatal(err)
	}
	if r, err := corrosion.GetBackupRepo(ctx, holder.DB, "e2erepo"); err != nil || r != nil {
		t.Errorf("e2erepo after the teardown is retried: %+v (%v), want it unregistered", r, err)
	}

	if held, _, err := corrosion.AcquireLeaseWithTerm(ctx, holder.DB, corrosion.LeaseKeyFailover, holder.Name, time.Hour, time.Now()); err != nil || !held {
		t.Fatalf("%s takes the failover lease: held=%v err=%v", holder.Name, held, err)
	}
	holder.Server.SweepVMScheduleOrphansForTest(ctx, time.Now())
	assertSchedulesEverywhere(t, c, "unborn/other")
}
