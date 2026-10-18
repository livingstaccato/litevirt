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
	"github.com/litevirt/litevirt/internal/capabilities"
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

// ageTombstone moves the deletion of table's row name two days back on every
// replica, locally: past the orphan grace.
func ageTombstone(t *testing.T, c *Cluster, table, name string) {
	t.Helper()
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	for _, n := range c.Nodes {
		if err := localExec(context.Background(), n.DB, `UPDATE `+table+` SET deleted_at = ? WHERE name = ? AND deleted_at IS NOT NULL`, old, name); err != nil {
			t.Fatal(err)
		}
	}
}

// sweepAsLeaseHolder runs one pass of the schedule orphan sweep on n, made
// the failover lease holder.
func sweepAsLeaseHolder(t *testing.T, n *Node) {
	t.Helper()
	ctx := context.Background()
	if held, _, err := corrosion.AcquireLeaseWithTerm(ctx, n.DB, corrosion.LeaseKeyFailover, n.Name, time.Hour, time.Now()); err != nil || !held {
		t.Fatalf("%s takes the failover lease: held=%v err=%v", n.Name, held, err)
	}
	n.Server.SweepScheduleOrphansForTest(ctx, time.Now())
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
	// Two days on, the lease holder's sweep leaves them dormant too: the
	// stack is live, and the next deploy brings web back.
	ageTombstone(t, c, "vms", "web")
	sweepAsLeaseHolder(t, c.Nodes[2])
	waitHistoryApplied(t, c, 30*time.Second)
	for _, n := range c.Nodes {
		if got := schedulesOn(t, n); !strings.Contains(got, "web/brrepo") || !strings.Contains(got, "web/ops") {
			t.Errorf("live schedules on %s after the cutover and a sweep = %q, want web/brrepo and web/ops kept", n.Name, got)
		}
	}
}

// A rebuild whose create fails after the teardown leaves web tombstoned, and
// its schedules dormant, as main did: past the grace the lease holder's sweep
// leaves them, and they serve web again once it is created anew.
//
// Mutation: drop the torn-down-stack clause from the orphan rule — red.
func TestFleet_AFailedRebuildLeavesTheSchedulesDormant(t *testing.T) {
	c, _ := newScheduledStackFleet(t)
	ctx := context.Background()
	n0 := c.Nodes[0]
	// Another web takes the name between the teardown and the create, so the
	// create is refused; it is then removed, leaving web tombstoned.
	n0.Server.SetRecreateTornDownHookForTest(func(name string) {
		if err := corrosion.InsertVM(ctx, n0.DB, corrosion.VMRecord{
			Name: name, StackName: "brs", HostName: n0.Name, State: "stopped",
			Spec: `{"name":"web","uuid":"7e1f0c2d-3b4a-4c5d-8e6f-9a0b1c2d3e4f"}`,
		}, nil, nil); err != nil {
			t.Errorf("insert another web: %v", err)
		}
	})
	t.Cleanup(func() { n0.Server.SetRecreateTornDownHookForTest(nil) })
	if _, err := c.SelfClient(n0).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"}); err == nil {
		t.Fatal("premise: the rebuild's create succeeded over another web")
	}
	n0.Server.SetRecreateTornDownHookForTest(nil)
	if err := corrosion.DeleteVM(ctx, n0.DB, "web"); err != nil {
		t.Fatal(err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	ageTombstone(t, c, "vms", "web")
	sweepAsLeaseHolder(t, c.Nodes[2])
	assertSchedulesEverywhere(t, c, "web/brrepo,web/ops")

	// The name comes back: the dormant schedules are web's again.
	deployClean(t, ctx, c.SelfClient(c.Nodes[1]), scheduledStack("third"))
	assertSchedulesEverywhere(t, c, "web/brrepo,web/ops")
	if vm, _ := corrosion.GetVM(ctx, n0.DB, "web"); vm == nil {
		t.Fatal("web was not created again")
	}
}

// compose down entered on node-1 while node-1's replica has no row of web
// yet: its own delete answers NotFound, the teardown fans the delete out, and
// node-0 deletes web as a peer's call — which leaves the schedules to the
// entry. The teardown removes them, and the repo goes with the stack.
//
// Mutation: drop the deleteVMSchedules call after a fan-out delete — red.
func TestFleet_ComposeDownThatFansTheDeleteOutTakesTheSchedules(t *testing.T) {
	c, _ := newScheduledStackFleet(t)
	ctx := context.Background()
	n1 := c.Nodes[1]
	n1.Server.SetStackMemberDeleteHookForTest(func(name string) {
		if err := localExec(ctx, n1.DB, `DELETE FROM vms WHERE name = ?`, name); err != nil {
			t.Errorf("drop %s from %s's replica: %v", name, n1.Name, err)
		}
	})
	t.Cleanup(func() { n1.Server.SetStackMemberDeleteHookForTest(nil) })
	for _, p := range deleteStackCollect(t, ctx, c.SelfClient(n1), "brs") {
		if p.Status == "error" {
			t.Fatalf("compose down: %s: %s", p.VmName, p.Error)
		}
	}
	// The entry's replica was cut apart from the others above, so the
	// replicas are compared on these rows only.
	eventually(t, 20*time.Second, "web's schedules removed and brrepo unregistered on every node", func() bool {
		for _, n := range c.Nodes {
			if r, _ := corrosion.GetBackupRepo(ctx, n.DB, "brrepo"); r != nil || schedulesOn(t, n) != "" {
				return false
			}
		}
		return true
	})
}

// lv ct rm entered on node-1 of a container on node-0 (forwarded to the
// owner): the entry removes the container's replication schedule on every
// replica; the other container's stays.
//
// Mutation: drop the deleteContainerSchedules call — red.
func TestFleet_ContainerRmTakesItsSchedules(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	ctx := context.Background()
	n0, n1 := c.Nodes[0], c.Nodes[1]
	replCT(t, c, n0, "ct1")
	replCT(t, c, n0, "ct2")
	drRepo(t, c.Nodes[2])
	ctSchedule(t, c, n0, "ct1", c.Nodes[2].Name, 2, false)
	ctSchedule(t, c, n0, "ct2", c.Nodes[2].Name, 2, false)
	c.WaitConverged(t, 20*time.Second)
	if _, err := c.SelfClient(n1).DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: n0.Name, Name: "ct1", Force: true}); err != nil {
		t.Fatalf("lv ct rm: %v", err)
	}
	eventually(t, 20*time.Second, "ct1's schedule removed on every node", func() bool {
		for _, n := range c.Nodes {
			if schedulesOn(t, n) != "@ct:_default/ct2/dr" {
				return false
			}
		}
		return true
	})
}

// A cluster that already holds schedules of a torn-down stack's VM and
// container deleted long ago — left by deletes on an older build, as on lab 2
// — heals with no migration: the VM's schedule no longer keeps the stack's
// repo registered, and the failover lease holder's sweep removes both on
// every replica. A schedule of a VM whose row has not arrived is kept.
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
	// A container of the stack, with a replication schedule, deleted too.
	if err := corrosion.UpsertContainer(ctx, n0.DB, corrosion.ContainerRecord{HostName: n0.Name, Name: "e2e-ct", State: "stopped",
		Labels: map[string]string{corrosion.LabelStack: "gone-stack"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainerReplicationSchedule(ctx, n0.DB, capabilities.GrantForTest(t, capabilities.FeatureContainerReplication),
		corrosion.BackupScheduleRecord{VMName: corrosion.ContainerScheduleKey("", "e2e-ct"), Scope: "container", Type: "replication",
			Repo: "dr", TargetPool: "dr", Cron: "0 * * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, n0.DB, "e2e-br"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, n0.DB, n0.Name, "e2e-ct"); err != nil {
		t.Fatal(err)
	}
	// The stack was torn down.
	if err := corrosion.UpsertStack(ctx, n0.DB, corrosion.StackRecord{Name: "gone-stack", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteStackRecord(ctx, n0.DB, "gone-stack"); err != nil {
		t.Fatal(err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	// The deletes were two days ago: past the grace.
	ageTombstone(t, c, "vms", "e2e-br")
	ageTombstone(t, c, "containers", "e2e-ct")

	// The stack's teardown, as the sweep of torn-down stacks' rows retries
	// it on any node, no longer keeps the repo for the leftover.
	if err := corrosion.DeleteStackBackupRepos(ctx, holder.DB, "gone-stack", nil); err != nil {
		t.Fatal(err)
	}
	if r, err := corrosion.GetBackupRepo(ctx, holder.DB, "e2erepo"); err != nil || r != nil {
		t.Errorf("e2erepo after the teardown is retried: %+v (%v), want it unregistered", r, err)
	}

	sweepAsLeaseHolder(t, holder)
	assertSchedulesEverywhere(t, c, "unborn/other")
}

const scheduledContainerStack = `name: cts

workloads:
  ct:
    kind: lxc
    image: IMAGE
    cpu: 1
    memory: 256
    placement:
      host: node-0
`

// A compose re-create of a container (its image changed) deletes and creates
// it again under its name: the container's replication schedule stays.
//
// Mutation: drop withSchedulesKept from recreateInline's container delete — red.
func TestFleet_AComposeContainerReCreateKeepsItsSchedule(t *testing.T) {
	node, client := newContainerComposeNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, strings.ReplaceAll(scheduledContainerStack, "IMAGE", "alpine:3.21"))
	before, err := corrosion.GetContainer(ctx, node.DB, node.Name, "ct")
	if err != nil || before == nil {
		t.Fatalf("container ct after the deploy: %+v (%v)", before, err)
	}
	if err := corrosion.UpsertContainerReplicationSchedule(ctx, node.DB, capabilities.GrantForTest(t, capabilities.FeatureContainerReplication),
		corrosion.BackupScheduleRecord{VMName: corrosion.ContainerScheduleKey("", "ct"), Scope: "container", Type: "replication",
			Repo: "dr", TargetPool: "dr", Cron: "0 * * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // a re-created row's created_at differs
	deployClean(t, ctx, client, strings.ReplaceAll(scheduledContainerStack, "IMAGE", "alpine:3.22"))
	after, err := corrosion.GetContainer(ctx, node.DB, node.Name, "ct")
	if err != nil || after == nil || after.CreatedAt == before.CreatedAt {
		t.Fatalf("premise: ct was not re-created: before %+v after %+v (%v)", before, after, err)
	}
	if got := schedulesOn(t, node); got != "@ct:_default/ct/dr" {
		t.Fatalf("schedules after the container re-create = %q, want @ct:_default/ct/dr kept", got)
	}
}
