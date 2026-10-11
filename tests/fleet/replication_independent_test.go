package fleet

// Replication's multi-node safety claims, each on independent replicas: every
// node has its own database and the production push loop carries writes
// between them, so a node can genuinely lag, sit behind a partition, or act on a
// stale view. A shared database cannot reach any of these (cluster.go).
//
//   - a failover that did not restore from the replica never deletes it (C1)
//   - a stale or fenced owner cannot add a replica (I3), container and VM
//   - a new owner that has not seen the direction switch does not replicate
//     onto itself, and is never reported a success (I2, M1), container and VM
//   - a reversal with a common base sends only the delta (I6)

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/qcow2"
)

const replWait = 20 * time.Second

func waitForRepl(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(replWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// scheduleOn is the schedule (key, repo) as n's own database holds it.
func scheduleOn(t *testing.T, n *Node, key, repo string) corrosion.BackupScheduleRecord {
	t.Helper()
	rows, err := corrosion.ListBackupSchedules(context.Background(), n.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.VMName == key && r.Repo == repo {
			return r
		}
	}
	t.Fatalf("%s holds no schedule %s|%s", n.Name, key, repo)
	return corrosion.BackupScheduleRecord{}
}

// containerHostOn is where n's own database says name runs.
func containerHostOn(t *testing.T, n *Node, name string) string {
	t.Helper()
	cts, err := corrosion.ListContainers(context.Background(), n.DB, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ct := range cts {
		if ct.Name == name {
			return ct.HostName
		}
	}
	return ""
}

func replHostStateOn(n *Node, host string) string {
	h, err := corrosion.GetHost(context.Background(), n.DB, host)
	if err != nil || h == nil {
		return ""
	}
	return h.State
}

// cutOff blocks every replication link INTO n: it keeps acting on what it
// last saw, as a host behind a partition or just back from a fence does.
func cutOff(c *Cluster, n *Node) {
	for _, o := range c.Nodes {
		if o != n {
			c.SetLinkFault(o, n, LinkFault{Block: true})
		}
	}
}

// probeCTRuntimes has every node list its containers in its runtime
// inventory, as an LXC-capable host does, whether or not the machine running
// the test has the lxc tooling: a replica restore asks each host's runtime.
func probeCTRuntimes(c *Cluster) {
	for _, n := range c.Nodes {
		n.Server.SetLXCCapableForTest(true)
	}
}

// relocateOnDB moves name's row from `from` to `to` on n's database and marks
// `from` fenced there: the end state of a failover relocation (the coordinator's
// tombstone of the old row and the new owner's row), arriving everywhere by
// replication.
func relocateOnDB(t *testing.T, n *Node, from, to *Node, name string) {
	t.Helper()
	ctx := context.Background()
	row, err := corrosion.GetContainer(ctx, n.DB, from.Name, name)
	if err != nil || row == nil {
		t.Fatalf("row of %s on %s: %v", name, from.Name, err)
	}
	if err := corrosion.UpdateHostState(ctx, n.DB, from.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	moved := *row
	moved.HostName, moved.CreatedAt = to.Name, ""
	moved.CreateSpec, _ = corrosion.WithNewPlacement(moved.CreateSpec) // a placement change
	if err := corrosion.UpsertContainer(ctx, n.DB, moved); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, n.DB, from.Name, name); err != nil {
		t.Fatal(err)
	}
}

// C1, end to end on independent replicas: the container's host is lost and it
// comes back up on another host WITHOUT its replica (re-created there from its
// image). The new owner's first run reaches the replica host. The replicas taken
// before the loss are the newest copy of the container's data; nothing proves the
// new owner's data contains them, so they are set aside: kept, listed as such,
// and removed only by an operator.
func TestReplicationIndependent_AFailoverThatDidNotUseTheReplicaKeepsIt(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	probeCTRuntimes(c)
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, b)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, b.Name, 2, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "the data before the loss")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-10*time.Minute)); err != nil {
		t.Fatalf("replicate to %s: %v", b.Name, err)
	}
	before := replicas(t, repo, name)
	if len(before) != 1 {
		t.Fatalf("want one replica on %s, got %d", b.Name, len(before))
	}

	// a is lost; the container comes back on d from its image, not from the
	// replica on b.
	c.Isolate(a)
	relocateOnDB(t, d, a, d, name)
	c.WaitConverged(t, convergeTimeout, b, d)
	d.CT.Seed(name, "re-created from the image")
	if got := containerHostOn(t, b, name); got != d.Name {
		t.Fatalf("%s does not yet see the container on %s (sees %q)", b.Name, d.Name, got)
	}

	if err := d.Server.RunReplication(ctx, scheduleOn(t, d, sched.VMName, sched.Repo), time.Now().UTC()); err != nil {
		t.Fatalf("the new owner's first run: %v", err)
	}
	after := replicas(t, repo, name)
	if len(after) != 2 {
		t.Fatalf("the replica from before the loss was deleted by the new owner's run: %d replica(s) left", len(after))
	}
	list, err := c.SelfClient(b).ListContainerReplicas(ctx, &pb.ListContainerReplicasRequest{Repo: "dr", Project: "_default", Name: name})
	if err != nil {
		t.Fatal(err)
	}
	var aside, current []string
	for _, r := range list.GetReplicas() {
		if r.SetAside {
			aside = append(aside, r.Timestamp)
		} else {
			current = append(current, r.Timestamp)
		}
	}
	if len(aside) != 1 || aside[0] != before[0].Timestamp || len(current) != 1 {
		t.Fatalf("want the earlier replica listed as set aside and the new one current: aside %v current %v", aside, current)
	}
	// N3: the kept replica can be restored by an operator, but never as a
	// second runnable copy: not while the container lives on d.
	restore := &pb.RestoreContainerReplicaRequest{Repo: "dr", Project: "_default", Name: name, Timestamp: aside[0]}
	if _, err := c.SelfClient(b).RestoreContainerReplica(ctx, restore); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("restoring a replica of a container that lives on %s: %v, want refused", d.Name, err)
	}
	// The container is deleted on d: its runtime, then its row.
	if err := d.CT.DeleteContainer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, d.DB, d.Name, name); err != nil {
		t.Fatal(err)
	}
	waitForRepl(t, b.Name+" to see the container gone", func() bool { return containerHostOn(t, b, name) == "" })
	// a, the host the replica was taken on, is asked too: while it is cut off
	// it still sees its own row live, and the restore is refused. a is cut off
	// from replication only, so it answers: "still sees" is its answer, not a
	// host that could not be asked ("cannot confirm").
	if _, err := c.SelfClient(b).RestoreContainerReplica(ctx, restore); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), a.Name+" still sees") {
		t.Fatalf("a restore while %s, the replica's source, still sees the container live: %v, want refused because it still sees it", a.Name, err)
	}
	// a comes back and learns the container moved and is gone. Its rows say
	// so, but its runtime still holds web, with the data from before the
	// loss: a copy with no row, which may be newer than the replica.
	c.ClearLinkFaults()
	waitForRepl(t, a.Name+" to see the container gone", func() bool { return containerHostOn(t, a, name) == "" })
	if _, err := c.SelfClient(b).RestoreContainerReplica(ctx, restore); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), a.Name+" runs "+name+" with no live row") {
		t.Fatalf("a restore while %s still holds the container's runtime: %v, want refused because it runs it with no row", a.Name, err)
	}
	// The operator deals with a's copy; now every host that could hold the
	// container says it holds none.
	if err := a.CT.DeleteContainer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(b).RestoreContainerReplica(ctx, restore); err != nil {
		t.Fatalf("restoring the set-aside replica: %v", err)
	}
	if got := b.CT.Payload(name); got != "the data before the loss" {
		t.Fatalf("the restored container holds %q, want the data from before the loss", got)
	}
	if got := containerHostOn(t, b, name); got != b.Name {
		t.Fatalf("the restored container's row is on %q, want %s", got, b.Name)
	}

	// Only a set-aside replica can be removed, and only by asking.
	if _, err := c.SelfClient(b).RemoveContainerReplicas(ctx, &pb.RemoveContainerReplicasRequest{
		Repo: "dr", Project: "_default", Name: name, Timestamps: current,
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("removing the current replica: %v, want refused", err)
	}
	if _, err := c.SelfClient(b).RemoveContainerReplicas(ctx, &pb.RemoveContainerReplicasRequest{
		Repo: "dr", Project: "_default", Name: name, Timestamps: aside,
	}); err != nil {
		t.Fatalf("removing the set-aside replica: %v", err)
	}
	if left := replicas(t, repo, name); len(left) != 1 {
		t.Fatalf("%d replica(s) after the removal, want the current one", len(left))
	}
}

// I3, container: the owner is fenced and its container relocated while it sits
// behind a partition. It still sees itself as the owner and its schedule as it
// was, and it can still reach the replica host. The replica host, which saw the
// fence and the relocation, refuses its push: a stale owner adds nothing that
// could later be promoted.
func TestReplicationIndependent_AStaleOwnerBehindAPartitionCannotPush(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, b)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, b.Name, 3, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "before")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	cutOff(c, a)
	relocateOnDB(t, coord, a, coord, name)
	waitForRepl(t, b.Name+" to see the fence and the relocation", func() bool {
		return replHostStateOn(b, a.Name) == "fenced" && containerHostOn(t, b, name) == coord.Name
	})
	if got := containerHostOn(t, a, name); got != a.Name {
		t.Fatalf("the premise: %s must still believe it owns the container (sees %q)", a.Name, got)
	}

	a.CT.Seed(name, "the abandoned branch")
	err := a.Server.RunReplication(ctx, scheduleOn(t, a, sched.VMName, sched.Repo), time.Now().UTC())
	if err == nil {
		t.Fatal("a fenced, relocated owner's push was accepted")
	}
	if n := len(replicas(t, repo, name)); n != 1 {
		t.Fatalf("the replica host holds %d replicas after the stale push, want only the one from before", n)
	}
}

// I2 + M1, container, under lag: the container moves onto its replica host,
// whose database has the new ownership but not yet the switch of direction
// (written by the host that committed the move). Its run must not put the
// replica beside the container, and must not report success; once the switch
// arrives it replicates to the host the container left.
func TestReplicationIndependent_ANewOwnerThatMissedTheSwitchWaits(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repoA, repoB := drRepo(t, a), drRepo(t, b)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, b.Name, 3, true)
	c.WaitConverged(t, convergeTimeout)

	// The move lands on b; the switch, written on a, is held back.
	row, err := corrosion.GetContainer(ctx, a.DB, a.Name, name)
	if err != nil || row == nil {
		t.Fatal(err)
	}
	moved := *row
	moved.HostName, moved.CreatedAt = b.Name, ""
	moved.CreateSpec, _ = corrosion.WithNewPlacement(moved.CreateSpec)
	if err := corrosion.UpsertContainer(ctx, b.DB, moved); err != nil {
		t.Fatal(err)
	}
	b.CT.Seed(name, "on b")
	c.SetLinkFault(a, b, LinkFault{Block: true})
	if err := corrosion.DeleteContainer(ctx, a.DB, a.Name, name); err != nil {
		t.Fatal(err)
	}
	if _, err := corrosion.ReverseReplicationOnMove(ctx, a.DB, "container", name, "", a.Name, b.Name, corrosion.ReverseOptions{}); err != nil {
		t.Fatal(err)
	}
	onB := scheduleOn(t, b, sched.VMName, sched.Repo)
	if onB.TargetHost != b.Name {
		t.Fatalf("the premise: %s must not have the switch yet (targets %q)", b.Name, onB.TargetHost)
	}
	err = b.Server.RunReplication(ctx, onB, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("a run onto the container's own host: %v, want suspended (never a success)", err)
	}
	if n := len(replicas(t, repoB, name)); n != 0 {
		t.Fatalf("a replica was written on the host the container runs on (%d)", n)
	}

	c.ClearLinkFaults()
	waitForRepl(t, "the switch to reach "+b.Name, func() bool { return scheduleOn(t, b, sched.VMName, sched.Repo).TargetHost == a.Name })
	if err := b.Server.RunReplication(ctx, scheduleOn(t, b, sched.VMName, sched.Repo), time.Now().UTC()); err != nil {
		t.Fatalf("after the switch: %v", err)
	}
	if n := len(replicas(t, repoA, name)); n != 1 {
		t.Fatalf("no replica reached %s after the switch (%d)", a.Name, n)
	}
}

// fill writes size random bytes to the container's rootfs file rel on n.
func fill(t *testing.T, dir, rel string, size int) {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rootfs", rel), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func chunkFiles(t *testing.T, ns string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	_ = filepath.WalkDir(filepath.Join(ns, "chunks"), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			out[filepath.Base(p)] = true
		}
		return nil
	})
	return out
}

// I6: a container moved there and back replicates in the old direction again,
// to a replica host that still holds the replicas from before. That is a common
// base: the run sends only the chunks around what changed, though a file in the
// middle of the archive grew (which shifts every later byte of the tar).
func TestReplicationIndependent_AReversalWithACommonBaseSendsOnlyTheDelta(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	drRepo(t, a)
	repoB := drRepo(t, b)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, b.Name, 3, true)
	c.WaitConverged(t, convergeTimeout)
	dir := a.CT.Seed(name, "payload")
	for _, f := range []string{"a.bin", "b.bin", "c.bin", "d.bin"} {
		fill(t, dir, f, 8<<20)
	}
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	if err := runMigrate(t, c, a, b, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate a->b: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if err := runMigrate(t, c, b, a, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate b->a: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := scheduleOn(t, a, sched.VMName, sched.Repo).TargetHost; got != b.Name {
		t.Fatalf("after the move back the schedule targets %q, want %q", got, b.Name)
	}
	// The first file grows: every later byte of the archive shifts.
	moved := filepath.Join(c.tmpRoot, a.Name, "lxc", name, "rootfs", "a.bin")
	f, err := os.OpenFile(moved, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	have := chunkFiles(t, replicaNS(repoB))
	if err := a.Server.RunReplication(ctx, scheduleOn(t, a, sched.VMName, sched.Repo), time.Now().UTC()); err != nil {
		t.Fatalf("the run after the move back: %v", err)
	}
	now := chunkFiles(t, replicaNS(repoB))
	fresh := 0
	for id := range now {
		if !have[id] {
			fresh++
		}
	}
	// Around the change, plus each file's tar header (an import does not keep
	// mtimes): a handful, against a whole-archive resend.
	if fresh*3 > len(now) {
		t.Fatalf("the run over a common base sent %d new chunk(s) of %d: only the chunks around the changes should cross", fresh, len(now))
	}
}

// vmFixture puts VM web on n with a qcow2 root disk, in every node's database
// through n (independent replicas: it travels).
func vmOnHost(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	src := filepath.Join(c.tmpRoot, n.Name, "web-root-src.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: "web", HostName: n.Name, State: "running", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "web", DiskName: "root", HostName: n.Name, Path: src, SizeBytes: 1 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
}

func vmHostOn(n *Node) string {
	vm, err := corrosion.GetVM(context.Background(), n.DB, "web")
	if err != nil || vm == nil {
		return ""
	}
	return vm.HostName
}

// I3, VM: as for a container, the VM's host is fenced and the VM moved while it
// is cut off; its push to the replica host is refused by that host's own view.
func TestReplicationIndependent_AFencedVMOwnerCannotPush(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	drPool(t, c, a)
	poolB := drPool(t, c, b)
	vmOnHost(t, c, a)
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: b.Name, KeepReplicas: 3,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, a.DB, sched); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if err := a.Server.RunReplication(ctx, sched, time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatalf("the owner's own run: %v", err)
	}
	if replicaRecordsIn(t, poolB, "web") != 1 {
		t.Fatal("the first replica did not land")
	}

	cutOff(c, a)
	if err := corrosion.UpdateHostState(ctx, coord.DB, a.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.TransferVMOwnerFresh(ctx, coord.DB, "web", coord.Name, "running"); err != nil {
		t.Fatal(err)
	}
	waitForRepl(t, b.Name+" to see the fence and the move", func() bool {
		return replHostStateOn(b, a.Name) == "fenced" && vmHostOn(b) == coord.Name
	})
	if vmHostOn(a) != a.Name {
		t.Fatalf("the premise: %s must still believe it owns the VM", a.Name)
	}
	if err := a.Server.RunReplication(ctx, sched, time.Now()); err == nil {
		t.Fatal("a fenced, moved owner's push was accepted")
	}
	if n := replicaRecordsIn(t, poolB, "web"); n != 1 {
		t.Fatalf("the replica host recorded %d replicas, want only the one from before", n)
	}
}

// I2 + M1, VM, under lag: the VM's new host has the move but not the switch.
func TestReplicationIndependent_AVMsNewOwnerThatMissedTheSwitchWaits(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	poolA := drPool(t, c, a)
	poolB := drPool(t, c, b)
	vmOnHost(t, c, a)
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: b.Name, KeepReplicas: 3,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, a.DB, sched); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	// b holds a's replica: what makes b's own run, once the VM is there, the
	// move's leftover rather than an operator's same-host copy.
	if err := a.Server.RunReplication(ctx, sched, time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatalf("the owner's own run: %v", err)
	}

	if err := corrosion.TransferVMOwnerFresh(ctx, a.DB, "web", b.Name, "running"); err != nil {
		t.Fatal(err)
	}
	waitForRepl(t, b.Name+" to see the move", func() bool { return vmHostOn(b) == b.Name })
	c.SetLinkFault(a, b, LinkFault{Block: true})
	if _, err := corrosion.ReverseReplicationOnMove(ctx, a.DB, "vm", "web", "", a.Name, b.Name, corrosion.ReverseOptions{}); err != nil {
		t.Fatal(err)
	}
	onB := scheduleOn(t, b, "web", "dr")
	if onB.TargetHost != b.Name {
		t.Fatalf("the premise: %s must not have the switch yet", b.Name)
	}
	if err := b.Server.RunReplication(ctx, onB, time.Now()); err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("a run onto the VM's own host: %v, want suspended", err)
	}
	if n := replicaRecordsIn(t, poolB, "web"); n != 1 {
		t.Fatalf("a replica was written beside the VM's disk (%d, want only a's)", n)
	}
	c.ClearLinkFaults()
	waitForRepl(t, "the switch to reach "+b.Name, func() bool { return scheduleOn(t, b, "web", "dr").TargetHost == a.Name })
	if err := b.Server.RunReplication(ctx, scheduleOn(t, b, "web", "dr"), time.Now()); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("after the switch: %v", err)
	}
	if n := replicaRecordsIn(t, poolA, "web"); n != 1 {
		t.Fatalf("no replica reached %s after the switch (%d)", a.Name, n)
	}
}

// N1, the reviewer's scenario: a container on D is lost and image-recreated on
// A (a relocate-recreate, which keeps created_at), then A is lost and it is
// image-recreated back onto D. D's replicas from before the first loss are the
// only copy of the real data. However many runs the container makes back on D,
// keep_replicas never trims them: a return to D is a new placement.
func TestReplicationIndependent_AReturnToAFormerHostNeverTrimsThePreLossReplicas(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	tgt, d, a := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, d, name)
	repo := drRepo(t, tgt)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, d, name, tgt.Name, 2, true)
	runningRow(t, d, name) // failover relocates a running container
	c.WaitConverged(t, convergeTimeout)
	base := time.Now().UTC().Add(-time.Hour)
	tick := 0
	run := func(n *Node) {
		t.Helper()
		tick++
		if err := n.Server.RunReplication(ctx, scheduleOn(t, n, sched.VMName, sched.Repo), base.Add(time.Duration(tick)*time.Minute)); err != nil {
			t.Fatalf("run %d on %s: %v", tick, n.Name, err)
		}
	}
	d.CT.Seed(name, "the real data")
	run(d)
	run(d)
	pre := map[string]bool{}
	for _, m := range replicas(t, repo, name) {
		pre[m.Timestamp] = true
	}
	if len(pre) != 2 {
		t.Fatalf("premise: two pre-loss replicas, got %d", len(pre))
	}
	relocate := func(from, to *Node, token string) {
		t.Helper()
		if err := corrosion.RelocateContainerWithToken(ctx, tgt.DB, from.Name, name, to.Name, token); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.CompleteContainerRelocation(ctx, tgt.DB, to.Name, name, token); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		to.CT.Seed(name, "recreated from the image on "+to.Name)
	}
	// A is lost before it ever runs: nothing sets D's pre-loss replicas aside,
	// so only the placement id keeps the return to D from trimming them.
	relocate(d, a, "tok-1")
	relocate(a, d, "tok-2")
	for i := 0; i < 4; i++ {
		run(d)
		have := map[string]bool{}
		for _, m := range replicas(t, repo, name) {
			have[m.Timestamp] = true
		}
		for ts := range pre {
			if !have[ts] {
				t.Fatalf("run %d back on %s trimmed the pre-loss replica %s", i+1, d.Name, ts)
			}
		}
	}
}

// R2-m3: the replica host's view can lag (a move's new row and the old row's
// tombstone travel on independent streams). A restore needs the container's
// last-known owner to confirm, positively, that it holds no live row: here the
// replica host has a tombstone the owner never received, and the restore is
// refused with the reason.
func TestReplicationIndependent_ARestoreNeedsTheLastOwnersWord(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, b)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, b.Name, 2, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "replicated")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("premise: one replica, got %d", len(ms))
	}
	cutOff(c, a) // a never learns of the tombstone below
	if err := corrosion.DeleteContainer(ctx, b.DB, a.Name, name); err != nil {
		t.Fatal(err)
	}
	if containerHostOn(t, b, name) != "" || containerHostOn(t, a, name) != a.Name {
		t.Fatal("premise: b sees no container, a still holds it")
	}
	_, err := c.SelfClient(b).RestoreContainerReplica(ctx, &pb.RestoreContainerReplicaRequest{
		Repo: "dr", Project: "_default", Name: name, Timestamp: ms[0].Timestamp,
	})
	// "still sees": the owner answered and contradicted the restore, which is
	// a different refusal from an owner that could not be asked.
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still sees") || !strings.Contains(err.Error(), a.Name) {
		t.Fatalf("a restore the last-known owner contradicts: %v, want refused because %s still sees it live", err, a.Name)
	}
	if b.CT.Exists(name) {
		t.Fatal("a second copy was laid down")
	}
}

// R3-I1, the migrate case: web moves from a to b. b's new row travels on b's
// stream and a's tombstone on a's, and b's stream is held from both the replica
// host and a. The replica host's newest row is a's tombstone, and a, asked,
// sees no live row either: only b can say web is running, so b must be asked.
func TestReplicationIndependent_ARestoreAsksTheHostAMigrateMovedTo(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, tg := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	probeCTRuntimes(c)
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, tg)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, tg.Name, 2, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "replicated")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("premise: one replica, got %d", len(ms))
	}
	// The migrate: b's stream is held from tg and from a, in both directions,
	// so neither learns of b's row by push or by pull.
	c.SetLinkFaultBoth(b, tg, LinkFault{Block: true})
	c.SetLinkFaultBoth(b, a, LinkFault{Block: true})
	row, err := corrosion.GetContainer(ctx, a.DB, a.Name, name)
	if err != nil || row == nil {
		t.Fatalf("row on %s: %v", a.Name, err)
	}
	moved := *row
	moved.HostName, moved.CreatedAt = b.Name, ""
	moved.CreateSpec, _ = corrosion.WithNewPlacement(moved.CreateSpec)
	if err := corrosion.UpsertContainer(ctx, b.DB, moved); err != nil {
		t.Fatal(err)
	}
	// The migrate removes the container's runtime from a, then its row.
	if err := a.CT.DeleteContainer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, a.DB, a.Name, name); err != nil {
		t.Fatal(err)
	}
	waitForRepl(t, tg.Name+" to apply "+a.Name+"'s tombstone", func() bool { return containerHostOn(t, tg, name) == "" })
	if onB, err := corrosion.GetContainer(ctx, b.DB, b.Name, name); containerHostOn(t, a, name) != "" || err != nil || onB == nil {
		t.Fatalf("premise: %s sees no container, %s runs it (%v)", a.Name, b.Name, err)
	}
	_, err = c.SelfClient(tg).RestoreContainerReplica(ctx, &pb.RestoreContainerReplicaRequest{
		Repo: "dr", Project: "_default", Name: name, Timestamp: ms[0].Timestamp,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still sees") || !strings.Contains(err.Error(), b.Name) {
		t.Fatalf("a restore while %s runs the container after a migrate: %v, want refused because %s still sees it live", b.Name, err, b.Name)
	}
	if tg.CT.Exists(name) {
		t.Fatal("a second copy was laid down")
	}
}

// R3-I1, the no-row case: the replica host holds replicas of a container it has
// no row for at all (the owner's stream to it is held; replicas arrive by a
// direct push). No row is not absence: the host the replica was taken on is
// asked, and it still runs the container.
func TestReplicationIndependent_ARestoreWithNoRowAsksTheReplicasSource(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, tg := c.Nodes[0], c.Nodes[2]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	repo := drRepo(t, tg)
	cutOff(c, tg) // tg never receives the container's row
	replCT(t, c, a, name)
	sched := ctSchedule(t, c, a, name, tg.Name, 2, true)
	a.CT.Seed(name, "replicated")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("premise: one replica on %s, got %d", tg.Name, len(ms))
	}
	if rows, err := tg.DB.Query(ctx, `SELECT host_name FROM containers WHERE name = ?`, name); err != nil || len(rows) != 0 {
		t.Fatalf("premise: %s holds no row of %s at all: %d row(s), %v", tg.Name, name, len(rows), err)
	}
	_, err := c.SelfClient(tg).RestoreContainerReplica(ctx, &pb.RestoreContainerReplicaRequest{
		Repo: "dr", Project: "_default", Name: name, Timestamp: ms[0].Timestamp,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still sees") || !strings.Contains(err.Error(), a.Name) {
		t.Fatalf("a restore on a host with no row while %s runs the container: %v, want refused because it is live on %s", a.Name, err, a.Name)
	}
	if tg.CT.Exists(name) {
		t.Fatal("a second copy was laid down")
	}
}

// R4-I1: a stale delete tombstones web's row on every host while web keeps
// running on a (the kvm003-f3 lab, 2026-09-30, with a container). Every host's
// rows say web is gone, a's included. a's runtime says otherwise, and it holds
// data newer than the replica: the restore is refused, naming a. Once a's copy
// is dealt with, the same restore goes through.
func TestReplicationIndependent_ARestoreAsksEveryHostsRuntime(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, tg := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	probeCTRuntimes(c)
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, tg)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, tg.Name, 2, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "replicated")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("premise: one replica, got %d", len(ms))
	}
	// The stale delete, served on b; a's runtime keeps running and writing.
	if err := corrosion.DeleteContainer(ctx, b.DB, a.Name, name); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		waitForRepl(t, n.Name+" to apply the tombstone", func() bool { return containerHostOn(t, n, name) == "" })
	}
	a.CT.Seed(name, "written after the replica")
	if !a.CT.Exists(name) {
		t.Fatalf("premise: %s still holds web's runtime", a.Name)
	}
	restore := &pb.RestoreContainerReplicaRequest{Repo: "dr", Project: "_default", Name: name, Timestamp: ms[0].Timestamp}
	_, err := c.SelfClient(tg).RestoreContainerReplica(ctx, restore)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), a.Name+" runs "+name+" with no live row") {
		t.Fatalf("a restore while %s runs the container with no row: %v, want refused naming %s", a.Name, err, a.Name)
	}
	if tg.CT.Exists(name) {
		t.Fatal("a second copy was laid down")
	}
	// Not vacuous: with a's copy gone, nothing else refuses.
	if err := a.CT.DeleteContainer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(tg).RestoreContainerReplica(ctx, restore); err != nil {
		t.Fatalf("the restore once %s no longer runs it: %v", a.Name, err)
	}
	if got := tg.CT.Payload(name); got != "replicated" {
		t.Fatalf("the restored container holds %q, want the replica's data", got)
	}
}

// The follow-ups to the restore's runtime ask (t2-dr-rereview-5.md P1 and P3),
// over real gRPC between real daemons:
//
//   - P3: another project's live row of the name on a host does not vouch for
//     that host's runtime when the runtime's own owner record says it is this
//     project's container (a ghost row over our orphan);
//   - P1: a member whose libvirt cannot be listed still proves the container
//     absent, from its container listing alone.
func TestReplicationIndependent_ARestoreReadsTheRuntimesOwnerRecord(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, tg := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	probeCTRuntimes(c)
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, tg)
	c.WaitConverged(t, convergeTimeout)
	sched := ctSchedule(t, c, a, name, tg.Name, 2, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "replicated")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("premise: one replica, got %d", len(ms))
	}
	if o, err := a.CT.ReadOwner(name); err != nil || o == nil || o.Project != "_default" {
		t.Fatalf("premise: %s's runtime of web is stamped _default: %+v, %v", a.Name, o, err)
	}
	// The stale delete, served on b; a's runtime keeps running and writing.
	if err := corrosion.DeleteContainer(ctx, b.DB, a.Name, name); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		waitForRepl(t, n.Name+" to apply the tombstone", func() bool { return containerHostOn(t, n, name) == "" })
	}
	a.CT.Seed(name, "written after the replica")
	// A ghost row of acme's web on a, over a's runtime of _default's web.
	if err := corrosion.UpsertContainer(ctx, b.DB, corrosion.ContainerRecord{HostName: a.Name, Name: name, Project: "acme", State: "stopped"}); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		waitForRepl(t, n.Name+" to see acme's row", func() bool {
			row, err := corrosion.GetContainer(ctx, n.DB, a.Name, name)
			return err == nil && row != nil && row.Project == "acme"
		})
	}
	// b's libvirt cannot be listed for the rest of the test.
	b.Virt.FailListDomains = func() error { return errors.New("libvirtd: connection reset") }
	defer func() { b.Virt.FailListDomains = nil }()

	restore := &pb.RestoreContainerReplicaRequest{Repo: "dr", Project: "_default", Name: name, Timestamp: ms[0].Timestamp}
	_, err := c.SelfClient(tg).RestoreContainerReplica(ctx, restore)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), a.Name+" runs "+name+", whose owner record says it is _default's") {
		t.Fatalf("a restore while %s runs our web under acme's row: %v, want refused naming %s", a.Name, err, a.Name)
	}
	if tg.CT.Exists(name) {
		t.Fatal("a second copy was laid down")
	}
	// Not vacuous: once a's runtime is acme's, nothing refuses, b's broken
	// libvirt included.
	if err := a.CT.StampOwner(name, lxc.ContainerOwner{Project: "acme"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(tg).RestoreContainerReplica(ctx, restore); err != nil {
		t.Fatalf("the restore once %s's web is acme's, with %s's libvirt down: %v", a.Name, b.Name, err)
	}
	if got := tg.CT.Payload(name); got != "replicated" {
		t.Fatalf("the restored container holds %q, want the replica's data", got)
	}
}
