// A delete whose client goes away after the delete has started acting.
//
// Lab 2, 2026-10-17 (lab2-stackrm-reaplo-proof.md, F1; 4 of 4 runs): a
// `lv compose down` killed mid-teardown. The member's owner ran its delete on
// the request context, which gRPC cancels when the coordinator's call is
// cancelled. The domain was destroyed and undefined; every step after that
// failed with "context canceled", the stop record among them, so the row was
// never tombstoned and still said running. 13 s later the reconciler read
// "running here, no domain" as a crashed guest and started the VM again, on
// the disk disk_leftover had just told the operator to remove by hand.
//
// Each scenario cancels the client at the exact moment the delete is past
// its point of no return: right after the domain is undefined (or the
// container's runtime is removed), holding there until the cancellation has
// reached the owner's handler.
package fleet

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

const deleteCancelYAML = `name: dcx

images:
  test:
    source: file:///dev/null

vms:
  dcx-1:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-1
`

// newDeleteCancelFleet is two independent replicas with dcx-1 running on
// node-1, deployed through node-0. It returns dcx-1's recorded disk paths.
func newDeleteCancelFleet(t *testing.T) (*Cluster, []string) {
	t.Helper()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
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
	deployClean(t, ctx, c.SelfClient(c.Nodes[0]), deleteCancelYAML)
	waitHistoryApplied(t, c, 20*time.Second)
	owner := c.Nodes[1]
	vm, err := corrosion.GetVM(ctx, owner.DB, "dcx-1")
	if err != nil || vm == nil || vm.HostName != owner.Name || vm.State != "running" {
		t.Fatalf("dcx-1 after the deploy: %+v (%v), want it running on %s", vm, err, owner.Name)
	}
	rows, err := owner.DB.Query(ctx, `SELECT path FROM vm_disks WHERE vm_name = 'dcx-1' AND deleted_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	var disks []string
	for _, r := range rows {
		if p := r.String("path"); p != "" {
			disks = append(disks, p)
		}
	}
	if len(disks) == 0 {
		t.Fatal("dcx-1 has no recorded disk")
	}
	for _, p := range disks {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("dcx-1 disk %s missing before the delete: %v", p, err)
		}
	}
	return c, disks
}

// cancelAfter arms owner so that the next call of method it serves cancels
// the client (cancel) as soon as act fires inside it, and holds act until the
// cancellation has reached that call's own context. It returns a channel that
// receives the handler's error once the handler has returned, and a func
// reporting whether the cancellation was delivered inside the window.
func cancelAfter(t *testing.T, owner *Node, method string, cancel context.CancelFunc) (returned <-chan error, armAct func() func(), reached func() bool) {
	t.Helper()
	srvCtx := make(chan context.Context, 1)
	out := make(chan error, 1)
	owner.HookUnary(method, func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		srvCtx <- ctx
		resp, err := handler(ctx, req)
		out <- err
		return resp, err
	})
	var (
		mu  sync.Mutex
		hit bool
	)
	armAct = func() func() {
		var once sync.Once
		return func() {
			once.Do(func() {
				var sctx context.Context
				select {
				case sctx = <-srvCtx:
				default:
					t.Errorf("%s acted on %s outside a %s call", owner.Name, method, method)
					return
				}
				cancel()
				select {
				case <-sctx.Done():
					mu.Lock()
					hit = true
					mu.Unlock()
				case <-time.After(20 * time.Second):
					t.Errorf("the client's cancellation did not reach %s's %s within 20s", owner.Name, method)
				}
			})
		}
	}
	reached = func() bool { mu.Lock(); defer mu.Unlock(); return hit }
	return out, armAct, reached
}

// waitHandler waits, bounded, for the owner's handler to return.
func waitHandler(t *testing.T, returned <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-returned:
		return err
	case <-time.After(60 * time.Second):
		t.Fatalf("the owner's %s had not returned 60s after its client left", what)
		return nil
	}
}

// assertVMDeleteFinished checks that a delete the client abandoned after the
// undefine finished on the owner: the row is tombstoned, the disks are freed,
// and no reconcile pass brings the VM back.
func assertVMDeleteFinished(t *testing.T, c *Cluster, owner *Node, disks []string, handlerErr error) {
	t.Helper()
	ctx := context.Background()
	if handlerErr != nil {
		t.Errorf("the owner's delete failed after its client left: %v", handlerErr)
	}
	if vm, _ := corrosion.GetVM(ctx, owner.DB, "dcx-1"); vm != nil {
		t.Errorf("dcx-1's row is live (state %q) with its domain undefined: the delete was half-applied", vm.State)
	}
	for _, p := range disks {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("disk %s is still there: the delete did not finish", p)
		}
	}
	rec := health.NewReconciler(owner.Name, filepath.Join(c.tmpRoot, owner.Name, "data"), owner.DB, owner.Virt)
	rec.ReconcileOnce(ctx)
	if owner.Virt.DomainExists("dcx-1") {
		st, _ := owner.Virt.DomainState("dcx-1")
		t.Errorf("a %s domain dcx-1 is on %s after a reconcile pass: the reconciler restarted a VM being deleted", st, owner.Name)
	}
}

// lv rm, entered on the owner and on another node. The cancellation reaches
// the owner as its own client's (on the owner) or as the entry's forward
// being cancelled (on node-0).
//
// Mutation: run deleteVM on the request context after the destroy (drop the
// detach) — every case goes red: the row stays live, and the reconciler
// starts dcx-1 again.
func TestFleet_DeleteVMFinishesWhenItsClientLeavesMidDelete(t *testing.T) {
	for _, entry := range []int{1, 0} {
		t.Run([]string{"entered on another node", "entered on the owner"}[entry], func(t *testing.T) {
			c, disks := newDeleteCancelFleet(t)
			owner := c.Nodes[1]
			cctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			returned, armAct, reached := cancelAfter(t, owner, "DeleteVM", cancel)
			act := armAct()
			owner.Virt.OnUndefined = func(name string) {
				if name == "dcx-1" {
					act()
				}
			}
			defer func() { owner.Virt.OnUndefined = nil }()

			_, err := c.SelfClient(c.Nodes[entry]).DeleteVM(cctx, &pb.DeleteVMRequest{Name: "dcx-1"})
			if err == nil {
				t.Log("the client saw the delete finish before its cancel took effect")
			}
			herr := waitHandler(t, returned, "DeleteVM")
			if !reached() {
				t.Fatal("the cancellation never reached the owner between its undefine and its tombstone; the scenario missed the window")
			}
			assertVMDeleteFinished(t, c, owner, disks, herr)
		})
	}
}

// compose down, entered on node-0, its stream cancelled while the member's
// owner (node-1) is mid-delete: the lab's shape.
//
// Mutation: as above — red.
func TestFleet_ComposeDownMemberDeleteFinishesWhenItsClientLeaves(t *testing.T) {
	c, disks := newDeleteCancelFleet(t)
	owner := c.Nodes[1]
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned, armAct, reached := cancelAfter(t, owner, "DeleteVM", cancel)
	act := armAct()
	owner.Virt.OnUndefined = func(name string) {
		if name == "dcx-1" {
			act()
		}
	}
	defer func() { owner.Virt.OnUndefined = nil }()

	stream, err := c.SelfClient(c.Nodes[0]).DeleteStack(cctx, &pb.DeleteStackRequest{Name: "dcx"})
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Logf("compose down's stream ended: %v", err)
			}
			break
		}
	}
	herr := waitHandler(t, returned, "DeleteVM")
	if !reached() {
		t.Fatal("the cancellation never reached the member's owner between its undefine and its tombstone; the scenario missed the window")
	}
	assertVMDeleteFinished(t, c, owner, disks, herr)
}

// lv ct rm entered on node-0 of a container on node-1: the runtime delete
// has happened when the client leaves. The row must not be left live over a
// container that no longer exists.
//
// Mutation: drop the detach in DeleteContainer — red: the row stays live.
func TestFleet_DeleteContainerFinishesWhenItsClientLeaves(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	owner := c.Nodes[1]
	owner.CT.Seed("dcx-ct", "data")
	if err := corrosion.UpsertContainer(ctx, owner.DB, corrosion.ContainerRecord{
		HostName: owner.Name, Name: "dcx-ct", State: "stopped", Image: "alpine:3.19",
	}); err != nil {
		t.Fatal(err)
	}
	waitHistoryApplied(t, c, 20*time.Second)

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	returned, armAct, reached := cancelAfter(t, owner, "DeleteContainer", cancel)
	act := armAct()
	owner.CT.OnDelete(func(name string) {
		if name == "dcx-ct" {
			act()
		}
	})
	_, _ = c.SelfClient(c.Nodes[0]).DeleteContainer(cctx, &pb.DeleteContainerRequest{Name: "dcx-ct", HostName: owner.Name})
	herr := waitHandler(t, returned, "DeleteContainer")
	if !reached() {
		t.Fatal("the cancellation never reached the owner between its runtime delete and its tombstone; the scenario missed the window")
	}
	if herr != nil {
		t.Errorf("the owner's container delete failed after its client left: %v", herr)
	}
	if rec, _ := corrosion.GetContainer(ctx, owner.DB, owner.Name, "dcx-ct"); rec != nil {
		t.Errorf("dcx-ct's row is live (state %q) with its runtime container removed: the delete was half-applied", rec.State)
	}
}

// undefineOnOwner leaves dcx-1's row running on node-1 with no domain there
// (a crash mid-teardown, a `virsh undefine`).
func undefineOnOwner(t *testing.T, owner *Node) {
	t.Helper()
	if err := owner.Virt.DestroyDomain("dcx-1"); err != nil {
		t.Fatal(err)
	}
	if err := owner.Virt.UndefineDomain("dcx-1", false); err != nil {
		t.Fatal(err)
	}
}

// lv rm on the owner of a VM whose domain is already gone there: the owner
// asks every peer whether it has the domain, then cleans up the record. The
// client leaves once the cleanup has started acting. Past that point the
// delete — devices, the stop record, disks, the tombstone — runs to its end.
//
// Mutation: drop the detach after the probes — red: the delete fails on its
// first write, and the row stays running with no domain.
func TestFleet_DeleteVMWithNoDomainFinishesWhenItsClientLeaves(t *testing.T) {
	c, _ := newDeleteCancelFleet(t)
	owner := c.Nodes[1]
	undefineOnOwner(t, owner)
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned, armAct, reached := cancelAfter(t, owner, "DeleteVM", cancel)
	act := armAct()
	owner.Server.SetDeleteStepHookForTest(func(vm, step string) {
		if vm == "dcx-1" && step == "acting" {
			act()
		}
	})
	t.Cleanup(func() { owner.Server.SetDeleteStepHookForTest(nil) })

	_, _ = c.SelfClient(owner).DeleteVM(cctx, &pb.DeleteVMRequest{Name: "dcx-1"})
	herr := waitHandler(t, returned, "DeleteVM")
	if !reached() {
		t.Fatal("the cancellation never reached the owner once its cleanup was acting; the scenario missed the window")
	}
	if herr != nil {
		t.Errorf("the owner's delete failed after its client left: %v", herr)
	}
	ctx := context.Background()
	if vm, _ := corrosion.GetVM(ctx, owner.DB, "dcx-1"); vm != nil {
		t.Errorf("dcx-1's row is live (state %q) with no domain anywhere: the delete did not finish", vm.State)
	}
	rec := health.NewReconciler(owner.Name, filepath.Join(c.tmpRoot, owner.Name, "data"), owner.DB, owner.Virt)
	rec.ReconcileOnce(ctx)
	if owner.Virt.DomainExists("dcx-1") {
		t.Errorf("a reconcile pass defined dcx-1 on %s after its delete", owner.Name)
	}
}

// The client leaves while the owner is still asking its peers. Nothing has
// been done yet, and a peer's answer is lost to the cancellation — one that
// has the domain among them — so the delete is refused and the record, the
// only handle on the VM, stays with its disks.
//
// Mutation: drop the ctx.Err() refusal after the probes — red: the owner
// tombstones the record on a view it never got.
func TestFleet_DeleteVMWithNoDomainCancelledDuringTheProbesIsRefused(t *testing.T) {
	c, disks := newDeleteCancelFleet(t)
	owner, peer := c.Nodes[1], c.Nodes[0]
	undefineOnOwner(t, owner)
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned, armAct, reached := cancelAfter(t, owner, "DeleteVM", cancel)
	act := armAct()
	peer.HookUnary("DeleteVM", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		act()
		return handler(ctx, req)
	})

	_, _ = c.SelfClient(owner).DeleteVM(cctx, &pb.DeleteVMRequest{Name: "dcx-1"})
	herr := waitHandler(t, returned, "DeleteVM")
	if !reached() {
		t.Fatal("the cancellation never reached the owner while it asked its peer; the scenario missed the window")
	}
	if herr == nil {
		t.Error("the owner's delete succeeded although its client left before it acted")
	}
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, owner.DB, "dcx-1")
	if vm == nil {
		t.Fatal("dcx-1's record was tombstoned by a delete whose peer answers were lost to the cancellation")
	}
	if vm.State != "running" {
		t.Errorf("dcx-1's row says %q after a refused delete; want it untouched (running)", vm.State)
	}
	for _, p := range disks {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("disk %s of a refused delete is gone: %v", p, err)
		}
	}
}

// A delete that runs past its own budget after the stop, and then fails,
// still records the stop: the abort has its own budget. Without the record
// the row says running over a stopped domain, and the reconciler starts the
// VM being deleted.
//
// Mutation: run abortDeleteAfterStop on the delete's context — red: the row
// stays running and the reconcile pass starts hb-1.
func TestFleet_DeleteVMAbortRecordsTheStopAfterItsBudgetRanOut(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployOneVM(t, ctx, node, client)
	node.Server.SetDeleteFinishTimeoutForTest(200 * time.Millisecond)
	node.Virt.FailUndefineDomain = func(name string, _ bool) error {
		if name != "hb-1" {
			return nil
		}
		time.Sleep(400 * time.Millisecond) // past the delete's budget
		return errors.New("injected: undefine refused")
	}

	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err == nil {
		t.Fatal("DeleteVM succeeded although the undefine was refused")
	}
	node.Virt.FailUndefineDomain = nil
	vm, err := corrosion.GetVM(ctx, node.DB, "hb-1")
	if err != nil || vm == nil {
		t.Fatalf("hb-1's row: %+v (%v), want it kept by the failed delete", vm, err)
	}
	if vm.State != "stopped" {
		t.Errorf("hb-1's row says %q after a delete that stopped it and failed; want stopped", vm.State)
	}
	rec := health.NewReconciler(node.Name, filepath.Join(c.tmpRoot, node.Name, "data"), node.DB, node.Virt)
	rec.ReconcileOnce(ctx)
	if active, _ := node.Virt.DomainIsActive("hb-1"); active {
		t.Error("a reconcile pass started hb-1, whose delete stopped it")
	}
}

// A delete that runs out of its budget at a step after the undefine — the
// NIC read, the address release, the tombstone — fails there. It must leave
// the row recorded stopped, never running (or starting) over an undefined
// domain whose disks are freed: the reconciler would start that VM again.
//
// Mutations: drop the abort on the NIC-read return, or on the tombstone
// return — that case goes red; record the stop only for a destroyed domain
// — the starting case goes red.
func TestFleet_DeleteVMRunningOutOfBudgetAfterTheUndefineRecordsTheStop(t *testing.T) {
	for _, tc := range []struct {
		name, step, state string
	}{
		{"running, before the NIC read", "nics", "running"},
		{"running, before the tombstone", "tombstone", "running"},
		{"starting with no active domain, before the NIC read", "nics", "starting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, node, client := newComposeFailNode(t)
			ctx := context.Background()
			deployOneVM(t, ctx, node, client)
			if tc.state != "running" {
				if err := node.Virt.DestroyDomain("hb-1"); err != nil {
					t.Fatal(err)
				}
				if err := corrosion.UpdateVMState(ctx, node.DB, "hb-1", tc.state, ""); err != nil {
					t.Fatal(err)
				}
			}
			node.Server.SetDeleteFinishTimeoutForTest(200 * time.Millisecond)
			var hit atomic.Bool
			node.Server.SetDeleteStepHookForTest(func(vm, step string) {
				if vm == "hb-1" && step == tc.step {
					hit.Store(true)
					time.Sleep(400 * time.Millisecond) // past the delete's budget
				}
			})
			t.Cleanup(func() { node.Server.SetDeleteStepHookForTest(nil) })

			if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err == nil {
				t.Fatal("DeleteVM succeeded although its budget ran out before the step")
			}
			if !hit.Load() {
				t.Fatalf("the delete never reached step %q", tc.step)
			}
			vm, err := corrosion.GetVM(ctx, node.DB, "hb-1")
			if err != nil || vm == nil {
				t.Fatalf("hb-1's row: %+v (%v), want it kept by the failed delete", vm, err)
			}
			if vm.State != "stopped" {
				t.Errorf("hb-1's row says %q after a delete that undefined it and failed; want stopped", vm.State)
			}
			rec := health.NewReconciler(node.Name, filepath.Join(c.tmpRoot, node.Name, "data"), node.DB, node.Virt)
			rec.ReconcileOnce(ctx)
			if node.Virt.DomainExists("hb-1") {
				t.Error("a reconcile pass defined hb-1, whose delete undefined it")
			}
		})
	}
}

// lv rm entered on the owner, its client gone mid-delete: the delete
// completes, and so do the steps the entry runs after it — here, the
// partial-recovery marker of the name is resolved, so a later VM of the name
// does not inherit it.
//
// Mutation: run the post-steps on the request context — red.
func TestFleet_DeleteVMOnTheOwnerRunsItsPostStepsWhenItsClientLeaves(t *testing.T) {
	c, disks := newDeleteCancelFleet(t)
	owner := c.Nodes[1]
	ctx := context.Background()
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, owner.DB, corrosion.HealthCondition{
		Evaluator: "replica_set", Code: "vm.promoted_partial", SubjectKind: "vm", SubjectID: "dcx-1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		Evidence: `{}`, ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: owner.Name,
	}); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	returned, armAct, reached := cancelAfter(t, owner, "DeleteVM", cancel)
	act := armAct()
	owner.Virt.OnUndefined = func(name string) {
		if name == "dcx-1" {
			act()
		}
	}
	defer func() { owner.Virt.OnUndefined = nil }()

	_, _ = c.SelfClient(owner).DeleteVM(cctx, &pb.DeleteVMRequest{Name: "dcx-1"})
	herr := waitHandler(t, returned, "DeleteVM")
	if !reached() {
		t.Fatal("the cancellation never reached the owner mid-delete; the scenario missed the window")
	}
	// Read before any reconcile pass: its gone-subject sweep would resolve
	// the marker by itself.
	row, found, err := corrosion.GetHealthCondition(ctx, owner.DB, "replica_set", "vm.promoted_partial", "vm", "dcx-1")
	if err != nil || !found {
		t.Fatalf("partial-recovery marker: found=%v err=%v", found, err)
	}
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("dcx-1's partial-recovery marker is %q after its delete; want resolved by the delete", row.Lifecycle)
	}
	assertVMDeleteFinished(t, c, owner, disks, herr)
}

// deployCancelledInside runs a deploy of yaml entered on entry, and lets arm
// install trigger wherever the scenario wants the client to leave: trigger
// cancels the client and holds its caller until entry's DeployStack context
// is done. It returns once that handler has returned.
func deployCancelledInside(t *testing.T, c *Cluster, entry *Node, yaml string, arm func(trigger func())) {
	t.Helper()
	watch := entry.WatchStream("DeployStack")
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		once sync.Once
		mu   sync.Mutex
		hit  bool
	)
	arm(func() {
		once.Do(func() {
			var sctx context.Context
			select {
			case sctx = <-watch.Started:
			default:
				t.Error("triggered outside the deploy")
				return
			}
			cancel()
			select {
			case <-sctx.Done():
				mu.Lock()
				hit = true
				mu.Unlock()
			case <-time.After(20 * time.Second):
				t.Error("the client's cancellation did not reach the deploy within 20s")
			}
		})
	})
	stream, err := c.SelfClient(entry).DeployStack(cctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err != nil {
		t.Fatalf("DeployStack: %v", err)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
	}
	select {
	case <-watch.Returned:
	case <-time.After(90 * time.Second):
		t.Fatal("the deploy had not returned 90s after its client left")
	}
	mu.Lock()
	defer mu.Unlock()
	if !hit {
		t.Fatal("the client never left inside the re-create; the scenario missed the window")
	}
}

// assertReplaced checks that name is live on owner, re-created from the
// update (its spec carries want), with its domain defined there.
func assertReplaced(t *testing.T, owner *Node, name, want string) {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), owner.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("%s is gone on %s after a re-create whose client left: no copy of the VM is left", name, owner.Name)
	}
	if !strings.Contains(vm.Spec, want) {
		t.Errorf("%s on %s is not the re-created VM: its spec lacks %q", name, owner.Name, want)
	}
	if !owner.Virt.DomainExists(name) {
		t.Errorf("%s has a row on %s but no domain", name, owner.Name)
	}
}

// A compose re-create whose client leaves once the teardown has started
// must not end with no copy of the VM: the replace runs to its create.
//
// Mutation: run the inline re-create's create (or delete) on the request
// context — red: web is gone.
func TestFleet_AComposeRecreateWhoseClientLeavesStillCreatesTheVM(t *testing.T) {
	t.Run("entered on the owner, client gone after the teardown", func(t *testing.T) {
		c, _ := newRecreateRemoteFleet(t, 0, "node-0")
		n0 := c.Nodes[0]
		deployCancelledInside(t, c, n0, recreateRemoteYAML("node-0", "second"), func(trigger func()) {
			n0.Server.SetRecreateTornDownHookForTest(func(string) { trigger() })
		})
		n0.Server.SetRecreateTornDownHookForTest(nil)
		assertReplaced(t, n0, "web", "second")
	})
	t.Run("entered on another node, client gone mid-delete on the owner", func(t *testing.T) {
		c, _ := newRecreateRemoteFleet(t, 1, "node-0")
		n0, n1 := c.Nodes[0], c.Nodes[1]
		ownerDone := make(chan struct{})
		var doneOnce sync.Once
		n0.HookUnary("DeleteVM", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
			defer doneOnce.Do(func() { close(ownerDone) })
			return handler(ctx, req)
		})
		deployCancelledInside(t, c, n1, recreateRemoteYAML("node-0", "second"), func(trigger func()) {
			n0.Virt.OnUndefined = func(name string) {
				if name == "web" {
					trigger()
				}
			}
		})
		n0.Virt.OnUndefined = nil
		select {
		case <-ownerDone:
		case <-time.After(60 * time.Second):
			t.Fatal("the owner's delete had not returned 60s after the client left")
		}
		assertReplaced(t, n0, "web", "second")
	})
}

// The same for a rolling update's re-create (recreateAs).
//
// Mutation: run recreateAs's create on the request context — red.
func TestFleet_ARollingRecreateWhoseClientLeavesStillCreatesTheVM(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	ctx := context.Background()
	if msgs, err := deployRolling(t, ctx, client, composeRolling, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}
	// An image change is a recreate-class change: the rolling engine
	// re-creates hb-1 (recreateAs).
	if err := corrosion.InsertImage(ctx, node.DB, corrosion.ImageRecord{Name: "test2", Format: "qcow2",
		SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if err := writeEmptyImageFile(node.Server.ImagePathForTests("test2")); err != nil {
		t.Fatal(err)
	}
	update := strings.Replace(strings.Replace(composeRolling,
		"    image: test\n", "    image: test2\n", 1),
		"  test:\n    source: file:///dev/null\n", "  test:\n    source: file:///dev/null\n  test2:\n    source: file:///dev/null\n", 1)
	deployCancelledInside(t, c, node, update, func(trigger func()) {
		node.Server.SetRecreateTornDownHookForTest(func(string) { trigger() })
	})
	node.Server.SetRecreateTornDownHookForTest(nil)
	assertReplaced(t, node, "hb-1", `"image":"test2"`)
}

// The same for lv rebuild: torn down, then created again from its stored
// spec, whatever becomes of the client.
//
// Mutation: drop the rebuild's detach — red: hb-1 is gone.
func TestFleet_ARebuildWhoseClientLeavesStillCreatesTheVM(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployOneVM(t, ctx, node, client)
	before, _ := corrosion.GetVM(ctx, node.DB, "hb-1")
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	returned, armAct, reached := cancelAfter(t, node, "RebuildVM", cancel)
	act := armAct()
	node.Server.SetRecreateTornDownHookForTest(func(string) { act() })
	t.Cleanup(func() { node.Server.SetRecreateTornDownHookForTest(nil) })

	_, _ = client.RebuildVM(cctx, &pb.RebuildVMRequest{Name: "hb-1"})
	herr := waitHandler(t, returned, "RebuildVM")
	if !reached() {
		t.Fatal("the cancellation never reached the rebuild after its teardown; the scenario missed the window")
	}
	if herr != nil {
		t.Errorf("the rebuild failed after its client left: %v", herr)
	}
	vm, err := corrosion.GetVM(ctx, node.DB, "hb-1")
	if err != nil || vm == nil {
		t.Fatal("hb-1 is gone after a rebuild whose client left: no copy of the VM is left")
	}
	if before != nil && vm.CreatedAt == before.CreatedAt {
		t.Errorf("hb-1 is still the old incarnation (created_at %s)", vm.CreatedAt)
	}
	if !node.Virt.DomainExists("hb-1") {
		t.Error("hb-1 has a row but no domain after its rebuild")
	}
}
