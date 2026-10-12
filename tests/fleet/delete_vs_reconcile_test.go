package fleet

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Lab 2 run c713, N-2: the reconciler restarted a VM whose delete was in
// progress. DeleteVM destroys and undefines the domain BEFORE it tombstones
// the row, and the row says "running" the whole time. A reconcile pass in
// that window reads "running here, no domain" — a crashed guest — and its
// self-heal defines and starts the VM again. The delete then tombstones the
// row over a running domain nothing names: on the lab, icr4-1 ran for 25
// minutes, visible only to the capacity evaluator.
//
// The reconciler's start path is serialised by the per-VM start lease, and
// the delete took none, so the two never excluded each other.

// The interleaving, made deterministic: a reconcile pass runs inside the
// delete, right after its undefine and before its tombstone.
func TestFleet_DeleteVMNotRestartedByReconcilerMidDelete(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployOneVM(t, ctx, node, client)

	rec := health.NewReconciler(node.Name, filepath.Join(c.tmpRoot, node.Name, "data"), node.DB, node.Virt)
	var once sync.Once
	ran := false
	node.Virt.OnUndefined = func(name string) {
		if name != "hb-1" {
			return
		}
		once.Do(func() {
			// The row must still be live here, or this is not the window.
			if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm == nil || vm.State != "running" {
				t.Errorf("mid-delete row = %+v, want hb-1 still running (the race window)", vm)
			}
			rec.ReconcileOnce(ctx)
			ran = true
		})
	}

	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	node.Virt.OnUndefined = nil
	if !ran {
		t.Fatal("the reconcile pass never ran inside the delete; the scenario did not reach the window")
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
		t.Fatalf("hb-1's row survived its delete: %+v", vm)
	}
	if node.Virt.DomainExists("hb-1") {
		st, _ := node.Virt.DomainState("hb-1")
		t.Fatalf("a %s domain hb-1 is left on %s after its delete: the reconciler restarted a VM being deleted",
			st, node.Name)
	}

	// Later passes, with the row gone, must not bring it back either.
	rec.ReconcileOnce(ctx)
	if node.Virt.DomainExists("hb-1") {
		t.Fatal("a reconcile pass after the delete defined hb-1 again")
	}
}

// holdReconcilerLease takes hb-1's start lease as this host's reconciler
// (its identity is the bare host name), as a start in flight holds it.
func holdReconcilerLease(t *testing.T, ctx context.Context, node *Node) {
	t.Helper()
	if held, err := health.TryVMStartLease(ctx, node.DB, node.Name, "hb-1", time.Now()); err != nil || held != node.Name {
		t.Fatalf("take the reconciler's start lease: held=%q err=%v", held, err)
	}
}

// releaseReconcilerLeaseAfter frees it after d, as that start finishing does.
func releaseReconcilerLeaseAfter(ctx context.Context, node *Node, d time.Duration) {
	go func() {
		time.Sleep(d)
		health.ReleaseVMStartLease(ctx, node.DB, node.Name, "hb-1")
	}()
}

// assertNothingTouched checks a refused delete left hb-1 as it was.
func assertNothingTouched(t *testing.T, ctx context.Context, node *Node, disks []string) {
	t.Helper()
	vm := assertDeleteKeptHandle(t, ctx, node, disks)
	if vm.State != "running" {
		t.Errorf("hb-1 recorded %q after a refused delete, want running (nothing touched)", vm.State)
	}
	if st, _ := node.Virt.DomainState("hb-1"); st != "running" {
		t.Errorf("hb-1 domain %q after a refused delete, want running", st)
	}
}

// assertLeaseGone checks the delete gave its lease back.
func assertLeaseGone(t *testing.T, ctx context.Context, node *Node) {
	t.Helper()
	if holder, _, ok, err := health.ReadVMStartLease(ctx, node.DB, "hb-1"); err != nil || ok {
		t.Errorf("start lease after the delete: holder=%q present=%v err=%v; want none", holder, ok, err)
	}
}

// The other order: a start already holds the lease. The delete waits for it
// — main deleted here, and `lv rm` of a crash-looping VM meets this all the
// time — and goes through once the start is done.
func TestFleet_DeleteVMWaitsForAStartHoldingTheLease(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployOneVM(t, ctx, node, client)

	holdReconcilerLease(t, ctx, node)
	releaseReconcilerLeaseAfter(ctx, node, 300*time.Millisecond)
	start := time.Now()
	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
		t.Fatalf("DeleteVM while a start held the lease for 300ms: %v", err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Errorf("the delete finished in %s, before the start released the lease", time.Since(start))
	}
	if node.Virt.DomainExists("hb-1") {
		t.Fatal("hb-1's domain survived its delete")
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
		t.Fatal("hb-1's row survived its delete")
	}
	assertLeaseGone(t, ctx, node)
}

// A start that holds the lease past the bound refuses the delete with
// Aborted — which a stack teardown retries — naming the holder, nothing
// touched; once the start is done the delete goes through.
func TestFleet_DeleteVMAbortedWhileAStartHoldsTheLeasePastTheBound(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	disks := deployOneVM(t, ctx, node, client)
	node.Server.SetDeleteLeaseWaitForTest(600 * time.Millisecond)

	holdReconcilerLease(t, ctx, node)
	_, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("DeleteVM while a start holds the lease past the bound: err=%v, want Aborted", err)
	}
	if !strings.Contains(status.Convert(err).Message(), "held by "+node.Name) {
		t.Errorf("refusal %q does not name the lease holder %s", status.Convert(err).Message(), node.Name)
	}
	assertNothingTouched(t, ctx, node, disks)
	if holder, _, ok, _ := health.ReadVMStartLease(ctx, node.DB, "hb-1"); !ok || holder != node.Name {
		t.Errorf("start lease after the refused delete: holder=%q present=%v, want the start's %s", holder, ok, node.Name)
	}

	health.ReleaseVMStartLease(ctx, node.DB, node.Name, "hb-1")
	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
		t.Fatalf("DeleteVM after the lease was released: %v", err)
	}
	if node.Virt.DomainExists("hb-1") {
		t.Fatal("hb-1's domain survived its delete")
	}
	assertLeaseGone(t, ctx, node)
}

// The caller giving up ends the wait: nothing touched, the start's lease
// left alone.
func TestFleet_DeleteVMWaitEndsWithItsContext(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	disks := deployOneVM(t, ctx, node, client)

	holdReconcilerLease(t, ctx, node)
	// When the server's handler returns: it must stop waiting with its
	// context, not poll on to the bound behind a caller that has gone.
	handlerDone := make(chan error, 1)
	node.HookUnary("DeleteVM", func(hctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		out, err := h(hctx, req)
		handlerDone <- err
		return out, err
	})
	cctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.DeleteVM(cctx, &pb.DeleteVMRequest{Name: "hb-1"})
	if code := status.Code(err); code != codes.DeadlineExceeded && code != codes.Canceled {
		t.Fatalf("DeleteVM whose context ended mid-wait: err=%v, want DeadlineExceeded or Canceled", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the delete outlived its context by %s", d)
	}
	select {
	case herr := <-handlerDone:
		if code := status.Code(herr); code != codes.DeadlineExceeded && code != codes.Canceled {
			t.Errorf("the server's delete ended with %v, want its context's status", herr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the server's delete is still waiting for the lease 3s after its caller gave up")
	}
	assertNothingTouched(t, ctx, node, disks)
	if holder, _, ok, _ := health.ReadVMStartLease(ctx, node.DB, "hb-1"); !ok || holder != node.Name {
		t.Errorf("start lease after the abandoned delete: holder=%q present=%v, want the start's %s", holder, ok, node.Name)
	}
	// The abandoned delete is over, not still waiting: when the start lets
	// go, nothing takes the lease and deletes the VM nobody is asking about.
	health.ReleaseVMStartLease(ctx, node.DB, node.Name, "hb-1")
	time.Sleep(time.Second)
	assertNothingTouched(t, ctx, node, disks)
}

// The start the delete waited for may have changed the row: the delete
// decides from the row as it is once it holds the lease. Here the VM moved
// to another host meanwhile, so this host must not tear its domain down.
func TestFleet_DeleteVMRereadsTheRowAfterTheWait(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	disks := deployOneVM(t, ctx, node, client)

	holdReconcilerLease(t, ctx, node)
	go func() {
		time.Sleep(300 * time.Millisecond)
		if err := corrosion.UpdateVMHost(ctx, node.DB, "hb-1", "node-elsewhere", "running"); err != nil {
			t.Errorf("move hb-1: %v", err)
		}
		health.ReleaseVMStartLease(ctx, node.DB, node.Name, "hb-1")
	}()
	_, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("DeleteVM of a VM that moved while it waited: err=%v, want Aborted", err)
	}
	if !node.Virt.DomainExists("hb-1") {
		t.Fatal("the delete tore down the domain of a VM that moved away while it waited")
	}
	if st, _ := node.Virt.DomainState("hb-1"); st != "running" {
		t.Errorf("hb-1 domain %q, want running (nothing touched)", st)
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm == nil {
		t.Fatal("the row of a VM that moved away was tombstoned")
	}
	_ = disks
}

// Review M-4: a daemon that crashed mid-delete leaves <host>/delete holding
// the lease. The reconciler does not take it over, so the VM is not
// restarted meanwhile; a retried delete is the same holder, re-takes it at
// once and completes.
func TestFleet_DeleteVMCrashedDeleteLeaseHoldsOffSelfHealUntilRetried(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployOneVM(t, ctx, node, client)

	// The crashed run: it took the lease before this daemon started and got
	// as far as removing the domain.
	if held, err := health.TryVMStartLease(ctx, node.DB, node.Name+"/delete", "hb-1", time.Now().Add(-5*time.Minute)); err != nil || held != node.Name+"/delete" {
		t.Fatalf("seed the crashed delete's lease: held=%q err=%v", held, err)
	}
	if err := node.Virt.DestroyDomain("hb-1"); err != nil {
		t.Fatal(err)
	}
	if err := node.Virt.UndefineDomain("hb-1", false); err != nil {
		t.Fatal(err)
	}

	rec := health.NewReconciler(node.Name, filepath.Join(c.tmpRoot, node.Name, "data"), node.DB, node.Virt)
	rec.ReconcileOnce(ctx)
	if node.Virt.DomainExists("hb-1") {
		t.Fatal("the reconciler restarted a VM whose delete crashed midway, under the delete's lease")
	}

	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
		t.Fatalf("retried DeleteVM after a crashed delete: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
		t.Fatal("hb-1's row survived the retried delete")
	}
	assertLeaseGone(t, ctx, node)
}

// The callers that do not retry the refusal at all go through when the start
// releases the lease mid-wait: a rolling recreate deletes the VM before it
// creates it again, and a blue-green cutover deletes the blue after the green
// is up.
func TestFleet_DeleteVMWaitLetsRollingRecreateThrough(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	if msgs, err := deployRolling(t, ctx, client, composeRolling, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}
	before, err := corrosion.GetVM(ctx, node.DB, "hb-1")
	if err != nil || before == nil {
		t.Fatalf("hb-1 after setup: %v %v", before, err)
	}
	// An image change: the VM cannot be kept, so it is deleted and created
	// again (a change that can keep it is applied in place, no delete).
	seedImage(t, ctx, node, "test2")
	next := strings.Replace(composeRolling, "    image: test\n", "    image: test2\n", 1)
	next = strings.Replace(next, "images:\n  test:\n", "images:\n  test2:\n    source: file:///dev/null\n  test:\n", 1)

	holdReconcilerLease(t, ctx, node)
	releaseReconcilerLeaseAfter(ctx, node, 500*time.Millisecond)
	start := time.Now()
	msgs, err := deployRolling(t, ctx, client, next, 30*time.Second)
	if err != nil {
		t.Fatalf("rolling update while a start held the lease: %v (%v)", err, msgs)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Errorf("error phase: %s %s", p.VmName, p.Error)
		}
	}
	vm, gerr := corrosion.GetVM(ctx, node.DB, "hb-1")
	if gerr != nil || vm == nil {
		t.Fatalf("hb-1 missing after the rolling recreate: %v", gerr)
	}
	if vm.CreatedAt == before.CreatedAt {
		t.Fatalf("hb-1 was not recreated (same incarnation %s); the scenario did not reach the delete", vm.CreatedAt)
	}
	if !strings.Contains(vm.Spec, "test2") {
		t.Errorf("hb-1 was recreated without the update: spec %s", vm.Spec)
	}
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Errorf("the recreate finished in %s, before the start released the lease", d)
	}
}

func TestFleet_DeleteVMWaitLetsBlueGreenCutoverThrough(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	if msgs, err := deployRolling(t, ctx, client, composeBlueGreen, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}
	seedImage(t, ctx, node, "test2")
	next := strings.Replace(composeBlueGreen, "    image: test\n", "    image: test2\n", 1)
	next = strings.Replace(next, "images:\n  test:\n", "images:\n  test2:\n    source: file:///dev/null\n  test:\n", 1)

	holdReconcilerLease(t, ctx, node)
	releaseReconcilerLeaseAfter(ctx, node, 500*time.Millisecond)
	msgs, err := deployRolling(t, ctx, client, next, 30*time.Second)
	if err != nil {
		t.Fatalf("blue-green update while a start held the blue's lease: %v (%v)", err, msgs)
	}
	if p := errorPhaseFor(msgs, "hb-1"); p != nil {
		t.Fatalf("the blue hb-1 was not removed: %s", p.Error)
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
		t.Error("the blue hb-1 row survived the cutover")
	}
	if node.Virt.DomainExists("hb-1") {
		t.Error("the blue hb-1 domain survived the cutover")
	}
	if vm, err := corrosion.GetVM(ctx, node.DB, "hb-1-green"); err != nil || vm == nil {
		t.Fatalf("the green hb-1-green is not there: vm=%v err=%v", vm, err)
	}
}
