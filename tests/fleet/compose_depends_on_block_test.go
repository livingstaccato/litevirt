package fleet

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/gitops"
)

// A depends-on condition that was not met holds the dependents back. db's
// wait timing out (or its create failing) used to be reported against db and
// then ignored: app — which asked for db to be healthy first — was created
// anyway, and so was everything that depended on app. The dependents are now
// reported as blocked, naming the dependency, its condition and why it was
// not met, and are neither created nor updated. A VM that does not depend on
// the failed one proceeds.

// db has a healthcheck nothing in these scenarios probes, so it runs but
// never becomes healthy; app waits for that, web waits for app, solo depends
// on nothing, and worker depends on solo — a dependency that is met.
const composeDependsBlock = `name: blk

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    healthcheck:
      type: tcp
      target: 10.0.0.9:5432
  app:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on:
      db:
        condition: vm_healthy
  web:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on:
      app:
        condition: vm_started
  solo:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
  worker:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on: [solo]
`

// recordingStream replays recorded deploy messages to gitops.DrainDeploy, so
// the gitops verdict is taken over the very deploy the test asserts on.
type recordingStream struct {
	msgs []*pb.DeployProgress
	i    int
}

func (r *recordingStream) Recv() (*pb.DeployProgress, error) {
	if r.i >= len(r.msgs) {
		return nil, io.EOF
	}
	r.i++
	return r.msgs[r.i-1], nil
}

func definedDomains(node *Node, from int) map[string]bool {
	out := map[string]bool{}
	for _, e := range node.Virt.EventLog()[from:] {
		if e.Op == "define" {
			out[e.Domain] = true
		}
	}
	return out
}

// assertBlocked checks that vm was held back by dep: an error phase naming
// the dependency, its condition and the reason, no VM record, no define.
func assertBlocked(t *testing.T, ctx context.Context, node *Node, msgs []*pb.DeployProgress, defined map[string]bool, vm, dep, cond, reason string) {
	t.Helper()
	p := errorPhaseFor(msgs, vm)
	if p == nil {
		t.Errorf("%s was not reported as blocked by %s; got %v", vm, dep, msgs)
	} else {
		for _, want := range []string{"blocked", dep, cond, reason} {
			if !strings.Contains(p.Error, want) {
				t.Errorf("%s's error %q does not mention %q", vm, p.Error, want)
			}
		}
	}
	for _, m := range msgs {
		if m.VmName == vm && m.Phase == "done" {
			t.Errorf("blocked %s was also reported done", vm)
		}
	}
	if defined[vm] {
		t.Errorf("blocked %s was defined in libvirt", vm)
	}
	if rec, _ := corrosion.GetVM(ctx, node.DB, vm); rec != nil {
		t.Errorf("blocked %s was created (state %s)", vm, rec.State)
	}
}

func assertDeployFailedNaming(t *testing.T, ctx context.Context, node *Node, msgs []*pb.DeployProgress, stack string, vms ...string) {
	t.Helper()
	if got := stackState(t, ctx, node.DB, stack); got != "degraded" {
		t.Errorf("stack state = %q, want degraded", got)
	}
	res, detail := lastAuditResult(t, ctx, node.DB, "stack.deploy", stack)
	if res != "error" {
		t.Errorf("stack.deploy audit result = %q (%s), want error", res, detail)
	}
	derr := gitops.DrainDeploy(&recordingStream{msgs: msgs})
	if derr == nil {
		t.Error("gitops.DrainDeploy judged the deploy clean")
	}
	for _, vm := range vms {
		if !strings.Contains(detail, vm) {
			t.Errorf("stack.deploy audit detail %q does not name %s", detail, vm)
		}
		if derr != nil && !strings.Contains(derr.Error(), vm+":") {
			t.Errorf("gitops.DrainDeploy error %q does not name %s", derr, vm)
		}
	}
}

func assertCreated(t *testing.T, ctx context.Context, node *Node, msgs []*pb.DeployProgress, vm string) {
	t.Helper()
	if p := errorPhaseFor(msgs, vm); p != nil {
		t.Errorf("%s, which depends on nothing that failed, failed: %s", vm, p.Error)
	}
	if rec, err := corrosion.GetVM(ctx, node.DB, vm); err != nil || rec == nil {
		t.Errorf("%s, which depends on nothing that failed, was not created (err=%v)", vm, err)
	}
}

// Inline path: a timed-out vm_healthy wait blocks app, and web behind it.
func TestFleet_ComposeTimedOutDependsOnBlocksTheDependents(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)

	from := len(node.Virt.EventLog())
	msgs := deployCollect(t, ctx, client, composeDependsBlock)
	defined := definedDomains(node, from)

	if p := errorPhaseFor(msgs, "db"); p == nil || !strings.Contains(p.Error, "timeout") {
		t.Fatalf("db's wait did not time out: %+v; got %v", p, msgs)
	}
	assertBlocked(t, ctx, node, msgs, defined, "app", "db", "vm_healthy", "timeout")
	assertBlocked(t, ctx, node, msgs, defined, "web", "app", "vm_started", "blocked")
	assertCreated(t, ctx, node, msgs, "solo")
	assertCreated(t, ctx, node, msgs, "worker")
	assertDeployFailedNaming(t, ctx, node, msgs, "blk", "db", "app", "web")
}

// A dependency whose create failed outright blocks too — here with the
// default vm_started condition.
func TestFleet_ComposeFailedDependencyCreateBlocksTheDependents(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)
	node.Virt.FailDefineDomain = func(xml string) error {
		if strings.Contains(xml, "<name>db</name>") {
			return errors.New("injected: define refused")
		}
		return nil
	}
	yaml := strings.Replace(composeDependsBlock, "condition: vm_healthy", "condition: vm_started", 1)

	from := len(node.Virt.EventLog())
	msgs := deployCollect(t, ctx, client, yaml)
	defined := definedDomains(node, from)

	if p := errorPhaseFor(msgs, "db"); p == nil || !strings.Contains(p.Error, "define refused") {
		t.Fatalf("db's create did not fail: %+v; got %v", p, msgs)
	}
	assertBlocked(t, ctx, node, msgs, defined, "app", "db", "vm_started", "define refused")
	assertBlocked(t, ctx, node, msgs, defined, "web", "app", "vm_started", "blocked")
	assertCreated(t, ctx, node, msgs, "solo")
	assertCreated(t, ctx, node, msgs, "worker")
	assertDeployFailedNaming(t, ctx, node, msgs, "blk", "db", "app", "web")
}

// Rolling path (a non-recreate strategy plus an update): its create loop and
// its updates honour the block as well. app exists from the setup deploy and
// is updated by the second; it must not be touched while db is not healthy.
func TestFleet_ComposeRollingTimedOutDependsOnBlocksTheDependents(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)

	// Setup: app alone (no dependency yet), under a rolling strategy.
	setup := `name: blk

images:
  test:
    source: file:///dev/null

vms:
  app:
    update:
      strategy: all-at-once
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
`
	msgs := deployCollect(t, ctx, client, setup)
	if p := errorPhaseFor(msgs, "app"); p != nil {
		t.Fatalf("setup deploy failed: %s", p.Error)
	}

	// Now app changes (an update for the rolling engine) and gains a
	// dependency on a new db that never becomes healthy.
	next := strings.Replace(composeDependsBlock,
		"  app:\n    image: test\n    cpu: 1\n",
		"  app:\n    update:\n      strategy: all-at-once\n    image: test\n    cpu: 2\n", 1)
	if next == composeDependsBlock {
		t.Fatal("fixture edit did not apply")
	}
	from := len(node.Virt.EventLog())
	msgs = deployCollect(t, ctx, client, next)
	sawRolling := false
	for _, p := range msgs {
		if p.Phase == "rolling-update" {
			sawRolling = true
		}
	}
	if !sawRolling {
		t.Fatalf("deploy did not take the rolling path; got %v", msgs)
	}
	if p := errorPhaseFor(msgs, "db"); p == nil || !strings.Contains(p.Error, "timeout") {
		t.Fatalf("db's wait did not time out: %+v; got %v", p, msgs)
	}
	p := errorPhaseFor(msgs, "app")
	if p == nil {
		t.Fatalf("app's update was not blocked by db; got %v", msgs)
	}
	for _, want := range []string{"blocked", "db", "vm_healthy", "timeout"} {
		if !strings.Contains(p.Error, want) {
			t.Errorf("app's error %q does not mention %q", p.Error, want)
		}
	}
	for _, e := range node.Virt.EventLog()[from:] {
		if e.Domain == "app" || e.Domain == "app-next" {
			t.Errorf("blocked app was touched: %s %s", e.Op, e.Domain)
		}
	}
	app, err := corrosion.GetVM(ctx, node.DB, "app")
	if err != nil || app == nil {
		t.Fatalf("app vanished: %v %v", app, err)
	}
	if !strings.Contains(app.Spec, `"cpu":1`) {
		t.Errorf("blocked app's spec was updated: %s", app.Spec)
	}
	defined := definedDomains(node, from)
	assertBlocked(t, ctx, node, msgs, defined, "web", "app", "vm_started", "blocked")
	assertCreated(t, ctx, node, msgs, "solo")
	assertCreated(t, ctx, node, msgs, "worker")
	assertDeployFailedNaming(t, ctx, node, msgs, "blk", "db", "app", "web")
}
