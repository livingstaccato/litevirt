package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// depends-on orders every create and update of a deploy, not only creates, and
// a dependency is waited on whatever this deploy does to it: created, updated
// (inline or rolling) or left unchanged. A dependent that is itself unchanged
// waits on nothing.

const composeOrderBase = `name: ord

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
`

// orderAppVM is app, depending on db with the given condition.
func orderAppVM(cond string) string {
	return `  app:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on:
      db:
        condition: ` + cond + "\n"
}

const orderUnprobedHealthcheck = "    healthcheck:\n      type: tcp\n      target: 10.0.0.9:5432\n"

// withDBHealthcheck gives db a healthcheck nothing in these scenarios probes,
// so db runs but never becomes healthy.
func withDBHealthcheck(yaml string) string {
	return strings.Replace(yaml, "  db:\n    image: test\n    cpu: 1\n    memory: 512\n    placement:\n      host: node-0\n",
		"  db:\n    image: test\n    cpu: 1\n    memory: 512\n    placement:\n      host: node-0\n"+orderUnprobedHealthcheck, 1)
}

func withRolling(yaml, vm string) string {
	return strings.Replace(yaml, "  "+vm+":\n    image: test\n", "  "+vm+":\n    update:\n      strategy: all-at-once\n    image: test\n", 1)
}

func bumpCPU(t *testing.T, yaml, vm string) string {
	t.Helper()
	for _, head := range []string{
		"  " + vm + ":\n    image: test\n    cpu: 1\n",
		"  " + vm + ":\n    update:\n      strategy: all-at-once\n    image: test\n    cpu: 1\n",
	} {
		if strings.Contains(yaml, head) {
			return strings.Replace(yaml, head, strings.Replace(head, "cpu: 1", "cpu: 2", 1), 1)
		}
	}
	t.Fatalf("no cpu line for %s in fixture", vm)
	return ""
}

// defineOrder returns the libvirt define events since from, in order.
func defineOrder(node *Node, from int) []string {
	var out []string
	for _, e := range node.Virt.EventLog()[from:] {
		if e.Op == "define" {
			out = append(out, e.Domain)
		}
	}
	return out
}

func indexOf(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

func deployClean(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string) []*pb.DeployProgress {
	t.Helper()
	msgs := deployCollect(t, ctx, client, yaml)
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("deploy failed for %s: %s", p.VmName, p.Error)
		}
	}
	return msgs
}

// Inline: a new app that depends on db runs AFTER db's update, which is waited
// on for it. By name, app would come first.
func TestFleet_ComposeCreateDependingOnAnUpdateRunsAfterIt(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(3 * time.Second)

	deployClean(t, ctx, client, composeOrderBase)
	next := bumpCPU(t, composeOrderBase+orderAppVM("vm_started"), "db")
	from := len(node.Virt.EventLog())
	msgs := deployClean(t, ctx, client, next)
	order := defineOrder(node, from)
	if indexOf(order, "db") < 0 || indexOf(order, "app") < 0 || indexOf(order, "db") > indexOf(order, "app") {
		t.Errorf("define order %v: want db's update before app's create", order)
	}
	waited := false
	for _, p := range msgs {
		if p.Phase == "waiting" && p.VmName == "db" {
			waited = true
		}
	}
	if !waited {
		t.Errorf("db's update was not waited on for app; got %v", msgs)
	}
}

// Inline: the updated db's wait times out, so app is held back.
func TestFleet_ComposeUpdatedDependencyIsWaitedOnAndBlocks(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)

	deployClean(t, ctx, client, withDBHealthcheck(composeOrderBase))
	next := bumpCPU(t, withDBHealthcheck(composeOrderBase)+orderAppVM("vm_healthy"), "db")
	from := len(node.Virt.EventLog())
	msgs := deployCollect(t, ctx, client, next)
	defined := definedDomains(node, from)
	if !defined["db"] {
		t.Fatalf("db was not recreated; got %v", msgs)
	}
	if p := errorPhaseFor(msgs, "db"); p == nil || !strings.Contains(p.Error, "timeout") {
		t.Fatalf("the updated db was not waited on: %+v; got %v", p, msgs)
	}
	assertBlocked(t, ctx, node, msgs, defined, "app", "db", "vm_healthy", "timeout")
	assertDeployFailedNaming(t, ctx, node, msgs, "ord", "db", "app")
}

// Rolling: app's update depends on db's update; db goes first (by name app
// would), and app's update does not start until db meets the condition.
func TestFleet_ComposeRollingUpdateWaitsOnItsDependency(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(3 * time.Second)

	// Setup without the dependency, so both exist.
	app := strings.Replace(orderAppVM("vm_started"), "    depends-on:\n      db:\n        condition: vm_started\n", "", 1)
	deployClean(t, ctx, client, withRolling(withRolling(composeOrderBase+app, "db"), "app"))

	next := withRolling(withRolling(composeOrderBase+orderAppVM("vm_started"), "db"), "app")
	next = bumpCPU(t, bumpCPU(t, next, "db"), "app")
	from := len(node.Virt.EventLog())
	msgs := deployClean(t, ctx, client, next)
	order := defineOrder(node, from)
	if indexOf(order, "db") < 0 || indexOf(order, "app") < 0 || indexOf(order, "db") > indexOf(order, "app") {
		t.Errorf("define order %v: want db's rolling update before app's", order)
	}
	waited := false
	for _, p := range msgs {
		if p.Phase == "waiting" && strings.Contains(p.Detail, "db") {
			waited = true
		}
	}
	if !waited {
		t.Errorf("app's rolling update did not wait on db; got %v", msgs)
	}
}

// Rolling: db's update never becomes healthy, so app's update never starts.
func TestFleet_ComposeRollingDependencyNotMetHoldsTheUpdate(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)

	app := strings.Replace(orderAppVM("vm_healthy"), "    depends-on:\n      db:\n        condition: vm_healthy\n", "", 1)
	deployClean(t, ctx, client, withRolling(withRolling(withDBHealthcheck(composeOrderBase)+app, "db"), "app"))

	next := withRolling(withRolling(withDBHealthcheck(composeOrderBase)+orderAppVM("vm_healthy"), "db"), "app")
	next = bumpCPU(t, bumpCPU(t, next, "db"), "app")
	from := len(node.Virt.EventLog())
	msgs := deployCollect(t, ctx, client, next)
	if order := defineOrder(node, from); indexOf(order, "db") < 0 {
		t.Fatalf("db was not updated; got %v", msgs)
	}
	p := errorPhaseFor(msgs, "app")
	if p == nil {
		t.Fatalf("app's update was not held back; got %v", msgs)
	}
	for _, want := range []string{"blocked", "db", "vm_healthy", "timeout"} {
		if !strings.Contains(p.Error, want) {
			t.Errorf("app's error %q does not mention %q", p.Error, want)
		}
	}
	for _, e := range node.Virt.EventLog()[from:] {
		if e.Domain == "app" || e.Domain == "app-next" {
			t.Errorf("held-back app was touched: %s %s", e.Op, e.Domain)
		}
	}
	rec, err := corrosion.GetVM(ctx, node.DB, "app")
	if err != nil || rec == nil || !strings.Contains(rec.Spec, `"cpu":1`) {
		t.Errorf("held-back app changed: %+v %v", rec, err)
	}
	if got := stackState(t, ctx, node.DB, "ord"); got != "degraded" {
		t.Errorf("stack state = %q, want degraded", got)
	}
}

// An unchanged dependency is still a dependency: the re-run after db failed
// to become healthy must not create app while db is still unhealthy.
func TestFleet_ComposeUnchangedDependencyIsWaitedOn(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)

	yaml := withDBHealthcheck(composeOrderBase) + orderAppVM("vm_healthy")
	msgs := deployCollect(t, ctx, client, yaml)
	if errorPhaseFor(msgs, "app") == nil {
		t.Fatalf("first deploy did not hold app back; got %v", msgs)
	}

	// db is unchanged now; app is still to be created.
	from := len(node.Virt.EventLog())
	msgs = deployCollect(t, ctx, client, yaml)
	if p := errorPhaseFor(msgs, "db"); p != nil {
		t.Errorf("unchanged db was reported as a failed action of its own: %s", p.Error)
	}
	assertBlocked(t, ctx, node, msgs, definedDomains(node, from), "app", "db", "vm_healthy", "timeout")
	if got := stackState(t, ctx, node.DB, "ord"); got != "degraded" {
		t.Errorf("stack state = %q, want degraded", got)
	}
}

// An unchanged dependent of an unchanged dependency does nothing: no wait,
// even when the dependency is not in the state the dependent once needed.
func TestFleet_ComposeUnchangedDependentDoesNotWait(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)

	yaml := composeOrderBase + orderAppVM("vm_started")
	deployClean(t, ctx, client, yaml)
	if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "db"}); err != nil {
		t.Fatalf("stop db: %v", err)
	}
	if db, _ := corrosion.GetVM(ctx, node.DB, "db"); db == nil || db.State == "running" {
		t.Fatalf("db = %+v, want it not running (the wait app once needed would fail)", db)
	}
	msgs := deployCollect(t, ctx, client, yaml)
	for _, p := range msgs {
		if p.Phase == "waiting" || p.Phase == "error" {
			t.Errorf("unchanged re-run did something: %v", p)
		}
	}
}

// ── containers ──────────────────────────────────────────────────────────

const composeContainerDeps = `name: ctd

images:
  test:
    source: file:///dev/null

workloads:
  ct:
    kind: lxc
    image: alpine:3.21
    cpu: 1
    memory: 256
    placement:
      host: node-0
  app:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on:
      ct:
        condition: vm_started
  app2:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on:
      ct:
        condition: vm_healthy
  ct2:
    kind: lxc
    image: alpine:3.21
    cpu: 1
    memory: 256
    placement:
      host: node-0
    depends-on:
      app:
        condition: vm_started
`

func newContainerComposeNode(t *testing.T) (*Node, pb.LiteVirtClient) {
	t.Helper()
	_, node, client := newComposeFailNode(t)
	if err := corrosion.SetHostLabel(context.Background(), node.DB, "node-0", corrosion.LabelLXCCapable, "true"); err != nil {
		t.Fatalf("label node-0 lxc-capable: %v", err)
	}
	return node, client
}

// A depends-on on a container, and a container's depends-on on a VM, are
// met: vm_started is the container running, and vm_healthy on a container
// (which has no healthcheck) is the same.
func TestFleet_ComposeContainerDependenciesAreMet(t *testing.T) {
	node, client := newContainerComposeNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(2 * time.Second)

	msgs := deployClean(t, ctx, client, composeContainerDeps)
	for _, vm := range []string{"app", "app2"} {
		if rec, err := corrosion.GetVM(ctx, node.DB, vm); err != nil || rec == nil {
			t.Errorf("%s not created: %v", vm, err)
		}
	}
	for _, ct := range []string{"ct", "ct2"} {
		if rec, err := corrosion.GetContainer(ctx, node.DB, "node-0", ct); err != nil || rec == nil || rec.State != "running" {
			t.Errorf("container %s = %+v err=%v, want running", ct, rec, err)
		}
	}
	waitedOnCT := false
	for _, p := range msgs {
		if p.Phase == "waiting" && p.VmName == "ct" {
			waitedOnCT = true
		}
	}
	if !waitedOnCT {
		t.Errorf("the container dependency was not waited on; got %v", msgs)
	}
}

// A container whose dependents need it running, and that is not, holds
// them back like a VM would.
func TestFleet_ComposeStoppedContainerDependencyBlocks(t *testing.T) {
	node, client := newContainerComposeNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(300 * time.Millisecond)

	only := composeContainerDeps[:strings.Index(composeContainerDeps, "  app:\n")]
	deployClean(t, ctx, client, only)
	if _, err := client.StopContainer(ctx, &pb.StopContainerRequest{HostName: "node-0", Name: "ct"}); err != nil {
		t.Fatalf("stop ct: %v", err)
	}
	from := len(node.Virt.EventLog())
	msgs := deployCollect(t, ctx, client, composeContainerDeps)
	assertBlocked(t, ctx, node, msgs, definedDomains(node, from), "app", "ct", "vm_started", "stopped")
}

// vm_healthy on a container that declares a healthcheck cannot be kept —
// container healthchecks are not probed — so the file is refused.
func TestFleet_ComposeVMHealthyOnAContainerHealthcheckIsRefused(t *testing.T) {
	node, client := newContainerComposeNode(t)
	ctx := context.Background()
	yaml := strings.Replace(composeContainerDeps, "    memory: 256\n    placement:\n      host: node-0\n  app:",
		"    memory: 256\n    placement:\n      host: node-0\n"+orderUnprobedHealthcheck+"  app:", 1)
	if yaml == composeContainerDeps {
		t.Fatal("fixture edit did not apply")
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil || !strings.Contains(err.Error(), "vm_healthy") || !strings.Contains(err.Error(), "container") {
		t.Fatalf("deploy: err=%v, want a validation error about vm_healthy on a container", err)
	}
	if rec, _ := corrosion.GetContainer(ctx, node.DB, "node-0", "ct"); rec != nil {
		t.Errorf("ct was created from a refused file")
	}
}
