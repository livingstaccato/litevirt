package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// vm_healthy means the VM's healthcheck PASSED — on its current incarnation,
// as published by its owning host — not merely that it is running. These
// scenarios run the real VMChecker on the node that owns the VMs, with the
// probe transport scripted (a fleet VM has no guest to answer a probe), and
// drive real deploys through the real gRPC DeployStack.

// fleetProbe is a scripted probe transport plus the loop that sweeps a node's
// VMChecker the way the daemon's ticker would, only faster.
type fleetProbe struct {
	mu      sync.Mutex
	pass    map[string]bool // VM name -> passes; absent fails
	running bool
	checker *health.VMChecker
}

func (p *fleetProbe) set(vm string, pass bool) {
	p.mu.Lock()
	p.pass[vm] = pass
	p.mu.Unlock()
}

func (p *fleetProbe) setAll(pass bool, vms ...string) {
	for _, vm := range vms {
		p.set(vm, pass)
	}
}

// pause stops the sweeps: from here on nothing probes and nothing publishes.
func (p *fleetProbe) pause() {
	p.mu.Lock()
	p.running = false
	p.mu.Unlock()
}

func (p *fleetProbe) fn(_ context.Context, vm corrosion.VMRecord, hc *pb.HealthCheckSpec) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pass[vm.Name] {
		return true, ""
	}
	return false, "tcp " + hc.Target + ": connection refused"
}

// startVMChecks runs node's VM health checker every 50ms until the test ends.
func startVMChecks(t *testing.T, node *Node) *fleetProbe {
	t.Helper()
	p := &fleetProbe{pass: map[string]bool{}, running: true}
	p.checker = health.NewVMChecker(node.Name, t.TempDir(), node.DB, nil)
	p.checker.SetProbeFunc(p.fn)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			p.mu.Lock()
			on := p.running
			p.mu.Unlock()
			if on {
				p.checker.SweepOnce(ctx)
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return p
}

// composeRollingHC is two rolling-updated VMs with a healthcheck that makes a
// verdict on every probe (retries 1) and probes every sweep.
const composeRollingHC = `name: hc

images:
  test:
    source: file:///dev/null

vms:
  hc-a:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    healthcheck:
      type: tcp
      target: 10.0.0.9:80
      interval: 1ms
      retries: 1
      action: alert
    update:
      strategy: rolling
      health-wait: 3s
  hc-b:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    healthcheck:
      type: tcp
      target: 10.0.0.9:81
      interval: 1ms
      retries: 1
      action: alert
    update:
      strategy: rolling
      health-wait: 3s
`

func rollingHCUpdate() string {
	return strings.ReplaceAll(composeRollingHC, "    cpu: 1\n", "    cpu: 2\n")
}

func vmSpecOf(t *testing.T, ctx context.Context, db *corrosion.Client, name string) string {
	t.Helper()
	vm, err := corrosion.GetVM(ctx, db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): vm=%v err=%v", name, vm, err)
	}
	return vm.Spec
}

func sawPhase(msgs []*pb.DeployProgress, vm, phase string) bool {
	for _, p := range msgs {
		if p.VmName == vm && p.Phase == phase {
			return true
		}
	}
	return false
}

// The rolling update's health wait now waits for the probe. A recreated VM
// whose probe fails stops the update AT that VM: the error names it and the
// probe's reason, the stack is degraded, and the next VM is never touched.
func TestFleet_ComposeRollingUpdateStopsAtAVMWhoseProbeFails(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	probe := startVMChecks(t, node)
	probe.setAll(true, "hc-a", "hc-b")

	if msgs, err := deployRolling(t, ctx, client, composeRollingHC, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}

	// Every probe fails from here: the first VM recreated never passes.
	probe.setAll(false, "hc-a", "hc-b")
	start := time.Now()
	msgs, err := deployRolling(t, ctx, client, rollingHCUpdate(), 20*time.Second)
	if err == nil {
		t.Fatalf("rolling update of a VM whose probe fails succeeded; got %v", msgs)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("failed health wait took %s; health-wait is 3s", d)
	}
	// Exactly one VM was recreated — the one that failed.
	failed, untouched := "hc-a", "hc-b"
	if !sawPhase(msgs, "hc-a", "creating") {
		failed, untouched = "hc-b", "hc-a"
	}
	if sawPhase(msgs, untouched, "creating") {
		t.Fatalf("rolling update did not stop at %s: %s was recreated too; got %v", failed, untouched, msgs)
	}
	for _, want := range []string{failed, "health-wait", "unhealthy", "connection refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("deploy error %q does not mention %q", err, want)
		}
	}
	if p := errorPhaseFor(msgs, failed); p == nil || !strings.Contains(p.Error, "connection refused") {
		t.Errorf("error phase for %s = %v, want the probe's reason", failed, p)
	}
	if !strings.Contains(vmSpecOf(t, ctx, node.DB, untouched), `"cpu":1`) {
		t.Errorf("%s was updated although the rolling update stopped before it", untouched)
	}
	// The rolling failure path is fail-fast: the stream ends in error and the
	// stack record is left as the last successful deploy wrote it, so the
	// half-applied update is never recorded as the stack's desired state.
	st, serr := corrosion.GetStack(ctx, node.DB, "hc")
	if serr != nil || st == nil {
		t.Fatalf("GetStack: %v %v", st, serr)
	}
	if strings.Contains(st.ComposeYAML, "cpu: 2") {
		t.Errorf("a rolling update that stopped at %s was recorded as the stack's desired state", failed)
	}
}

func TestFleet_ComposeRollingUpdateProceedsWhenTheProbePasses(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	probe := startVMChecks(t, node)
	probe.setAll(true, "hc-a", "hc-b")

	if msgs, err := deployRolling(t, ctx, client, composeRollingHC, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}
	msgs, err := deployRolling(t, ctx, client, rollingHCUpdate(), 20*time.Second)
	if err != nil {
		t.Fatalf("rolling update with passing probes failed: %v (%v)", err, msgs)
	}
	for _, vm := range []string{"hc-a", "hc-b"} {
		if !sawPhase(msgs, vm, "done") {
			t.Errorf("%s never reported done; got %v", vm, msgs)
		}
		if !strings.Contains(vmSpecOf(t, ctx, node.DB, vm), `"cpu":2`) {
			t.Errorf("%s was not updated", vm)
		}
	}
	if got := stackState(t, ctx, node.DB, "hc"); got != "active" {
		t.Errorf("stack state = %q, want active", got)
	}
}

// A verdict from before the recreate must not satisfy the wait for the new
// VM. The setup deploy leaves hc-a and hc-b healthy; then the checker stops,
// so nothing ever probes the recreated VM — the only thing that could let the
// update through is the previous incarnation's pass.
func TestFleet_ComposeStalePassDoesNotSatisfyTheRollingWait(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	probe := startVMChecks(t, node)
	probe.setAll(true, "hc-a", "hc-b")

	if msgs, err := deployRolling(t, ctx, client, composeRollingHC, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}
	// Both verdicts are published and passing before the update starts.
	deadline := time.Now().Add(5 * time.Second)
	for _, vm := range []string{"hc-a", "hc-b"} {
		for {
			rec, _ := corrosion.GetVM(ctx, node.DB, vm)
			h, herr := health.EvaluateVMHealth(ctx, node.DB, rec)
			if herr == nil && h.Satisfied {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("setup: %s never became healthy: %+v %v", vm, h, herr)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	probe.pause()

	msgs, err := deployRolling(t, ctx, client, rollingHCUpdate(), 20*time.Second)
	if err == nil {
		t.Fatalf("the previous incarnation's pass satisfied the rolling wait; got %v", msgs)
	}
	if !strings.Contains(err.Error(), "previous incarnation") {
		t.Errorf("deploy error %q does not say the only verdict is a previous incarnation's", err)
	}
}

// composeDependsHC: app waits for db's healthcheck to pass.
const composeDependsHC = `name: dep

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
      interval: 1ms
      retries: 1
      action: alert
  app:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on:
      db:
        condition: vm_healthy
`

func TestFleet_ComposeDependsOnVMHealthyHoldsUntilTheProbePasses(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(15 * time.Second)
	probe := startVMChecks(t, node) // db fails until released

	// Release the probe once db is running and has been failing for a while;
	// app must not exist before then.
	released := make(chan time.Time, 1)
	appEarly := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if db, _ := corrosion.GetVM(ctx, node.DB, "db"); db != nil && db.State == "running" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(1500 * time.Millisecond)
		if app, _ := corrosion.GetVM(ctx, node.DB, "app"); app != nil {
			appEarly <- app.State
		}
		released <- time.Now()
		probe.set("db", true)
	}()

	msgs := deployCollect(t, ctx, client, composeDependsHC)
	select {
	case st := <-appEarly:
		t.Fatalf("app was created (state %s) while db's probe was still failing", st)
	default:
	}
	var at time.Time
	select {
	case at = <-released:
	default:
		t.Fatalf("deploy finished before db's probe was released; got %v", msgs)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Errorf("error phase: %s %s", p.VmName, p.Error)
		}
	}
	app, err := corrosion.GetVM(ctx, node.DB, "app")
	if err != nil || app == nil {
		t.Fatalf("app was never created: %v", err)
	}
	created, perr := time.Parse(time.RFC3339Nano, app.CreatedAt)
	if perr != nil {
		t.Fatalf("app created_at %q: %v", app.CreatedAt, perr)
	}
	if created.Before(at) {
		t.Errorf("app created at %s, before db's probe passed at %s", created, at)
	}
	if got := stackState(t, ctx, node.DB, "dep"); got != "active" {
		t.Errorf("stack state = %q, want active", got)
	}
}

// Without a healthcheck, vm_healthy keeps its old meaning: running. Nothing
// probes anything in this scenario and the deploy goes straight through.
func TestFleet_ComposeDependsOnVMHealthyWithoutAHealthcheckIsRunning(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(5 * time.Second)
	yaml := strings.Replace(composeDependsHC,
		"    healthcheck:\n      type: tcp\n      target: 10.0.0.9:5432\n      interval: 1ms\n      retries: 1\n      action: alert\n", "", 1)
	if strings.Contains(yaml, "healthcheck") {
		t.Fatal("fixture still has a healthcheck")
	}
	start := time.Now()
	msgs := deployCollect(t, ctx, client, yaml)
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Errorf("error phase: %s %s", p.VmName, p.Error)
		}
	}
	if !sawPhase(msgs, "app", "done") {
		t.Errorf("app never reported done; got %v", msgs)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("deploy took %s waiting on a running VM without a healthcheck", d)
	}
}
