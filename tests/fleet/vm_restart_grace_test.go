package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/health"
)

// `lv restart` on a running VM destroys and starts its domain while the VM's
// row stays "running", so the healthcheck's sweep cannot see the start. The
// daemon tells the checker instead (grpcapi.VMStartObserver), and the
// restarted guest gets its start grace: a failed probe right after the
// restart does not run the healthcheck's action.
func TestFleet_RestartVMOpensTheHealthcheckStartGrace(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()

	if _, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: n.Name},
		// action alert: it fires, and is visible, without a libvirt connection
		// on the checker.
		Healthcheck: &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:80", Interval: "1ms", Retries: 1, Action: "alert"},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	// Out of its creation grace, so only a start can hold the action off.
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := n.DB.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'web'`, old); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}

	fp := &fleetProbe{pass: map[string]bool{"web": true}}
	fp.checker = health.NewVMChecker(n.Name, t.TempDir(), n.DB, nil)
	fp.checker.SetProbeFunc(fp.fn)
	bus := events.NewBus()
	evs, cancel := bus.Subscribe()
	t.Cleanup(cancel)
	fp.checker.SetEventBus(bus)
	n.Server.SetVMStartObserver(fp.checker)

	fp.checker.SweepOnce(ctx) // passing: the checker has seen the VM running
	fp.set("web", false)

	if _, err := c.SelfClient(n).RestartVM(ctx, &pb.RestartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("RestartVM: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, n.DB, "web")
	if err != nil || vm == nil || vm.State != "running" {
		t.Fatalf("after RestartVM: vm=%+v err=%v, want running", vm, err)
	}

	fp.checker.SweepOnce(ctx) // fails, right after the restart
	for {
		select {
		case e := <-evs:
			if e.Action == "vm.health.failed" && e.Target == "web" {
				t.Fatalf("the healthcheck acted on a VM just restarted by RestartVM (%s): no start grace", e.Detail)
			}
			continue
		default:
		}
		break
	}
	h, err := health.EvaluateVMHealth(ctx, n.DB, mustGetVM(t, n, "web"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Verdict != health.VerdictUnhealthy {
		t.Errorf("the failure inside the grace was not published: %+v", h)
	}
}

func mustGetVM(t *testing.T, n *Node, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): vm=%v err=%v", name, vm, err)
	}
	return vm
}
