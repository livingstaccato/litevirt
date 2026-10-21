package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// When a storage pool fills, QEMU pauses the guest on the failed write
// (I/O error, ENOSPC). litevirt folded that into an operator's pause: no
// condition, nothing anywhere said the guest was frozen (VERIFY bug 10). The
// owner now raises vm_io_paused about the VM, replicated so every node's
// `lv health` shows it, and resolves it once the guest runs again. The VM is
// not treated as stopped — its row stays running, nothing restarts,
// destroys or resumes it — and an operator's pause raises nothing.
func TestFleet_IOErrorPauseIsVisibleAndNotAStop(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	owner, peer := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)

	for _, name := range []string{"db", "web"} {
		if _, err := c.SelfClient(owner).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: name, Cpu: 1, MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: owner.Name},
			Restart:   &pb.RestartPolicy{Condition: "always", Delay: "1ms"},
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
	}
	if err := owner.Virt.PauseOnIOError("db"); err != nil {
		t.Fatalf("PauseOnIOError: %v", err)
	}
	if err := owner.Virt.SuspendDomain("web"); err != nil { // an operator's pause
		t.Fatalf("SuspendDomain: %v", err)
	}
	before := len(owner.Virt.EventLog())

	r := owner.Reconciler()
	checker := newRestartChecker(t, owner)
	for i := 0; i < 3; i++ {
		r.ReconcileOnce(ctx)
		checker.SweepOnce(ctx)
	}

	open := func(n *Node, vm string) (corrosion.HealthCondition, bool) {
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, health.VMIOPausedEvaluator, health.CondVMIOPaused, "vm", vm)
		if err != nil {
			t.Fatalf("read %s condition on %s: %v", vm, n.Name, err)
		}
		return row, ok && row.Lifecycle != corrosion.ConditionResolved
	}
	if _, ok := open(owner, "db"); !ok {
		t.Fatalf("no open vm_io_paused about db on its owner")
	}
	c.WaitConverged(t, convergeTimeout)
	row, ok := open(peer, "db")
	if !ok {
		t.Fatalf("vm_io_paused about db did not replicate to %s", peer.Name)
	}
	var ev struct {
		PausedReason string `json:"paused_reason"`
		Host         string `json:"host"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.PausedReason != "io-error" || ev.Host != owner.Name {
		t.Errorf("vm_io_paused evidence %q (err %v), want paused_reason io-error on host %s", row.Evidence, err, owner.Name)
	}
	if row.Severity != corrosion.SeverityWarning {
		t.Errorf("vm_io_paused severity %q, want warning", row.Severity)
	}
	if _, ok := open(owner, "web"); ok {
		t.Errorf("an operator's pause raised vm_io_paused")
	}

	for _, e := range owner.Virt.EventLog()[before:] {
		switch e.Op {
		case "start", "destroy", "shutdown", "resume", "undefine":
			t.Errorf("a paused guest was acted on: libvirt %s of %s", e.Op, e.Domain)
		}
	}
	if st, _ := owner.Virt.RawState("db"); st != libvirtfake.StatePaused {
		t.Errorf("db is %q, want left paused (no automatic resume)", st)
	}
	for _, name := range []string{"db", "web"} {
		vm := mustGetVM(t, owner, name)
		if vm.State != "running" || vm.StateDetail != "" {
			t.Errorf("%s row %s/%q, want running: a paused guest is not a stop", name, vm.State, vm.StateDetail)
		}
	}

	// The operator frees space and resumes the guest: the owner resolves it.
	if err := owner.Virt.ResumeDomain("db"); err != nil {
		t.Fatalf("ResumeDomain: %v", err)
	}
	r.ReconcileOnce(ctx)
	c.WaitConverged(t, convergeTimeout)
	if _, ok := open(peer, "db"); ok {
		t.Errorf("vm_io_paused about db still open on %s after the guest resumed", peer.Name)
	}
}
