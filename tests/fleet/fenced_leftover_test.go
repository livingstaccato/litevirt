package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_FencedHostCleansUnknownReasonLeftover is the fence-and-return case
// as it happens on real hardware: the fence is a hard power-off, and libvirt
// does not persist the shutoff reason across it, so the victim comes back with
// its leftover domain reporting `shut off (unknown)` — not the "destroyed" that
// TestFleet_OneOwnerAfterHeal models. The reason allowlist refuses "unknown", so
// before this was handled the leftover sat there forever, logged every tick.
//
// The victim may clean it only because the DB owner, asked over real gRPC for
// its OWN libvirt view, reports the VM running. The control half of the test
// stops the survivor's copy and shows the same leftover is then left alone.
func TestFleet_FencedHostCleansUnknownReasonLeftover(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	now := time.Now().UTC()

	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "vm-own", HostName: victim.Name, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	victim.Virt.SetState("vm-own", libvirtfake.StateRunning)

	seedHealth(t, a, []string{a.Name, b.Name}, victim.Name, 5, now.Format(time.RFC3339))
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.Now = func() time.Time { return now }
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.RunOnce(ctx)

	vmAfter, _ := corrosion.GetVM(ctx, a.DB, "vm-own")
	if vmAfter == nil || vmAfter.HostName == victim.Name {
		t.Fatalf("vm-own should have been reassigned off the fenced victim, got %+v", vmAfter)
	}
	survivor := c.Node(vmAfter.HostName)

	// The victim was powered off by the fence and has rebooted: its copy is shut
	// off and libvirt no longer knows why.
	victim.Virt.SetState("vm-own", libvirtfake.StateDefined)
	victim.Virt.SetStateReason("vm-own", "unknown")

	rec := health.NewReconciler(victim.Name, t.TempDir(), victim.DB, victim.Virt)
	rec.SetPeerRuntimeChecker(victim.Server.CheckPeerVMRuntime)

	// Control: the survivor has NOT started it yet (defined, stopped). There is
	// no live copy anywhere to prove this one is the stale one — keep it.
	survivor.Virt.SetState("vm-own", libvirtfake.StateDefined)
	rec.ReconcileOnce(ctx)
	if !victim.Virt.DomainExists("vm-own") {
		t.Fatal("the victim must NOT clean an unknown-reason leftover while the owner does not run the VM")
	}

	// The survivor runs it: now the victim's copy is provably the stale one.
	survivor.Virt.SetState("vm-own", libvirtfake.StateRunning)
	rec.ReconcileOnce(ctx)
	if victim.Virt.DomainExists("vm-own") {
		t.Fatal("the fenced victim must clean its shut-off (unknown) leftover once the owner runs the VM")
	}

	var owners []string
	for _, n := range c.Nodes {
		if n.Virt.DomainExists("vm-own") {
			owners = append(owners, n.Name)
		}
	}
	if len(owners) != 1 || owners[0] != vmAfter.HostName {
		t.Fatalf("expected exactly one owner == %s, got %v", vmAfter.HostName, owners)
	}
}
