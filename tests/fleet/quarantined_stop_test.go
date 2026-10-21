package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A local `lv stop` on a node in write quarantine cannot record the
// operator's stop: every replicated write is refused, so the row keeps
// "running" and no operator-stop detail lands. The domain stopped anyway,
// and once the quarantine lifted the reconciler recorded the stop as an
// out-of-band destroy and the restart policy started the VM again: the
// operator's stop was undone (VERIFY bug 11, M3).
//
// A stop that cannot be recorded is refused before it touches libvirt: the
// guest keeps running, the operator is told why, and no restart-policy or
// reconciler pass, during the quarantine or after it lifts, starts or
// stops anything.
func TestFleet_QuarantinedStopIsRefusedNotUndone(t *testing.T) {
	for _, force := range []bool{false, true} {
		name := "graceful"
		if force {
			name = "force"
		}
		t.Run(name, func(t *testing.T) {
			c := New(t, Options{Nodes: 1})
			n := c.Nodes[0]
			ctx := context.Background()

			if _, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
				Name: "web", Cpu: 1, MemoryMib: 512,
				Placement: &pb.PlacementSpec{Host: n.Name},
				Restart:   &pb.RestartPolicy{Condition: "always", Delay: "1ms"},
			}}); err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			if st, _ := n.Virt.RawState("web"); st != libvirtfake.StateRunning {
				t.Fatalf("after CreateVM the domain is %q, want running", st)
			}

			quarantine := "rolled back below latched token(s): test"
			n.DB.SetWriteQuarantine(func() string { return quarantine })
			before := len(n.Virt.EventLog())

			_, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: force})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("StopVM under write quarantine: err=%v, want FailedPrecondition (a stop it cannot record is refused)", err)
			}
			for _, e := range n.Virt.EventLog()[before:] {
				if e.Domain == "web" && (e.Op == "shutdown" || e.Op == "destroy") {
					t.Errorf("the refused stop reached libvirt: %s %s", e.Op, e.Domain)
				}
			}
			if st, _ := n.Virt.RawState("web"); force && st != libvirtfake.StateRunning {
				// libvirt's own reason for a domain an operator's stop
				// destroyed, which the fake leaves unset.
				n.Virt.SetStateReason("web", "destroyed")
			}

			// Restart-policy and reconciler passes under the quarantine and
			// after it lifts, as on the node once it is upgraded again.
			checker := newRestartChecker(t, n)
			r := n.Reconciler()
			checker.SweepOnce(ctx)
			r.ReconcileOnce(ctx)
			n.DB.SetWriteQuarantine(nil)
			for i := 0; i < 3; i++ {
				r.ReconcileOnce(ctx)
				checker.SweepOnce(ctx)
			}

			for _, e := range n.Virt.EventLog()[before:] {
				if e.Domain == "web" && (e.Op == "start" || e.Op == "shutdown" || e.Op == "destroy") {
					t.Errorf("after a stop under quarantine: libvirt %s of web, want the domain left as the refusal found it", e.Op)
				}
			}
			if st, _ := n.Virt.RawState("web"); st != libvirtfake.StateRunning {
				t.Errorf("the domain is %q, want still running (the stop was refused)", st)
			}
			vm, err := corrosion.GetVM(ctx, n.DB, "web")
			if err != nil || vm == nil || vm.State != "running" {
				t.Errorf("row after the passes: %+v err=%v, want running", vm, err)
			}

			// Unquarantined, the same stop sticks through the same passes.
			if _, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: force}); err != nil {
				t.Fatalf("StopVM unquarantined: %v", err)
			}
			for i := 0; i < 3; i++ {
				r.ReconcileOnce(ctx)
				checker.SweepOnce(ctx)
			}
			if st, _ := n.Virt.RawState("web"); st == libvirtfake.StateRunning {
				t.Errorf("an unquarantined operator stop was undone: domain %q", st)
			}
		})
	}
}

// newRestartChecker is the node's VM checker as the daemon runs its
// restart-policy pass: over the node's libvirt fake.
func newRestartChecker(t *testing.T, n *Node) *health.VMChecker {
	t.Helper()
	v := health.NewVMChecker(n.Name, n.FW.DataDir, n.DB, nil)
	v.SetBackend(n.Virt)
	return v
}
