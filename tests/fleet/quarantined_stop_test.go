package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A local `lv stop` on a node in write quarantine cannot record the
// operator's stop: every replicated write is refused, so the row keeps
// "running" and no operator-stop detail lands. A forced stop destroyed the
// domain anyway, libvirt's reason was "destroyed", and once the quarantine
// lifted the reconciler recorded an out-of-band destroy that the restart
// policy started again: the operator's stop was undone (VERIFY bug 11, M3).
// A graceful stop whose guest ignored ACPI was force-killed after its
// timeout, the same shape.
//
// Under quarantine a graceful stop is never force-killed. A graceful stop
// the guest honours still runs, as on base: the guest shuts down, the answer
// says the stop was not recorded, and once the quarantine lifts it is
// recorded as a clean guest shutdown, which the restart policy leaves alone.
// `--force` records itself on the host first (quarantined_force_stop_test.go).
func TestFleet_QuarantinedStopIsRefusedNotUndone(t *testing.T) {
	for _, tc := range []struct {
		name        string
		force       bool
		ignoresACPI bool
		wantCode    codes.Code
		wantRunning bool // the domain once the passes have run
	}{
		{name: "graceful", wantCode: codes.Internal, wantRunning: false},
		{name: "graceful-ignored", ignoresACPI: true, wantCode: codes.FailedPrecondition, wantRunning: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			if tc.ignoresACPI {
				n.Virt.IgnoreShutdown = func(string) bool { return true }
			}

			quarantine := "rolled back below latched token(s): test"
			n.DB.SetWriteQuarantine(func() string { return quarantine })
			before := len(n.Virt.EventLog())

			_, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: tc.force, Timeout: 1})
			if status.Code(err) != tc.wantCode {
				t.Errorf("StopVM under write quarantine: err=%v, want %v", err, tc.wantCode)
			}
			shutdowns := 0
			for _, e := range n.Virt.EventLog()[before:] {
				if e.Domain != "web" {
					continue
				}
				switch e.Op {
				case "destroy":
					t.Errorf("a stop under write quarantine destroyed the domain")
				case "shutdown":
					shutdowns++
				}
			}
			if wantShutdown := !tc.force; (shutdowns > 0) != wantShutdown {
				t.Errorf("ACPI shutdowns asked: %d, want asked=%v", shutdowns, wantShutdown)
			}
			if st, _ := n.Virt.RawState("web"); st != libvirtfake.StateRunning {
				// libvirt's own reason for a guest that shut down on ACPI,
				// which the fake leaves unset.
				n.Virt.SetStateReason("web", "guest-shutdown")
			}

			// Restart-policy and reconciler passes under the quarantine and
			// after it lifts, as on the node once it is upgraded again.
			checker := newRestartChecker(t, n)
			r := n.Reconciler()
			checker.SweepOnce(ctx)
			r.ReconcileOnce(ctx)
			n.DB.SetWriteQuarantine(nil)
			n.Virt.IgnoreShutdown = nil
			for i := 0; i < 3; i++ {
				r.ReconcileOnce(ctx)
				checker.SweepOnce(ctx)
			}

			for _, e := range n.Virt.EventLog()[before:] {
				if e.Domain == "web" && e.Op == "start" {
					t.Errorf("a stop under write quarantine was undone: libvirt start of web")
				}
			}
			if st, _ := n.Virt.RawState("web"); (st == libvirtfake.StateRunning) != tc.wantRunning {
				t.Errorf("the domain is %q, want running=%v", st, tc.wantRunning)
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
