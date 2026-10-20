// Fleet scenarios for the other paths that reach a VM whose row was left
// `migrating`: a reconfigure with a restart, a delete asked on another host,
// and the start-up raise of its condition.
package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// defineWebOn defines web on n, running when running is set.
func defineWebOn(t *testing.T, n *Node, running bool) {
	t.Helper()
	if err := n.Virt.DefineDomain(`<domain type='kvm'><name>web</name><uuid>33333333-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if running {
		n.Virt.SetState("web", libvirtfake.StateRunning)
	}
}

// `lv update --restart-if-needed` of a VM whose row was left migrating, its
// guest running on the move's target. The source has either no domain of it
// (the cut-over undefined it) or one shut off. The reconfigure is refused
// naming the move, nothing is started on the source, the row stays
// migrating and the guest keeps running on the target: one copy.
//
// Before the fix the reconfigure stopped nothing, redefined the source's
// domain and started it: two copies over one disk.
//
// Mutations: the reconfigure's own refusal and the stop primitive's refusal
// of a migrating row both removed — the stop records the row stopped, the
// start sees a stopped row, and web boots on the source, red.
func TestFleet_UpdateRestartOfAVMLeftMigratingStartsNoSecondCopy(t *testing.T) {
	for _, source := range []string{"source-undefined", "source-shut-off"} {
		t.Run(source, func(t *testing.T) {
			c, src, dst := leftMigrating(t)
			defineWebOn(t, dst, true)
			if source == "source-undefined" {
				if err := src.Virt.UndefineDomain("web", false); err != nil {
					t.Fatal(err)
				}
			}
			allow := true
			_, err := c.SelfClient(src).UpdateVM(context.Background(), &pb.UpdateVMRequest{
				Name: "web", MemoryMib: 512, AllowRestart: &allow,
			})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "migrating") {
				t.Errorf("update --restart-if-needed of a VM left migrating = %v; want FailedPrecondition naming the move", err)
			}
			if n := countOp(src.Virt.EventLog(), "start", "web"); n != 0 {
				t.Errorf("web was started %d time(s) on its source", n)
			}
			if st, _ := src.Virt.DomainState("web"); st == "running" {
				t.Errorf("web runs on the source")
			}
			if st := webState(t, src); st != "migrating" {
				t.Errorf("web = %s; want still migrating", st)
			}
			if st, _ := dst.Virt.DomainState("web"); st != "running" {
				t.Errorf("web on the target = %q; want still running", st)
			}
		})
	}
}

// RaiseLeftMigrating names a VM recorded migrating only while no operation
// holds its lock: a move or another request in flight is that operation's to
// settle. Once the lock is free the condition is raised.
//
// Mutation: the lock check removed — the first raise names web, red.
func TestFleet_RaiseLeftMigratingSkipsAVMWhoseLockIsHeld(t *testing.T) {
	_, src, dst := leftMigrating(t)
	ctx := context.Background()
	release := src.Server.HoldVMLockForTest("web")
	src.Server.RaiseLeftMigrating(ctx)
	if cond, ok, _ := corrosion.GetHealthCondition(ctx, src.DB, "drain", "vm.migration_unresolved", "vm", "web"); ok && cond.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("vm.migration_unresolved raised for web while its lock is held: %+v", cond)
	}
	release()
	src.Server.RaiseLeftMigrating(ctx)
	cond, ok, err := corrosion.GetHealthCondition(ctx, src.DB, "drain", "vm.migration_unresolved", "vm", "web")
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cond.Evidence, dst.Name) {
		t.Fatalf("vm.migration_unresolved once the lock is free = %+v ok=%v err=%v; want it open, naming %s", cond, ok, err, dst.Name)
	}
}

// A delete of a VM left migrating asked on a host that is not its own asks
// the VM's host whether the guest runs there, as a delete asked on that host
// looks itself: one that does is deleted (the operator's intent, as a stop
// of it is), without asking the target.
//
// Before the fix the delete asked elsewhere always asked the target, and
// asked on the target itself was refused as naming no target to ask.
//
// Mutation: the source not asked — the delete asked on the target is
// refused, red.
func TestFleet_DeleteOfAVMLeftMigratingAskedElsewhereChecksItsSource(t *testing.T) {
	c, src, dst := leftMigrating(t)
	src.Virt.SetState("web", libvirtfake.StateRunning)
	if _, err := c.SelfClient(dst).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("delete asked on %s of web running on %s: %v", dst.Name, src.Name, err)
	}
	if row, _ := corrosion.GetVM(context.Background(), src.DB, "web"); row != nil {
		t.Fatalf("web after the delete = %+v; want gone", row)
	}
	if src.Virt.DomainExists("web") {
		t.Fatal("web is still defined on its source")
	}
}
