// Fleet scenarios for a delete of a VM whose row was left `migrating`, asked
// on a host that is not its own, or whose guest stops running on its host
// under the owner's lock.
package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A delete asked on a host that is not the VM's own, whose source cannot be
// asked whether the guest runs there, falls through to the target ask, and
// on the target itself is refused: an unreachable source is not taken as
// running the guest.
//
// Mutation: an unreachable source taken as running — the delete goes ahead,
// red.
func TestFleet_DeleteOfAVMLeftMigratingAskedElsewhereWithItsSourceUnreachableIsRefused(t *testing.T) {
	c, src, dst := leftMigrating(t)
	src.Virt.SetState("web", libvirtfake.StateRunning)
	src.RefuseRPCs("GetRuntimeInventory")
	_, err := c.SelfClient(dst).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "web", Force: true})
	if err == nil {
		t.Fatal("delete asked on the target with the source unreachable went ahead; want it refused")
	}
	if st := webState(t, src); st != "migrating" {
		t.Fatalf("web = %s; want still migrating", st)
	}
	if st, _ := src.Virt.DomainState("web"); st != "running" {
		t.Fatalf("web on its source = %q; want still running", st)
	}
}

// The delete's runs-on-source check is made again under the owner's lock: a
// guest that ran on its host when the entry looked, and no longer does when
// the owner holds the lock (its move cut over meanwhile), is not deleted,
// since the target was never asked. The delete is aborted for a retry,
// which asks the target.
//
// Mutation: no re-check under the lock — the row and disks go while the
// target may run the guest, red.
func TestFleet_DeleteOfAVMLeftMigratingWhoseGuestStopsRunningUnderTheLockIsRetried(t *testing.T) {
	for _, entry := range []string{"source", "target"} {
		t.Run("asked on the "+entry, func(t *testing.T) {
			c, src, dst := leftMigrating(t)
			src.Virt.SetState("web", libvirtfake.StateRunning)
			// The cut-over lands once the owner holds the delete's lease.
			src.Server.SetDeleteLeaseTakenHookForTest(func(name string) {
				if name == "web" {
					src.Virt.SetState("web", libvirtfake.StateDefined)
				}
			})
			from := src
			if entry == "target" {
				from = dst
			}
			_, err := c.SelfClient(from).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "web", Force: true})
			if status.Code(err) != codes.Aborted {
				t.Fatalf("delete of web whose guest stopped running here under the lock = %v; want Aborted for a retry", err)
			}
			if row, _ := corrosion.GetVM(context.Background(), src.DB, "web"); row == nil || row.State != "migrating" {
				t.Fatalf("web = %+v; want its migrating row kept", row)
			}
			if !src.Virt.DomainExists("web") {
				t.Fatal("web's domain was removed from its source")
			}
		})
	}
}
