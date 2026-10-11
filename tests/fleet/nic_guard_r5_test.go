package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_NICGuard_HeldAfterAFailedCommitIsReported (re-review m4): the
// guest of a paused hand-over arrives on the target, and the source cannot
// commit the move's ownership — the VM's row was moved elsewhere meanwhile.
// The source says so to the target, which keeps the guest paused, keeps its
// record, and raises firewall.nic.held naming the guest and the repair.
func TestFleet_NICGuard_HeldAfterAFailedCommitIsReported(t *testing.T) {
	c, src, dst, _ := heldCluster(t)
	ctx := context.Background()
	land := src.Virt.OnMigrateToTarget
	src.Virt.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		// A write elsewhere moved the row while the guest was in flight: the
		// commit's guard refuses it.
		return corrosion.UpdateVMHost(ctx, src.DB, name, "ghost", "migrating")
	}
	if err := migrateAt(t, c, src, "old", dst.Name); err == nil {
		t.Fatal("fixture: the ownership commit did not fail")
	}
	if st := rawState(dst, "old"); st != libvirtfake.StatePaused {
		t.Fatalf("fixture: the guest is %s on the target, want paused", st)
	}
	dst.Server.ResumeHeldGuestsOnce(ctx)
	row, raised := heldCondition(t, dst)
	if !raised || !strings.Contains(row.Evidence, "old") || !strings.Contains(row.Evidence, "lv doctor repair-owner old "+dst.Name) {
		t.Fatalf("held condition = %+v (raised %v), want it naming the guest and the repair", row, raised)
	}
	if st := rawState(dst, "old"); st != libvirtfake.StatePaused {
		t.Errorf("a guest whose ownership is not recorded on the target was resumed there: %s", st)
	}
	if held := dst.Server.HeldGuestsForTests(); len(held) != 1 {
		t.Errorf("the target dropped the record of the guest it holds: %v", held)
	}
}
