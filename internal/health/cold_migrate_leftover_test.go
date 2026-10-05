package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A cold migration of a stopped VM commits its handoff — the row names the
// target, state stopped — BEFORE the source undefines its shut-off domain. A
// source that crashes in between restarts with that domain still defined and a
// row naming another host. Nothing on the source may start it: the target owns
// the VM and its disks, and a second copy booted here would run on the source's
// stale disk while the target's is the VM's.
//
// What decides it on the source: StartOnbootVMs and reconcile list only the
// VMs whose row names this host (ListVMs(..., r.hostName)), and selfFence,
// which walks every local domain, only ever undefines one whose row points
// elsewhere. libvirt's own autostart is never set on a VM domain.
//
// Mutation: list every VM in StartOnbootVMs (ListVMs(ctx, r.db, "", "")) —
// the onboot VM is started here and this goes red.
func TestReconciler_ColdMigrationLeftoverIsNeverStarted(t *testing.T) {
	for _, tc := range []struct {
		reason      string
		wantCleaned bool // a clearly-dead leftover is undefined; "unknown" needs owner proof it lacks
	}{
		{"guest-shutdown", true},
		{"unknown", false}, // the shape after a host reboot
	} {
		t.Run(tc.reason, func(t *testing.T) {
			ctx := context.Background()
			db := testReconcilerDB(t)
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "os1", HostName: "node-b", State: "stopped",
				Spec: `{"name":"os1","onboot":true}`,
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			fake := libvirtfake.New()
			if err := fake.DefineDomain(`<domain type='kvm'><name>os1</name></domain>`); err != nil {
				t.Fatalf("DefineDomain: %v", err)
			}
			fake.SetStateReason("os1", tc.reason)
			r := NewReconciler("node-a", t.TempDir(), db, fake)

			r.StartOnbootVMs(ctx)
			r.reconcile(ctx)
			r.selfFence(ctx)
			r.reconcile(ctx)

			if hadOp(fake, "os1", "start") {
				t.Fatal("the source started a cold-migrated VM's leftover domain whose row names another host")
			}
			if cleaned := !fake.DomainExists("os1"); cleaned != tc.wantCleaned {
				t.Errorf("leftover cleaned = %v, want %v", cleaned, tc.wantCleaned)
			}
		})
	}
}
