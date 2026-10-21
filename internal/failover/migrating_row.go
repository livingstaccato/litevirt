package failover

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// MigratingVerdict is what recovery may do with a VM recorded `migrating` on
// a host being recovered (SettleMigratingRow).
type MigratingVerdict int

const (
	// MigratingHold: the guest may run on the migration's target, or whether
	// it does cannot be told. Nothing is started or moved; the recovery is
	// retried next tick, and an operator is told why.
	MigratingHold MigratingVerdict = iota
	// MigratingRecover: the guest runs nowhere but on the failed source — the
	// target has no domain of it, or is proven powered off. Recovered as any
	// running VM is.
	MigratingRecover
	// MigratingSettled: the row is no longer this migration's on the source —
	// re-pointed to the target that runs the guest, or changed since it was
	// read. Nothing is left to recover.
	MigratingSettled
)

// recoverMigratingVM decides a VM whose row says `migrating` on h, a host
// being recovered. A live migration that cut over in libvirt runs the guest
// on its target, and a source that died before the ownership commit leaves
// the row naming the source: restarting it elsewhere would be a second
// running copy. Reports whether the VM is recovered as a running one.
//
// The guarantee is enforced here, where the reschedule is created, so no peer
// has to cooperate: a coordinator that holds does not mint, claim or write.
// With SettleMigratingRow unwired every such VM is held (fail closed).
func (c *Coordinator) recoverMigratingVM(ctx context.Context, h *corrosion.HostRecord, vm corrosion.VMRecord) bool {
	verdict, detail := MigratingHold, "no way to ask the migration's target whether the guest runs there"
	if c.SettleMigratingRow != nil {
		verdict, detail = c.SettleMigratingRow(ctx, vm, h.Name)
	}
	switch verdict {
	case MigratingRecover:
		slog.Info("failover: a VM recorded migrating has no running copy on its target; recovering it",
			"vm", vm.Name, "host", h.Name, "detail", detail)
		return true
	case MigratingSettled:
		slog.Warn("failover: a VM recorded migrating runs on its target; its row now names it, nothing is started",
			"vm", vm.Name, "host", h.Name, "detail", detail)
		c.mVM(ActionReschedule, ResultSkipped, ErrMigrating)
		return false
	default:
		slog.Warn("failover: holding a VM recorded migrating — the guest may run on its target",
			"vm", vm.Name, "host", h.Name, "detail", detail)
		c.mVM(ActionReschedule, ResultRefused, ErrMigrating)
		c.noteHold(h.Name, "VM "+vm.Name+" is recorded migrating and may run on its target: "+detail)
		c.retryClaimsFor(h.Name)
		return false
	}
}
