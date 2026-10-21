package failover

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// MigratingVerdict is what recovery may do with a VM recorded `migrating` on
// a host being recovered (SettleMigratingRows).
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

// MigratingDecision is SettleMigratingRows' answer for one VM.
type MigratingDecision struct {
	Verdict MigratingVerdict
	Detail  string
}

// settleMigratingVMs decides, once per recovery pass, every VM in vms whose
// row says `migrating` on h. A live migration that cut over in libvirt runs
// the guest on its target, and a source that died before the ownership
// commit leaves the row naming the source: restarting it elsewhere would be a
// second running copy. One call covers the whole pass, so the targets are
// asked once each, under one bound, whatever the number of VMs.
//
// The guarantee is enforced here, where the reschedule is created, so no peer
// has to cooperate: a coordinator that holds does not mint, claim or write.
// With SettleMigratingRows unwired every such VM is held (fail closed).
func (c *Coordinator) settleMigratingVMs(ctx context.Context, h *corrosion.HostRecord, vms []corrosion.VMRecord) map[string]MigratingDecision {
	var migrating []corrosion.VMRecord
	for _, vm := range vms {
		if vm.State == "migrating" {
			migrating = append(migrating, vm)
		}
	}
	if len(migrating) == 0 {
		return nil
	}
	if c.SettleMigratingRows == nil {
		return map[string]MigratingDecision{}
	}
	return c.SettleMigratingRows(ctx, h.Name, migrating)
}

// recoverMigratingVM acts on vm's decision. Reports whether the VM is
// recovered as a running one.
func (c *Coordinator) recoverMigratingVM(h *corrosion.HostRecord, vm corrosion.VMRecord, decisions map[string]MigratingDecision) bool {
	d, ok := decisions[vm.Name]
	if !ok {
		d = MigratingDecision{Verdict: MigratingHold, Detail: "no way to ask the migration's target whether the guest runs there"}
	}
	switch d.Verdict {
	case MigratingRecover:
		slog.Info("failover: a VM recorded migrating has no running copy on its target; recovering it",
			"vm", vm.Name, "host", h.Name, "detail", d.Detail)
		return true
	case MigratingSettled:
		slog.Warn("failover: a VM recorded migrating runs on its target; its row now names it, nothing is started",
			"vm", vm.Name, "host", h.Name, "detail", d.Detail)
		c.mVM(ActionReschedule, ResultSkipped, ErrMigrating)
		return false
	default:
		slog.Warn("failover: holding a VM recorded migrating — the guest may run on its target",
			"vm", vm.Name, "host", h.Name, "detail", d.Detail)
		c.mVM(ActionReschedule, ResultRefused, ErrMigrating)
		c.noteHold(h.Name, "VM "+vm.Name+" is recorded migrating and may run on its target: "+d.Detail)
		c.retryClaimsFor(h.Name)
		return false
	}
}
