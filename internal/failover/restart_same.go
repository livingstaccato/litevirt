package failover

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/randid"
)

// restart-same waits for its host when the VM has a host-local disk.
//
// recoverWorkloads always ran restart-same on a FENCED host, whose row is
// never active, so it fell through to placement and restarted the VM on any
// healthy host — for a host-local disk, on a disk rebuilt blank from its
// image, although the policy says "wait for the original host". A VM with any
// host-local disk now stays on its host, recorded (health.RecordHeldForHost),
// and that host starts it on its real disk when it is back. A VM whose disks
// are all shared keeps being restarted elsewhere, as before: its data moves
// with it, and refusing that would newly refuse a recovery main performed.

// holdRestartSame leaves vm on host and records why. The event, audit row and
// notification are written once per change (auditSkip), not every pass.
func (c *Coordinator) holdRestartSame(ctx context.Context, host string, vm corrosion.VMRecord, disks []corrosion.DiskRecord) {
	c.mVM(ActionReschedule, ResultSkipped, ErrHeldForHost)
	detail, err := health.RecordHeldForHost(ctx, c.db, c.hostName, vm.Name, host, disks, c.now())
	if err != nil {
		slog.Error("failover: could not record a restart-same VM held on its host", "vm", vm.Name, "host", host, "error", err)
		detail = "held on " + host + ": on-host-failure is restart-same and it has a host-local disk"
	}
	slog.Warn("failover: restart-same VM with a host-local disk left on its failed host to wait for it",
		"vm", vm.Name, "host", host)
	if !c.auditSkip(ctx, host, vm.Name, detail, "skipped") {
		return
	}
	if err := corrosion.InsertVMEvent(ctx, c.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm.Name, HostName: c.hostName, Type: "vm.failover.held",
		Result: "ok", Severity: "warn", Detail: detail, Username: "failover-coordinator",
	}); err != nil {
		slog.Warn("failover: record the held VM's event", "vm", vm.Name, "error", err)
	}
	c.publish("vm.failover.held", vm.Name, detail)
	if c.OnDiskStranded != nil {
		c.OnDiskStranded(vm.Name, host, detail)
	}
}
