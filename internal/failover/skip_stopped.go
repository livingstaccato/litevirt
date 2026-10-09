package failover

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/randid"
)

// Stopped workloads stay where they are.
//
// Failover recovers what was RUNNING on a failed host. A stopped VM or
// container runs nowhere, so there is nothing to recover, and every
// recovery action starts the workload: a reschedule writes "pending", a
// promotion defines and starts the replica, a relocation recreates and
// starts the container. Before this rule a stopped VM with a failure policy
// was rescheduled like a running one, started on a disk rebuilt blank from
// its image when its real disk was host-local, and the real disk, left on
// the failed host and no longer recorded, was later set aside and deleted by
// the superseded-disk sweep (kvm003 drill 1, merge-lab 2026-10-08).
//
// So a stopped workload stays on its host, stopped, with its disks, and when
// the host returns it is exactly as the operator left it. While the host is
// down its data stays there; `lv host rm --dead` lists such workloads with
// the operator's choices (grpcapi.strandedOn).

// stoppedVMDetail is the audit and event detail for a stopped VM left on host.
func stoppedVMDetail(host string) string {
	return "stopped: left on " + host + " with its disks; failover never starts or moves a stopped VM. " +
		"Start it once " + host + " is back"
}

// stoppedContainerDetail is stoppedVMDetail for a container.
func stoppedContainerDetail(host string) string {
	return "stopped: left on " + host + "; failover never recreates or starts a stopped container. " +
		"Start it once " + host + " is back"
}

// skipStoppedVM records that recoverWorkloads left the stopped vm on host.
// The metric counts every pass. The audit row and the event are written once
// per change (auditSkip), and only for a VM that failover would otherwise
// have recovered: one with a failure policy or enrolled in auto-promote. A
// stopped VM that opted out was never a candidate, and saying so for every
// one on every fence would bury the ones that were.
func (c *Coordinator) skipStoppedVM(ctx context.Context, host string, vm corrosion.VMRecord) {
	c.mVM(ActionReschedule, ResultSkipped, ErrStopped)
	p := vmFailurePolicy(vm)
	if (p == "" || p == "none") && (c.Promoter == nil || !c.autoPromoteEnabled(ctx, vm.Name)) {
		return
	}
	detail := stoppedVMDetail(host)
	slog.Info("failover: stopped VM left on its failed host with its disks; not restarted", "vm", vm.Name, "host", host)
	if !c.auditSkip(ctx, host, vm.Name, detail, "skipped") {
		return
	}
	if err := corrosion.InsertVMEvent(ctx, c.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm.Name, HostName: c.hostName, Type: "vm.failover.skipped",
		Result: "ok", Severity: "warn", Detail: detail, Username: "failover-coordinator",
	}); err != nil {
		slog.Warn("failover: record the stopped VM's event", "vm", vm.Name, "error", err)
	}
	c.publish("vm.failover.skipped", vm.Name, detail)
}

// skipStoppedContainer is skipStoppedVM for a container. Containers have no
// event table, so its event goes to the live stream only; the audit row is
// the durable record.
func (c *Coordinator) skipStoppedContainer(ctx context.Context, host string, ct corrosion.ContainerRecord) {
	c.mCt(ActionRelocate, ResultSkipped, ErrStopped)
	if ct.OnHostFailure == "" || ct.OnHostFailure == "none" {
		return
	}
	detail := stoppedContainerDetail(host)
	slog.Info("failover: stopped container left on its failed host; not relocated", "container", ct.Name, "host", host)
	if !c.auditSkip(ctx, host, "ct/"+ct.Name, detail, "skipped") {
		return
	}
	c.publish("ct.failover.skipped", ct.Name, detail)
}

// publish sends a coordinator event to Events, if one is wired.
func (c *Coordinator) publish(action, target, detail string) {
	if c.Events == nil {
		return
	}
	c.Events.Publish(events.Event{Action: action, Target: target, Detail: detail, Username: "failover-coordinator"})
}
