package failover

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/health"
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

// stoppedLocalDiskDetail is the detail for a VM that stopped without anyone
// asking (detail, health.classifyStop's record) and has a host-local disk:
// recovering it would rebuild that disk blank from its image elsewhere.
func stoppedLocalDiskDetail(host, detail string) string {
	return "stopped (" + detail + ") with a host-local disk: left on " + host + " with its disks; " +
		"restarting it elsewhere would rebuild that disk blank. Start it once " + host + " is back"
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
func (c *Coordinator) skipStoppedVM(ctx context.Context, host string, vm corrosion.VMRecord, detail string) {
	c.mVM(ActionReschedule, ResultSkipped, ErrStopped)
	if !c.vmWasCandidate(ctx, vm) {
		return
	}
	slog.Info("failover: stopped VM left on its failed host with its disks; not restarted", "vm", vm.Name, "host", host, "why", detail)
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

// vmWasCandidate reports whether failover would have recovered vm had it been
// running: a failure policy, or enrolment in auto-promote.
func (c *Coordinator) vmWasCandidate(ctx context.Context, vm corrosion.VMRecord) bool {
	if p := vmFailurePolicy(vm); p != "" && p != "none" {
		return true
	}
	return c.Promoter != nil && c.autoPromoteEnabled(ctx, vm.Name)
}

// stoppedVMRekeyable reports whether a VM stopped by intent on the failed
// host can be moved to a live host still stopped (rekeyStoppedVM): it was a
// failover candidate, every disk is on shared storage, it has no host-local
// firmware state, its ownership is not in dispute, and — for a writable
// shared disk under the shared-storage fence — the old owner is proven off,
// as for a running VM's transfer. Anything else stays where it is.
func (c *Coordinator) stoppedVMRekeyable(ctx context.Context, host string, vm corrosion.VMRecord, disks []corrosion.DiskRecord, fenceEpoch string) bool {
	if !c.vmWasCandidate(ctx, vm) || vmUsesFirmwareState(vm) || corrosion.VMHasHostLocalDisk(disks) {
		return false
	}
	if disputed, _, err := corrosion.WorkloadHasActiveOwnershipCondition(ctx, c.db, "vm", vm.Name); err != nil || disputed {
		return false
	}
	if fenceEpoch == "" && c.sharedStorageFenceEnforced(ctx) && corrosion.VMHasWritableSharedDisk(disks) {
		return false
	}
	return true
}

// rekeyStoppedDetail is the audit and event detail for a stopped VM moved off
// host to target.
func rekeyStoppedDetail(host, target string) string {
	return "stopped: moved from " + host + " to " + target + " on its shared disks, still stopped; " +
		"failover never starts a stopped VM. Start it there with `lv start`"
}

// rekeyStoppedVM moves a VM stopped by intent, all of whose disks are
// shared, off the failed host to target, still stopped
// (corrosion.RekeyStoppedVM). The target's reconciler then defines its
// domain there, shut off. Like every move off a failed host it is taken only
// under the decision gate and this coordinator's tenure.
func (c *Coordinator) rekeyStoppedVM(ctx context.Context, host string, vm corrosion.VMRecord, target string) {
	if c.gateEnforced(ctx) {
		if g := c.decideGate(ctx, host); !g.OK {
			slog.Warn("failover: decision gate refused moving a stopped VM", "vm", vm.Name, "reason", g.Reason)
			c.noteGateRefused(ActionReschedule, g.Reason)
			c.mVM(ActionReschedule, ResultError, ErrNoQuorum)
			return
		}
	}
	if !c.stillOurTenure(ctx) {
		c.noteGateRefused(ActionReschedule, health.ReasonStaleLeaseTerm)
		c.mVM(ActionReschedule, ResultError, ErrStaleLeaseTerm)
		return
	}
	fresh, err := corrosion.GetVM(ctx, c.db, vm.Name)
	if err != nil || fresh == nil || fresh.HostName != host {
		c.mVM(ActionReschedule, ResultError, ErrDBError)
		return
	}
	if err := corrosion.RekeyStoppedVM(ctx, c.db, vm.Name, host, target, "stopped", fresh.OwnerEpoch); err != nil {
		slog.Warn("failover: move a stopped VM off its failed host; it stays there this pass",
			"vm", vm.Name, "from", host, "to", target, "error", err)
		c.mVM(ActionReschedule, ResultError, ErrDBError)
		return
	}
	c.fenceRelocated[host] = true
	c.mVM(ActionReschedule, ResultSuccess, ErrStopped)
	detail := rekeyStoppedDetail(host, target)
	slog.Info("failover: stopped VM moved off its failed host, still stopped", "vm", vm.Name, "from", host, "to", target)
	c.audit(ctx, "failover.rekey-stopped", vm.Name, detail, "ok")
	if err := corrosion.InsertVMEvent(ctx, c.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm.Name, HostName: c.hostName, Type: "vm.failover.rekeyed",
		Result: "ok", Severity: "info", Detail: detail, Username: "failover-coordinator",
	}); err != nil {
		slog.Warn("failover: record the stopped VM's event", "vm", vm.Name, "error", err)
	}
	c.publish("vm.failover.rekeyed", vm.Name, detail)
}
