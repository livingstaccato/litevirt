package failover

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/randid"
)

// A failover restart never leaves the VM's real disk behind silently.
//
// A running VM with a host-local disk is restarted elsewhere under its
// failure policy, exactly as before: `on-host-failure: restart-any` is the
// operator's explicit opt-in (a `migrate:` block in compose, whose plan warns
// "local disk with on-host-failure=restart-any — data loss risk"), and the
// documented cost is a disk rebuilt from the VM's image. What changes is that
// the data it leaves on the failed host is recorded and kept: the record
// (health.RecordStrandedDisks, condition vm_disk_stranded) names the host and
// each disk's path, and the host, once back, sets the disk aside and keeps it
// while the VM exists (health/stranded_disk.go).
//
// Holding the VM instead, or refusing the restart, would newly refuse the
// recovery main performed and that the policy asks for. A VM whose data
// matters more than its uptime has no failure policy (`none`): it stays on
// its host, with its disk, until the host is back.

// noteDiskStranded records the host-local disks of vm that its reschedule
// from host to target leaves on host. It runs after the reschedule write
// committed, so a refused or lost decision records nothing.
func (c *Coordinator) noteDiskStranded(ctx context.Context, host string, vm corrosion.VMRecord, target string) {
	if vm.State == "pending" {
		// A transfer onto host that host never carried out: the VM never ran
		// there, so nothing of its data is there either.
		return
	}
	disks, err := corrosion.GetVMDisks(ctx, c.db, vm.Name)
	if err != nil {
		slog.Error("failover: cannot read the disks of a rescheduled VM to record what it left behind",
			"vm", vm.Name, "host", host, "error", err)
		return
	}
	detail, err := health.RecordStrandedDisks(ctx, c.db, c.hostName, vm.Name, host, target, disks, c.now())
	if err != nil {
		slog.Error("failover: could not record the host-local disks a rescheduled VM left on its failed host",
			"vm", vm.Name, "host", host, "error", err)
		return
	}
	if detail == "" {
		return // every disk is on shared storage and moved with it
	}
	detail = "restarted on " + target + " on a disk rebuilt from its image: " + detail +
		"; " + host + " keeps them once it is back (lv host superseded-disks " + host + ")"
	slog.Warn("failover: a VM restarted elsewhere left its host-local disk on the failed host; recorded and kept",
		"vm", vm.Name, "host", host, "target", target)
	c.audit(ctx, "failover.disk-stranded", vm.Name, detail, "ok")
	if err := corrosion.InsertVMEvent(ctx, c.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm.Name, HostName: c.hostName, Type: "vm.failover.disk_stranded",
		Result: "ok", Severity: "warn", Detail: detail, Username: "failover-coordinator",
	}); err != nil {
		slog.Warn("failover: record the stranded disk's event", "vm", vm.Name, "error", err)
	}
	c.publish("vm.failover.disk_stranded", vm.Name, detail)
	if c.OnDiskStranded != nil {
		c.OnDiskStranded(vm.Name, host, detail)
	}
}

// noteRootfsStranded records that a relocation of ct from host to target
// (how: image-recreate | backup-restore) left the container's own rootfs on
// host (health/stranded_rootfs.go). Surface only: nothing is moved or
// removed.
func (c *Coordinator) noteRootfsStranded(ctx context.Context, host string, ct corrosion.ContainerRecord, target, how string) {
	if ct.State == "pending" {
		// A relocation onto host that host never carried out: the container
		// never ran there, so none of its data is there.
		return
	}
	detail, err := health.RecordStrandedRootfs(ctx, c.db, c.hostName, ct.Name, host, target, how, c.now())
	if err != nil {
		slog.Error("failover: could not record the rootfs a relocated container left on its failed host",
			"container", ct.Name, "host", host, "error", err)
		return
	}
	c.audit(ctx, "failover.rootfs-stranded", ct.Name, detail, "ok")
	c.publish("ct.failover.rootfs_stranded", ct.Name, detail)
	if c.OnRootfsStranded != nil {
		c.OnRootfsStranded(ct.Name, host, detail)
	}
}
