package failover

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// containerPlacementRequest is the placement a container's host-loss
// relocation asks for (pickContainerTarget).
func (c *Coordinator) containerPlacementRequest(ct corrosion.ContainerRecord) placement.Request {
	return placement.Request{
		// A container holds memory only: its cpu_limit is no vCPU reservation
		// and it carries no qemu overhead.
		VMName: ct.Name, Container: true, MemMiBNeeded: ct.MemMiB,
		Capacity: c.capacity,
		// Region scope keeps a relocation in the source host's region.
		RequireRegion: c.containerRecoveryRegion(ct.HostName),
	}
}

// retrySkippedOnRemovedHost reports whether a relocate-skipped container on h
// is relocated again this pass. Only on a host removed for good (the
// removed-host pass, recoverRemovedHosts), and only once a host can take it.
//
// On a fenced host the skip stays terminal: the host may come back with the
// container's rootfs, and an operator recovers it there. A host removed for
// good never comes back, and its name is not re-admitted while the container
// is recorded on it (corrosion.WorkloadsOnRemovedHost). Kept terminal there,
// a container skipped because no host could run it when its host died, say
// the only host with a container runtime, would hold that name refused for
// good, and the only way out would be to delete it (kvm003 drill 6,
// main-e004c250). So once placement finds a host for it, it goes through the
// relocation again, under a recovery claim like any other.
//
// While no host can take it, nothing is written or audited: the skip already
// said so. A container with no image to re-pull can come back only from a
// backup, and a restore that already failed onto a target fails again, so it
// is retried once per target.
func (c *Coordinator) retrySkippedOnRemovedHost(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord) bool {
	if h == nil || h.State != "removed" {
		return false
	}
	repullable := containerImageRepullable(ct.Image)
	if !repullable && c.Restorer == nil {
		return false // nothing a target could rebuild it from
	}
	target, err := placement.Select(ctx, c.db, c.containerPlacementRequest(ct))
	if err != nil || target == "" || c.targetHasLiveContainer(ctx, target, ct.Name) {
		return false
	}
	if !repullable {
		key := h.Name + "/" + ct.Name
		if c.skipRetried[key] == target {
			return false
		}
		if c.skipRetried == nil {
			c.skipRetried = map[string]string{}
		}
		c.skipRetried[key] = target
	}
	slog.Info("failover: a host can now take a container skipped on a host removed for good; relocating it",
		"container", ct.Name, "host", h.Name, "target", target)
	return true
}
