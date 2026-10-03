package failover

import (
	"context"
	"errors"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// skippedNoContainerRuntime handles a container placement refused because no
// active host has a container runtime (placement.ErrNoContainerRuntime), and
// reports whether it did. No amount of capacity places such a container, so
// re-placing it every pass only repeats the refusal: it is marked
// relocate-skipped — the terminal state the other skips use, the row left
// visible for operator recovery — and the audit log says why.
func (c *Coordinator) skippedNoContainerRuntime(ctx context.Context, ct corrosion.ContainerRecord, err error) bool {
	if !errors.Is(err, placement.ErrNoContainerRuntime) {
		return false
	}
	if serr := corrosion.SetContainerStateDetail(ctx, c.db, ct.HostName, ct.Name, "stopped", corrosion.ContainerRelocateSkippedDetail); serr != nil {
		slog.Warn("failover: mark container relocate-skipped", "container", ct.Name, "error", serr)
	}
	slog.Warn("failover: no surviving host has a container runtime — container relocation skipped",
		"container", ct.Name, "host", ct.HostName, "error", err)
	c.audit(ctx, "ct.relocate.skipped", ct.Name,
		"no active host has a container runtime ("+corrosion.LabelLXCCapable+") after fencing "+ct.HostName+
			" (left for operator recovery)", "skipped")
	c.mCt(ActionRelocate, ResultSkipped, ErrNoCandidates)
	return true
}
