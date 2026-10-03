package health

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostLacksContainerRuntime reports whether this host's record does not say it
// runs containers: corrosion.HostRunsContainers, the rule placement applies, so
// only litevirt.lxc=true (written by the daemon from lxc.Available) qualifies
// and a host with no label lacks a runtime. A read that fails, or finds no host
// row, decides nothing: the failure this gates is terminal.
func (c *ContainerChecker) hostLacksContainerRuntime(ctx context.Context) bool {
	h, err := corrosion.GetHost(ctx, c.db, c.hostName)
	return err == nil && h != nil && !corrosion.HostRunsContainers(*h)
}

// failRelocationWithoutRuntime ends a relocation onto this host that can never
// complete because the host has no container runtime: retrying only repeats
// "lxc-create not found" every sweep, and the proof stayed in_progress forever
// (drill D3: blct on node-3, relocated there before placement refused such a
// host). The proof is failed — terminal, through the same lifecycle helper a
// failed VM start uses — and the row leaves the relocate-recreate marker for
// "error" with the cause, left visible for operator recovery.
func (c *ContainerChecker) failRelocationWithoutRuntime(ctx context.Context, ct corrosion.ContainerRecord, proofID string) {
	const detail = "relocation failed: this host has no container runtime (" + corrosion.LabelLXCCapable + " is not true)"
	if proofID != "" {
		if err := corrosion.FailActionProof(ctx, c.db, proofID, "", "no_container_runtime", detail); err != nil {
			slog.Warn("containercheck: fail the relocation proof", "container", ct.Name, "proof", proofID, "error", err)
			return // keep the marker: the next sweep retries the failure, not a recreate
		}
	}
	if err := corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "error", detail); err != nil {
		slog.Warn("containercheck: mark the relocation failed", "container", ct.Name, "error", err)
		c.noteStateWriteFail(corrosion.OpContainerState, err)
		return
	}
	slog.Error("containercheck: a container was relocated to this host, which has no container runtime; relocation failed",
		"container", ct.Name, "proof", proofID)
	c.publish("ct.relocate.failed", ct.Name, detail)
}
