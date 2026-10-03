package health

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostLacksContainerRuntime reports whether this host recorded that it has no
// container runtime (corrosion.LabelLXCCapable = "false", written by its daemon
// at every start from lxc.Available). A host with no label at all — a daemon
// from before the label — is not taken to lack one, as in placement.
func (c *ContainerChecker) hostLacksContainerRuntime(ctx context.Context) bool {
	h, err := corrosion.GetHost(ctx, c.db, c.hostName)
	return err == nil && h != nil && h.Labels[corrosion.LabelLXCCapable] == "false"
}

// failRelocationWithoutRuntime ends a relocation onto this host that can never
// complete because the host has no container runtime: retrying only repeats
// "lxc-create not found" every sweep, and the proof stayed in_progress forever
// (drill D3: blct on node-3, relocated there before placement refused such a
// host). The proof is failed — terminal, through the same lifecycle helper a
// failed VM start uses — and the row leaves the relocate-recreate marker for
// "error" with the cause, left visible for operator recovery.
func (c *ContainerChecker) failRelocationWithoutRuntime(ctx context.Context, ct corrosion.ContainerRecord, proofID string) {
	const detail = "relocation failed: this host has no container runtime (" + corrosion.LabelLXCCapable + "=false)"
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
