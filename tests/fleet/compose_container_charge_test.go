package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A compose container is charged what it uses: its memory limit, with no qemu
// overhead, and no host vCPU for its cpu figure — the same rule host admission
// applies when the container is created. The planner used to place it like a
// VM, so a container the host would admit could not even be planned.
const composeBigContainer = `name: ctc

workloads:
  ct:
    kind: lxc
    image: alpine:3.21
    cpu: 8
    memory: 3000
    placement:
      host: node-0
`

func TestFleet_ComposeContainerIsChargedMemoryOnly(t *testing.T) {
	node, client := newContainerComposeNode(t)
	ctx := context.Background()
	// 1 vCPU / 4096 MiB → 3 allocatable vCPU and 3072 allocatable MiB under the
	// default policy: cpu 8 fits only uncharged, 3000 MiB only without +128.
	if err := node.DB.Execute(ctx, `UPDATE hosts SET cpu_total = 1, mem_total = 4096 WHERE name = ?`, node.Name); err != nil {
		t.Fatalf("size host: %v", err)
	}
	deployClean(t, ctx, client, composeBigContainer)
	rec, err := corrosion.GetContainer(ctx, node.DB, node.Name, "ct")
	if err != nil || rec == nil || rec.State != "running" || rec.MemMiB != 3000 {
		t.Fatalf("container ct = %+v err=%v, want running with 3000 MiB on %s", rec, err, node.Name)
	}
}
