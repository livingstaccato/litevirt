package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A compose container's `cpu: N` is a cap of N cores. It was written into
// cpu.max as N*1000 per 100000 period — N/100 of a core — so `cpu: 2` capped the
// container at 2% of one core while its shares, the project vCPU quota and host
// pressure all read it as 2 cores.
const composeContainerCPU = `name: ctcpu

workloads:
  ct:
    kind: lxc
    image: alpine:3.21
    cpu: 2
    memory: 256
    placement:
      host: node-0
`

func TestFleet_ComposeContainerCPUIsCores(t *testing.T) {
	node, client := newContainerComposeNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, composeContainerCPU)

	rec, err := corrosion.GetContainer(ctx, node.DB, node.Name, "ct")
	if err != nil || rec == nil || rec.CPULimit != 2 {
		t.Fatalf("container ct = %+v err=%v, want cpu_limit 2 (cores)", rec, err)
	}
	cfg := node.CT.CgroupConfig("ct")
	for _, want := range []string{"lxc.cgroup2.cpu.max = 200000 100000\n", "lxc.cgroup.cpu.shares = 2048\n"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("cgroup config for cpu 2 =\n%s\nwant %q", cfg, want)
		}
	}
	// The runtime reads back the limit the row records, in the same unit.
	if cpu, _, err := node.CT.ContainerLimits(ctx, "ct"); err != nil || cpu != 2 {
		t.Errorf("runtime cpu limit = %d (err %v), want 2 cores", cpu, err)
	}
}
