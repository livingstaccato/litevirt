package planner

import (
	"fmt"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// NameCollisions lists every planned create whose name is already taken by a
// workload that does not belong to the plan's stack, one message per create.
//
// The planner diffs a stack against its OWN workloads only, so a name another
// stack (or no stack) holds reads as "not there yet" and plans a create — which
// then fails at create time with AlreadyExists, after the actions ahead of it
// have run. A workload of the same stack never collides: it is diffed as an
// update or no-change, never a create.
//
// The name spaces match what CreateVM and CreateContainer refuse: a VM name is
// cluster-wide (vms is keyed by name), a container name is per host (containers
// is keyed by host and name), so a container create collides only with a
// container on the host it is placed on. VMs and containers do not share a
// name space.
func NameCollisions(plan *ResolvedPlan, state *ClusterState) []string {
	vmStack := make(map[string]string, len(state.VMs))
	for _, vm := range state.VMs {
		vmStack[vm.Name] = vm.StackName
	}
	type hostName struct{ host, name string }
	ctStack := make(map[hostName]string, len(state.Containers))
	for _, ct := range state.Containers {
		ctStack[hostName{ct.HostName, ct.Name}] = ct.Labels[corrosion.LabelStack]
	}

	var out []string
	for _, a := range plan.VMs {
		if a.Kind != OpCreate {
			continue
		}
		if a.IsContainer {
			owner, ok := ctStack[hostName{a.TargetHost, a.VMName}]
			if ok && owner != plan.StackName {
				out = append(out, compose.NameCollision(
					fmt.Sprintf("container %q already exists on host %q", a.VMName, a.TargetHost), owner))
			}
			continue
		}
		if owner, ok := vmStack[a.VMName]; ok && owner != plan.StackName {
			out = append(out, compose.NameCollision(fmt.Sprintf("vm %q already exists", a.VMName), owner))
		}
	}
	return out
}
