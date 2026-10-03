package placement

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// lxcHosts: node-1 has the most room but no container runtime (the daemon
// wrote litevirt.lxc=false), node-2 has one, node-3 never recorded either
// way (a build that predates the label).
func lxcHosts(node1, node2 string) []corrosion.HostRecord {
	hosts := makeHostsWithResources([]struct {
		name string
		cpu  int
		mem  int
	}{{"node-1", 16, 65536}, {"node-2", 4, 4096}})
	if node1 != "" {
		hosts[0].Labels = map[string]string{corrosion.LabelLXCCapable: node1}
	}
	if node2 != "" {
		hosts[1].Labels = map[string]string{corrosion.LabelLXCCapable: node2}
	}
	return hosts
}

// A container is never placed on a host whose daemon recorded it has no
// container runtime. Drill D3 (main-8d1e56dc) relocated blct to node-3, which
// has no LXC, and node-3 retried "lxc-create not found" forever. A VM is not
// affected, and a host that never recorded the label is not refused on it.
//
// Mutation: drop the container-runtime filter — the container lands on node-1
// and this goes red.
func TestSelectBatch_ContainerNeedsAContainerRuntime(t *testing.T) {
	results, err := SelectBatch(lxcHosts("false", "true"), nil, nil, nil, nil, time.Time{}, []Request{
		{VMName: "ct", Container: true, MemMiBNeeded: 256},
		{VMName: "vm", CPUNeeded: 1, MemMiBNeeded: 256},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if got := results["ct"].Host; got != "node-2" {
		t.Fatalf("container placed on %q, want node-2 (node-1 has no container runtime)", got)
	}
	if got := results["vm"].Host; got != "node-1" {
		t.Fatalf("VM placed on %q, want node-1: the container-runtime filter must not touch VMs", got)
	}

	results, err = SelectBatch(lxcHosts("false", ""), nil, nil, nil, nil, time.Time{}, []Request{
		{VMName: "ct", Container: true, MemMiBNeeded: 256},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if got := results["ct"].Host; got != "node-2" {
		t.Fatalf("container placed on %q, want node-2 (no label recorded is not a refusal)", got)
	}
}

// With no active host that has a container runtime, the refusal says so, and
// callers can tell it apart from a capacity shortfall.
//
// Mutation: leave NoContainerRuntime unset — errors.Is fails and this goes red.
func TestSelectBatch_NoContainerRuntimeAnywhereIsNamed(t *testing.T) {
	results, err := SelectBatch(lxcHosts("false", "false"), nil, nil, nil, nil, time.Time{}, []Request{
		{VMName: "ct", Container: true, MemMiBNeeded: 256},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	perr := results["ct"].Err
	if perr == nil || results["ct"].Host != "" {
		t.Fatalf("container placed with no container runtime anywhere: %+v", results["ct"])
	}
	if !errors.Is(perr, ErrNoContainerRuntime) || !errors.Is(perr, ErrNoEligibleHost) {
		t.Fatalf("refusal %v is not ErrNoContainerRuntime and ErrNoEligibleHost", perr)
	}
	if !strings.Contains(perr.Error(), "container runtime") {
		t.Fatalf("refusal does not name the missing container runtime: %v", perr)
	}

	// One host short of memory, one without a runtime: a capacity shortfall,
	// not the runtime refusal.
	results, _ = SelectBatch(lxcHosts("false", "true"), nil, nil, nil, nil, time.Time{}, []Request{
		{VMName: "ct", Container: true, MemMiBNeeded: 8192},
	})
	if perr := results["ct"].Err; perr == nil || errors.Is(perr, ErrNoContainerRuntime) {
		t.Fatalf("a capacity shortfall on the only container host read as %v", perr)
	}
}
