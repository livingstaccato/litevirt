package placement

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// lxcHosts: node-1 has the most room, node-2 has less. Each host's
// litevirt.lxc label is the given value; "" leaves the host unlabelled.
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
// affected.
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
}

// Placement is strict: only a host whose label is exactly "true" runs a
// container. A host with no label, or any other value, is refused like one
// labelled "false" — and when no host qualifies the refusal is still
// ErrNoContainerRuntime. A VM is not affected by the label.
//
// Mutation: restore the lenient check (refuse only "false") — the container
// lands on the roomier unlabelled node-1, and the all-unlabelled case places
// it instead of refusing, so this goes red.
func TestSelectBatch_UnlabelledHostRunsNoContainer(t *testing.T) {
	for _, node1 := range []string{"", "yes", "TRUE"} {
		results, err := SelectBatch(lxcHosts(node1, "true"), nil, nil, nil, nil, time.Time{}, []Request{
			{VMName: "ct", Container: true, MemMiBNeeded: 256},
			{VMName: "vm", CPUNeeded: 1, MemMiBNeeded: 256},
		})
		if err != nil {
			t.Fatalf("SelectBatch: %v", err)
		}
		if got := results["ct"].Host; got != "node-2" {
			t.Fatalf("litevirt.lxc=%q: container placed on %q, want node-2", node1, got)
		}
		if got := results["vm"].Host; got != "node-1" {
			t.Fatalf("litevirt.lxc=%q: VM placed on %q, want node-1", node1, got)
		}
	}

	results, err := SelectBatch(lxcHosts("", ""), nil, nil, nil, nil, time.Time{}, []Request{
		{VMName: "ct", Container: true, MemMiBNeeded: 256},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if perr := results["ct"].Err; perr == nil || !errors.Is(perr, ErrNoContainerRuntime) {
		t.Fatalf("no labelled host: got %+v, want an ErrNoContainerRuntime refusal", results["ct"])
	}
	if !strings.Contains(results["ct"].Err.Error(), corrosion.LabelLXCCapable) {
		t.Fatalf("refusal does not name the label: %v", results["ct"].Err)
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
