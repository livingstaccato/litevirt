package planner

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// lxcHost is a makeHost that advertises the LXC capability label.
func lxcHost(name string, cpu, memMiB int) corrosion.HostRecord {
	h := makeHost(name, cpu, memMiB)
	h.Labels = map[string]string{corrosion.LabelLXCCapable: "true"}
	return h
}

func ctFile() *compose.File {
	return makeFile("mystack", map[string]compose.VMDef{
		"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.21", CPU: 1, Memory: 256},
	})
}

func stackContainer(host string) corrosion.ContainerRecord {
	return corrosion.ContainerRecord{
		HostName: host, Name: "web", State: "running",
		Image: "alpine:3.21", CPULimit: 1, MemMiB: 256,
		Labels: map[string]string{corrosion.LabelStack: "mystack"},
	}
}

func ctAction(plan *ResolvedPlan, name string) *VMAction {
	for i := range plan.VMs {
		if plan.VMs[i].VMName == name {
			return &plan.VMs[i]
		}
	}
	return nil
}

// A new container is placed only on an LXC-capable host — even when a
// bigger non-LXC host would otherwise win on resources.
func TestResolve_ContainerPlacedOnLXCHostOnly(t *testing.T) {
	state := makeState(
		[]corrosion.HostRecord{
			makeHost("big-novm", 128, 262144), // more resources, but NOT LXC-capable
			lxcHost("lxc1", 8, 8192),          // smaller, but LXC-capable
		}, nil, nil)

	plan, err := Resolve(context.Background(), ctFile(), state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	a := ctAction(plan, "web")
	if a == nil || a.Kind != OpCreate {
		t.Fatalf("expected OpCreate for web, got %+v", a)
	}
	if !a.IsContainer {
		t.Error("web should be marked IsContainer")
	}
	if a.TargetHost != "lxc1" {
		t.Errorf("container placed on %q, want lxc1 (the only LXC-capable host)", a.TargetHost)
	}
}

// With no LXC-capable host, container placement fails rather than landing on a
// host that can't run it (the live-test gap: it was placed on a non-LXC node).
func TestResolve_ContainerNoLXCHostFails(t *testing.T) {
	state := makeState([]corrosion.HostRecord{makeHost("h1", 64, 65536)}, nil, nil)
	if _, err := Resolve(context.Background(), ctFile(), state); err == nil {
		t.Fatal("expected placement failure when no host is LXC-capable")
	}
}

// Re-applying an unchanged stack is idempotent: an existing matching container
// diffs to OpNoChange, not OpCreate (the live-test "already exists" gap).
func TestResolve_ContainerIdempotentNoChange(t *testing.T) {
	state := makeState([]corrosion.HostRecord{lxcHost("lxc1", 8, 8192)}, nil, nil)
	state.Containers = []corrosion.ContainerRecord{stackContainer("lxc1")}

	plan, err := Resolve(context.Background(), ctFile(), state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	a := ctAction(plan, "web")
	if a == nil || a.Kind != OpNoChange {
		t.Fatalf("re-apply of unchanged container: got %+v, want OpNoChange", a)
	}
	if !a.IsContainer {
		t.Error("web should be marked IsContainer")
	}
}

// A spec change (cpu) on an existing container is an OpUpdate (recreate),
// pinned to the container's current host, marked IsContainer.
func TestResolve_ContainerUpdate(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.21", CPU: 2, Memory: 256}, // cpu 1→2
	})
	state := makeState([]corrosion.HostRecord{lxcHost("lxc1", 8, 8192)}, nil, nil)
	state.Containers = []corrosion.ContainerRecord{stackContainer("lxc1")} // cpu=1

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	a := ctAction(plan, "web")
	if a == nil || a.Kind != OpUpdate {
		t.Fatalf("container cpu change: got %+v, want OpUpdate", a)
	}
	if !a.IsContainer || a.TargetHost != "lxc1" {
		t.Errorf("update should be IsContainer pinned to lxc1, got isCT=%v host=%q", a.IsContainer, a.TargetHost)
	}
}

// A container present in the stack but removed from the compose file diffs to
// OpDelete, IsContainer, pinned to its current host (so the executor's
// DeleteContainer targets the right node).
func TestResolve_ContainerDelete(t *testing.T) {
	// Compose file declares NO containers (web removed); only a VM remains.
	f := makeFile("mystack", map[string]compose.VMDef{})
	state := makeState([]corrosion.HostRecord{lxcHost("lxc1", 8, 8192)}, nil, nil)
	state.Containers = []corrosion.ContainerRecord{stackContainer("lxc1")}

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	a := ctAction(plan, "web")
	if a == nil || a.Kind != OpDelete {
		t.Fatalf("removed container: got %+v, want OpDelete", a)
	}
	if !a.IsContainer || a.TargetHost != "lxc1" {
		t.Errorf("delete should be IsContainer pinned to lxc1, got isCT=%v host=%q", a.IsContainer, a.TargetHost)
	}
}

// A container tagged to a DIFFERENT stack must not appear in this stack's plan.
func TestResolve_ContainerOtherStackIgnored(t *testing.T) {
	state := makeState([]corrosion.HostRecord{lxcHost("lxc1", 8, 8192)}, nil, nil)
	other := stackContainer("lxc1")
	other.Name = "web"
	other.Labels = map[string]string{corrosion.LabelStack: "different-stack"}
	state.Containers = []corrosion.ContainerRecord{other}

	plan, err := Resolve(context.Background(), ctFile(), state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// web is a fresh create for mystack (the other-stack container is not its current state).
	a := ctAction(plan, "web")
	if a == nil || a.Kind != OpCreate {
		t.Fatalf("other-stack container must be ignored; web should be OpCreate, got %+v", a)
	}
}
