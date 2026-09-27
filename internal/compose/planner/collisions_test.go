package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func resolveCollisions(t *testing.T, f *compose.File, state *ClusterState) []string {
	t.Helper()
	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return NameCollisions(plan, state)
}

// A VM outside any stack holds its name cluster-wide as firmly as one in a
// stack does, and the refusal says where it lives.
func TestNameCollisions_VMOutsideAnyStack(t *testing.T) {
	state := makeState([]corrosion.HostRecord{makeHost("h1", 64, 65536)},
		[]corrosion.VMRecord{{Name: "db", HostName: "h1", State: "running"}}, nil)
	f := makeFile("app", map[string]compose.VMDef{
		"db": {Image: "img", CPU: 1, Memory: 512},
	})
	got := resolveCollisions(t, f, state)
	want := `vm "db" already exists outside any stack — rename it in this file or delete it there`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("collisions = %q, want [%q]", got, want)
	}
}

// A VM of the plan's own stack is an update, never a collision.
func TestNameCollisions_SameStackVMIsNotACollision(t *testing.T) {
	state := makeState([]corrosion.HostRecord{makeHost("h1", 64, 65536)},
		[]corrosion.VMRecord{{Name: "db", HostName: "h1", State: "running", StackName: "app"}}, nil)
	f := makeFile("app", map[string]compose.VMDef{
		"db": {Image: "img", CPU: 1, Memory: 512},
	})
	if got := resolveCollisions(t, f, state); len(got) != 0 {
		t.Fatalf("same-stack VM reported as a collision: %q", got)
	}
}

// Even a create — however the diff came to plan one — never collides with a
// workload of its own stack; only another owner's name is refused.
func TestNameCollisions_CreateOverOwnStackWorkloadIsNotRefused(t *testing.T) {
	state := makeState(nil, []corrosion.VMRecord{{Name: "db", StackName: "app"}}, nil)
	state.Containers = []corrosion.ContainerRecord{{HostName: "h1", Name: "web",
		Labels: map[string]string{corrosion.LabelStack: "app"}}}
	plan := &ResolvedPlan{StackName: "app", VMs: []VMAction{
		{Kind: OpCreate, VMName: "db", TargetHost: "h1"},
		{Kind: OpCreate, VMName: "web", TargetHost: "h1", IsContainer: true},
	}}
	if got := NameCollisions(plan, state); len(got) != 0 {
		t.Fatalf("own-stack workloads reported as collisions: %q", got)
	}
	plan.StackName = "app_v2"
	if got := NameCollisions(plan, state); len(got) != 2 {
		t.Fatalf("another stack's workloads: collisions = %q, want both", got)
	}
}

// Container names are per host, as CreateContainer checks them: another
// stack's container of the same name collides only on the host this one lands
// on, and a VM of that name does not collide with a container at all.
func TestNameCollisions_ContainerIsPerHost(t *testing.T) {
	other := func(host string) corrosion.ContainerRecord {
		ct := stackContainer(host)
		ct.Labels = map[string]string{corrosion.LabelStack: "other"}
		return ct
	}

	state := makeState([]corrosion.HostRecord{lxcHost("lxc1", 8, 8192)}, nil, nil)
	state.Containers = []corrosion.ContainerRecord{other("lxc1")}
	got := resolveCollisions(t, ctFile(), state)
	want := `container "web" already exists on host "lxc1" in stack "other" — rename it in this file or delete it there`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("same-host collisions = %q, want [%q]", got, want)
	}

	state = makeState([]corrosion.HostRecord{lxcHost("lxc1", 8, 8192), makeHost("vmonly", 8, 8192)},
		[]corrosion.VMRecord{{Name: "web", HostName: "vmonly", State: "running", StackName: "other"}}, nil)
	state.Containers = []corrosion.ContainerRecord{other("elsewhere")}
	if got := resolveCollisions(t, ctFile(), state); len(got) != 0 {
		t.Fatalf("container on another host / a VM of the name reported as a collision: %q", strings.Join(got, "; "))
	}
}
