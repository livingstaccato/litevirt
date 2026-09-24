package compose

import (
	"reflect"
	"testing"
)

func createOrder(ops []Op) []string {
	var out []string
	for _, op := range ops {
		if op.Kind == OpCreate {
			out = append(out, op.VMName)
		}
	}
	return out
}

// A deploy of the same compose file must create its VMs in the same order
// every time. The order came from Go map iteration (the file's VM map, then
// Kahn's queue seeded from a map), so independent VMs were created in a
// different order on each run: the deploy's output and its partial-failure
// shape changed between runs of an unchanged file, and a fleet test that held
// one VM's create deadlocked whenever that VM came first.
func TestTopologicalSortOps_IndependentCreatesAreInNameOrder(t *testing.T) {
	want := []string{"a", "b", "c", "d", "e", "f"}
	for i := 0; i < 50; i++ {
		ops := []Op{{Kind: OpCreate, VMName: "e"}, {Kind: OpCreate, VMName: "b"}, {Kind: OpCreate, VMName: "f"},
			{Kind: OpCreate, VMName: "a"}, {Kind: OpCreate, VMName: "d"}, {Kind: OpCreate, VMName: "c"}}
		if got := createOrder(TopologicalSortOps(ops)); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: create order %v, want %v", i, got, want)
		}
	}
}

// Dependencies still come first; among VMs ready at the same time, name order.
func TestTopologicalSortOps_DependenciesFirstThenNameOrder(t *testing.T) {
	want := []string{"db", "cache", "web-1", "web-2"}
	for i := 0; i < 50; i++ {
		ops := []Op{
			{Kind: OpCreate, VMName: "web-2", DependsOn: DependsOn{"db": {}}},
			{Kind: OpCreate, VMName: "web-1", DependsOn: DependsOn{"db": {}}},
			{Kind: OpCreate, VMName: "db"},
			{Kind: OpCreate, VMName: "cache", DependsOn: DependsOn{"db": {}}},
		}
		if got := createOrder(TopologicalSortOps(ops)); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: create order %v, want %v", i, got, want)
		}
	}
}

// End to end through Build: an unchanged file yields the same op order.
func TestBuild_OpOrderIsStableAcrossRuns(t *testing.T) {
	f := makeFile("s", map[string]VMDef{
		"alpha": {Image: "i", CPU: 1, Memory: 512}, "bravo": {Image: "i", CPU: 1, Memory: 512},
		"charlie": {Image: "i", CPU: 1, Memory: 512}, "delta": {Image: "i", CPU: 1, Memory: 512},
		"echo": {Image: "i", CPU: 1, Memory: 512},
	})
	var first []string
	for i := 0; i < 50; i++ {
		plan, err := Build(f, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := createOrder(plan.Ops)
		if i == 0 {
			first = got
			continue
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d: op order %v differs from run 0 %v", i, got, first)
		}
	}
}
