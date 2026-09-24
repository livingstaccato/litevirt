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

func opOrder(ops []Op) []string {
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		out = append(out, string(op.Kind)+":"+op.VMName)
	}
	return out
}

// Creates and updates are ordered together by depends-on: a new VM that
// depends on a VM being updated comes after that update, and an update that
// depends on another op comes after it. Among ready ops, name order; no-change
// and delete ops keep their relative place after them.
func TestTopologicalSortOps_CreatesAndUpdatesInterleaveByDependency(t *testing.T) {
	want := []string{
		"create:a", "update:db", "create:app", "update:web-1", "update:web-2",
		"no-change:zz", "delete:old",
	}
	for i := 0; i < 50; i++ {
		ops := []Op{
			{Kind: OpCreate, VMName: "app", DependsOn: DependsOn{"db": {}}},
			{Kind: OpCreate, VMName: "a"},
			{Kind: OpUpdate, VMName: "web-2", DependsOn: DependsOn{"app": {}}},
			{Kind: OpNoChange, VMName: "zz"},
			{Kind: OpUpdate, VMName: "web-1", DependsOn: DependsOn{"app": {}}},
			{Kind: OpUpdate, VMName: "db"},
			{Kind: OpDelete, VMName: "old"},
		}
		if got := opOrder(TopologicalSortOps(ops)); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: op order %v, want %v", i, got, want)
		}
	}
}

func buildOrder(t *testing.T, yml string) []string {
	t.Helper()
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	plan, err := Build(f, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return createOrder(TopologicalSortOps(plan.Ops))
}

// "db" is not "db-backup". Matched by prefix, zapp (depends on db) would also
// depend on db-backup — which depends on zapp: a false cycle, broken by
// falling back to name order, which puts db-backup before zapp.
func TestTopologicalSortOps_PrefixIsNotADependency(t *testing.T) {
	got := buildOrder(t, `name: s
vms:
  db:
    image: i
  zapp:
    image: i
    depends-on: [db]
  db-backup:
    image: i
    depends-on: [zapp]
`)
	if want := []string{"db", "zapp", "db-backup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("create order %v, want %v", got, want)
	}
}

// Replicas are still matched through their compose name.
func TestTopologicalSortOps_ReplicasMatchTheirComposeName(t *testing.T) {
	got := buildOrder(t, `name: s
vms:
  app:
    image: i
    depends-on: [zdb]
  zdb:
    image: i
    replicas: 2
`)
	if want := []string{"zdb-1", "zdb-2", "app"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("create order %v, want %v", got, want)
	}
}
