package corrosion

import (
	"encoding/json"
	"slices"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestVMMigratePriority(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want int32
	}{
		{"", 0},
		{"{}", 0},
		{"not json", 0},
		{`{"migrate":{}}`, 0},
		{`{"migrate":null}`, 0},
		{`{"migrate":{"priority":7}}`, 7},
		{`{"migrate":{"priority":-3,"timeout_sec":5}}`, -3},
		// A top-level "priority" is not the migrate policy's.
		{`{"priority":9}`, 0},
	} {
		if got := VMMigratePriority(VMRecord{Name: "v", Spec: tc.spec}); got != tc.want {
			t.Errorf("VMMigratePriority(%q) = %d, want %d", tc.spec, got, tc.want)
		}
	}
}

// TestVMMigratePriority_ReadsTheStoredSpec: the reader agrees with the
// writer. CreateVM stores the spec with encoding/json (grpcapi vm.go), and
// compose fills MigrationPolicy.Priority; a JSON-tag mismatch between the two
// would read every VM as 0 and silently drop all ordering.
func TestVMMigratePriority_ReadsTheStoredSpec(t *testing.T) {
	b, err := json.Marshal(&pb.VMSpec{Name: "v", OnHostFailure: "restart-any",
		Migrate: &pb.MigrationPolicy{Priority: 42, OnHostFailure: pb.HostFailurePolicy_RESTART_SAME}})
	if err != nil {
		t.Fatal(err)
	}
	if got := VMMigratePriority(VMRecord{Name: "v", Spec: string(b)}); got != 42 {
		t.Fatalf("VMMigratePriority(%s) = %d, want 42", b, got)
	}
}

// TestSortVMsByMigratePriority: highest first, and ties by name, whatever
// order they came in (ListVMs returns a replica's insertion order, which is
// not the same on every node).
//
// Mutations: reverse the priority comparison (lowest first) — red; drop the
// name tie-break (return 0) — the ties come back in input order, red; return
// the input unsorted — red.
func TestSortVMsByMigratePriority(t *testing.T) {
	spec := func(p string) string { return `{"migrate":{"priority":` + p + `}}` }
	in := []VMRecord{
		{Name: "d", Spec: ""},
		{Name: "a", Spec: "{}"},
		{Name: "b", Spec: spec("10")},
		{Name: "c", Spec: spec("-1")},
		{Name: "e", Spec: spec("10")},
		{Name: "f", Spec: spec("5")},
	}
	for i := 0; i < 40; i++ {
		in = append(in, VMRecord{Name: "t" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Spec: spec("1")})
	}
	var ties []string
	for _, vm := range in {
		if VMMigratePriority(vm) == 1 {
			ties = append(ties, vm.Name)
		}
	}
	if slices.IsSorted(ties) {
		t.Fatal("setup: the tied VMs must come in out of name order, or the tie-break is untested")
	}
	slices.Sort(ties)
	got := SortVMsByMigratePriority(slices.Clone(in))
	var names []string
	for _, vm := range got {
		names = append(names, vm.Name)
	}
	want := append([]string{"b", "e", "f"}, ties...)
	want = append(want, "a", "d", "c")
	if !slices.Equal(names, want) {
		t.Fatalf("order = %v\nwant    %v", names, want)
	}
}
