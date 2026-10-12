package health

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestWalkOrder_PriorityWithinDeferralRank: the reconcile walk starts the
// deferred VMs first, by rank, as before; within each group, and among the
// VMs that were not deferred, the highest compose migrate.priority goes first
// and ties go by name. A deferral still outranks priority: a VM deferred for
// time never had its turn, and must not be starved by a busier host's
// higher-priority arrivals.
//
// Mutations: walk deferredFirst(vms) without the priority sort — the
// not-deferred group comes back in input order, red; sort AFTER
// deferredFirst — "hi-fresh" overtakes the deferred "lo-time", red.
func TestWalkOrder_PriorityWithinDeferralRank(t *testing.T) {
	prio := func(p string) string { return `{"migrate":{"priority":` + p + `}}` }
	in := []corrosion.VMRecord{
		{Name: "b-zero", Spec: "{}"},
		{Name: "lo-probe", Spec: prio("1")},
		{Name: "a-zero", Spec: ""},
		{Name: "hi-fresh", Spec: prio("50")},
		{Name: "lo-time", Spec: prio("2")},
		{Name: "hi-time", Spec: prio("9")},
		{Name: "mid-fresh", Spec: prio("10")},
	}
	deferred := map[string]int{
		"lo-time":  rankTime,
		"hi-time":  rankTime,
		"lo-probe": rankProbeFailed,
	}
	var got []string
	for _, vm := range walkOrder(slices.Clone(in), deferred) {
		got = append(got, vm.Name)
	}
	want := []string{"hi-time", "lo-time", "lo-probe", "hi-fresh", "mid-fresh", "a-zero", "b-zero"}
	if !slices.Equal(got, want) {
		t.Fatalf("walk order = %v\nwant         %v", got, want)
	}

	// No deferrals: priority alone.
	got = got[:0]
	for _, vm := range walkOrder(slices.Clone(in), nil) {
		got = append(got, vm.Name)
	}
	want = []string{"hi-fresh", "mid-fresh", "hi-time", "lo-time", "lo-probe", "a-zero", "b-zero"}
	if !slices.Equal(got, want) {
		t.Fatalf("walk order with nothing deferred = %v\nwant                              %v", got, want)
	}
}
