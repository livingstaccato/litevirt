package grpcapi

import (
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
)

// Failed replicas are updated first (#32), but never ahead of what they
// depend on: the priority only chooses among actions that are ready. Deletes
// and no-change actions keep their slots.
func TestSortVMActions_FailedFirstWithoutBreakingDependencyOrder(t *testing.T) {
	actions := []planner.VMAction{
		{Kind: planner.OpCreate, VMName: "a"},
		{Kind: planner.OpUpdate, VMName: "db"},
		{Kind: planner.OpCreate, VMName: "app", DependsOn: compose.DependsOn{"db": {}}},
		{Kind: planner.OpUpdate, VMName: "web", DependsOn: compose.DependsOn{"app": {}}},
		{Kind: planner.OpUpdate, VMName: "zz"},
		{Kind: planner.OpNoChange, VMName: "keep"},
		{Kind: planner.OpDelete, VMName: "old"},
	}
	current := []compose.CurrentVM{
		{Name: "db", State: "running"},
		{Name: "web", State: "error"},
		{Name: "zz", State: "error"},
	}
	sortVMActions(actions, current)
	var got []string
	for _, a := range actions {
		got = append(got, a.VMName)
	}
	want := []string{"zz", "a", "db", "app", "web", "keep", "old"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}
