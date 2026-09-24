package planner

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// Each update is applied with the least destructive mechanism the change
// allows; a recreate says why the workload cannot be kept.
func TestUpdateMechanism(t *testing.T) {
	restart := compose.ChangePlan{RestartReasons: []string{"cpu shrink 2→1 needs a restart"}}
	spice := compose.ChangePlan{
		RestartReasons:    []string{"graphics (spice) change needs a redefine"},
		NotReconfigurable: []string{"graphics (spice) change needs a redefine"},
	}
	cases := []struct {
		name       string
		op         compose.Op
		a          VMAction
		stored     bool
		want       compose.Action
		wantReason string
	}{
		{"labels", compose.Op{}, VMAction{Plan: compose.ChangePlan{MetadataChanges: []compose.Delta{{Field: "labels"}}}}, true, compose.ActionLive, ""},
		{"no classified change", compose.Op{}, VMAction{}, true, compose.ActionLive, ""},
		{"restart", compose.Op{}, VMAction{Plan: restart}, true, compose.ActionRestart, ""},
		{"not reconfigurable", compose.Op{}, VMAction{Plan: spice}, true, compose.ActionRecreate, "not reconfigurable in place"},
		{"image", compose.Op{}, VMAction{Plan: compose.ChangePlan{RecreateReasons: []string{`image "a"→"b" recreates`}}}, true, compose.ActionRecreate, "image"},
		{"container", compose.Op{}, VMAction{IsContainer: true, Plan: compose.ChangePlan{MetadataChanges: []compose.Delta{{Field: "labels"}}}}, true, compose.ActionRecreate, "containers"},
		{"retry", compose.Op{Retry: true, Detail: "retry db (was state=error)"}, VMAction{}, true, compose.ActionRecreate, "did not finish"},
		{"no stored spec", compose.Op{}, VMAction{}, false, compose.ActionRecreate, "stored spec"},
	}
	for _, c := range cases {
		got, reason := updateMechanism(c.op, c.a, c.stored)
		if got != c.want || !strings.Contains(reason, c.wantReason) {
			t.Errorf("%s: mechanism %v (%q), want %v (%q)", c.name, got, reason, c.want, c.wantReason)
		}
	}
}

func TestUpdateMechanismText(t *testing.T) {
	for _, c := range []struct {
		a    VMAction
		want string
	}{
		{VMAction{Apply: compose.ActionLive}, "in place, no restart"},
		{VMAction{Apply: compose.ActionRestart}, "disks kept"},
		{VMAction{Apply: compose.ActionRecreate, RecreateReason: "image"}, "recreate — disks are replaced (image)"},
		{VMAction{Apply: compose.ActionRecreate, IsContainer: true, RecreateReason: "x"}, "recreate — the container is replaced"},
	} {
		if got := UpdateMechanismText(c.a); !strings.Contains(got, c.want) {
			t.Errorf("UpdateMechanismText(%+v) = %q, want it to contain %q", c.a, got, c.want)
		}
	}
}
