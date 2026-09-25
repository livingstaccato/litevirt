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
		disks      bool
		want       compose.Action
		wantReason string
		wantRepair bool
	}{
		{"labels", compose.Op{}, VMAction{Plan: compose.ChangePlan{MetadataChanges: []compose.Delta{{Field: "labels"}}}}, true, true, compose.ActionLive, "", false},
		{"no classified change", compose.Op{}, VMAction{}, true, true, compose.ActionLive, "", false},
		{"restart", compose.Op{}, VMAction{Plan: restart}, true, true, compose.ActionRestart, "", false},
		{"not reconfigurable", compose.Op{}, VMAction{Plan: spice}, true, true, compose.ActionRecreate, "not reconfigurable in place", false},
		{"image", compose.Op{}, VMAction{Plan: compose.ChangePlan{RecreateReasons: []string{`image "a"→"b" recreates`}}}, true, true, compose.ActionRecreate, "image", false},
		{"container", compose.Op{}, VMAction{IsContainer: true, Plan: compose.ChangePlan{MetadataChanges: []compose.Delta{{Field: "labels"}}}}, true, true, compose.ActionRecreate, "containers", false},
		{"no stored spec", compose.Op{}, VMAction{}, false, true, compose.ActionRecreate, "stored spec", false},
		{"retry with disks", compose.Op{Retry: true}, VMAction{}, true, true, compose.ActionRestart, "", true},
		{"retry with disks and a live change", compose.Op{Retry: true}, VMAction{Plan: compose.ChangePlan{MetadataChanges: []compose.Delta{{Field: "labels"}}}}, true, true, compose.ActionRestart, "", true},
		{"retry with nothing made", compose.Op{Retry: true}, VMAction{}, true, false, compose.ActionRecreate, "nothing was made", false},
		{"retry with an image change", compose.Op{Retry: true}, VMAction{Plan: compose.ChangePlan{RecreateReasons: []string{`image "a"→"b" recreates`}}}, true, true, compose.ActionRecreate, "image", false},
	}
	for _, c := range cases {
		got, reason, repair := updateMechanism(c.op, c.a, c.stored, c.disks)
		if got != c.want || !strings.Contains(reason, c.wantReason) || repair != c.wantRepair {
			t.Errorf("%s: mechanism %v (%q) repair=%v, want %v (%q) repair=%v", c.name, got, reason, repair, c.want, c.wantReason, c.wantRepair)
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
		{VMAction{Apply: compose.ActionRestart, Retry: true, Repair: true}, "retry — repaired in place, disks kept"},
		{VMAction{Apply: compose.ActionRecreate, Retry: true, RecreateReason: "nothing was made"}, "retry — created again (nothing was made)"},
	} {
		if got := UpdateMechanismText(c.a); !strings.Contains(got, c.want) {
			t.Errorf("UpdateMechanismText(%+v) = %q, want it to contain %q", c.a, got, c.want)
		}
	}
}
