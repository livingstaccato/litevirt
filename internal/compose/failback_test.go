package compose

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// placement.failback opts a VM in to returning after maintenance: it parses,
// it inherits down the scope chain like the other hard fields, and it reaches
// the stored spec the daemon reads.
//
// Mutation: drop `Failback: eff.Failback` from BuildVMSpec — the spec check
// fails; drop the merge clause — the inherited check fails.
func TestPlacementFailback_ParsesInheritsAndReachesTheSpec(t *testing.T) {
	var p PlacementDef
	if err := yaml.Unmarshal([]byte("failback: true\n"), &p); err != nil || !p.Failback {
		t.Fatalf("failback did not parse: %+v err=%v", p, err)
	}

	merged := MergePlacement(&PlacementDef{Failback: true}, &PlacementDef{Policy: "balance"})
	if merged == nil || !merged.Failback {
		t.Fatalf("a stack-level failback was not inherited by the VM: %+v", merged)
	}
	if m := MergePlacement(&PlacementDef{Policy: "balance"}, &PlacementDef{Failback: true}); m == nil || !m.Failback {
		t.Fatalf("a VM's own failback was lost in the merge: %+v", m)
	}
	if m := MergePlacement(&PlacementDef{}, &PlacementDef{Policy: "balance"}); m.Failback {
		t.Fatal("failback appeared from nowhere")
	}

	f := baseFile("web", nil)
	spec := mustBuildVMSpec(t, "web", "web", &VMDef{Image: "ubuntu", Placement: &PlacementDef{Failback: true}}, f)
	if spec.GetPlacement().GetFailback() != true {
		t.Fatalf("spec placement = %+v, want failback", spec.GetPlacement())
	}
	spec = mustBuildVMSpec(t, "web", "web", &VMDef{Image: "ubuntu", Placement: &PlacementDef{Policy: "balance"}}, f)
	if spec.GetPlacement().GetFailback() {
		t.Fatal("a VM that did not opt in carries failback")
	}
}
