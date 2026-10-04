package scheduler

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestResolveVMPolicy_LegacyOnDemandReadsAsDryRun: a vms.spec written before
// on-demand was removed (or by an older node mid rolling upgrade, whose
// ha-critical preset still expands to it) must resolve to dry-run.
func TestResolveVMPolicy_LegacyOnDemandReadsAsDryRun(t *testing.T) {
	spec := &pb.VMSpec{Placement: &pb.PlacementSpec{
		Policy:    "spread-strict",
		Rebalance: &pb.RebalanceSpec{Mode: "on-demand"},
	}}
	if got := resolveVMPolicyFromSpec(spec).Mode; got != ModeDryRun {
		t.Errorf("Mode = %q, want %q", got, ModeDryRun)
	}
}
