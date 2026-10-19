package planner

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A compose Secure Boot / vTPM VM is placed only on a host that advertises
// the capability, as CreateVM's own placement requires
// (grpcapi.addCapabilityLabels), and the file's own require map is not
// written to.
//
// Mutation: drop the capability labels from buildPlacementRequest — red.
func TestBuildPlacementRequest_FirmwareVMRequiresTheCapabilityLabels(t *testing.T) {
	require := map[string]string{"zone": "a"}
	req := buildPlacementRequest(&pb.VMSpec{Name: "vm", Cpu: 1, MemoryMib: 512, SecureBoot: true, Tpm: true,
		Placement: &pb.PlacementSpec{Require: require}}, corrosion.CapacityPolicy{})
	for _, k := range []string{corrosion.LabelSecureBootCapable, corrosion.LabelTPMCapable} {
		if req.RequireLabels[k] != "true" {
			t.Errorf("RequireLabels[%s] = %q, want true (labels %v)", k, req.RequireLabels[k], req.RequireLabels)
		}
	}
	if req.RequireLabels["zone"] != "a" {
		t.Errorf("the file's own require label was lost: %v", req.RequireLabels)
	}
	if len(require) != 1 {
		t.Errorf("the compose file's require map was written to: %v", require)
	}
	plain := buildPlacementRequest(&pb.VMSpec{Name: "p", Cpu: 1, MemoryMib: 512}, corrosion.CapacityPolicy{})
	if len(plain.RequireLabels) != 0 {
		t.Errorf("a plain VM requires %v", plain.RequireLabels)
	}
}
