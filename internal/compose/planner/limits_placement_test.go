package planner

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A cpu cap bounds how much CPU a VM may take, not what it needs to be placed:
// the cap can be raised or removed live, and the VM's vCPUs are scheduled onto
// host cores whatever the cap, so placement and quota charge the full vCPU count.
func TestBuildPlacementRequest_CappedVMNeedsItsFullVCPUs(t *testing.T) {
	req := buildPlacementRequest(&pb.VMSpec{Name: "vm", Cpu: 8, MemoryMib: 1024, CpuLimit: 0.5, CpuShares: 100},
		corrosion.CapacityPolicy{})
	if req.CPUNeeded != 8 {
		t.Errorf("CPUNeeded = %d for an 8-vCPU VM capped at 0.5 cores, want 8", req.CPUNeeded)
	}
}
