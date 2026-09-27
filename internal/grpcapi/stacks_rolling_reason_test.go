package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The planner's reason a VM cannot be kept reaches the rolling engine, so an
// in-place refusal names it rather than "spec change".
func TestExecuteWithRollingUpdates_InPlaceRefusalNamesThePlannersReason(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "web", &pb.VMSpec{Name: "web", Cpu: 2, MaxCpu: 8, MemoryMib: 2048}, 2, 2048)

	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 2, Update: &compose.UpdateDef{Strategy: "in-place"}},
	}}
	const reason = "the VM's stored spec could not be read"
	resolved := &planner.ResolvedPlan{StackName: "st", VMs: []planner.VMAction{{
		Kind: planner.OpUpdate, VMName: "web", TargetHost: "test-host",
		Spec:  &pb.VMSpec{Name: "web", Cpu: 2, Image: "ubuntu"},
		Apply: compose.ActionRecreate, RecreateReason: reason,
	}}}
	stream := &progressStream[pb.DeployProgress]{ctx: ctx}

	err := s.executeWithRollingUpdates(ctx, f, resolved, stream, newDeployFailures(stream))
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Errorf("err = %v, want the in-place refusal to name %q", err, reason)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("VM was deleted by a refused in-place update")
	}
}
