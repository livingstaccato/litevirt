package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// A compose recreate of a stack container (an image or cpu change) keeps the
// container's current privilege and confinement: a main-era member, which is
// privileged with legacy confinement, comes back the same, also for a
// non-admin deployer. A brand-new member gets the defaults.
func TestComposeRecreate_KeepsTheMembersSecurity(t *testing.T) {
	s, rt := secServer(t)
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{
		"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.21", CPU: 2},
		"new": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.21"},
	}}
	// web was deployed by main: no security recorded.
	seedSecCT(t, s, rt, "web", "running", corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine"})
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "running", Labels: map[string]string{corrosion.LabelStack: "st"},
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine"}),
	}); err != nil {
		t.Fatal(err)
	}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := s.deleteWorkload(ctOperatorCtx(), upd); err != nil {
		t.Fatal(err)
	}
	if err := s.deployCreatePlanned(ctOperatorCtx(), upd, f); err != nil {
		t.Fatalf("operator recreate of a main-era member: %v", err)
	}
	last := rt.createCalls[len(rt.createCalls)-1]
	if last.IDMapBase != 0 || last.Confinement != lxc.ConfinementLegacy {
		t.Fatalf("recreated as %+v, want privileged legacy as before", last)
	}

	if err := s.deployCreatePlanned(ctOperatorCtx(), planner.VMAction{Kind: planner.OpCreate, VMName: "new", TargetHost: "host-a", IsContainer: true}, f); err != nil {
		t.Fatal(err)
	}
	last = rt.createCalls[len(rt.createCalls)-1]
	if last.IDMapBase == 0 || last.Confinement != lxc.ConfinementDefault {
		t.Fatalf("a new member was created as %+v, want the defaults", last)
	}
}
