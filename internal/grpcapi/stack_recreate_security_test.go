package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/auth"
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

// Recreating a privileged member keeps its privilege only for a caller who
// could create a privileged container (Admin) or holds ct.exec on the member
// being replaced (root in it already). Anyone else is refused, clearly: the
// member is never silently dropped to unprivileged, which would break it.
func TestComposeRecreate_InheritedPrivilegeNeedsExecOrAdmin(t *testing.T) {
	s, rt := secServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "carl", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	for _, r := range []corrosion.RoleRecord{
		{Name: "Builder", Verbs: []string{"ct.create", "ct.delete", "ct.start", "ct.read"}},
		{Name: "Shell", Verbs: []string{"ct.exec"}},
	} {
		if err := corrosion.InsertRole(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "carl-build", Path: "/", Role: "Builder", Principal: "user:carl@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine(s.db)
	reload := func() {
		if err := engine.Reload(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reload()
	s.SetAuthEngine(engine)
	carl := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "carl"), ctxKeyRole, "viewer")

	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine"})
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	// Refused before the delete: the member stays, untouched.
	err := s.deleteWorkload(carl, upd)
	if err == nil || !strings.Contains(err.Error(), "privileged") || !strings.Contains(err.Error(), "ct.exec") {
		t.Fatalf("recreate by a caller without ct.exec: %v", err)
	}
	if len(rt.deleteCalls) != 0 {
		t.Fatalf("the member was deleted: %v", rt.deleteCalls)
	}
	if row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "web"); row == nil {
		t.Fatal("the member's row is gone")
	}

	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "carl-shell", Path: "/projects/acme/containers/web", Role: "Shell", Principal: "user:carl@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	reload()
	if err := s.deleteWorkload(carl, upd); err != nil {
		t.Fatal(err)
	}
	if err := s.deployCreatePlanned(carl, upd, f); err != nil {
		t.Fatalf("recreate by a caller with ct.exec on the member: %v", err)
	}
	if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase != 0 {
		t.Fatalf("recreated as %+v, want privileged", last)
	}
}
