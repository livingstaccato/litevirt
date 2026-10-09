package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	if err := recreateMember(ctOperatorCtx(), s, upd, f); err != nil {
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

// carlCtx is a non-admin deployer who may create and delete containers
// (Builder at /) but holds no ct.exec anywhere.
func carlCtx(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "carl", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRole(ctx, s.db, corrosion.RoleRecord{
		Name: "Builder", Verbs: []string{"ct.create", "ct.delete", "ct.start", "ct.read"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "carl-build", Path: "/", Role: "Builder", Principal: "user:carl@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	return context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "carl"), ctxKeyRole, "viewer")
}

// recreateMember runs a compose recreate of one container member the way the
// deploy executor does (recreateInline: judge, delete, create).
func recreateMember(ctx context.Context, s *Server, a planner.VMAction, f *compose.File) error {
	return s.recreateInline(ctx, a, f, newDependsOnGate(s, f, []planner.VMAction{a}, nil))
}

// seedMember records stack member web as a main-era container: privileged,
// legacy, created from the LXC download template alpine:<release>.
func seedMember(t *testing.T, s *Server, rt *fakeCTRuntime, release string) {
	t.Helper()
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "stopped", Project: "acme", Image: "alpine:" + release,
		Labels: map[string]string{corrosion.LabelStack: "st"},
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Template: "download", Distro: "alpine", Release: release, Arch: "amd64"}),
	}); err != nil {
		t.Fatal(err)
	}
}

func memberExists(t *testing.T, s *Server, rt *fakeCTRuntime) {
	t.Helper()
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "web"); row == nil {
		t.Fatal("the member's row is gone: a refused recreate deleted it")
	}
	if len(rt.deleteCalls) != 0 {
		t.Fatalf("the member was deleted: %v", rt.deleteCalls)
	}
}

// Recreating an existing privileged member with the SAME image keeps its
// privilege for whoever may deploy the stack, as on main, where every
// member was privileged (final review M5, owner ruling on R1-2): a cpu or
// memory change must not be refused, and dropping the member to
// unprivileged would break its workload. For a non-Admin the carry-over is
// recorded, after the create, as an audit event and a WARN naming the
// remedy. A stack file that states the mode the member already has keeps
// it too.
func TestComposeRecreate_SameImageKeepsAPrivilegedMemberForADeployer(t *testing.T) {
	for _, tc := range []struct {
		name string
		def  compose.VMDef
	}{
		{"mode not stated", compose.VMDef{Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", CPU: 4}},
		{"privileged stated", compose.VMDef{Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", CPU: 4, Privileged: true, Confinement: lxc.ConfinementLegacy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			s, rt := secServer(t)
			carl := carlCtx(t, s)
			seedMember(t, s, rt, "3.22")
			f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": tc.def}}
			upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
			if err := recreateMember(carl, s, upd, f); err != nil {
				t.Fatalf("same-image recreate of a main-era member by a deployer: %v", err)
			}
			if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase != 0 || last.Confinement != lxc.ConfinementLegacy {
				t.Fatalf("recreated as %+v, want privileged legacy as before", last)
			}
			row := lastAuditRow(t, s, "ct.recreate-security")
			if !row.found || row.user != "carl" || row.target != "web" || !strings.Contains(row.detail, "recreate kept privileged") {
				t.Errorf("audit row %+v, want carl's recreate that kept web privileged", row)
			}
			if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "container=web") ||
				!strings.Contains(out, "lv ct convert") {
				t.Errorf("no WARN naming web and the remedy; log:\n%s", out)
			}
		})
	}
}

// A recreate that CHANGES the image of a privileged or legacy-confined member
// hands the deployer a rootfs of their choosing running as host root, so it
// needs the Admin role or ct.exec on that member (root inside it already).
// Anyone else is refused BEFORE the delete half runs: the member is never
// deleted by a refused recreate.
func TestComposeRecreate_AChangedImageOfAPrivilegedMemberNeedsExecOrAdmin(t *testing.T) {
	changed := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.23"}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}

	t.Run("a deployer without ct.exec is refused, the member kept", func(t *testing.T) {
		s, rt := secServer(t)
		carl := carlCtx(t, s)
		seedMember(t, s, rt, "3.22")
		err := recreateMember(carl, s, upd, changed)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "privileged") ||
			!strings.Contains(err.Error(), "ct.exec") || !strings.Contains(err.Error(), "alpine:3.23") {
			t.Fatalf("changed-image recreate by a deployer without ct.exec: %v", err)
		}
		memberExists(t, s, rt)
		if len(rt.createCalls) != 0 {
			t.Fatalf("a container was created: %+v", rt.createCalls)
		}
		if row := lastAuditRow(t, s, "ct.recreate-security"); !row.found || row.result != "denied" {
			t.Errorf("audit row %+v, want a denied ct.recreate-security", row)
		}
	})
	t.Run("ct.exec on the member", func(t *testing.T) {
		s, rt := secServer(t)
		carl := carlCtx(t, s)
		seedMember(t, s, rt, "3.22")
		ctx := context.Background()
		if err := corrosion.InsertRole(ctx, s.db, corrosion.RoleRecord{Name: "Shell", Verbs: []string{"ct.exec"}}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
			ID: "carl-shell", Path: "/projects/acme/containers/web", Role: "Shell", Principal: "user:carl@local", Propagate: true}); err != nil {
			t.Fatal(err)
		}
		engine := auth.NewEngine(s.db)
		if err := engine.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		s.SetAuthEngine(engine)
		if err := recreateMember(carl, s, upd, changed); err != nil {
			t.Fatalf("changed-image recreate with ct.exec on the member: %v", err)
		}
		if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase != 0 {
			t.Fatalf("recreated as %+v, want privileged", last)
		}
	})
	t.Run("admin", func(t *testing.T) {
		s, rt := secServer(t)
		seedMember(t, s, rt, "3.22")
		if err := recreateMember(adminCtx(), s, upd, changed); err != nil {
			t.Fatalf("changed-image recreate by an admin: %v", err)
		}
		if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase != 0 || last.Confinement != lxc.ConfinementLegacy {
			t.Fatalf("recreated as %+v, want privileged legacy", last)
		}
		if row := lastAuditRow(t, s, "ct.recreate-security"); row.found {
			t.Errorf("an admin's recreate was recorded as a carry-over: %+v", row)
		}
	})
}

// The carry-over is recorded only once the new container exists: a create
// that fails leaves no "kept privileged" event.
func TestComposeRecreate_NoCarryOverEventWhenTheCreateFails(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedMember(t, s, rt, "3.22")
	rt.createErr = errors.New("lxc-create failed")
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); err == nil {
		t.Fatal("the recreate succeeded with a failing runtime create")
	}
	if row := lastAuditRow(t, s, "ct.recreate-security"); row.found {
		t.Errorf("a carry-over was recorded for a create that failed: %+v", row)
	}
}

// A NEW privileged container still needs the Admin role, from a stack file
// as from lv ct create: a new member, or an opt-out the replaced member did
// not have. The latter is refused before the delete (review R1-3), so the
// member is kept.
func TestComposeCreate_ANewPrivilegedMemberNeedsAdmin(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{
		"fresh":  {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", Privileged: true},
		"legacy": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", Confinement: lxc.ConfinementLegacy},
	}}
	for _, name := range []string{"fresh", "legacy"} {
		err := s.deployCreatePlanned(carl, planner.VMAction{Kind: planner.OpCreate, VMName: name, TargetHost: "host-a", IsContainer: true}, f)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("new %s member by a non-admin: %v, want PermissionDenied", name, err)
		}
	}
	// An unprivileged, default-confined member whose stack file now asks for
	// privileged, or for legacy confinement, asks for a new opt-out.
	// The members run the very image the stack file names, so only the new
	// opt-out can refuse them (review M2: a changed image would refuse them
	// for another reason and hide a missing opt-out check).
	for _, name := range []string{"fresh", "legacy"} {
		spec := corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64",
			IDMapBase: s.idmapSlotBase(s.idmapStartSlot()), Confinement: lxc.ConfinementDefault}
		seedSecCT(t, s, rt, name, "stopped", spec)
		if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
			HostName: "host-a", Name: name, State: "stopped", Project: "acme", Image: "alpine:3.22",
			Labels: map[string]string{corrosion.LabelStack: "st"}, CreateSpec: corrosion.EncodeCreateSpec(spec)}); err != nil {
			t.Fatal(err)
		}
		upd := planner.VMAction{Kind: planner.OpUpdate, VMName: name, TargetHost: "host-a", IsContainer: true}
		if err := recreateMember(carl, s, upd, f); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s recreate of an unprivileged member by a non-admin: %v, want PermissionDenied", name, err)
		}
		if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", name); row == nil {
			t.Fatalf("%s: a refused recreate deleted the member", name)
		}
	}
	if len(rt.deleteCalls) != 0 || len(rt.createCalls) != 0 {
		t.Fatalf("runtime touched: deletes %v creates %+v", rt.deleteCalls, rt.createCalls)
	}
	if err := s.deployCreatePlanned(adminCtx(), planner.VMAction{Kind: planner.OpCreate, VMName: "legacy2", TargetHost: "host-a", IsContainer: true},
		&compose.File{Name: "st", VMs: map[string]compose.VMDef{"legacy2": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", Confinement: lxc.ConfinementLegacy}}}); err != nil {
		t.Fatalf("admin create of a legacy member: %v", err)
	}
}
