package grpcapi

import (
	"bytes"
	"context"
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

// Recreating an existing privileged member keeps its privilege for whoever
// may deploy the stack, as on main, where every member was privileged (final
// whole-branch review M5): refusing would newly block a compose update, and
// dropping it to unprivileged would break its workload. For a non-Admin the
// carry-over is recorded, as an audit event and a WARN naming the remedy. A
// stack file that states the mode the member already has keeps it too.
func TestComposeRecreate_KeepsAnExistingPrivilegedMemberForADeployer(t *testing.T) {
	for _, tc := range []struct {
		name string
		def  compose.VMDef
	}{
		{"mode not stated", compose.VMDef{Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}},
		{"privileged stated", compose.VMDef{Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", Privileged: true, Confinement: lxc.ConfinementLegacy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			s, rt := secServer(t)
			carl := carlCtx(t, s)
			f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": tc.def}}
			// web was deployed by main: no security recorded, so privileged legacy.
			seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine"})
			upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
			if err := s.deleteWorkload(carl, upd); err != nil {
				t.Fatalf("delete half of a recreate by a deployer: %v", err)
			}
			if err := s.deployCreatePlanned(carl, upd, f); err != nil {
				t.Fatalf("recreate of a main-era member by a deployer: %v", err)
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

// A NEW privileged container still needs the Admin role, from a stack file
// as from lv ct create: a new member, or an opt-out the replaced member did
// not have.
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
	// An unprivileged member whose stack file now asks for privileged is a
	// new opt-out too.
	seedSecCT(t, s, rt, "fresh", "stopped", corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine",
		IDMapBase: s.idmapSlotBase(s.idmapStartSlot()), Confinement: lxc.ConfinementDefault})
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "fresh", TargetHost: "host-a", IsContainer: true}
	if err := s.deleteWorkload(carl, upd); err != nil {
		t.Fatal(err)
	}
	if err := s.deployCreatePlanned(carl, upd, f); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("privileged recreate of an unprivileged member by a non-admin: %v, want PermissionDenied", err)
	}
	if len(rt.createCalls) != 0 {
		t.Fatalf("runtime create called: %+v", rt.createCalls)
	}
	if err := s.deployCreatePlanned(adminCtx(), planner.VMAction{Kind: planner.OpCreate, VMName: "legacy", TargetHost: "host-a", IsContainer: true}, f); err != nil {
		t.Fatalf("admin create of a legacy member: %v", err)
	}
}
