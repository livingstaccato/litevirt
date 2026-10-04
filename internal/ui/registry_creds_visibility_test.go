package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// The registry-credentials page decided whether to show its global controls
// from the caller's coarse legacy role, while the RPCs behind them ask the RBAC
// engine for registry.cred.global at "/". A user whose access came from a role
// binding — here a custom role holding only that verb, over a legacy "viewer"
// role — was shown a read-only page for an action the RPC let them take. The
// page now asks the daemon the gate's own question (CheckPermissions). Hiding a
// control is display only: the RPC check stays the boundary.

// newUIBoundToCustomRole is newUIBoundToSvc for a role that is not built in,
// over the given legacy role.
func newUIBoundToCustomRole(t *testing.T, user, legacyRole, role string, verbs []string) (*Server, *corrosion.Client, *grpcapi.Server) {
	t.Helper()
	ctx := context.Background()
	s, db, svc := newUIOverRealDaemonSvc(t, user, legacyRole)
	if err := corrosion.InsertRole(ctx, db, corrosion.RoleRecord{Name: role, Verbs: verbs}); err != nil {
		t.Fatalf("InsertRole: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
		ID: user + "-root", Path: "/", Role: role, Principal: "user:" + user + "@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	svc.SetAuthEngine(engine)
	return s, db, svc
}

func seedGlobalRegistryCred(t *testing.T, db *corrosion.Client) {
	t.Helper()
	if err := corrosion.UpsertRegistryCredential(context.Background(), db, corrosion.RegistryCredential{
		ID: "g1", Scope: corrosion.RegistryScopeGlobal, Registry: "ghcr.io", Username: "bot", Secret: "s3cret",
	}); err != nil {
		t.Fatalf("UpsertRegistryCredential: %v", err)
	}
}

// globalControls reports whether the page shows the global delete button and
// the modal offers the Global checkbox.
func globalControls(t *testing.T, s *Server) (deleteBtn, checkbox bool) {
	t.Helper()
	w := serveRequest(s, uiSessionReq(t, "GET", "/account/registry", nil))
	assertStatus(t, w, http.StatusOK)
	page := w.Body.String()
	if !strings.Contains(page, "ghcr.io") {
		t.Fatalf("page does not list the seeded global credential; body = %s", truncBody(w))
	}
	deleteBtn = strings.Contains(page, "global=true")
	w = serveRequest(s, uiSessionReq(t, "GET", "/ui/registry-creds/add-modal", nil))
	assertStatus(t, w, http.StatusOK)
	checkbox = strings.Contains(w.Body.String(), `name="global"`)
	return deleteBtn, checkbox
}

// rpcAdmitsGlobalWrite submits the page's own global-add form and reports
// whether the RPC accepted it.
func rpcAdmitsGlobalWrite(t *testing.T, s *Server) bool {
	t.Helper()
	w := serveRequest(s, uiSessionReq(t, "POST", "/ui/registry-creds", url.Values{
		"registry": {"quay.io"}, "username": {"u"}, "password": {"p"}, "global": {"on"},
	}))
	return w.Code == http.StatusOK
}

func TestRegistryCredsPage_GlobalControlsFollowTheRPCGate(t *testing.T) {
	cases := []struct {
		name string
		mk   func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server)
		want bool
	}{
		{"custom role with registry.cred.global over legacy viewer", func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIBoundToCustomRole(t, "rita", "viewer", "RegistryAdmin", []string{"registry.cred.global"})
		}, true},
		{"bound Admin over legacy viewer", func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIBoundToSvc(t, "ada", "Admin")
		}, true},
		// Built-in Operator does not hold registry.cred.global; only the legacy
		// no-bindings fallback lets an operator manage global credentials.
		{"bound Operator over legacy viewer", func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIBoundToSvc(t, "olga", "Operator")
		}, false},
		{"legacy operator, no bindings", func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIOverRealDaemonSvc(t, "oscar", "operator")
		}, true},
		{"bound Viewer", func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIBoundToSvc(t, "vic", "Viewer")
		}, false},
		{"legacy viewer, no bindings", func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIOverRealDaemonSvc(t, "val", "viewer")
		}, false},
		{"custom role without the verb over legacy operator", func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			// The legacy role says operator; the binding is authoritative.
			return newUIBoundToCustomRole(t, "otto", "operator", "ImageReader", []string{"image.read"})
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db, _ := tc.mk(t)
			seedGlobalRegistryCred(t, db)
			del, box := globalControls(t, s)
			if del != tc.want || box != tc.want {
				t.Errorf("global delete button shown = %v, Global checkbox shown = %v; want both %v", del, box, tc.want)
			}
			// The page shows what the RPC enforces, no more and no less.
			if got := rpcAdmitsGlobalWrite(t, s); got != tc.want {
				t.Errorf("RPC admitted a global write = %v, want %v", got, tc.want)
			}
		})
	}
}

// A gate name the daemon does not know is refused, so a typo on the UI side
// fails loudly here instead of silently hiding a control.
func TestCheckPermissions_UnknownGateRefused(t *testing.T) {
	if gateRegistryCredGlobal != grpcapi.GateRegistryCredGlobal {
		t.Fatalf("UI gate %q is not the daemon's %q", gateRegistryCredGlobal, grpcapi.GateRegistryCredGlobal)
	}
	s, _, _ := newUIOverRealDaemonSvc(t, "admin1", "admin")
	r := uiSessionReq(t, "GET", "/", nil)
	_, err := s.grpc.CheckPermissions(s.uiBearerCtx(r), &pb.CheckPermissionsRequest{Gates: []string{"no.such.gate"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown gate: err = %v, want InvalidArgument", err)
	}
	got, err := s.grpc.CheckPermissions(s.uiBearerCtx(r), &pb.CheckPermissionsRequest{Gates: uiRegistryGates})
	if err != nil {
		t.Fatalf("CheckPermissions(%v): %v", uiRegistryGates, err)
	}
	for _, g := range uiRegistryGates {
		if !got.Allowed[g] {
			t.Errorf("admin: gate %q = false, want true", g)
		}
	}
}
