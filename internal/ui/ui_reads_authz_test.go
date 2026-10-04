package ui

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The UI's pages used to READ replicated tables in-process through the
// host-local Corrosion handle, which answers to no authorization at all. Each
// of the reads below has an RPC twin that applies a check or a per-caller
// filter the page skipped, so a session saw what `lv` would have refused it:
//
//   - /rbac listed every binding in the cluster. ListRoleBindings limits a
//     non-admin to the bindings that name them, so a project Viewer read the
//     whole privilege map — every principal, role, path and project name.
//   - /resource-mappings listed every passthrough mapping. ListResourceMappings
//     asks for resourcemap.read at `/`, which a project-scoped grant does not
//     reach.
//   - /firewall and the VM hardware modals answered a session whose bearer is a
//     SCOPED API token. The cookie is a bearer like any other, and RequireRole
//     refuses a scoped token on a handler that is not scope-aware; the pages did
//     not ask.

// seedOtherTenantsBindings adds bindings that do not name the bound user: another
// user in another project, and a group in a third.
func seedOtherTenantsBindings(t *testing.T, db *corrosion.Client) {
	t.Helper()
	for _, b := range []corrosion.RoleBindingRecord{
		{ID: "bob-teamB", Path: "/projects/teamB", Role: "Admin", Principal: "user:bob@local", Propagate: true},
		{ID: "ops-secretco", Path: "/projects/secretco", Role: "Operator", Principal: "group:ops@local", Propagate: true},
	} {
		if err := corrosion.InsertRoleBinding(context.Background(), db, b); err != nil {
			t.Fatalf("InsertRoleBinding(%s): %v", b.ID, err)
		}
	}
}

func TestUIRBAC_AProjectViewerSeesOnlyItsOwnBindings(t *testing.T) {
	s, db, _ := newUIBoundAt(t, "pat", "/projects/teamA", "Viewer")
	seedOtherTenantsBindings(t, db)

	w := serveRequest(s, uiSessionReq(t, "GET", "/rbac", nil))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	mustContain(t, body, "user:pat@local", "teamA")
	for _, leaked := range []string{"user:bob@local", "group:ops@local", "teamB", "secretco"} {
		if strings.Contains(body, leaked) {
			t.Errorf("/rbac showed a project Viewer %q, which ListRoleBindings withholds from a non-admin", leaked)
		}
	}
}

func TestUIRBAC_AnAdminSeesEveryBinding(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "ada", "admin")
	seedOtherTenantsBindings(t, db)

	w := serveRequest(s, uiSessionReq(t, "GET", "/rbac", nil))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), "user:bob@local", "group:ops@local", "teamB", "secretco",
		`hx-delete="/ui/rbac/bindings/bob-teamB"`)
}

func seedSecretMapping(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.CreateResourceMapping(ctx, db, "gpu-secret", "the A100 pool"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, db, "gpu-secret", "kvm-07", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}
}

func TestUIResourceMappings_AProjectScopedGrantCannotListThem(t *testing.T) {
	s, db, _ := newUIBoundAt(t, "pat", "/projects/teamA", "Admin")
	seedSecretMapping(t, db)

	w := serveRequest(s, uiSessionReq(t, "GET", "/resource-mappings", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("a project-scoped grant listing resource mappings: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if body := w.Body.String(); strings.Contains(body, "gpu-secret") || strings.Contains(body, "kvm-07") {
		t.Error("/resource-mappings listed the cluster's passthrough mappings to a grant scoped to one project")
	}
}

func TestUIResourceMappings_AClusterViewerStillListsThem(t *testing.T) {
	s, db := newUIBoundTo(t, "vera", "Viewer")
	seedSecretMapping(t, db)

	w := serveRequest(s, uiSessionReq(t, "GET", "/resource-mappings", nil))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), "gpu-secret", "the A100 pool", "kvm-07", "0000:41:00.0")
}

// scopeUISession restricts the harness's session token to scopes, so the
// cookie is a scoped API token — which the UI accepts as a session, because
// Whoami answers it.
func scopeUISession(t *testing.T, db *corrosion.Client, scopes string) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`UPDATE tokens SET scope_paths = ? WHERE id = 'ui-session'`, scopes); err != nil {
		t.Fatalf("scope the session token: %v", err)
	}
}

func seedSecretFirewall(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertClusterFirewallRule(ctx, db, corrosion.FirewallRule{
		ID: "r1", Direction: "ingress", Proto: "tcp", PortRange: "6443", CIDR: "198.51.100.0/24",
		Action: "accept", Priority: 100, Comment: "fw-secret-comment",
	}); err != nil {
		t.Fatalf("InsertClusterFirewallRule: %v", err)
	}
	if err := corrosion.InsertHostFirewallRule(ctx, db, corrosion.FirewallRule{
		ID: "h1", HostName: "kvm-03", Direction: "ingress", Proto: "tcp", PortRange: "22", Action: "drop", Priority: 100,
	}); err != nil {
		t.Fatalf("InsertHostFirewallRule: %v", err)
	}
	if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, ""); err != nil {
		t.Fatalf("SetFirewallDefault: %v", err)
	}
	if err := corrosion.InsertIPSet(ctx, db, corrosion.IPSet{ID: "s1", Name: "blocklist-secret", CIDRs: []string{"192.0.2.0/24"}}); err != nil {
		t.Fatalf("InsertIPSet: %v", err)
	}
}

func TestUIFirewall_AScopedTokenSessionCannotReadClusterPolicy(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "ada", "admin")
	seedSecretFirewall(t, db)
	scopeUISession(t, db, `["/projects/teamA"]`)

	w := serveRequest(s, uiSessionReq(t, "GET", "/firewall", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("a scoped token reading the cluster firewall: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if body := w.Body.String(); strings.Contains(body, "fw-secret-comment") || strings.Contains(body, "blocklist-secret") {
		t.Error("/firewall rendered cluster policy to a token scoped to one project, which the firewall RPCs refuse")
	}
}

func TestUIFirewall_AViewerStillReadsClusterPolicy(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "vic", "viewer")
	seedSecretFirewall(t, db)

	w := serveRequest(s, uiSessionReq(t, "GET", "/firewall", nil))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), "fw-secret-comment", ":6443", "198.51.100.0/24",
		`hx-delete="/ui/firewall/cluster-rules/r1"`,
		"kvm-03", `hx-delete="/ui/firewall/host-rules/h1"`,
		"@blocklist-secret", "192.0.2.0/24", `hx-delete="/ui/firewall/ipsets/s1"`,
		`<span class="badge badge-red">default-deny</span>`)
}

func TestUIAddPCIModal_AScopedTokenSessionDoesNotLearnTheVMsHost(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "ada", "admin")
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: "vm-x", HostName: "host-secret", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	scopeUISession(t, db, `["/projects/teamA"]`)

	w := serveRequest(s, uiSessionReq(t, "GET", "/ui/vms/vm-x/add-pci-modal", nil))
	if strings.Contains(w.Body.String(), "host-secret") {
		t.Error("the Add-PCI modal named the VM's host to a scoped token that InspectVM refuses")
	}
}
