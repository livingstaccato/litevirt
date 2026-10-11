package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/auth/oidctest"
)

// TestFleet_OIDC_GroupBindingAuthorizesAcrossNodes: alice signs in on node-0
// through the IdP as a member of lv-operators. Her session's verified groups
// travel with the session, so node-1 — which never saw the login — authorizes
// an action she holds ONLY through the group binding (her own user binding is
// elsewhere, so she is off her legacy role). Once the group binding is revoked
// and she signs in again, the same action is refused on both nodes; and after
// the IdP drops her from the group, a binding on the group no longer reaches
// the session her next login mints (review M5).
func TestFleet_OIDC_GroupBindingAuthorizesAcrossNodes(t *testing.T) {
	ctx := context.Background()
	f := newOIDCFleet(t)
	a, b := f.c.Nodes[0], f.c.Nodes[1]
	admin := f.c.SelfClient(a)
	if err := auth.SeedBuiltinRoles(ctx, a.DB); err != nil {
		t.Fatal(err)
	}
	// Open the login_policy release feature (a policy covering only the local
	// realm). Before it opens a login records no groups.
	if _, err := admin.SetLoginPolicy(ctx, &pb.SetLoginPolicyRequest{Require_2Fa: "local"}); err != nil {
		t.Fatalf("SetLoginPolicy: %v", err)
	}
	grant := func(principal, path string) string {
		t.Helper()
		r, err := admin.GrantRole(ctx, &pb.GrantRoleRequest{Role: "Viewer", Principal: principal, Path: path, Propagate: true})
		if err != nil {
			t.Fatalf("GrantRole %s: %v", principal, err)
		}
		return r.Binding.Id
	}
	signIn := func() string {
		t.Helper()
		br := f.browser(t)
		resp := get(t, br, f.beginAtIdP(t, br, a).String())
		tok := sessionCookie(resp)
		if tok == "" {
			t.Fatalf("no session (HTTP %d)", resp.StatusCode)
		}
		return tok
	}
	engines := func() {
		t.Helper()
		f.c.WaitConverged(t, convergeTimeout)
		for _, n := range f.c.Nodes {
			e := auth.NewEngine(n.DB)
			if err := e.Reload(ctx); err != nil {
				t.Fatal(err)
			}
			n.Server.SetAuthEngine(e)
		}
	}
	// ListContainers needs ct.read at "/": alice holds it only through the
	// group's Viewer binding at "/"; her own binding is on another project.
	listAs := func(n *Node, tok string) error {
		_, err := f.c.bearerClient(n, tok).ListContainers(ctx, &pb.ListContainersRequest{})
		return err
	}
	grant("user:alice@oidc:corp", "/projects/elsewhere")
	groupBinding := grant("group:oidc:corp/lv-operators", "/")
	engines()

	tok := signIn()
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range f.c.Nodes {
		if err := listAs(n, tok); err != nil {
			t.Fatalf("%s: an action granted only through the group binding: %v", n.Name, err)
		}
	}

	if _, err := admin.RevokeRole(ctx, &pb.RevokeRoleRequest{Id: groupBinding}); err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	engines()
	tok2 := signIn()
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{a, b} {
		if err := listAs(n, tok2); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: after the group binding was revoked and alice signed in again: %v, want PermissionDenied", n.Name, err)
		}
	}

	// The binding back, but the IdP no longer lists her in the group.
	grant("group:oidc:corp/lv-operators", "/")
	engines()
	f.idp.SignIn(&oidctest.User{Subject: "sub-alice", PreferredUsername: "alice", Groups: []string{"lv-viewers"}})
	tok3 := signIn()
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{a, b} {
		if err := listAs(n, tok3); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: a session minted after the IdP dropped the group: %v, want PermissionDenied", n.Name, err)
		}
	}
	// The session minted while she was a member keeps its snapshot until it
	// ends (documented): still allowed through the restored binding.
	if err := listAs(b, tok); err != nil {
		t.Fatalf("%s: the earlier session's snapshot: %v", b.Name, err)
	}
}
