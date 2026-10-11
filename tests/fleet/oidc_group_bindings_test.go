package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/auth/oidctest"
)

// TestFleet_OIDC_GroupBindingFollowsTheSessionAcrossNodes: alice signs in on
// node-0 through the IdP as a member of lv-operators. Her session's verified
// groups travel with the session, so node-1 — which never saw the login —
// applies the group binding to her session too. After the IdP drops her from
// the group, the session her next login mints holds no group binding on
// either node.
func TestFleet_OIDC_GroupBindingFollowsTheSessionAcrossNodes(t *testing.T) {
	ctx := context.Background()
	f := newOIDCFleet(t)
	a, b := f.c.Nodes[0], f.c.Nodes[1]
	if err := auth.SeedBuiltinRoles(ctx, a.DB); err != nil {
		t.Fatal(err)
	}
	r, err := f.c.SelfClient(a).GrantRole(ctx, &pb.GrantRoleRequest{
		Role: "Operator", Principal: "group:lv-operators@oidc:corp", Path: "/projects/acme", Propagate: true,
	})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	bindingID := r.Binding.Id
	// Open the login_policy release feature (a policy covering only the local
	// realm), as a cluster that has used it holds it open. Before it opens a
	// login records no groups; TestGroupBinding_NotRecordedWithoutTheReleaseFeature
	// covers that side.
	if _, err := f.c.SelfClient(a).SetLoginPolicy(ctx, &pb.SetLoginPolicyRequest{Require_2Fa: "local"}); err != nil {
		t.Fatalf("SetLoginPolicy: %v", err)
	}
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range f.c.Nodes {
		e := auth.NewEngine(n.DB)
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		n.Server.SetAuthEngine(e)
	}

	signIn := func() string {
		br := f.browser(t)
		resp := get(t, br, f.beginAtIdP(t, br, a).String())
		tok := sessionCookie(resp)
		if tok == "" {
			t.Fatalf("no session (HTTP %d)", resp.StatusCode)
		}
		return tok
	}
	ownBindings := func(n *Node, tok string) []string {
		t.Helper()
		lr, err := f.c.bearerClient(n, tok).ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{})
		if err != nil {
			t.Fatalf("ListRoleBindings on %s: %v", n.Name, err)
		}
		var ids []string
		for _, rb := range lr.Bindings {
			ids = append(ids, rb.Id)
		}
		return ids
	}

	tok := signIn()
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range f.c.Nodes {
		if got := ownBindings(n, tok); strings.Join(got, ",") != bindingID {
			t.Fatalf("%s: alice's session sees bindings %v, want the group binding %s", n.Name, got, bindingID)
		}
	}

	f.idp.SignIn(&oidctest.User{Subject: "sub-alice", PreferredUsername: "alice", Groups: []string{"lv-viewers"}})
	tok2 := signIn()
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{a, b} {
		if got := ownBindings(n, tok2); len(got) != 0 {
			t.Fatalf("%s: the session minted after the group was removed sees %v", n.Name, got)
		}
	}
}
