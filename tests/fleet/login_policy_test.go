// Fleet scenario for the login rules (account disable/expiry and the mandatory
// second factor) over real gRPC and independent replicas: written on one
// node, enforced on another node's authentication path once replication has
// carried it, and refused everywhere until login_policy_v1 has latched.
package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func assertNoLifecycleRows(t *testing.T, n *Node) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT username FROM user_lifecycle`)
	if err != nil {
		t.Fatalf("%s: query user_lifecycle: %v", n.Name, err)
	}
	if len(rows) != 0 {
		t.Fatalf("%s holds %d user_lifecycle rows written before login_policy_v1 latched", n.Name, len(rows))
	}
}

// TestFleet_DisableWrittenOnOneNodeRefusedOnAnother: bob's session and API
// token, both minted and used on node-1, stop working there once a disable
// written on node-0 replicates; node-2 refuses his password. Re-enabled from
// node-1, his token works again on node-0. Before the latch, the disable is
// refused and nothing reaches any replica.
func TestFleet_DisableWrittenOnOneNodeRefusedOnAnother(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 64})
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		g := gates[n.Name]
		n.DB.SetLoginPolicyGate(func() bool { return g.DurablyLatched(capabilities.LoginPolicyV1) })
		n.DB.SetClusterPolicyGate(func() bool { return g.DurablyLatched(capabilities.FailoverScopeV1) })
	}
	c.WaitConverged(t, convergeTimeout)
	a, b, cc := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	adminA, adminB := c.SelfClient(a), c.SelfClient(b)

	for _, u := range []*pb.CreateUserRequest{
		{Username: "admin", Password: "admin-password-0123456789", Role: "admin"},
		{Username: "bob", Password: "bobs-password-0123456789", Role: "operator"},
	} {
		if _, err := adminA.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser %s: %v", u.Username, err)
		}
	}
	tok, err := adminA.CreateToken(ctx, &pb.CreateTokenRequest{Username: "bob", Name: "ci"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)

	// 1. Before the latch: refused, naming the token, nothing written anywhere.
	yes := true
	_, err = adminA.SetUserAccount(ctx, &pb.SetUserAccountRequest{Username: "bob", Disabled: &yes})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("SetUserAccount before the latch: %v, want FailedPrecondition", err)
	}
	for _, n := range c.Nodes {
		assertNoLifecycleRows(t, n)
	}

	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.LoginPolicyV1) || !gates[n.Name].DurablyLatched(capabilities.LoginPolicyV1) {
			t.Fatalf("%s: login_policy_v1 did not latch on a uniform fleet", n.Name)
		}
	}

	login, err := c.SelfClient(b).Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bobs-password-0123456789"})
	if err != nil {
		t.Fatalf("bob's login on %s: %v", b.Name, err)
	}
	session := c.bearerClient(b, login.Token)
	token := c.bearerClient(b, tok.Token)
	for name, cl := range map[string]pb.LiteVirtClient{"session": session, "token": token} {
		if _, err := cl.Whoami(ctx, &emptypb.Empty{}); err != nil {
			t.Fatalf("bob's %s on %s before the disable: %v", name, b.Name, err)
		}
	}

	// 2. Disabled on node-0; refused on node-1 and node-2 once it arrives.
	if _, err := adminA.SetUserAccount(ctx, &pb.SetUserAccountRequest{Username: "bob", Disabled: &yes}); err != nil {
		t.Fatalf("SetUserAccount on %s: %v", a.Name, err)
	}
	eventually(t, convergeTimeout, "bob's session and token refused on "+b.Name, func() bool {
		_, e1 := session.Whoami(ctx, &emptypb.Empty{})
		_, e2 := token.Whoami(ctx, &emptypb.Empty{})
		return status.Code(e1) == codes.Unauthenticated && status.Code(e2) == codes.Unauthenticated
	})
	eventually(t, convergeTimeout, "bob's password refused on "+cc.Name, func() bool {
		_, err := c.SelfClient(cc).Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bobs-password-0123456789"})
		return status.Code(err) == codes.Unauthenticated
	})

	// 3. Re-enabled from node-1: the token works again on node-0.
	no := false
	if _, err := adminB.SetUserAccount(ctx, &pb.SetUserAccountRequest{Username: "bob", Disabled: &no}); err != nil {
		t.Fatalf("SetUserAccount on %s: %v", b.Name, err)
	}
	eventually(t, convergeTimeout, "bob's token accepted again on "+a.Name, func() bool {
		_, err := c.bearerClient(a, tok.Token).Whoami(ctx, &emptypb.Empty{})
		return err == nil
	})
}

// TestFleet_TwoFactorPolicySetOnOneNodeEnforcedOnAnother: a policy set on
// node-0 confines a login on node-2 to enrollment.
func TestFleet_TwoFactorPolicySetOnOneNodeEnforcedOnAnother(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 641})
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		g := gates[n.Name]
		n.DB.SetLoginPolicyGate(func() bool { return g.DurablyLatched(capabilities.LoginPolicyV1) })
		n.DB.SetClusterPolicyGate(func() bool { return g.DurablyLatched(capabilities.FailoverScopeV1) })
	}
	c.WaitConverged(t, convergeTimeout)
	a, cc := c.Nodes[0], c.Nodes[2]
	for _, n := range c.Nodes {
		for _, tok := range []string{capabilities.LoginPolicyV1, capabilities.FailoverScopeV1} {
			if !gates[n.Name].Enforced(ctx, tok) || !gates[n.Name].DurablyLatched(tok) {
				t.Fatalf("%s: %s did not latch on a uniform fleet", n.Name, tok)
			}
		}
	}
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "bob", Password: "bobs-password-0123456789", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := c.SelfClient(a).SetLoginPolicy(ctx, &pb.SetLoginPolicyRequest{Require_2Fa: "all"}); err != nil {
		t.Fatalf("SetLoginPolicy on %s: %v", a.Name, err)
	}
	var resp *pb.LoginResponse
	eventually(t, convergeTimeout, "an enrollment-only login on "+cc.Name, func() bool {
		r, err := c.SelfClient(cc).Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bobs-password-0123456789"})
		if err != nil || !r.GetRequires_2FaEnrollment() {
			return false
		}
		resp = r
		return true
	})
	bob := c.bearerClient(cc, resp.Token)
	if _, err := bob.ListHosts(ctx, &pb.ListHostsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListHosts from an enrollment-only session: %v, want PermissionDenied", err)
	}
	// A first factor needs an admin-issued code (review I5), and a code is
	// spent only on the node that issued it (rereview N3): one issued on
	// node-0 is refused on node-2, naming node-0, once it has replicated.
	code, err := c.SelfClient(a).IssueEnrollmentCode(ctx, &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatalf("IssueEnrollmentCode: %v", err)
	}
	eventually(t, convergeTimeout, "node-0's code refused on "+cc.Name+" naming node-0", func() bool {
		_, err := bob.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: code.GetCode()})
		return status.Code(err) == codes.FailedPrecondition && strings.Contains(err.Error(), a.Name)
	})
	here, err := c.SelfClient(cc).IssueEnrollmentCode(ctx, &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatalf("IssueEnrollmentCode on %s: %v", cc.Name, err)
	}
	enr, err := bob.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: here.GetCode()})
	if err != nil || !enr.GetSessionEnded() {
		t.Fatalf("EnrollTOTP from the enrollment-only session: ended=%v err=%v", enr.GetSessionEnded(), err)
	}
	if _, err := bob.Whoami(ctx, &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("the enrollment-only session after enrolling: %v, want Unauthenticated", err)
	}
}

// latchLoginPolicy wires the login-policy and cluster-policy gates to each
// node's real checker and drives both latches.
func latchLoginPolicy(t *testing.T, c *Cluster) {
	t.Helper()
	ctx := context.Background()
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		g := gates[n.Name]
		n.DB.SetLoginPolicyGate(func() bool { return g.DurablyLatched(capabilities.LoginPolicyV1) })
		n.DB.SetClusterPolicyGate(func() bool { return g.DurablyLatched(capabilities.FailoverScopeV1) })
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		for _, tok := range []string{capabilities.LoginPolicyV1, capabilities.FailoverScopeV1} {
			if !gates[n.Name].Enforced(ctx, tok) || !gates[n.Name].DurablyLatched(tok) {
				t.Fatalf("%s: %s did not latch on a uniform fleet", n.Name, tok)
			}
		}
	}
}

// TestFleet_SessionMintedWhereThePolicyHadNotArrivedIsConfined (review C1):
// the policy is set on node-0 while node-2 is cut off; bob logs in on node-2
// with no factor and gets a full session there. Once the policy reaches
// node-2, that session is confined — it never presented a factor — although
// node-0's revocation sweep never saw it.
func TestFleet_SessionMintedWhereThePolicyHadNotArrivedIsConfined(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 642})
	latchLoginPolicy(t, c)
	a, b, cc := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "bob", Password: "bobs-password-0123456789", Role: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	c.Partition(a, cc)
	c.Partition(b, cc)
	if _, err := c.SelfClient(a).SetLoginPolicy(ctx, &pb.SetLoginPolicyRequest{Require_2Fa: "all"}); err != nil {
		t.Fatalf("SetLoginPolicy: %v", err)
	}
	login, err := c.SelfClient(cc).Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bobs-password-0123456789"})
	if err != nil || login.GetRequires_2FaEnrollment() {
		t.Fatalf("login on the cut-off node: %+v %v, want a plain session (the policy has not arrived)", login, err)
	}
	bob := c.bearerClient(cc, login.Token)
	if _, err := bob.ListHosts(ctx, &pb.ListHostsRequest{}); err != nil {
		t.Fatalf("bob's session before the policy arrived: %v", err)
	}

	c.Heal(a, cc)
	c.Heal(b, cc)
	eventually(t, convergeTimeout, "bob's pre-policy session confined on "+cc.Name, func() bool {
		_, err := bob.ListHosts(ctx, &pb.ListHostsRequest{})
		return status.Code(err) == codes.PermissionDenied
	})
}

// TestFleet_DelegatedRevokesOnTwoNodesNeverEmptyAPrincipal (review I3): a
// delegate revokes carol's two bindings, one on node-0 and one on node-1, each
// node still holding the other binding when it decides. Each revoke leaves a
// NoAccess sentinel, so once both have crossed, carol still holds a binding on
// every node and never falls back to her cluster-wide legacy operator role.
func TestFleet_DelegatedRevokesOnTwoNodesNeverEmptyAPrincipal(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 643})
	a, b := c.Nodes[0], c.Nodes[1]
	admin := c.SelfClient(a)
	for _, u := range []*pb.CreateUserRequest{
		{Username: "pat", Password: "pats-password-0123456789", Role: "viewer"},
		{Username: "carol", Password: "carols-password-0123456789", Role: "operator"},
	} {
		if _, err := admin.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	engines := map[string]*auth.Engine{}
	for _, n := range c.Nodes {
		if err := auth.SeedBuiltinRoles(ctx, n.DB); err != nil {
			t.Fatal(err)
		}
		engines[n.Name] = auth.NewEngine(n.DB)
		n.Server.SetAuthEngine(engines[n.Name])
	}
	grantOn := func(path, role, principal string) string {
		r, err := admin.GrantRole(ctx, &pb.GrantRoleRequest{Path: path, Role: role, Principal: principal, Propagate: true})
		if err != nil {
			t.Fatalf("GrantRole %s %s: %v", role, principal, err)
		}
		return r.Binding.Id
	}
	grantOn("/projects/acme", "Operator", "user:pat@local")
	grantOn("/projects/acme", "PermissionAdmin", "user:pat@local")
	first := grantOn("/projects/acme/vms/web", "VMOperator", "user:carol@local")
	second := grantOn("/projects/acme/vms/db", "VMOperator", "user:carol@local")
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if err := engines[n.Name].Reload(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Cut the link so each node decides without seeing the other's revoke.
	c.Partition(a, b)
	for i, n := range []*Node{a, b} {
		login, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: "pat", Password: "pats-password-0123456789"})
		if err != nil {
			t.Fatal(err)
		}
		id := []string{first, second}[i]
		if _, err := c.bearerClient(n, login.Token).RevokeRole(ctx, &pb.RevokeRoleRequest{Id: id}); err != nil {
			t.Fatalf("pat revokes %s on %s: %v", id, n.Name, err)
		}
	}
	c.Heal(a, b)
	c.WaitConverged(t, convergeTimeout)

	for _, n := range c.Nodes {
		rows, err := corrosion.ListBindingsForPrincipal(ctx, n.DB, "user:carol@local")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatalf("%s: carol holds no binding after two delegated revokes; she is a cluster-wide operator again", n.Name)
		}
		for _, r := range rows {
			if r.Role != corrosion.SentinelRole {
				t.Fatalf("%s: carol still holds %s at %s", n.Name, r.Role, r.Path)
			}
		}
	}
}
