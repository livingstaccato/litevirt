// Fleet scenario for the login rules (account disable/expiry and the mandatory
// second factor) over real gRPC and independent replicas: written on one
// node, enforced on another node's authentication path once replication has
// carried it, and refused everywhere until login_policy_v1 has latched.
package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
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
	enr, err := bob.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone"})
	if err != nil || !enr.GetSessionEnded() {
		t.Fatalf("EnrollTOTP from the enrollment-only session: ended=%v err=%v", enr.GetSessionEnded(), err)
	}
	if _, err := bob.Whoami(ctx, &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("the enrollment-only session after enrolling: %v, want Unauthenticated", err)
	}
}
