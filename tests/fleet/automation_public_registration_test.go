package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Removing public registration or accepting a legacy-only session as an enrolled
// principal must fail at the real generated-client TLS boundary. This fixture
// creates only an ordinary account; it supplies no automation authority.
func TestFleet_AutomationPublicRegistrationRejectsUnenrolledLogin(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n := c.Nodes[0]
	legacy := c.SelfClient(n)
	if _, err := legacy.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "ordinary", Password: "ordinary-password-0123456789", Role: "viewer",
	}); err != nil {
		t.Fatalf("ordinary account creation: %v", err)
	}
	login, err := legacy.Login(ctx, &pb.LoginRequest{
		Username: "ordinary", Password: "ordinary-password-0123456789", Realm: "local",
	})
	if err != nil || !strings.HasPrefix(login.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("ordinary Login did not issue a local session: %v", err)
	}
	bearer := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+login.GetToken())
	identity, err := legacy.Whoami(bearer, &emptypb.Empty{})
	if err != nil || identity.GetUsername() != "ordinary" || identity.GetRole() != "viewer" || identity.GetRealm() != "local" {
		t.Fatalf("real TLS interceptor did not authenticate the ordinary Login bearer: %v", err)
	}
	// The negative identity precondition is known from readable storage, rather
	// than inferred from a failed authority lookup or an unavailable database.
	counts := func() []int64 {
		t.Helper()
		var result []int64
		for _, table := range []string{"local_automation_authority", "local_automation_identities", "local_automation_owners", "local_automation_prefix"} {
			rows, err := n.DB.Query(ctx, "SELECT COUNT(*) AS n FROM "+table)
			if err != nil || len(rows) != 1 {
				t.Fatalf("readable negative fixture %s: %v", table, err)
			}
			result = append(result, rows[0].Int64("n"))
		}
		return result
	}
	before := counts()
	for i, count := range before {
		if count != 0 {
			t.Fatalf("ordinary account unexpectedly acquired automation state at index %d: %d", i, count)
		}
	}
	// Use the SAME TLS connection and production fleet registration that just
	// authenticated Whoami; no test-owned public registration or fake handler.
	public := automationv1.NewAutomationClient(n.selfConn)
	response, err := public.EnsureOwner(bearer, &automationv1.EnsureOwnerRequest{
		Owner:     &automationv1.OwnerRef{ProjectUid: "unassigned-project", OwnerId: "ordinary-owner"},
		RequestId: "unenrolled-login-request",
	})
	for i, count := range counts() {
		if count != before[i] {
			t.Errorf("refused public request changed automation state at index %d: %d -> %d", i, before[i], count)
		}
	}
	if response != nil {
		t.Error("unenrolled Login received an owner response")
	}
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Errorf("RED_PUBLIC_REGISTRATION: real ordinary Login bearer EnsureOwner got=%s want=Unauthenticated: %v", got, err)
	}
}
