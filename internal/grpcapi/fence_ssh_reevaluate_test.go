package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestGetFenceSSHStatus_ReevaluateIsAdminOnly: a re-evaluation has every
// answering host log in to its own sshd as root, so only an admin may ask for
// one; a viewer or operator is refused before anything runs, and still reads
// the status without it.
//
// Mutation: drop the admin check: the viewer is answered, red.
func TestGetFenceSSHStatus_ReevaluateIsAdminOnly(t *testing.T) {
	s := &Server{hostName: "node-a"}
	for _, role := range []string{"viewer", "operator"} {
		ctx := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "u"), ctxKeyRole, role)
		_, err := s.GetFenceSSHStatus(ctx, &pb.FenceSSHStatusRequest{Reevaluate: true})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s with reevaluate: %v, want PermissionDenied", role, err)
		}
		if _, err := s.GetFenceSSHStatus(ctx, &pb.FenceSSHStatusRequest{}); err != nil {
			t.Fatalf("%s without reevaluate: %v", role, err)
		}
	}
	st, err := s.GetFenceSSHStatus(adminCtx(), &pb.FenceSSHStatusRequest{Reevaluate: true})
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	// No agent on this host: nothing was evaluated, so nothing is proven.
	if n := st.GetNodes(); len(n) != 1 || n[0].GetEvaluatedForRequest() {
		t.Fatalf("admin, no agent: %+v", n)
	}
}
