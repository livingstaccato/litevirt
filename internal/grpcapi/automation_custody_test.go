package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// These real service entry points must reject anonymous/bearer callers before
// resolving any private custody root or parsing an attacker-supplied request.
func TestAutomationCustodyRPCRequiresDirectPeer(t *testing.T) {
	s := &Server{}
	for _, ctx := range []context.Context{context.Background(), metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer caller"))} {
		if r, err := s.PrepareAutomationCustodyRecipient(ctx, &pb.PrepareAutomationCustodyRecipientRequest{RequestJson: []byte(`{}`)}); r != nil || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("recipient direct-peer gate: %v", err)
		}
		if r, err := s.ImportAutomationCustodyEquality(ctx, &pb.ImportAutomationCustodyEqualityRequest{RequestJson: []byte(`{}`), Capsule: []byte("ciphertext")}); r != nil || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("import direct-peer gate: %v", err)
		}
	}
}
