package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestAcknowledgeLeaseTermTie_RefusesAPeer turns the handler's own doc into a
// check.
//
// It says "Node-local and NOT peer-callable ... a node must never be able to
// acknowledge its own contest, which is exactly what a peer-callable path
// would allow" — but nothing refused a peer certificate, and a peer authorizes
// as admin. Either claimant in a term contest could therefore dial every peer
// and durably suppress the tie it is itself a party to, with the audit row
// attributing it to "admin", while the SAFETY-FAULT on leader_lease_terms
// stands and `lv health` reads clean.
//
// The existing tests only exercise the operator path and stay green with the
// guard deleted.
func TestAcknowledgeLeaseTermTie_RefusesAPeer(t *testing.T) {
	s := testServer(t)
	ctx := context.WithValue(context.Background(), ctxKeyPrincipalKind, principalKindPeer)

	_, err := s.AcknowledgeLeaseTermTie(ctx, &pb.AcknowledgeLeaseTermTieRequest{
		Key: "failover", Term: 1,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a peer acknowledged a lease-term tie (err=%v); a node must not be able "+
			"to acknowledge a contest it is a party to", err)
	}
}
