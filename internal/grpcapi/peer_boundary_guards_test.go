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

// TestCloneVM_DoesNotLeakSourceExistence: CloneVM resolved the source and
// reported NotFound before any authorization ran, so an authenticated caller
// with no rights in the source's project could enumerate VM names by reading
// the status code — NotFound means the name is free, PermissionDenied means
// another tenant owns it. VM names routinely encode customer and service
// identity.
//
// The clone itself was always refused; the leak was existence and naming.
func TestCloneVM_DoesNotLeakSourceExistence(t *testing.T) {
	s := testServer(t)
	// A caller with no role at all: requirePermPrecheck must refuse before the
	// source lookup, so both a real and an absent source answer identically.
	ctx := context.Background()

	_, errPresent := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "someone-elses-vm", Target: "mine"})
	_, errAbsent := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "no-such-vm-anywhere", Target: "mine"})

	if status.Code(errPresent) == codes.NotFound || status.Code(errAbsent) == codes.NotFound {
		t.Fatalf("CloneVM answered NotFound before authorizing (present=%v absent=%v); "+
			"that is a cross-tenant existence oracle", errPresent, errAbsent)
	}
	if status.Code(errPresent) != status.Code(errAbsent) {
		t.Errorf("a present and an absent source gave different codes (%v vs %v); "+
			"the difference is the oracle", status.Code(errPresent), status.Code(errAbsent))
	}
}
