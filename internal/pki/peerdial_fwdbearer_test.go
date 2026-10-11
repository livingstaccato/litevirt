package pki

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestPropagateFwdBearer(t *testing.T) {
	// Inbound authorization bearer → outgoing FwdBearerMDKey (not "authorization").
	in := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer lvs_abc"))
	out := propagateFwdBearer(in)
	md, ok := metadata.FromOutgoingContext(out)
	if !ok {
		t.Fatal("no outgoing metadata")
	}
	if got := md.Get(FwdBearerMDKey); len(got) != 1 || got[0] != "Bearer lvs_abc" {
		t.Fatalf("%s = %v, want [Bearer lvs_abc]", FwdBearerMDKey, got)
	}
	// The standard authorization key is NOT set on the outgoing side (old
	// receivers must not switch identity).
	if got := md.Get("authorization"); len(got) != 0 {
		t.Errorf("outgoing authorization = %v, want none", got)
	}
}

func TestPropagateFwdBearer_PreservesExistingOutgoing(t *testing.T) {
	// Existing outgoing metadata (e.g. a repair-actor / proof header) must survive.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer lvs_abc"))
	ctx = metadata.AppendToOutgoingContext(ctx, "x-litevirt-repair-actor", "keep-me")
	out := propagateFwdBearer(ctx)
	md, _ := metadata.FromOutgoingContext(out)
	if got := md.Get("x-litevirt-repair-actor"); len(got) != 1 || got[0] != "keep-me" {
		t.Errorf("existing outgoing md dropped: %v", got)
	}
	if len(md.Get(FwdBearerMDKey)) != 1 {
		t.Errorf("fwd-bearer not appended alongside existing md")
	}
}

func TestPropagateFwdBearer_NoInboundBearer(t *testing.T) {
	// A system continuation (no inbound bearer) propagates nothing → the receiver
	// sees a plain peer call (system identity).
	out := propagateFwdBearer(context.Background())
	if md, ok := metadata.FromOutgoingContext(out); ok && len(md.Get(FwdBearerMDKey)) != 0 {
		t.Errorf("propagated fwd-bearer with no inbound bearer: %v", md.Get(FwdBearerMDKey))
	}

	// Inbound metadata present but empty authorization → nothing propagated.
	in := metadata.NewIncomingContext(context.Background(), metadata.Pairs("other", "x"))
	out = propagateFwdBearer(in)
	if md, ok := metadata.FromOutgoingContext(out); ok && len(md.Get(FwdBearerMDKey)) != 0 {
		t.Errorf("propagated fwd-bearer with no authorization header: %v", md.Get(FwdBearerMDKey))
	}
}

// Present-but-empty inbound MD (the notifyDetachedContext shape) must not
// propagate a bearer — empty is not "absent", and a nil-vs-empty confusion
// here would reintroduce finding 6.
func TestPropagateFwdBearer_PresentButEmptyIncomingMD(t *testing.T) {
	in := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	out := propagateFwdBearer(in)
	if md, ok := metadata.FromOutgoingContext(out); ok && len(md.Get(FwdBearerMDKey)) != 0 {
		t.Errorf("propagated fwd-bearer from empty inbound MD: %v", md.Get(FwdBearerMDKey))
	}
}

// A bearer that arrived forwarded is relayed ONLY where a caller asks for it
// (RelayForwardedBearer), not by every peer dial: the clone's own continuation
// calls ask, a third hop of any other operation does not change identity.
//
// Mutation: make propagateFwdBearer relay FwdBearerMDKey again, or drop the
// relay from RelayForwardedBearer.
func TestForwardedBearerIsRelayedOnlyOnRequest(t *testing.T) {
	in := metadata.NewIncomingContext(context.Background(), metadata.Pairs(FwdBearerMDKey, "Bearer lvs_abc"))
	if md, ok := metadata.FromOutgoingContext(propagateFwdBearer(in)); ok && len(md.Get(FwdBearerMDKey)) != 0 {
		t.Fatalf("every peer dial relays a forwarded bearer: %v", md)
	}
	md, ok := metadata.FromOutgoingContext(RelayForwardedBearer(in))
	if !ok || len(md.Get(FwdBearerMDKey)) != 1 || md.Get(FwdBearerMDKey)[0] != "Bearer lvs_abc" {
		t.Fatalf("RelayForwardedBearer dropped the caller: %v", md)
	}
	// With an authorization bearer the dial's own propagation already carries it.
	in = metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer mine", FwdBearerMDKey, "Bearer other"))
	if md, _ := metadata.FromOutgoingContext(RelayForwardedBearer(in)); len(md.Get(FwdBearerMDKey)) != 0 {
		t.Fatalf("RelayForwardedBearer added a second bearer beside authorization: %v", md.Get(FwdBearerMDKey))
	}
}
