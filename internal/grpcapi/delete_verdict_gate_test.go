package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

// The "target asked" verdict a delete's entry carries to the VM's host is
// honoured only over a peer certificate: a client (an operator bearer, a
// client certificate) that sets the header does not skip the owner's
// re-check under the lock — it could otherwise delete a VM whose guest cut
// over to the move's target, with the target never asked.
//
// Mutation: the header honoured without requirePeerCert — the operator's
// call passes, red.
func TestMoveTargetAsked_HonoursTheHeaderOnlyFromAPeer(t *testing.T) {
	s, _ := provableCreateServer(t)
	withHeader := func(ctx context.Context) context.Context {
		return metadata.NewIncomingContext(ctx, metadata.Pairs(moveTargetAskedMD, "1"))
	}
	if s.moveTargetAsked(withHeader(adminCtx())) {
		t.Fatal("an operator's call that sets the header was taken as the entry's verdict")
	}
	if s.moveTargetAsked(withHeader(context.Background())) {
		t.Fatal("a bare call that sets the header was taken as the entry's verdict")
	}
	if !s.moveTargetAsked(withHeader(peerCtxFor(t, s, "node-entry"))) {
		t.Fatal("a peer's forward that sets the header was not taken as the entry's verdict")
	}
	if s.moveTargetAsked(peerCtxFor(t, s, "node-quiet")) {
		t.Fatal("a peer's forward without the header was taken as the entry's verdict")
	}
	if !s.moveTargetAsked(withMoveTargetAsked(adminCtx())) {
		t.Fatal("the entry's own mark on its context was not honoured")
	}
}
