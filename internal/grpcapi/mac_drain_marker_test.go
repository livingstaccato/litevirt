package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// The drain-resume marker, with the context the auth
// interceptor builds for each kind of caller.
func macr3Setup(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	const dup = "52:54:00:00:1f:01"
	// Recorded stopped by a drain for its move, as the target's row is.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "moved", HostName: s.hostName, State: "stopped", StateDetail: health.DrainStopDetail("op-1")},
		[]corrosion.InterfaceRecord{{VMName: "moved", NetworkName: "lan", MAC: dup}}, nil); err != nil {
		t.Fatal(err)
	}
	seedNICOf(t, s, "theirs", dup)
	return s
}

func macr3Marked(c context.Context, from string) context.Context {
	return metadata.NewIncomingContext(c, metadata.Pairs(DrainResumeFromMDKey, from))
}

// A drain's source host whose StartVM carried the operator's bearer
// (startOnOwner runs on the DrainHost request's context, and PeerDial relays
// its authorization as x-litevirt-fwd-bearer). With auth.forwarded_identity
// enforced, authenticateForwardedBearer promotes the call: auth method
// session, principal kind peer, CN the source's transport CN. The marker is
// still the source's, over its own peer mTLS.
func TestStartVM_AForwardedIdentityDrainKeepsItsMarker(t *testing.T) {
	s := macr3Setup(t)
	_ = peerCtxFor(t, s, "src-host") // the source is a live host
	ctx := context.WithValue(context.Background(), ctxKeyAuthMethod, authMethodSession)
	ctx = context.WithValue(ctx, ctxKeyUsername, "op")
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	ctx = context.WithValue(ctx, ctxKeyPrincipalKind, principalKindPeer)
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, "src-host")
	if err := s.refuseStartOnSharedMAC(macr3Marked(ctx, "src-host"), "moved"); err != nil {
		t.Fatalf("the source's marker on a forwarded-identity peer call was ignored: %v", err)
	}
}

// The on-node root CLI (host certificate over loopback) is classified
// local-root, auth method mtls, CN this host. A drain's source is never the
// target, so a marker naming this host is not a drain resume.
func TestStartVM_LocalRootCannotClaimItsOwnDrain(t *testing.T) {
	s := macr3Setup(t)
	_ = peerCtxFor(t, s, s.hostName) // this host's own row
	if err := s.refuseStartOnSharedMAC(macr3Marked(localRootCtx(s.hostName), s.hostName), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("on-node root with a marker naming this host: got %v, want FailedPrecondition", err)
	}
}

// A peer whose CN is not a cluster host (no row, no host certificate) is
// ignored even when its CN equals the claim.
func TestStartVM_AnUntrustedCNEqualToTheClaimIsIgnored(t *testing.T) {
	s := macr3Setup(t)
	if err := s.refuseStartOnSharedMAC(macr3Marked(mtlsCtx("ghost-host"), "ghost-host"), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an untrusted CN equal to the claim: got %v, want FailedPrecondition", err)
	}
}

// A removed host whose certificate CN equals the claim is ignored.
func TestStartVM_ARemovedHostsMarkerIsIgnored(t *testing.T) {
	s := macr3Setup(t)
	ctx := peerCtxFor(t, s, "gone-host")
	if err := s.db.Execute(context.Background(), `UPDATE hosts SET deleted_at = 't' WHERE name = 'gone-host'`); err != nil {
		t.Fatal(err)
	}
	if err := s.refuseStartOnSharedMAC(macr3Marked(ctx, "gone-host"), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a removed host's marker: got %v, want FailedPrecondition", err)
	}
}

// The marker exempts only a VM a drain recorded stopped for its move: on a
// VM an operator stopped, the same peer's marker exempts nothing.
func TestStartVM_ADrainMarkerOnAnOperatorStoppedVMIsChecked(t *testing.T) {
	s := macr3Setup(t)
	ctx := peerCtxFor(t, s, "src-host")
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state_detail = 'operator-stop' WHERE name = 'moved'`); err != nil {
		t.Fatal(err)
	}
	if err := s.refuseStartOnSharedMAC(macr3Marked(ctx, "src-host"), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a marker on an operator-stopped VM: got %v, want FailedPrecondition", err)
	}
}
