package grpcapi

import (
	"context"
	"strconv"
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

// macr3Marked is c carrying a drain-resume marker from host from, bound to
// the owner epoch VM "moved" is at in s.
func macr3Marked(s *Server, c context.Context, from string) context.Context {
	vm, err := corrosion.GetVM(context.Background(), s.db, "moved")
	if err != nil || vm == nil {
		panic("macr3Marked: no VM moved")
	}
	return metadata.NewIncomingContext(c, metadata.Pairs(DrainResumeFromMDKey, from,
		DrainResumeEpochMDKey, strconv.FormatInt(vm.OwnerEpoch, 10)))
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
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, ctx, "src-host"), "moved"); err != nil {
		t.Fatalf("the source's marker on a forwarded-identity peer call was ignored: %v", err)
	}
}

// The on-node root CLI (host certificate over loopback) is classified
// local-root, auth method mtls, CN this host. A drain's source is never the
// target, so a marker naming this host is not a drain resume.
func TestStartVM_LocalRootCannotClaimItsOwnDrain(t *testing.T) {
	s := macr3Setup(t)
	_ = peerCtxFor(t, s, s.hostName) // this host's own row
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, localRootCtx(s.hostName), s.hostName), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("on-node root with a marker naming this host: got %v, want FailedPrecondition", err)
	}
}

// A peer whose CN is not a cluster host (no row, no host certificate) is
// ignored even when its CN equals the claim.
func TestStartVM_AnUntrustedCNEqualToTheClaimIsIgnored(t *testing.T) {
	s := macr3Setup(t)
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, mtlsCtx("ghost-host"), "ghost-host"), "moved"); status.Code(err) != codes.FailedPrecondition {
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
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, ctx, "gone-host"), "moved"); status.Code(err) != codes.FailedPrecondition {
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
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, ctx, "src-host"), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a marker on an operator-stopped VM: got %v, want FailedPrecondition", err)
	}
}

// A host that dials its own advertise address arrives non-loopback, so it is
// classified a peer with CN = this host. A drain's source is never its
// target: its marker naming this host is no resume.
func TestStartVM_APeerCallFromThisHostCannotClaimItsOwnDrain(t *testing.T) {
	s := macr3Setup(t)
	ctx := peerCtxFor(t, s, s.hostName)
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, ctx, s.hostName), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a peer-classified call from this host with a self marker: got %v, want FailedPrecondition", err)
	}
}

// An operator's direct bearer carries no principal kind, whatever CN its
// transport presents: its marker naming the transport host is ignored.
func TestStartVM_AnOperatorBearerCannotPoseAsAPeer(t *testing.T) {
	s := macr3Setup(t)
	_ = peerCtxFor(t, s, "src-host")
	ctx := context.WithValue(context.Background(), ctxKeyAuthMethod, authMethodSession)
	ctx = context.WithValue(ctx, ctxKeyUsername, "op")
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, "src-host")
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, ctx, "src-host"), "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an operator bearer's marker: got %v, want FailedPrecondition", err)
	}
}

// The marker is bound to the move: it exempts the VM only at the owner epoch
// the drain handed it over at. A VM that has moved since (an operator's cold
// migrate of the stopped VM leaves it stopped with an empty detail, at a
// later epoch), and a marker with no epoch (an earlier build's source), are
// checked as any start.
func TestStartVM_ADrainMarkerIsBoundToTheMovesEpoch(t *testing.T) {
	s := macr3Setup(t)
	ctx := peerCtxFor(t, s, "src-host")
	if err := s.refuseStartOnSharedMAC(macr3Marked(s, ctx, "src-host"), "moved"); err != nil {
		t.Fatalf("the marker at the VM's epoch: %v", err)
	}
	noEpoch := metadata.NewIncomingContext(ctx, metadata.Pairs(DrainResumeFromMDKey, "src-host"))
	if err := s.refuseStartOnSharedMAC(noEpoch, "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a marker with no epoch: got %v, want FailedPrecondition", err)
	}
	stale := macr3Marked(s, ctx, "src-host")
	if err := s.db.Execute(context.Background(), `UPDATE vms SET vm_owner_epoch = vm_owner_epoch + 1, state_detail = '' WHERE name = 'moved'`); err != nil {
		t.Fatal(err)
	}
	if err := s.refuseStartOnSharedMAC(stale, "moved"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a marker from an earlier placement: got %v, want FailedPrecondition", err)
	}
}
