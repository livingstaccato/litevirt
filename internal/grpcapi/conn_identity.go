package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/pki"
)

// connIdentityGate refuses an RPC whose connection's identity is no longer
// acceptable, on every RPC, before anything else runs — Ping and the other
// unauthenticated methods included.
//
// Revocation and supersession are checked at the TLS handshake, but a gRPC
// connection outlives both: without this, a client holding a connection made
// before `lv host revoke-cert` (or before a renewal replaced its certificate)
// could go on starting RPCs on it — as a bearerless admin, or as a peer —
// until the connection tracker happened to close it, and an RPC kept in
// flight was enough to hold it open. So:
//
//   - a connection made with a REVOKED client certificate, or on which this
//     host served a certificate since revoked, refuses the RPC and is closed
//     at once (pki.DrainConnection), RPCs in flight included;
//   - a connection made with a certificate the CA has REPLACED (a standing
//     renewal successor this node holds, pki.SupersededBy) refuses the RPC
//     with Unavailable and drains: no new RPC is accepted on it, the RPCs
//     already in flight finish (up to pki.DefaultStreamGrace), and it is
//     closed when the last one ends. A legitimate client — the renewed host
//     itself, or this host's own UI/REST loopback client — reconnects and
//     presents its renewed certificate;
//   - a connection the tracker has already judged (draining) refuses every
//     new RPC.
//
// auth.trust_rotated_peer_certs turns the supersession check off, as it does
// the serial pins; revocation is never relaxed.
func (s *Server) connIdentityGate(ctx context.Context) error {
	ci, tracked := pki.ConnFromContext(ctx)
	if tracked && ci.Draining {
		return status.Errorf(codes.Unavailable, "this connection is closing (%s); reconnect", ci.DrainReason)
	}
	if s.pkiDir == "" {
		return nil
	}
	if leaf := peerLeafCert(ctx); leaf != nil && leaf.SerialNumber != nil {
		serial := strings.ToLower(leaf.SerialNumber.Text(16))
		if pki.IsRevokedCached(s.pkiDir, leaf.SerialNumber) {
			why := "the client certificate " + serial + " has been revoked"
			pki.DrainConnection(ctx, why, true)
			return status.Error(codes.Unauthenticated, why)
		}
		if !s.trustRotatedPeerCerts.Load() {
			if err := pki.SupersededError(s.pkiDir, leaf); err != nil {
				pki.DrainConnection(ctx, err.Error(), false)
				return status.Errorf(codes.Unavailable, "%v; reconnect to present the current certificate", err)
			}
		}
	}
	if tracked && ci.ServedSerial != "" {
		if n := mustSerialInt(ci.ServedSerial); n != nil && pki.IsRevokedCached(s.pkiDir, n) {
			why := "the certificate this host served on the connection (" + ci.ServedSerial + ") has been revoked"
			pki.DrainConnection(ctx, why, true)
			return status.Error(codes.Unavailable, why+"; reconnect")
		}
	}
	return nil
}
