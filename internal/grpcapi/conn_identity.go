package grpcapi

import (
	"context"
	"crypto/x509"
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
//     at once (pki.DrainConnection), RPCs in flight included — unless the
//     revoked certificate has a standing CA-issued successor this node holds
//     (pki.SupersededBy): then it was revoked because a renewal replaced it
//     (`lv host renew-cert` revokes the replaced certificate at once), which
//     is not an emergency, and the connection drains as below;
//   - a connection made with a certificate the CA has REPLACED (a standing
//     renewal successor this node holds, pki.SupersededBy), revoked yet or
//     not, refuses the RPC with Unavailable and drains: no new RPC is accepted
//     on it, the RPCs already in flight finish (up to pki.DefaultStreamGrace),
//     and it is closed when the last one ends. A legitimate client — the
//     renewed host itself, or this host's own UI/REST loopback client —
//     reconnects and presents its renewed certificate;
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
			if s.revokedByRenewal(leaf) {
				why := "the client certificate " + serial + " was replaced by a renewal and has been revoked"
				pki.DrainConnection(ctx, why, false)
				return status.Error(codes.Unavailable, why+"; reconnect to present the current certificate")
			}
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
			renewed := s.servedRevokedByRenewal(ci.ServedSerial)
			if renewed {
				why = "the certificate this host served on the connection (" + ci.ServedSerial +
					") was replaced by a renewal and has been revoked"
			}
			pki.DrainConnection(ctx, why, !renewed)
			return status.Error(codes.Unavailable, why+"; reconnect")
		}
	}
	return nil
}

// revokedByRenewal reports whether cert has a standing CA-issued successor
// this node holds (pki.SupersededBy): a revocation of it is the renewal's
// (`lv host renew-cert` revokes the replaced certificate at once), so a
// connection made with it drains — no new RPC, the RPCs in flight finish
// within pki.DefaultStreamGrace — rather than being cut. A revoked
// certificate with no such successor (`lv host rm`, `lv host revoke-cert` of
// a live identity, a stolen key) is the emergency path and is cut at once.
// Only the CA can sign a successor, and a successor revoked unused (an
// abandoned renewal) stands for nothing, so no replicated row can turn an
// emergency revocation into a drain.
func (s *Server) revokedByRenewal(cert *x509.Certificate) bool {
	return cert != nil && s.pkiDir != "" && pki.SupersededError(s.pkiDir, cert) != nil
}

// servedRevokedByRenewal is revokedByRenewal for a certificate this host
// SERVED, known by its serial. The host's current certificate is recorded as
// evidence first, so a node whose own renewal its certificate watch has not
// noticed yet still judges its replaced certificate a renewal.
func (s *Server) servedRevokedByRenewal(serial string) bool {
	if s.pkiDir == "" || serial == "" {
		return false
	}
	cur, err := pki.ServedHostCertificate(s.pkiDir)
	if err != nil || cur == nil {
		return false
	}
	pki.NoteSuccessor(s.pkiDir, cur)
	_, ok := pki.SupersededBy(s.pkiDir, cur.Subject.CommonName, serial)
	return ok
}
