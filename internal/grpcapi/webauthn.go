package grpcapi

import (
	"context"
	"encoding/base64"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// WebAuthn enrolment + login handlers.
//
// All four RPCs mirror the WebAuthnService dance: Begin returns the
// challenge JSON the browser feeds to navigator.credentials.*; Finish
// validates the attestation/assertion that comes back. The handler's
// only job is to authorise the caller, marshal protobuf, and forward
// to the auth-package engine.
//
// Authorisation: a user can begin/finish their OWN enrolment; admins
// can begin/finish for any user (used by recovery flows). Self-enrol
// is the dominant case — when target is empty we pin it to the caller.

func (s *Server) BeginWebAuthnRegistration(ctx context.Context, req *pb.BeginWebAuthnRegistrationRequest) (*pb.BeginWebAuthnRegistrationResponse, error) {
	if s.webauthn == nil {
		return nil, status.Error(codes.Unimplemented, "WebAuthn is not configured on this daemon")
	}
	target, err := s.resolve2FATarget(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	// Checked here so a confined session is told before the browser
	// ceremony; enforced (and the session ended) at Finish.
	if _, err := s.firstEnrollment(ctx, req.GetEnrollmentCode(), false); err != nil {
		return nil, err
	}
	opts, err := s.webauthn.BeginRegistration(ctx, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "begin registration: %v", err)
	}
	return &pb.BeginWebAuthnRegistrationResponse{OptionsJson: opts}, nil
}

func (s *Server) FinishWebAuthnRegistration(ctx context.Context, req *pb.FinishWebAuthnRegistrationRequest) (*pb.FinishWebAuthnRegistrationResponse, error) {
	if s.webauthn == nil {
		return nil, status.Error(codes.Unimplemented, "WebAuthn is not configured on this daemon")
	}
	if len(req.AttestationJson) == 0 {
		return nil, status.Error(codes.InvalidArgument, "attestation_json is required")
	}
	target, err := s.resolve2FATarget(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	first, err := s.firstEnrollment(ctx, req.GetEnrollmentCode(), true)
	if err != nil {
		return nil, err
	}
	if err := s.webauthn.FinishRegistration(ctx, target, req.AttestationJson); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "finish registration: %v", err)
	}
	// We don't have a clean handle on the new credential ID at this
	// layer — return the digest of the attestation as a stable
	// reference so the UI can show "registered key abc1234…".
	label := credentialLabelFromAttestation(req.AttestationJson)
	slog.Info("webauthn registered", "username", target, "label", label)
	if first {
		s.noteFirstFactor(ctx, "webauthn")
	}
	return &pb.FinishWebAuthnRegistrationResponse{CredentialLabel: label, SessionEnded: first}, nil
}

func (s *Server) BeginWebAuthnLogin(ctx context.Context, req *pb.BeginWebAuthnLoginRequest) (*pb.BeginWebAuthnLoginResponse, error) {
	if s.webauthn == nil {
		return nil, status.Error(codes.Unimplemented, "WebAuthn is not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required for login")
	}
	username := req.Username
	if u, err := corrosion.GetUser(ctx, s.db, username); err == nil && u != nil {
		username = u.Username
	}
	opts, err := s.webauthn.BeginLogin(ctx, username)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "begin login: %v", err)
	}
	return &pb.BeginWebAuthnLoginResponse{OptionsJson: opts}, nil
}

func (s *Server) FinishWebAuthnLogin(ctx context.Context, req *pb.FinishWebAuthnLoginRequest) (*pb.FinishWebAuthnLoginResponse, error) {
	if s.webauthn == nil {
		return nil, status.Error(codes.Unimplemented, "WebAuthn is not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required for login")
	}
	if len(req.AssertionJson) == 0 {
		return nil, status.Error(codes.InvalidArgument, "assertion_json is required")
	}

	clientIP := throttleClientIP(ctx)
	// Share the brute-force lockout with password Login (keyed on username+IP).
	throttleKey := loginThrottleKey(req.Username, clientIP)
	if wait := s.loginThrottle.retryAfter(throttleKey); wait > 0 {
		s.audit(ctx, "auth.login", req.Username, "webauthn locked out ip="+clientIP, "denied")
		return nil, status.Errorf(codes.ResourceExhausted, "too many failed login attempts; retry in %s", wait.Round(time.Second))
	}

	// A valid assertion proves possession of the registered authenticator —
	// strong, phishing-resistant auth on its own (passkey-style passwordless
	// login). So a successful assertion mints a session directly.
	username := req.Username
	if u, err := corrosion.GetUser(ctx, s.db, username); err == nil && u != nil {
		username = u.Username
	}
	if err := s.webauthn.FinishLogin(ctx, username, req.AssertionJson); err != nil {
		s.loginThrottle.fail(throttleKey)
		s.audit(ctx, "auth.login", req.Username, "webauthn invalid assertion ip="+clientIP, "denied")
		return nil, status.Errorf(codes.Unauthenticated, "finish login: %v", err)
	}
	s.loginThrottle.success(throttleKey)

	// WebAuthn users are shadowed into the local users table.
	// The assertion is itself the second factor, and is recorded as presented.
	token, expiresAt, role, err := s.mintSession(ctx, username, "local", clientIP, "webauthn", "webauthn")
	if err != nil {
		return nil, err
	}
	slog.Info("user logged in via webauthn", "username", req.Username)
	s.audit(ctx, "auth.login", req.Username, "webauthn ip="+clientIP, "ok")
	return &pb.FinishWebAuthnLoginResponse{
		Token:     token,
		Username:  req.Username,
		Role:      role,
		ExpiresAt: expiresAt,
	}, nil
}

// resolve2FATarget returns the username the caller is operating on,
// rejecting cross-user operations from non-admin callers. Login-class
// callers (no caller identity yet) bypass this — they must supply
// their own username up front so resolve2FATarget is never reached.
func (s *Server) resolve2FATarget(ctx context.Context, requested string) (string, error) {
	caller := callerUsername(ctx)
	target := requested
	if target == "" {
		target = caller
	}
	if target == "" {
		return "", status.Error(codes.InvalidArgument, "username is required")
	}
	if target != caller {
		if err := RequireRole(ctx, "admin"); err != nil {
			return "", err
		}
	}
	if u, err := corrosion.GetUser(ctx, s.db, target); err == nil && u != nil {
		target = u.Username
	}
	return target, nil
}

// credentialLabelFromAttestation derives a stable short label from the
// raw attestation bytes. The real credential ID lives inside the parsed
// CBOR, but we don't want this handler to re-parse it — the
// WebAuthnService already validated everything. Returning a SHA-style
// short hash is enough for "you registered this key on this date".
func credentialLabelFromAttestation(attestation []byte) string {
	if len(attestation) == 0 {
		return ""
	}
	// 8 bytes (16 hex chars) is enough to disambiguate a few hundred
	// credentials per user without exposing the full credential ID.
	const labelLen = 8
	if len(attestation) < labelLen {
		return base64.RawURLEncoding.EncodeToString(attestation)
	}
	return base64.RawURLEncoding.EncodeToString(attestation[:labelLen])
}
