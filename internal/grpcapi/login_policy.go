package grpcapi

// Login rules auditors ask for: account disable and expiry, and a cluster-wide
// mandatory second factor (docs/auth.md, "Account lifecycle" and "Mandatory
// second factor"). Both are gated on login_policy_v1; see
// corrosion/user_lifecycle.go for why the state lives where it does.
//
// WHERE THEY ARE ENFORCED. On every path that turns a credential into a user
// identity, and on nothing else:
//
//   - Login and the WebAuthn login (mintSession): no session is minted for an
//     inactive account.
//   - a session bearer, an API token, and either one forwarded by a peer
//     (authenticate, authenticateForwardedBearer): an existing credential stops
//     working the moment the replica says the account is inactive, so a disable
//     needs no revocation sweep to take effect, and an expiry needs no timer.
//
// The bearerless mTLS identities are not user accounts and are not touched:
// local-root (`lv user reset-admin` is the recovery path, and must keep
// working) and peer. The distributable lv-cli client certificate is the one
// gap a disable cannot close: it authenticates as the cluster admin with no
// user behind it. auth.strict_mtls_identity closes it, and docs/auth.md says
// so next to `lv user disable`.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// enrollmentOnlyMethods is everything an enrollment-only session may call:
// learn who it is, enroll a factor for ITS OWN account, read the policy that
// put it here, and log out. Cross-user enrollment is refused by the handlers'
// own RequireRole("admin"), because an enrollment-only session carries no
// role at all.
var enrollmentOnlyMethods = map[string]bool{
	"/litevirt.v1.LiteVirt/Whoami":                     true,
	"/litevirt.v1.LiteVirt/Logout":                     true,
	"/litevirt.v1.LiteVirt/GetLoginPolicy":             true,
	"/litevirt.v1.LiteVirt/ListTwoFactors":             true,
	"/litevirt.v1.LiteVirt/EnrollTOTP":                 true,
	"/litevirt.v1.LiteVirt/BeginWebAuthnRegistration":  true,
	"/litevirt.v1.LiteVirt/FinishWebAuthnRegistration": true,
}

// callerEnrollOnly reports whether the caller holds an enrollment-only session.
func callerEnrollOnly(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyEnrollOnly).(bool)
	return v
}

// gateEnrollmentOnly refuses every method but enrollmentOnlyMethods to an
// enrollment-only session. Runs in both interceptors right after authenticate.
func gateEnrollmentOnly(ctx context.Context, fullMethod string) error {
	if !callerEnrollOnly(ctx) || enrollmentOnlyMethods[fullMethod] {
		return nil
	}
	return status.Error(codes.PermissionDenied,
		"the login policy requires a second factor for your account and none is enrolled: "+
			"enroll one (`lv 2fa enroll-totp`, or Account in the web UI), then log in again")
}

// refuseInactiveAccount fails unless username's account may authenticate now.
// A read that fails refuses too (Unavailable, retryable): an unreadable
// lifecycle cannot rule out a disable.
func (s *Server) refuseInactiveAccount(ctx context.Context, username string) error {
	life, err := corrosion.GetUserLifecycle(ctx, s.db, username)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"could not confirm account %q is active; refusing rather than guessing: %v", username, err)
	}
	if reason := life.InactiveReason(time.Now().UTC()); reason != "" {
		return status.Error(codes.Unauthenticated, reason)
	}
	return nil
}

// secondFactorRequirement reports whether the policy requires a second factor
// of a login through realm, and if so whether username has one enrolled. Any
// read that fails is an error, which every caller turns into a refusal: an
// unreadable policy cannot rule out "required", and an unreadable factor list
// cannot rule out an enrolled factor that a password-only login would skip.
func (s *Server) secondFactorRequirement(ctx context.Context, username, realm string) (required, enrolled bool, err error) {
	p, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return false, false, fmt.Errorf("read the second-factor policy: %w", err)
	}
	if !p.Requires(realm) {
		return false, false, nil
	}
	// An emptied credential table reads as "no factors", which would turn an
	// enrolled account into an enrollment-only one — and let whoever holds the
	// password enroll a factor of their own. Same refusal as LocalRealm's.
	if s.db.CredentialsUnhydrated() {
		return true, false, errors.New("this node's credential tables are not hydrated yet " +
			"(a reseed emptied them); cannot tell whether a second factor is enrolled")
	}
	factors, err := corrosion.ListUser2FA(ctx, s.db, username)
	if err != nil {
		return true, false, fmt.Errorf("list enrolled second factors for %q: %w", username, err)
	}
	return true, len(factors) > 0, nil
}

// sessionEnrollOnly reports whether a session through realm is
// enrollment-only: the policy requires a second factor there and the account
// has none. Evaluated on every request, so a policy switched on, or a user's
// last factor removed, restricts a live session at once. A read that fails
// refuses the request (Unavailable).
func (s *Server) sessionEnrollOnly(ctx context.Context, username, realm string) (bool, error) {
	required, enrolled, err := s.secondFactorRequirement(ctx, username, realm)
	if err != nil {
		return false, status.Errorf(codes.Unavailable,
			"could not evaluate the second-factor policy for %q; refusing rather than guessing: %v", username, err)
	}
	return required && !enrolled, nil
}

// endEnrollmentSession revokes the caller's session when it is enrollment-only
// and reports whether it did. The session proved a password and nothing else;
// the factor it just enrolled has not been presented yet, so it does not get
// to become a full session — the next login presents it.
func (s *Server) endEnrollmentSession(ctx context.Context) bool {
	sid := callerSessionID(ctx)
	if !callerEnrollOnly(ctx) || sid == "" {
		return false
	}
	if err := corrosion.RevokeSession(ctx, s.db, sid); err != nil {
		slog.Warn("could not end the enrollment-only session after enrollment; it ends at its expiry",
			"user", callerUsername(ctx), "error", err)
		return false
	}
	s.audit(ctx, "auth.enrollment_session_end", callerUsername(ctx), "session="+sid, "ok")
	return true
}

// loginPolicySettable reports whether this host may write user_lifecycle and
// the second-factor policy: login_policy_v1 durably latched, as the corrosion
// gate requires too.
func (s *Server) loginPolicySettable() bool {
	return s.gate != nil && s.gate.DurablyLatched(capabilities.LoginPolicyV1)
}

func loginPolicyNotLatched() error {
	return status.Errorf(codes.FailedPrecondition,
		"account disable, expiry and the second-factor policy cannot be changed until %s has "+
			"latched on every host: finish rolling every host (and every host in maintenance) "+
			"to this release first", capabilities.LoginPolicyV1)
}

// SetUserAccount disables, re-enables, or sets the expiry of an account.
//
// Disabling an account, or giving it an expiry, ends its sessions as well as
// refusing them: a disable is enforced at authentication whatever happens
// here, but a session that outlived a disable would come back to life on
// re-enable, and re-enabling an account is not re-authenticating its holder.
// API tokens are left alone and work again on re-enable — they are
// administrator-issued automation, and `lv user token-revoke` is the tool for
// ending one.
func (s *Server) SetUserAccount(ctx context.Context, req *pb.SetUserAccountRequest) (*pb.User, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	if req.Disabled == nil && req.ExpiresAt == nil {
		return nil, status.Error(codes.InvalidArgument, "nothing to change: set disabled and/or expires_at")
	}
	var expires *string
	if req.ExpiresAt != nil {
		norm, err := corrosion.NormalizeExpiry(req.GetExpiresAt())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid expiry %q: %v", req.GetExpiresAt(), err)
		}
		expires = &norm
	}
	if !s.loginPolicySettable() {
		return nil, loginPolicyNotLatched()
	}
	user, err := corrosion.GetUser(ctx, s.db, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "look up user %q: %v", req.GetUsername(), err)
	}
	if user == nil {
		return nil, status.Errorf(codes.NotFound, "user %q not found", req.GetUsername())
	}
	cur, err := corrosion.GetUserLifecycle(ctx, s.db, user.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read account state of %q: %v", user.Username, err)
	}
	next := cur
	next.Unreadable = ""
	if req.Disabled != nil {
		next.Disabled = req.GetDisabled()
	}
	if expires != nil {
		next.ExpiresAt = *expires
	}
	// Never leave the cluster with only administrators who cannot log in. An
	// expiry counts as well as a disable: it is a disable on a timer. Only an
	// admin that is enabled with NO expiry counts as the one that remains.
	// Two admins restricting each other on two nodes can still race past this
	// (the check and the write are not atomic across replicas); `lv user
	// reset-admin` re-enables the admin account and is the recovery path.
	if user.Role == "admin" && !next.Unrestricted() {
		other, oerr := corrosion.OtherUnrestrictedAdminExists(ctx, s.db, user.Username)
		if oerr != nil {
			return nil, status.Errorf(codes.Internal,
				"check for another admin before restricting %q: %v", user.Username, oerr)
		}
		if !other {
			return nil, status.Errorf(codes.FailedPrecondition,
				"user %q is the cluster's last admin account that is enabled with no expiry; "+
					"create or enable another admin first, or the cluster may be left with no "+
					"administrator", user.Username)
		}
	}
	if err := corrosion.SetUserLifecycle(ctx, s.db, user.Username, req.Disabled, expires, callerUsername(ctx)); err != nil {
		if errors.Is(err, corrosion.ErrLoginPolicyGateClosed) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "set account state: %v", err)
	}

	var detail []string
	if req.Disabled != nil {
		detail = append(detail, fmt.Sprintf("disabled=%t", req.GetDisabled()))
	}
	if expires != nil {
		e := *expires
		if e == "" {
			e = "never"
		}
		detail = append(detail, "expires_at="+e)
	}
	ended := 0
	if (req.Disabled != nil && req.GetDisabled()) || expires != nil && *expires != "" {
		ended = s.revokeUserSessions(ctx, user.Username)
		detail = append(detail, fmt.Sprintf("sessions_ended=%d", ended))
	}
	s.audit(ctx, "user.account", user.Username, strings.Join(detail, " "), "ok")
	s.publish("user.account", user.Username, strings.Join(detail, " "))
	slog.Info("account state changed", "username", user.Username, "detail", strings.Join(detail, " "),
		"by", callerUsername(ctx))

	out := &pb.User{Username: user.Username, Role: user.Role, Disabled: next.Disabled, ExpiresAt: next.ExpiresAt}
	if t, err := time.Parse(time.RFC3339, user.CreatedAt); err == nil {
		out.CreatedAt = timestamppb.New(t)
	}
	return out, nil
}

// revokeUserSessions ends every live session of username and returns how many
// it ended. Best effort: the disable is enforced at authentication either way.
func (s *Server) revokeUserSessions(ctx context.Context, username string) int {
	sessions, err := corrosion.ListSessionsForUser(ctx, s.db, username)
	if err != nil {
		slog.Warn("could not list sessions to end them; they are refused at authentication anyway",
			"username", username, "error", err)
		return 0
	}
	n := 0
	for _, sess := range sessions {
		if err := corrosion.RevokeSession(ctx, s.db, sess.ID); err != nil {
			slog.Warn("could not end a session; it is refused at authentication anyway",
				"username", username, "session", sess.ID, "error", err)
			continue
		}
		n++
	}
	return n
}

// GetLoginPolicy reports the second-factor policy as this host's replica holds
// it. Any authenticated caller may read it, an enrollment-only session
// included: it is the rule that put that session there.
func (s *Server) GetLoginPolicy(ctx context.Context, _ *emptypb.Empty) (*pb.LoginPolicy, error) {
	p, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the second-factor policy: %v", err)
	}
	return s.loginPolicyPB(p, 0), nil
}

func (s *Server) loginPolicyPB(p corrosion.TwoFactorPolicy, revoked int) *pb.LoginPolicy {
	v := p.Value
	if p.Unknown {
		v = fmt.Sprintf("%s (unknown to this build: enforced as %q)", p.Value, corrosion.TwoFactorPolicyAll)
	}
	return &pb.LoginPolicy{
		Require_2Fa:     v,
		Realms:          p.Realms,
		AllRealms:       p.All,
		SetBy:           p.SetBy,
		UpdatedAt:       p.UpdatedAt,
		Settable:        s.loginPolicySettable(),
		SessionsRevoked: int32(revoked),
	}
}

// SetLoginPolicy changes the second-factor policy.
//
// Every live session in a realm the change newly covers is ended. Those
// sessions were opened under the old rule, so some proved only a password; a
// session row does not record which, so all of them go, the caller's own
// included. That is what makes the policy true from the moment it is set,
// rather than from the moment the last pre-policy session expires. API tokens
// are not sessions, are not ended, and are not subject to the policy.
func (s *Server) SetLoginPolicy(ctx context.Context, req *pb.SetLoginPolicyRequest) (*pb.LoginPolicy, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	next, err := corrosion.ParseTwoFactorPolicy(req.GetRequire_2Fa())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid policy %q: %v (valid: off, all, or a "+
			"comma-separated list of realms)", req.GetRequire_2Fa(), err)
	}
	if !s.loginPolicySettable() {
		return nil, loginPolicyNotLatched()
	}
	prev, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the current policy: %v", err)
	}
	if err := corrosion.SetTwoFactorPolicy(ctx, s.db, next, callerUsername(ctx)); err != nil {
		if errors.Is(err, corrosion.ErrLoginPolicyGateClosed) || errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "set the second-factor policy: %v", err)
	}
	revoked := 0
	if sessions, lerr := corrosion.ListLiveSessions(ctx, s.db); lerr != nil {
		slog.Warn("second-factor policy set, but the sessions it newly covers could not be listed "+
			"to end them; they are restricted at authentication if their account has no factor",
			"error", lerr)
	} else {
		for _, sess := range sessions {
			if !next.Requires(sess.Realm) || prev.Requires(sess.Realm) {
				continue
			}
			if rerr := corrosion.RevokeSession(ctx, s.db, sess.ID); rerr != nil {
				slog.Warn("could not end a session the policy newly covers", "session", sess.ID, "error", rerr)
				continue
			}
			revoked++
		}
	}
	detail := fmt.Sprintf("require_2fa=%s previous=%s sessions_ended=%d", next.Value, prev.Value, revoked)
	s.audit(ctx, "auth.login_policy", corrosion.LoginTwoFactorPolicyKey, detail, "ok")
	s.publish("auth.login_policy", next.Value, "set by "+callerUsername(ctx))
	cur, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the policy back: %v", err)
	}
	return s.loginPolicyPB(cur, revoked), nil
}
