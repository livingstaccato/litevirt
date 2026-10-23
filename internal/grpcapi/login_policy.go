package grpcapi

// Login rules auditors ask for: account disable and expiry, and a cluster-wide
// mandatory second factor (docs/auth.md, "Account lifecycle" and "Mandatory
// second factor"). Both are the release feature login_policy
// (login_policy_gate.go); see corrosion/user_lifecycle.go for why the state
// lives where it does.
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
	"github.com/litevirt/litevirt/internal/notify"
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
		"the login policy requires a second factor and this session's login presented none: "+
			"log in again with your second factor, or, if you have none yet, enroll one "+
			"(`lv 2fa enroll-totp --code <code from an admin>`, or Account in the web UI) and then log in again")
}

// revokeSessionFn is corrosion.RevokeSession, a variable so a test can make it
// fail (TestC1_FailedRevokeFailsTheEnrollment).
var revokeSessionFn = corrosion.RevokeSession

// walQuarantineUserRefusal begins refuseUserBearersInQuarantine's refusal.
const walQuarantineUserRefusal = "this host is in WAL quarantine"

// refuseUserBearersInQuarantine refuses every user credential on a node in WAL
// quarantine: its binary is below a capability the cluster has latched, so it
// may not enforce what that capability's rows say — a disable, the
// second-factor policy, a later release's rules. Local-root and peer mTLS are
// still served; they are how the node is repaired (t1-auth-review I8).
func (s *Server) refuseUserBearersInQuarantine() error {
	if s.db == nil {
		return nil
	}
	if reason := s.db.WriteQuarantineReason(); reason != "" {
		return status.Errorf(codes.Unavailable,
			walQuarantineUserRefusal+" (%s) and accepts no user logins, sessions or API tokens; "+
				"use another node", reason)
	}
	return nil
}

// refuseAmbiguousAccount refuses an API token whose account is one of two
// that normalize alike. A token names its account by exact stored name and so
// never passed through GetUser's duplicate refusal; a token of a legacy `ALICE`
// shadow would otherwise keep working beside a disabled `alice` (rereview m-d).
func (s *Server) refuseAmbiguousAccount(ctx context.Context, username string) error {
	if _, err := corrosion.GetUser(ctx, s.db, username); err != nil {
		if errors.Is(err, corrosion.ErrAmbiguousUsername) {
			return status.Errorf(codes.Unauthenticated, "%v (an administrator must remove one: "+
				"`lv user delete --exact <name>`)", err)
		}
		return status.Errorf(codes.Unavailable, "could not confirm account %q: %v", username, err)
	}
	return nil
}

// refuseInactiveAccount fails unless username's account may authenticate now.
// username must be the name as stored (corrosion.UserRecord.Username). A read
// that fails refuses too (Unavailable, retryable): an unreadable lifecycle
// cannot rule out a disable.
func (s *Server) refuseInactiveAccount(ctx context.Context, username string) error {
	_, err := s.accountLifecycle(ctx, username)
	return err
}

func (s *Server) accountLifecycle(ctx context.Context, username string) (corrosion.UserLifecycle, error) {
	life, err := corrosion.GetUserLifecycle(ctx, s.db, username)
	if err != nil {
		return life, status.Errorf(codes.Unavailable,
			"could not confirm account %q is active; refusing rather than guessing: %v", username, err)
	}
	if reason := life.InactiveReason(time.Now().UTC()); reason != "" {
		return life, status.Error(codes.Unauthenticated, reason)
	}
	return life, nil
}

// refuseInactiveToken is refuseInactiveAccount for an API token created at
// createdAt: it also refuses a token from before the account's last delete or
// re-create, so a token whose revoke never reached this node does not come
// back with the name (rereview-2 m-4).
func (s *Server) refuseInactiveToken(ctx context.Context, username, createdAt string) error {
	life, err := s.accountLifecycle(ctx, username)
	if err != nil {
		return err
	}
	if life.TokenPredates(createdAt) {
		return status.Error(codes.Unauthenticated, tokenCutoffRefusal(life, username, createdAt, ""))
	}
	return nil
}

// tokenCutoffAheadText describes a token cut-off dated further in the future
// than the skew margin: a node whose clock ran ahead wrote it, and every token
// of the account made before that time is refused (login-fu review Minor 2,
// as docs/auth.md says).
func tokenCutoffAheadText(life corrosion.UserLifecycle, username string) string {
	return fmt.Sprintf("the account's API token cut-off is dated %s, in the future, so no token made before then "+
		"works; a node's clock is ahead (see the clock-skew health check). For an admin account, root corrects the "+
		"cut-off at once with `lv user reset-admin --user %s` on a node whose litevirtd is running",
		life.TokensNotBefore, username)
}

// tokenCutoffRefusal is the message of an API token TokenPredates refuses,
// prefixed by prefix. A token created within the skew margin of the cut-off
// was most likely minted on a node the account's delete or re-create had not
// reached yet: it never works, and the message says why and what to do
// (re-review 4, m-4).
func tokenCutoffRefusal(life corrosion.UserLifecycle, username, createdAt, prefix string) string {
	if corrosion.CutoffAhead(life.TokensNotBefore, time.Now()) {
		return prefix + tokenCutoffAheadText(life, username)
	}
	if life.TokenNearCutoff(createdAt) {
		return fmt.Sprintf("%sAPI token was created at %s, within %s of the account's last delete or re-create "+
			"(%s), and the cut-off that change set refuses it: a token minted for the re-created account on a node "+
			"the change had not reached yet never works; create a new token, through the node the account was "+
			"re-created on, or once the change has replicated", prefix, createdAt, corrosion.SessionCutoffSkewMargin,
			life.TokensNotBefore)
	}
	return prefix + "API token predates the account's last delete or re-create"
}

// refuseInactiveSession is refuseInactiveAccount for a session created at
// createdAt: it also refuses a session from before the account's last disable
// or expiry, so re-enabling an account revives none of its old sessions —
// not even one whose row reached this node after the revocation sweep (m2).
func (s *Server) refuseInactiveSession(ctx context.Context, username, createdAt string) error {
	life, err := s.accountLifecycle(ctx, username)
	if err != nil {
		return err
	}
	if life.SessionPredates(createdAt) {
		return status.Error(codes.Unauthenticated, "session predates the account's last disable or expiry")
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
	enrolled, err = s.hasSecondFactor(ctx, username)
	return true, enrolled, err
}

// hasSecondFactor reports whether username has a factor enrolled, refusing to
// guess on a node whose credential tables a reseed emptied: an empty user_2fa
// there would read as "none", and an enrollment-only session could then enroll
// a factor of its own beside the real one. Same refusal as LocalRealm's.
func (s *Server) hasSecondFactor(ctx context.Context, username string) (bool, error) {
	if s.db.CredentialsUnhydrated() {
		return false, errors.New("this node's credential tables are not hydrated yet " +
			"(a reseed emptied them); cannot tell whether a second factor is enrolled")
	}
	factors, err := corrosion.ListUser2FA(ctx, s.db, username)
	if err != nil {
		return false, fmt.Errorf("list enrolled second factors for %q: %w", username, err)
	}
	if len(factors) > 0 {
		return true, nil
	}
	// A held factor counts: an enrollment-only session must not enroll one
	// of its own beside it.
	held, err := corrosion.ListHeldUser2FA(ctx, s.db, username)
	if err != nil {
		return false, fmt.Errorf("list held second factors for %q: %w", username, err)
	}
	return len(held) > 0, nil
}

// sessionEnrollOnly reports whether session sid, opened through realm, is
// confined: the policy requires a second factor there, and the session's
// login did not PRESENT one. That is a fact recorded when the session was
// minted (session_factors), never re-derived from the account's factors now —
// re-deriving it let a password-only session become a full one the moment
// anyone enrolled a factor for the account (t1-auth-review C1). So a confined
// session is confined for life. Evaluated on every request, so a policy
// switched on restricts a live session at once. A read that fails refuses the
// request (Unavailable).
func (s *Server) sessionEnrollOnly(ctx context.Context, sid, realm string) (bool, error) {
	p, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return false, status.Errorf(codes.Unavailable,
			"could not read the second-factor policy; refusing rather than guessing: %v", err)
	}
	if !p.Requires(realm) {
		return false, nil
	}
	factor, err := corrosion.SessionFactor(ctx, s.db, sid)
	if err != nil {
		return false, status.Errorf(codes.Unavailable,
			"could not read what this session's login presented; refusing rather than guessing: %v", err)
	}
	return factor == "", nil
}

// firstEnrollment is what an enrollment from a confined session must clear
// before anything is written (t1-auth-review C1, I5):
//
//   - the account has no factor yet. A confined session of an account that
//     HAS one proved only the password, and may not add a factor beside the
//     real one;
//   - an admin-issued enrollment code, unless the policy's self-enrollment
//     window is open;
//   - with commit, the session itself is ended FIRST, and a failure to end it
//     fails the enrollment: a confined session never outlives the factor it
//     enrolled, and is never promoted. Then the code is used up.
//
// It reports whether the caller is enrolling a first factor from a confined
// session; false (and nil) for every other caller, whom it leaves alone.
func (s *Server) firstEnrollment(ctx context.Context, code string, commit bool) (bool, error) {
	if !callerEnrollOnly(ctx) {
		return false, nil
	}
	user := callerUsername(ctx)
	has, err := s.hasSecondFactor(ctx, user)
	if err != nil {
		return false, status.Errorf(codes.Unavailable, "%v", err)
	}
	if has {
		return false, status.Error(codes.PermissionDenied,
			"this session's login did not present your second factor, so it cannot enroll another: "+
				"log in again presenting the one you have")
	}
	p, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return false, status.Errorf(codes.Unavailable, "read the second-factor policy: %v", err)
	}
	selfOK := p.SelfEnrollOpen(time.Now().UTC())
	if !selfOK {
		if err := corrosion.CheckEnrollmentCode(ctx, s.db, user, code, s.hostName); err != nil {
			var elsewhere corrosion.ErrEnrollmentCodeElsewhere
			if errors.As(err, &elsewhere) {
				s.audit(ctx, "2fa.enroll", user, "enrollment code issued on "+elsewhere.Node, "denied")
				return false, status.Error(codes.FailedPrecondition, err.Error())
			}
			s.audit(ctx, "2fa.enroll", user, "first factor without a valid enrollment code", "denied")
			return false, status.Error(codes.PermissionDenied,
				"enrolling your first factor needs an enrollment code from an administrator "+
					"(`lv 2fa enroll-code <user>`): "+err.Error())
		}
	}
	if !commit {
		return true, nil
	}
	if sid := callerSessionID(ctx); sid != "" {
		if err := revokeSessionFn(ctx, s.db, sid); err != nil {
			return false, status.Errorf(codes.Unavailable,
				"could not end this enrollment-only session, so nothing was enrolled: %v", err)
		}
		s.kickStreams()
	}
	if !selfOK {
		if err := s.withLoginPolicy(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
			if err := corrosion.ConsumeEnrollmentCode(ctx, s.db, g, user, code, s.hostName); err != nil {
				return status.Error(codes.PermissionDenied,
					"the enrollment code could not be used (used elsewhere, or expired): "+err.Error())
			}
			return nil
		}); err != nil {
			return false, err
		}
	}
	return true, nil
}

// noteFirstFactor records a first-factor enrollment from a confined session:
// an audit row, an event and a notification (auth.first_factor_enrolled), so
// an account claimed by whoever held only its password does not go unseen.
func (s *Server) noteFirstFactor(ctx context.Context, method string) {
	user := callerUsername(ctx)
	detail := "method=" + method + " from an enrollment-only session"
	s.audit(ctx, "auth.first_factor_enrolled", user, detail, "ok")
	s.publish("auth.first_factor_enrolled", user, detail)
	s.notify(ctx, notify.Notification{
		Kind: "auth.first_factor_enrolled", Severity: notify.SevWarn, Subject: user,
		Detail: user + " enrolled a first second factor (" + method + "); if that was not them, " +
			"remove it (`lv 2fa disable --user " + user + "`) and reset the account's password",
	})
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
		other, oerr := corrosion.OtherUnrestrictedAdminExists(ctx, s.db, user.Username, false)
		if oerr != nil {
			if pend := (*corrosion.AdminCredentialPendingError)(nil); errors.As(oerr, &pend) {
				return nil, status.Error(codes.Unavailable, lastAdminPendingRefusal(user.Username, pend))
			}
			return nil, status.Errorf(codes.Internal,
				"check for another admin before restricting %q: %v", user.Username, oerr)
		}
		if !other {
			return nil, status.Error(codes.FailedPrecondition, lastAdminRefusal(ctx, s.db, user.Username,
				"restricting it may leave the cluster with no administrator"))
		}
	}
	if err := s.withLoginPolicy(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		if err := corrosion.SetUserLifecycle(ctx, s.db, g, user.Username, req.Disabled, expires, callerUsername(ctx)); err != nil {
			if errors.Is(err, corrosion.ErrLoginPolicyGateClosed) {
				return status.Error(codes.FailedPrecondition, err.Error())
			}
			return userWriteStatus(err, "set account state")
		}
		return nil
	}); err != nil {
		return nil, err
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
	// Open streams of the account are re-checked now, not at the next tick.
	s.kickStreams()
	s.audit(ctx, "user.account", user.Username, strings.Join(detail, " "), "ok")
	s.publish("user.account", user.Username, strings.Join(detail, " "))
	slog.Info("account state changed", "username", user.Username, "detail", strings.Join(detail, " "),
		"by", callerUsername(ctx))

	out := &pb.User{Username: user.Username, Role: user.Role, Disabled: next.Disabled, ExpiresAt: next.ExpiresAt,
		Status: accountStatus(next, time.Now().UTC())}
	if t, err := time.Parse(time.RFC3339, user.CreatedAt); err == nil {
		out.CreatedAt = timestamppb.New(t)
	}
	return out, nil
}

// accountStatus is User.status: "active", "disabled" or "expired", judged by
// this daemon's clock (m1) — the clock every refusal on this node uses.
func accountStatus(l corrosion.UserLifecycle, now time.Time) string {
	if l.Disabled || l.Unreadable != "" {
		return "disabled"
	}
	if l.InactiveReason(now) != "" {
		return "expired"
	}
	return "active"
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
				"username", username, "session", sessionHandle(sess.ID), "error", err)
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
	return s.loginPolicyPB(p, 0, nil), nil
}

func (s *Server) loginPolicyPB(p corrosion.TwoFactorPolicy, revoked int, warnings []string) *pb.LoginPolicy {
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
		Settable:        s.ReleaseFeatureAvailable(capabilities.FeatureLoginPolicy),
		SessionsRevoked: int32(revoked),
		SelfEnrollBy:    p.SelfEnrollBy,
		Warnings:        warnings,
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
	// Self-enrollment is the exception and has to be asked for, with an end:
	// by default a first factor is enrolled only with an admin-issued code
	// (t1-auth-review I5). Re-setting the policy without the flag closes any
	// window an earlier change opened.
	if req.GetAllowSelfEnroll() {
		by, perr := time.Parse(time.RFC3339, req.GetEnrollBy())
		if perr != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"--allow-self-enroll needs --enroll-by <RFC3339>, the instant self-enrollment ends: %v", perr)
		}
		if !by.After(time.Now()) {
			return nil, status.Errorf(codes.InvalidArgument, "--enroll-by %s is not in the future", req.GetEnrollBy())
		}
		next.SelfEnrollBy = by.UTC().Format(time.RFC3339)
	} else if req.GetEnrollBy() != "" {
		return nil, status.Error(codes.InvalidArgument, "--enroll-by needs --allow-self-enroll")
	}
	// A realm named that this node does not have configured covers nothing
	// here (a typo, or a realm configured elsewhere). Set anyway, and say so.
	var warnings []string
	if s.realmRegistry != nil || len(next.Realms) > 0 {
		known := map[string]bool{"local": true}
		if s.realmRegistry != nil {
			for _, n := range s.realmRegistry.Names() {
				known[n] = true
			}
		}
		for _, r := range next.Realms {
			if !known[r] {
				warnings = append(warnings, fmt.Sprintf("realm %q is not configured on %s; the policy covers "+
					"it only where it is", r, s.hostName))
			}
		}
	}
	prev, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the current policy: %v", err)
	}
	if err := s.withLoginPolicy(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		if err := corrosion.SetTwoFactorPolicy(ctx, s.db, g, next, callerUsername(ctx)); err != nil {
			if errors.Is(err, corrosion.ErrLoginPolicyGateClosed) || errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
				return status.Error(codes.FailedPrecondition, err.Error())
			}
			return status.Errorf(codes.Internal, "set the second-factor policy: %v", err)
		}
		return nil
	}); err != nil {
		return nil, err
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
				slog.Warn("could not end a session the policy newly covers", "session", sessionHandle(sess.ID), "error", rerr)
				continue
			}
			revoked++
		}
	}
	s.kickStreams()
	detail := fmt.Sprintf("require_2fa=%s previous=%s self_enroll_by=%s sessions_ended=%d",
		next.Value, prev.Value, next.SelfEnrollBy, revoked)
	s.audit(ctx, "auth.login_policy", corrosion.LoginTwoFactorPolicyKey, detail, "ok")
	s.publish("auth.login_policy", next.Value, "set by "+callerUsername(ctx))
	cur, err := corrosion.GetTwoFactorPolicy(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the policy back: %v", err)
	}
	return s.loginPolicyPB(cur, revoked, warnings), nil
}

// IssueEnrollmentCode mints the single-use, short-lived code with which an
// enrollment-only session of an account enrolls its first factor (I5). Admin
// only — local root included, which is how a sole admin whose factor was
// cleared (`lv user reset-admin --clear-2fa`) gets one. The code is returned
// once and stored hashed; issuing another replaces it.
func (s *Server) IssueEnrollmentCode(ctx context.Context, req *pb.IssueEnrollmentCodeRequest) (*pb.IssueEnrollmentCodeResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if req.GetTtlSeconds() < 0 || ttl > corrosion.EnrollmentCodeMaxTTL {
		return nil, status.Errorf(codes.InvalidArgument, "an enrollment code lives between 1 second and %s",
			corrosion.EnrollmentCodeMaxTTL)
	}
	user, err := corrosion.GetUser(ctx, s.db, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "look up user %q: %v", req.GetUsername(), err)
	}
	if user == nil {
		return nil, status.Errorf(codes.NotFound, "user %q not found", req.GetUsername())
	}
	var code, exp string
	if err := s.withLoginPolicy(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		var ierr error
		code, exp, ierr = corrosion.IssueEnrollmentCode(ctx, s.db, g, user.Username, ttl, callerUsername(ctx), s.hostName)
		if ierr != nil {
			if errors.Is(ierr, corrosion.ErrLoginPolicyGateClosed) {
				return status.Error(codes.FailedPrecondition, ierr.Error())
			}
			return userWriteStatus(ierr, "issue enrollment code")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	s.audit(ctx, "2fa.enroll_code", user.Username, "expires_at="+exp+" issued_on="+s.hostName, "ok")
	// The code is bound to this node (rereview N3); say which, so the
	// operator hands the user the right address with it (rereview-2 m-5).
	return &pb.IssueEnrollmentCodeResponse{Code: code, ExpiresAt: exp, IssuedOn: s.hostName}, nil
}

// ListUserVariants lists every live account whose name normalizes like
// req.Username — the spellings a normalized lookup refuses to choose between —
// with what an operator chooses by: creation time, role, realm, last login
// seen here, and the factors and tokens each holds. Each carries the id an
// exact delete takes (rereview-2 m-7). Admin only.
func (s *Server) ListUserVariants(ctx context.Context, req *pb.ListUserVariantsRequest) (*pb.ListUserVariantsResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetUsername()) == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	vs, err := corrosion.UserVariants(ctx, s.db, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list accounts named like %q: %v", req.GetUsername(), err)
	}
	resp := &pb.ListUserVariantsResponse{}
	for _, v := range vs {
		resp.Variants = append(resp.Variants, &pb.UserVariant{
			Id: v.ID, Username: v.Username, CreatedAt: v.CreatedAt, Role: v.Role, Realm: v.Realm,
			LastLogin: v.LastLogin, Factors: int32(v.Factors), Tokens: int32(v.Tokens),
		})
	}
	return resp, nil
}

// ClearIdentityBinding drops the directory entry an external-realm account is
// bound to (rereview-2 N5), for when the directory re-created the user's entry
// under a new immutable id: the account's next login binds afresh. Admin only,
// audited, and refused until the login_policy release feature opens.
func (s *Server) ClearIdentityBinding(ctx context.Context, req *pb.ClearIdentityBindingRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetUsername() == "" || req.GetRealm() == "" {
		return nil, status.Error(codes.InvalidArgument, "username and realm required")
	}
	// One spelling of a case-duplicate pair is unbound by its exact stored
	// name (re-review 3, m-4): the normalized lookup refuses the pair.
	name := req.GetUsername()
	u, err := corrosion.GetUser(ctx, s.db, name)
	if errors.Is(err, corrosion.ErrAmbiguousUsername) {
		u, err = corrosion.GetUserExact(ctx, s.db, name)
		if err == nil && u == nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"two accounts are named like %q and neither is stored exactly so; `lv user delete --exact %s` "+
					"lists their stored names: run lv user unbind with the one you mean", name, name)
		}
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "look up user %q: %v", name, err)
	}
	if u != nil {
		name = u.Username
	}
	var was []string
	if err := s.withLoginPolicy(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		var cerr error
		was, cerr = corrosion.ClearIdentityBinding(ctx, s.db, g, name, req.GetRealm())
		if cerr != nil {
			if errors.Is(cerr, corrosion.ErrLoginPolicyGateClosed) {
				return status.Error(codes.FailedPrecondition, cerr.Error())
			}
			return status.Errorf(codes.Internal, "clear the identity binding: %v", cerr)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	s.audit(ctx, "user.identity_unbind", name, "realm="+req.GetRealm()+" was="+strings.Join(was, ","), "ok")
	return &emptypb.Empty{}, nil
}
