package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// Login validates credentials via the configured realm and mints a
// session-bearer ("lvs_<id>") on success. If the user has 2FA enrolled and
// no totp_code was supplied, returns RequiresTwoFA=true with an empty token
// so the client can re-call Login with the second factor (wires
// TOTP verification; until then enrolled-but-not-verified is rejected).
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	realmName := req.Realm
	if realmName == "" {
		realmName = "local"
	}

	// At least one credential family must be supplied. OIDC code-flow
	// uses oidc_code + oidc_state; password realms use username +
	// password. Mixed inputs are tolerated — the realm picks what it
	// needs from Credentials.
	hasPassword := req.Username != "" && req.Password != ""
	hasOIDCCode := req.OidcCode != "" && req.OidcState != ""
	if !hasPassword && !hasOIDCCode {
		return nil, status.Error(codes.InvalidArgument,
			"login requires either username+password or oidc_code+oidc_state")
	}

	clientIP := throttleClientIP(ctx)

	// A node in WAL quarantine accepts no user login (I8).
	if err := s.refuseUserBearersInQuarantine(); err != nil {
		return nil, err
	}

	// Brute-force lockout: refuse early if this (username, IP) is currently
	// locked out from too many recent failures. Keyed on the attempted
	// username so a correct password can't be ground out, and on IP so one
	// attacker can't lock a victim's account from afar.
	throttleKey := loginThrottleKey(req.Username, clientIP)
	if wait := s.loginThrottle.retryAfter(throttleKey); wait > 0 {
		s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" locked out ip="+clientIP, "denied")
		return nil, status.Errorf(codes.ResourceExhausted,
			"too many failed login attempts; retry in %s", wait.Round(time.Second))
	}

	// Realm dispatch: if a registry is wired, route by
	// name. Otherwise fall back to a hard-coded LocalRealm so tests
	// that don't construct a registry keep working.
	var realm auth.Realm
	if s.realmRegistry != nil {
		realm = s.realmRegistry.Get(realmName)
		if realm == nil {
			return nil, status.Errorf(codes.Unimplemented, "realm %q not configured", realmName)
		}
	} else if realmName == "local" {
		realm = auth.NewLocalRealm(s.db)
	} else {
		return nil, status.Errorf(codes.Unimplemented, "realm %q not configured (no registry)", realmName)
	}

	creds := auth.Credentials{
		Username:        req.Username,
		Password:        req.Password,
		OIDCCode:        req.OidcCode,
		OIDCState:       req.OidcState,
		OIDCRedirectURI: req.OidcRedirectUri,
	}
	principal, err := realm.Authenticate(ctx, creds)
	if err != nil {
		// Login is in skipAuth, so callerUsername(ctx) is empty here — record
		// the attempted username from the request as the audit target.
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.loginThrottle.fail(throttleKey)
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" invalid credentials", "denied")
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if errors.Is(err, auth.ErrRealmUnavailable) {
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" unavailable", "denied")
			return nil, status.Errorf(codes.Unavailable, "realm unavailable: %v", err)
		}
		s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" error", "denied")
		return nil, status.Errorf(codes.Internal, "authenticate: %v", err)
	}

	// One directory entry is one account (rereview-2 N5): an id already bound
	// to another account of this realm does not log in as this one. Checked
	// before the shadow, so a refused login creates no account.
	bindID := ""
	if realmName != "local" && principal.ExternalID != "" {
		bindID = principal.ExternalID
		bound, berr := corrosion.AccountsBoundTo(ctx, s.db, realmName, bindID)
		if berr != nil {
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" identity binding unreadable", "denied")
			return nil, status.Errorf(codes.Unavailable, "read the directory identity binding: %v", berr)
		}
		for _, other := range bound {
			if corrosion.NormalizeUsername(other) != corrosion.NormalizeUsername(principal.Subject) {
				s.audit(ctx, "auth.identity_mismatch", principal.Subject,
					"realm="+realmName+" directory id "+bindID+" is bound to the account "+other, "denied")
				return nil, status.Errorf(codes.PermissionDenied,
					"this directory entry is bound to another account; an administrator can clear the binding (lv user unbind)")
			}
		}
	}

	// External realms (OIDC/LDAP) may surface users not yet in the
	// local users table. Auto-shadow them so sessions / RBAC have a
	// stable subject. Default role is viewer; admins promote via
	// `lv role grant`.
	if realmName != "local" {
		if err := auth.EnsureUserShadow(ctx, s.db, principal, "viewer"); err != nil {
			return nil, status.Errorf(codes.Internal, "shadow user: %v", err)
		}
	}

	// Every per-account row is keyed on the name as stored, and every lookup
	// normalizes (corrosion.NormalizeUsername): from here on the subject is
	// the stored name, so `ALICE` is checked as the account `alice` is (I2).
	if u, uerr := corrosion.GetUser(ctx, s.db, principal.Subject); uerr != nil {
		s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" account lookup failed", "denied")
		return nil, status.Errorf(codes.Internal, "look up account: %v", uerr)
	} else if u != nil {
		principal.Subject = u.Username
	}

	// Account lifecycle: a disabled or expired account gets no session, and
	// no second-factor prompt either. Checked only after the credentials
	// verified, so it tells nothing to someone who does not hold them.
	if err := s.refuseInactiveAccount(ctx, principal.Subject); err != nil {
		s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" "+status.Convert(err).Message(), "denied")
		return nil, err
	}

	// The account is bound to the directory entry that first logged in to it
	// after the upgrade (rereview-2 N5): another entry answering to the same
	// name is refused, and audited, whatever its credentials.
	boundID := ""
	if bindID != "" {
		got, berr := corrosion.GetIdentityBinding(ctx, s.db, principal.Subject, realmName)
		if berr != nil {
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" identity binding unreadable", "denied")
			return nil, status.Errorf(codes.Unavailable, "read the directory identity binding: %v", berr)
		}
		if got != "" && got != bindID {
			s.audit(ctx, "auth.identity_mismatch", principal.Subject,
				"realm="+realmName+" bound to "+got+", login through "+bindID, "denied")
			return nil, status.Errorf(codes.PermissionDenied,
				"the account %q is bound to another directory entry; an administrator can clear the binding (lv user unbind)",
				principal.Subject)
		}
		boundID = got
	}

	// A login inside the skew margin after a lifecycle change would be
	// refused at the mint anyway (mintSession); refuse it HERE, before the
	// second factor is checked, so it does not use up the TOTP step (m-3).
	if life, lerr := s.accountLifecycle(ctx, principal.Subject); lerr != nil {
		return nil, lerr
	} else if life.SessionPredates(time.Now().UTC().Format(time.RFC3339)) {
		return nil, status.Errorf(codes.Unavailable,
			"the account was changed moments ago; log in again in %s", corrosion.SessionCutoffSkewMargin)
	}

	// Mandatory second factor. LocalRealm already demands an enrolled factor;
	// the policy demands it of every realm it covers, and a covered account
	// with none gets an enrollment-only session rather than no session.
	required, enrolled, perr := s.secondFactorRequirement(ctx, principal.Subject, realmName)
	if perr != nil {
		s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" second-factor policy unreadable", "denied")
		return nil, status.Errorf(codes.Unavailable, "evaluate the second-factor policy: %v", perr)
	}
	if required && enrolled {
		principal.Requires2FA = true
		// An OIDC code is single-use, so there is no second round in which to
		// ask for the factor: it has to arrive with the code. Answering
		// Requires_2Fa would send the client back with a spent code.
		if hasOIDCCode && !hasPassword && req.TotpCode == "" {
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" second factor missing", "denied")
			return nil, status.Errorf(codes.Unauthenticated,
				"realm %q requires a second factor: send totp_code together with the OIDC code", realmName)
		}
	}

	if principal.Requires2FA && req.TotpCode == "" {
		return &pb.LoginResponse{Requires_2Fa: true}, nil
	}
	if principal.Requires2FA {
		ok, err := s.verifyTOTP(ctx, principal.Subject, req.TotpCode)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "verify 2FA: %v", err)
		}
		if !ok {
			s.loginThrottle.fail(throttleKey)
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" invalid second factor", "denied")
			return nil, status.Error(codes.Unauthenticated, "invalid second factor")
		}
	}

	// Successful credential + (if required) second-factor verification —
	// clear any accumulated failure state for this key.
	s.loginThrottle.success(throttleKey)

	// First login since the upgrade (or since an unbind): bind the account to
	// the entry that just name-matched and proved its credentials. Before
	// login_policy_v1 latches nothing is written and the login proceeds
	// unbound, as on main.
	if bindID != "" && boundID == "" {
		switch berr := corrosion.BindIdentity(ctx, s.db, principal.Subject, realmName, bindID); {
		case berr == nil:
			s.audit(ctx, "auth.identity_bound", principal.Subject, "realm="+realmName+" id="+bindID, "ok")
		case errors.Is(berr, corrosion.ErrLoginPolicyGateClosed):
		case errors.Is(berr, corrosion.ErrIdentityBindingConflict):
			s.audit(ctx, "auth.identity_mismatch", principal.Subject,
				"realm="+realmName+" directory id "+bindID+" is bound to another account", "denied")
			return nil, status.Error(codes.PermissionDenied, "this directory entry is bound to another account")
		default:
			return nil, status.Errorf(codes.Unavailable, "record the directory identity binding: %v", berr)
		}
	}

	// What this login PRESENTED is recorded on the session (C1): the session
	// is a full one under the policy only if a factor was presented here.
	presented := ""
	if principal.Requires2FA {
		presented = "totp"
	}
	token, expiresAt, role, err := s.mintSession(ctx, principal.Subject, realmName, clientIP, req.UserAgent, presented)
	if err != nil {
		return nil, err
	}

	enrollOnly := required && !enrolled
	detail := "realm=" + realmName + " ip=" + clientIP
	if enrollOnly {
		// The role is withheld from the response as it is from the session:
		// until a factor is enrolled the session can do nothing that needs one.
		role = ""
		detail += " enrollment-only (second factor required, none enrolled)"
	}
	slog.Info("user logged in", "username", principal.Subject, "realm", realmName, "enrollment_only", enrollOnly)
	s.audit(ctx, "auth.login", principal.Subject, detail, "ok")
	return &pb.LoginResponse{
		Token:                  token,
		Username:               principal.Subject,
		Role:                   role,
		ExpiresAt:              expiresAt,
		Requires_2FaEnrollment: enrollOnly,
	}, nil
}

// mintSession creates a session row for an already-authenticated user and
// returns the bearer token, hard-expiry (RFC3339), and the user's role. Shared
// by password Login and the WebAuthn login flow so both produce identical
// session semantics.
//
// factor is the second factor this login presented ("" for none); it is
// recorded with the session (corrosion.InsertSessionWithFactor), and the
// second-factor policy reads it back for the session's whole life.
func (s *Server) mintSession(ctx context.Context, username, realm, clientIP, userAgent, factor string) (token, expiresAt, role string, err error) {
	// Fail closed if a reseed ran while these credentials were being checked.
	// See refuseIfReseedMovedSinceEntry: the interceptor's gate cannot drain a
	// request that was already inside when the reseed started.
	if err := s.refuseIfReseedMovedSinceEntry(ctx); err != nil {
		return "", "", "", err
	}
	user, gerr := corrosion.GetUser(ctx, s.db, username)
	if gerr != nil || user == nil {
		return "", "", "", status.Errorf(codes.Internal, "post-auth user lookup: %v", gerr)
	}
	// Every login path ends here, so this is the one check no path can skip —
	// the WebAuthn login reaches no other.
	if err := s.refuseUserBearersInQuarantine(); err != nil {
		return "", "", "", err
	}
	life, lerr := s.accountLifecycle(ctx, user.Username)
	if lerr != nil {
		return "", "", "", lerr
	}
	// A session minted inside the skew margin after a lifecycle change would
	// be refused on its first use (corrosion.SessionCutoffSkewMargin); say so
	// now instead of handing out a dead bearer.
	if life.SessionPredates(time.Now().UTC().Format(time.RFC3339)) {
		return "", "", "", status.Errorf(codes.Unavailable,
			"the account was changed moments ago; log in again in %s", corrosion.SessionCutoffSkewMargin)
	}
	username = user.Username
	id, ierr := newSessionID()
	if ierr != nil {
		return "", "", "", status.Errorf(codes.Internal, "generate session id: %v", ierr)
	}
	now := time.Now().UTC()
	exp := now.Add(s.hardExpiry())
	if serr := corrosion.InsertSessionWithFactor(ctx, s.db, corrosion.SessionRecord{
		ID:         id,
		Username:   username,
		Realm:      realm,
		IP:         clientIP,
		UserAgent:  userAgent,
		CreatedAt:  now.Format(time.RFC3339),
		LastUsedAt: now.Format(time.RFC3339),
		ExpiresAt:  exp.Format(time.RFC3339),
	}, factor); serr != nil {
		return "", "", "", status.Errorf(codes.Internal, "store session: %v", serr)
	}
	return SessionTokenPrefix + id, exp.Format(time.RFC3339), user.Role, nil
}

// ListRealms enumerates the authentication realms the daemon accepts
// Login against. The "local" realm is always present; OIDC/LDAP names
// come from auth.realms in the config. Bypasses auth so the login UI
// can populate the realm dropdown before any user is signed in.
func (s *Server) ListRealms(_ context.Context, _ *emptypb.Empty) (*pb.ListRealmsResponse, error) {
	resp := &pb.ListRealmsResponse{}
	if s.realmRegistry != nil {
		resp.Realms = s.realmRegistry.Names()
	} else {
		// Legacy / test path: no registry → only local works.
		resp.Realms = []string{"local"}
	}
	return resp, nil
}

// Logout revokes the current session (if the caller authenticated with one).
// Tokens (legacy API tokens) are not affected — use RevokeToken instead.
func (s *Server) Logout(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	sid := callerSessionID(ctx)
	if sid == "" {
		return &emptypb.Empty{}, nil
	}
	if err := corrosion.RevokeSession(ctx, s.db, sid); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke session: %v", err)
	}
	s.kickStreams()
	slog.Info("user logged out", "username", callerUsername(ctx))
	s.audit(ctx, "auth.logout", callerUsername(ctx), "session="+sid, "ok")
	return &emptypb.Empty{}, nil
}

// ListSessions returns active sessions for the requested user, or for the
// caller if username is empty. Listing other users' sessions requires admin.
func (s *Server) ListSessions(ctx context.Context, req *pb.ListSessionsRequest) (*pb.ListSessionsResponse, error) {
	caller := callerUsername(ctx)
	target := req.Username
	if target == "" {
		target = caller
	}
	if target != caller {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
		if u, err := corrosion.GetUser(ctx, s.db, target); err == nil && u != nil {
			target = u.Username
		}
	}
	rows, err := corrosion.ListSessionsForUser(ctx, s.db, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	resp := &pb.ListSessionsResponse{}
	for _, r := range rows {
		resp.Sessions = append(resp.Sessions, &pb.Session{
			Id:         r.ID,
			Username:   r.Username,
			Realm:      r.Realm,
			Ip:         r.IP,
			UserAgent:  r.UserAgent,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
			ExpiresAt:  r.ExpiresAt,
		})
	}
	return resp, nil
}

// RevokeSession terminates a session by id. The owning user can revoke
// their own; admins can revoke anyone's.
func (s *Server) RevokeSession(ctx context.Context, req *pb.RevokeSessionRequest) (*emptypb.Empty, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "session id required")
	}
	sess, err := corrosion.GetSession(ctx, s.db, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup session: %v", err)
	}
	if sess == nil {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if sess.Username != callerUsername(ctx) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	if err := corrosion.RevokeSession(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke session: %v", err)
	}
	s.kickStreams()
	slog.Info("session revoked", "id", req.Id, "username", sess.Username, "by", callerUsername(ctx))
	s.audit(ctx, "session.revoke", sess.Username, "session="+req.Id, "ok")
	return &emptypb.Empty{}, nil
}

// verifyTOTP delegates to the auth package's TOTP verifier. A successful
// recovery-code submission also returns true; the code is marked used.
func (s *Server) verifyTOTP(ctx context.Context, username, code string) (bool, error) {
	return auth.VerifyTOTP(ctx, s.db, username, code)
}

// loginThrottleKey identifies a brute-force bucket. An empty username (OIDC
// code-flow, which carries no username) falls back to IP-only so the bucket
// is still meaningful.
func loginThrottleKey(username, ip string) string {
	// Normalized like every account lookup, so `ALICE` and `alice ` share
	// alice's bucket instead of each getting a fresh allowance (I2).
	username = corrosion.NormalizeUsername(username)
	if username == "" {
		username = "_anon"
	}
	return username + "|" + ip
}

// newSessionID returns a 256-bit random hex string suitable as a session id.
func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.User, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	// Stored trimmed: every lookup ignores surrounding whitespace and ASCII
	// case (corrosion.NormalizeUsername), so the stored name must too.
	username := strings.Trim(req.Username, " \t\r\n")
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}
	role := req.Role
	if role == "" {
		role = "viewer"
	}

	existing, gerr := corrosion.GetUser(ctx, s.db, username)
	if gerr != nil {
		return nil, status.Errorf(codes.Internal, "look up user %q: %v", username, gerr)
	}
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "user %q already exists (as %q: names are compared "+
			"ignoring case and surrounding spaces)", username, existing.Username)
	}
	// An explicit CreateUser starts the name afresh: enabled, no expiry, and
	// none of a deleted namesake's sessions honoured. DeleteUser keeps the
	// lifecycle on purpose (m3), so this is the one place that clears it.
	// Before inserting, so a refusal leaves nothing behind.
	if err := corrosion.ResetUserLifecycle(ctx, s.db, username, callerUsername(ctx)); err != nil {
		if errors.Is(err, corrosion.ErrLoginPolicyGateClosed) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"%q belonged to an account with a disable or expiry, and this node cannot clear it until "+
					"login_policy_v1 has latched here; retry shortly or create it on another node", username)
		}
		return nil, status.Errorf(codes.Internal, "reset account state of %q: %v", username, err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), auth.BcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash password: %v", err)
	}

	if err := corrosion.InsertUser(ctx, s.db, username, role, string(hash)); err != nil {
		return nil, status.Errorf(codes.Internal, "create user: %v", err)
	}

	slog.Info("user created", "username", username, "role", role)
	s.publish("user.created", username, "role="+role)
	s.audit(ctx, "user.create", username, "role="+role, "ok")

	return &pb.User{Username: username, Role: role, Status: "active"}, nil
}

func (s *Server) ListUsers(ctx context.Context, _ *emptypb.Empty) (*pb.ListUsersResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	users, err := corrosion.ListUsers(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list users: %v", err)
	}

	lifecycles, err := corrosion.ListUserLifecycles(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list account states: %v", err)
	}

	resp := &pb.ListUsersResponse{}
	now := time.Now().UTC()
	for _, u := range users {
		life := lifecycles[u.Username]
		pbUser := &pb.User{Username: u.Username, Role: u.Role, Disabled: life.Disabled, ExpiresAt: life.ExpiresAt,
			Status: accountStatus(life, now)}
		if u.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, u.CreatedAt); err == nil {
				pbUser.CreatedAt = timestamppb.New(t)
			}
		}
		resp.Users = append(resp.Users, pbUser)
	}
	return resp, nil
}

func (s *Server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}

	// Refuse to remove the last account that can administer the cluster.
	//
	// There is no way back from that state through the API: `lv user
	// reset-admin` resets an EXISTING admin and deliberately refuses to mint a
	// missing one, and the daemon's startup seed only mints when the cluster has
	// never had a user at all. So the recovery path is rebuilding a node.
	//
	// The delete is also a soft delete, which makes the state worse than empty
	// rather than merely empty: a tombstoned admin is a row InsertUser will
	// REACTIVATE (`SET deleted_at = NULL`) with a fresh password and the admin
	// role still attached, and that reactivation replicates. A revoked
	// administrator is therefore one careless "is there anybody" check away from
	// coming back cluster-wide, so the cheapest place to stop it is here, before
	// the tombstone is ever written.
	//
	// A lookup that FAILS is not a report that the user is harmless. Falling
	// through on an unreadable database would skip the guard in exactly the
	// conditions where its answer matters most.
	//
	// Exact (`lv user delete --exact`) names the account as stored, byte for
	// byte: the one way to remove one of two accounts that differ only in case
	// or surrounding spaces, which every normalized lookup refuses (rereview
	// m-d). It is audited as such.
	var target *corrosion.UserRecord
	var err error
	if req.GetExact() {
		// The operator chooses ONE of the spellings by the id `lv user
		// delete --exact` lists (ListUserVariants) with the facts to choose
		// by — never by typing a name that differs from another only in case
		// or space (rereview-2 m-7).
		if req.GetExactId() == "" {
			return nil, status.Errorf(codes.InvalidArgument,
				"an exact delete names the account by id: run `lv user delete --exact %s` without --id to list the accounts and their ids",
				req.Username)
		}
		target, err = corrosion.GetUserExact(ctx, s.db, req.Username)
		if err == nil && (target == nil || corrosion.VariantID(target.Username, target.CreatedAt) != req.GetExactId()) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"no account %q with id %s; list them again with `lv user delete --exact %s`",
				req.Username, req.GetExactId(), req.Username)
		}
	} else {
		target, err = corrosion.GetUser(ctx, s.db, req.Username)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "look up user %q: %v", req.Username, err)
	}
	if target != nil && target.Role == "admin" {
		// Only an admin that can log in — enabled, with no expiry — counts
		// as the one that remains (t1-auth-review I4): a disabled successor
		// is "a live successor that cannot actually log in".
		other, oerr := corrosion.OtherUnrestrictedAdminExists(ctx, s.db, target.Username)
		if oerr != nil {
			return nil, status.Errorf(codes.Internal,
				"check for another admin before deleting %q: %v", req.Username, oerr)
		}
		if !other {
			return nil, status.Errorf(codes.FailedPrecondition,
				"user %q is the cluster's last admin account that is enabled with no expiry; create or "+
					"enable another admin first "+
					"(`lv user create <username> --role admin`), or the cluster is left with no "+
					"administrator",
				req.Username)
		}
	}

	name := req.Username
	if target != nil {
		name = target.Username
	}
	// A deleted account's credentials end with it, IN THE DELETE'S OWN BATCH
	// (rereview N2, rereview-2 N6/m-4): its sessions and API tokens are
	// revoked and durable session and token cut-offs written, so a floor
	// reinstatement or a re-create brings none of them back; and its open
	// streams are re-checked now and cut.
	ended, revokedTokens, err := corrosion.DeleteUserCounted(ctx, s.db, name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "delete user: %v", err)
	}
	s.kickStreams()
	// The OtherLiveAdminExists check above and this delete are two independent
	// operations against replicated state, and nothing makes that pair atomic
	// across LWW replicas. Two admins, one delete issued on each of two nodes:
	// both checks see the other admin alive, both pass, both tombstones
	// replicate, and the cluster has no administrator and no way back in.
	//
	// So the invariant is repaired rather than defended. This check, right
	// after the local delete, only catches a peer's tombstone that already
	// arrived; in the race above it has not, and this sees the other admin
	// alive. The repair that covers the race is the daemon's periodic admin
	// floor check (corrosion/admin_floor.go), which every node runs against
	// its own replica once the tombstones have crossed, and which picks the
	// same account on every replica. context.WithoutCancel: the delete has
	// already happened, and a cancelled request must not leave the cluster
	// admin-less.
	if reinstated, rerr := corrosion.ReinstateAdminIfNoneRemain(
		context.WithoutCancel(ctx), s.db); rerr != nil {
		slog.Error("could not verify an admin survived the delete", "deleted", req.Username, "error", rerr)
	} else if reinstated != "" {
		slog.Warn("deleting this user would have left the cluster with no administrator; "+
			"the most recently deleted admin was reinstated",
			"deleted", req.Username, "reinstated", reinstated)
		s.audit(ctx, "user.admin_reinstated", reinstated, "", "ok")
	}
	// Drop the deleted user's bindings from the live engine immediately, in
	// memory, for both the canonical and legacy-bare principal forms (matching
	// the DB tombstone in corrosion.DeleteUser) so access is revoked without
	// waiting for a reload.
	if s.authEngine != nil {
		s.authEngine.RemovePrincipal("user:" + name)
		s.authEngine.RemovePrincipal("user:" + name + "@local")
	}
	slog.Info("user deleted", "username", name, "sessions_ended", ended, "tokens_revoked", revokedTokens)
	s.publish("user.deleted", name, "")
	detail := fmt.Sprintf("sessions_ended=%d tokens_revoked=%d", ended, revokedTokens)
	if req.GetExact() {
		detail += " exact"
	}
	s.audit(ctx, "user.delete", name, detail, "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.Token, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "token name required")
	}

	// Verify user exists
	user, err := corrosion.GetUser(ctx, s.db, req.Username)
	if err != nil || user == nil {
		return nil, status.Errorf(codes.NotFound, "user %q not found", req.Username)
	}

	// Generate a random 32-byte token
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, status.Errorf(codes.Internal, "generate token: %v", err)
	}
	tokenStr := hex.EncodeToString(raw)

	hash, err := bcrypt.GenerateFromPassword([]byte(tokenStr), auth.BcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash token: %v", err)
	}

	id := randid.New()
	// Parse and normalise the expiry to bare UTC RFC3339.
	//
	// Expiry is enforced by ONE thing — the SQL string comparison
	// `t.expires_at > ?` against a bare RFC3339 now (corrosion/users.go). Storing
	// the caller's string verbatim made that a control that fails OPEN on a typo:
	// `--expires 30d` sorts above every "2..." timestamp, so the token never
	// expires, while the CLI reports success and `token-ls` shows an expiry that
	// means nothing. Normalising to UTC matters for the same reason — an
	// offset-bearing value parses but compares wrong by its offset.
	var expiresAt string
	if req.Expires != "" {
		t, perr := time.Parse(time.RFC3339, req.Expires)
		if perr != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid --expires %q: want an RFC3339 timestamp such as 2026-12-31T00:00:00Z (%v)",
				req.Expires, perr)
		}
		expiresAt = t.UTC().Format(time.RFC3339)
	}

	if err := corrosion.InsertToken(ctx, s.db, corrosion.TokenRecord{
		ID:         id,
		Username:   user.Username,
		Name:       req.Name,
		TokenHash:  string(hash),
		ExpiresAt:  expiresAt,
		ScopePaths: req.ScopePaths,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store token: %v", err)
	}

	slog.Info("token created", "username", req.Username, "name", req.Name, "id", id, "scopes", req.ScopePaths)
	s.audit(ctx, "token.create", id, "user="+req.Username+" name="+req.Name, "ok")
	// Return the plaintext token — only shown once.
	return &pb.Token{
		Id:       id,
		Username: req.Username,
		Name:     req.Name,
		Token:    tokenStr,
	}, nil
}

func (s *Server) RevokeToken(ctx context.Context, req *pb.RevokeTokenRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if err := corrosion.RevokeToken(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke token: %v", err)
	}
	s.kickStreams()
	slog.Info("token revoked", "id", req.Id)
	s.audit(ctx, "token.revoke", req.Id, "", "ok")
	return &emptypb.Empty{}, nil
}

// throttleClientIP is the address the brute-force lockout is keyed on.
//
// The HOST only. Addr.String() on TCP is "IP:PORT", and every reconnect gets a
// fresh ephemeral source port — so keying on it gave each attempt its own
// lockout bucket, and an attacker opening a new connection per try never
// accumulated a single failure. The limit existed and never engaged.
//
// A malformed or non-TCP address falls back to the whole string rather than to
// "": an unparsed address still separates one client from another, while ""
// collapses every caller into one bucket and lets a single attacker lock out
// the whole cluster.
func throttleClientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	full := p.Addr.String()
	host, _, err := net.SplitHostPort(full)
	if err != nil {
		return full
	}
	return host
}
