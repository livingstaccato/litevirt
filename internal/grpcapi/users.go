package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
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
	"github.com/litevirt/litevirt/internal/capabilities"
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
	// uses oidc_code + oidc_state (or oidc_pending + totp_code, resuming one
	// that stopped for the second factor); password realms use username +
	// password. Mixed inputs are tolerated — the realm picks what it
	// needs from Credentials.
	hasPassword := req.Username != "" && req.Password != ""
	hasOIDCCode := req.OidcCode != "" && req.OidcState != ""
	oidcResume := req.OidcPending != "" && !hasPassword && !hasOIDCCode
	if !hasPassword && !hasOIDCCode && !oidcResume {
		return nil, status.Error(codes.InvalidArgument,
			"login requires either username+password, oidc_code+oidc_state, or oidc_pending+totp_code")
	}
	if oidcResume && !strings.HasPrefix(realmName, "oidc:") {
		return nil, status.Errorf(codes.InvalidArgument, "oidc_pending is only for an OIDC realm, not %q", realmName)
	}

	// The browser's address when this node's UI or REST gateway relays the
	// login, else the caller's own (forwardedClientAddress): recorded on the
	// session and keying the throttle, which otherwise saw every UI login as
	// 127.0.0.1.
	clientIP := s.forwardedClientAddress(ctx, req.ClientAddress)

	// A node in WAL quarantine accepts no user login (I8).
	if err := s.refuseUserBearersInQuarantine(); err != nil {
		return nil, err
	}

	// Brute-force lockout: refuse early if this (username, IP) is currently
	// locked out from too many recent failures. Keyed on the attempted
	// username so a correct password can't be ground out, and on IP so one
	// attacker can't lock a victim's account from afar.
	//
	// An OIDC realm takes no username from the client: the account is what
	// the IdP proves. Its failures are charged to the anonymous bucket (or,
	// resuming, to the subject the IdP proved, below), never to whatever a
	// client put in the username field, which would let a failed exchange
	// charge a real account's ceiling.
	throttleUser := req.Username
	if strings.HasPrefix(realmName, "oidc:") {
		throttleUser = ""
	}
	throttleKey := loginThrottleKey(throttleUser, clientIP)
	var pending *auth.Principal
	if oidcResume {
		// The principal the IdP proved is held on this node under the
		// handle; nothing about it comes from this request.
		p, ok := s.oidcPending.reserve(req.OidcPending, realmName)
		if !ok {
			s.audit(ctx, "auth.login", "", "realm="+realmName+" unknown or expired second-factor handle ip="+clientIP, "denied")
			return nil, status.Error(codes.Unauthenticated,
				"this OIDC login is unknown or expired on this node (or used up its attempts); log in again")
		}
		pending = p
		// A second factor is ground out per ACCOUNT, as the password realms'
		// is, not in the anonymous bucket every OIDC login shares.
		throttleKey = loginThrottleKey(p.Subject, clientIP)
	}
	if wait := s.loginThrottle.retryAfter(throttleKey); wait > 0 {
		why := " locked out ip=" + clientIP
		if s.loginThrottle.accountRetryAfter(throttleKey) > 0 {
			why = " locked out by the account throttle ip=" + clientIP
		}
		s.audit(ctx, "auth.login", req.Username, "realm="+realmName+why, "denied")
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
		OIDCBinding:     req.OidcBinding,
	}
	var principal *auth.Principal
	var err error
	if pending != nil {
		principal = pending
	} else {
		principal, err = realm.Authenticate(ctx, creds)
	}
	if err != nil {
		// Login is in skipAuth, so callerUsername(ctx) is empty here — record
		// the attempted username from the request as the audit target.
		if errors.Is(err, auth.ErrOIDCFlowBindingMismatch) {
			// A real state redeemed by a client that did not begin it: the
			// flow is now spent and the code was never presented. Not counted
			// against the shared anonymous bucket (that would let a stray
			// callback lock out every OIDC user of this node), but audited.
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" OIDC login redeemed by a client that did not begin it ip="+clientIP, "denied")
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if errors.Is(err, auth.ErrOIDCFlowUnknown) {
			// Not a credential guess (the state is 256 random bits), so it
			// does not count against the shared anonymous bucket — a stray
			// or replayed callback must not lock every OIDC user of this
			// node out.
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" unknown OIDC state ip="+clientIP, "denied")
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.loginThrottle.fail(throttleKey)
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" invalid credentials ip="+clientIP, "denied")
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if errors.Is(err, auth.ErrRealmUnavailable) {
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" unavailable ip="+clientIP, "denied")
			return nil, status.Errorf(codes.Unavailable, "realm unavailable: %v", err)
		}
		s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" error ip="+clientIP, "denied")
		return nil, status.Errorf(codes.Internal, "authenticate: %v", err)
	}

	// One directory entry is one account (rereview-2 N5): an id already bound
	// to another account of this realm does not log in as this one. Checked
	// before the shadow, so a refused login creates no account. Every id the
	// entry carries is checked (re-review 3, m-3), and the owner of an id
	// bound to two accounts by two nodes is the first binding (m-1).
	bindID := ""
	if realmName != "local" && principal.ExternalID != "" {
		bindID = principal.ExternalID
		for _, id := range entryIDs(principal) {
			own, berr := corrosion.IdentityOwner(ctx, s.db, realmName, id)
			if berr != nil {
				s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" identity binding unreadable ip="+clientIP, "denied")
				return nil, status.Errorf(codes.Unavailable, "read the directory identity binding: %v", berr)
			}
			if own.Contested() {
				s.auditBindingConflict(ctx, principal.Subject, realmName, "directory id "+id+" bound to accounts", own)
			}
			if other := otherOwner(own, principal.Subject); other != "" {
				s.audit(ctx, "auth.identity_mismatch", principal.Subject,
					"realm="+realmName+" directory id "+id+" is bound to the account "+other, "denied")
				return nil, status.Errorf(codes.PermissionDenied,
					"this directory entry is bound to the account %q; an administrator can clear that binding: "+
						"lv user unbind %s %s", other, other, realmName)
			}
		}
	}

	// External realms (OIDC/LDAP) may surface users not yet in the
	// local users table. Auto-shadow them so sessions / RBAC have a
	// stable subject. Default role is viewer; admins promote via
	// `lv role grant`.
	if realmName != "local" {
		if err := auth.EnsureUserShadow(ctx, s.db, principal, "viewer"); err != nil {
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" shadow refused ip="+clientIP, "denied")
			switch {
			case errors.Is(err, auth.ErrShadowPending):
				return nil, status.Errorf(codes.Unavailable, "retry: %v", err)
			case errors.Is(err, auth.ErrExternalUnproven):
				return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
			case errors.Is(err, auth.ErrLocalAccount):
				return nil, status.Errorf(codes.PermissionDenied, "%v", err)
			}
			return nil, status.Errorf(codes.Internal, "shadow user: %v", err)
		}
	}

	// Every per-account row is keyed on the name as stored, and every lookup
	// normalizes (corrosion.NormalizeUsername): from here on the subject is
	// the stored name, so `ALICE` is checked as the account `alice` is (I2).
	if u, uerr := corrosion.GetUser(ctx, s.db, principal.Subject); uerr != nil {
		s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" account lookup failed ip="+clientIP, "denied")
		if realmName == "local" && hasPassword && !principal.Requires2FA {
			// Password authentication succeeded, but the current account can no
			// longer be established. Never downgrade this to missing local proof.
			return nil, automationCredentialUnavailable(uerr)
		}
		return nil, status.Errorf(codes.Internal, "look up account: %v", uerr)
	} else if u != nil {
		principal.Subject = u.Username
	}

	// Account lifecycle: a disabled or expired account gets no session, and
	// no second-factor prompt either. Checked only after the credentials
	// verified, so it tells nothing to someone who does not hold them.
	if err := s.refuseInactiveAccount(ctx, principal.Subject); err != nil {
		s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" "+status.Convert(err).Message()+" ip="+clientIP, "denied")
		return nil, err
	}

	// The account is bound to the directory entry that first logged in to it
	// after the upgrade (rereview-2 N5): another entry answering to the same
	// name is refused, and audited, whatever its credentials.
	//
	// Bindings are first-binder-wins (re-review 3, m-1): a later binding a
	// lagging node made beside the first never displaces it, two too close
	// for clocks to order refuse every login until an administrator unbinds,
	// and both are audited. The binding holds when it is ANY immutable id the
	// entry carries (m-3), so a directory that starts returning a stronger id
	// first does not lock the account out; a DN never stands in for one.
	boundID := ""
	var losingBindings []corrosion.IdentityBinding
	if bindID != "" {
		res, berr := corrosion.ResolveIdentityBinding(ctx, s.db, principal.Subject, realmName)
		if berr != nil {
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" identity binding unreadable ip="+clientIP, "denied")
			return nil, status.Errorf(codes.Unavailable, "read the directory identity binding: %v", berr)
		}
		if res.Contested() {
			s.auditBindingConflict(ctx, principal.Subject, realmName, "account bound to directory ids", res)
		}
		if res.Conflict {
			return nil, status.Errorf(codes.PermissionDenied,
				"the account %q is bound to %d directory entries at once, and none was bound first; an "+
					"administrator must clear the bindings: lv user unbind %s %s",
				principal.Subject, len(res.All), principal.Subject, realmName)
		}
		got := res.Winner.ExternalID
		if got != "" && !slices.Contains(entryIDs(principal), got) {
			s.audit(ctx, "auth.identity_mismatch", principal.Subject,
				"realm="+realmName+" bound to "+got+", login through "+bindID, "denied")
			return nil, status.Errorf(codes.PermissionDenied,
				"the account %q is bound to another directory entry; if the directory re-created this user's "+
					"entry, an administrator can clear the binding: lv user unbind %s %s",
				principal.Subject, principal.Subject, realmName)
		}
		boundID = got
		if res.Contested() {
			losingBindings = res.All[1:]
		}
	}

	// A login inside the skew margin after a lifecycle change would be
	// refused at the mint anyway (mintSession); refuse it HERE, before the
	// second factor is checked, so it does not use up the TOTP step (m-3).
	if life, lerr := s.accountLifecycle(ctx, principal.Subject); lerr != nil {
		return nil, lerr
	} else if life.SessionPredates(time.Now().UTC().Format(time.RFC3339)) {
		return nil, sessionCutoffRefusal(life, principal.Subject)
	}

	// Mandatory second factor. LocalRealm already demands an enrolled factor;
	// the policy demands it of every realm it covers, and a covered account
	// with none gets an enrollment-only session rather than no session.
	required, enrolled, perr := s.secondFactorRequirement(ctx, principal.Subject, realmName)
	if perr != nil {
		s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" second-factor policy unreadable ip="+clientIP, "denied")
		return nil, status.Errorf(codes.Unavailable, "evaluate the second-factor policy: %v", perr)
	}
	oidcLogin := (hasOIDCCode || oidcResume) && !hasPassword
	if required && enrolled {
		principal.Requires2FA = true
	}
	// litevirt's own policy decides the second factor for an OIDC login too:
	// what the IdP did (its amr/acr claims) is not read, because nothing in
	// litevirt's design makes an IdP's MFA stand in for the account's factor.

	if principal.Requires2FA && req.TotpCode == "" {
		if oidcLogin {
			// The OIDC code is spent, so there is no second round that could
			// resend it. Hold what the IdP proved under a short-lived handle
			// on this node; the client sends the factor with it.
			handle := req.OidcPending
			if !oidcResume {
				h, perr := s.oidcPending.put(realmName, principal)
				if perr != nil {
					return nil, status.Error(codes.ResourceExhausted, perr.Error())
				}
				handle = h
			}
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" second factor required ip="+clientIP, "pending")
			return &pb.LoginResponse{Requires_2Fa: true, OidcPending: handle}, nil
		}
		return &pb.LoginResponse{Requires_2Fa: true}, nil
	}
	if principal.Requires2FA {
		ok, err := s.verifyTOTP(ctx, principal.Subject, req.TotpCode)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "verify 2FA: %v", err)
		}
		if !ok {
			s.loginThrottle.fail(throttleKey)
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" invalid second factor ip="+clientIP, "denied")
			return nil, status.Error(codes.Unauthenticated, "invalid second factor")
		}
	}
	if oidcResume {
		// Single use: whatever happens from here, this handle is done.
		defer s.oidcPending.drop(req.OidcPending)
	}

	// Successful credential + (if required) second-factor verification —
	// clear any accumulated failure state for this key.
	s.loginThrottle.success(throttleKey)

	// First login since the upgrade (or since an unbind): bind the account to
	// the entry that just name-matched and proved its credentials. Until the
	// login_policy release feature opens nothing is written and the login
	// proceeds unbound, as on main; a login is never refused for it
	// (withLoginPolicyIfAvailable).
	// A login through the binding that won a conflict proves that entry once
	// more; the losing bindings beside it are cleared, so the conflict is
	// audited once rather than at every login, and an unbind is never needed
	// to settle a conflict the rule already decided.
	if len(losingBindings) > 0 {
		if err := s.withLoginPolicyIfAvailable(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
			return corrosion.ClearIdentityBindingRows(ctx, s.db, g, losingBindings)
		}); err == nil {
			s.audit(ctx, "auth.identity_conflict", principal.Subject,
				"realm="+realmName+" cleared the later bindings "+strings.Join(corrosion.IdentityResolution{All: losingBindings}.IDs(), ",")+
					" after a login through the first, "+boundID, "ok")
		} else if !errors.Is(err, corrosion.ErrLoginPolicyGateClosed) {
			slog.Warn("could not clear the losing directory bindings", "user", principal.Subject, "realm", realmName, "error", err)
		}
	}
	if bindID != "" && boundID == "" {
		switch berr := s.withLoginPolicyIfAvailable(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
			return corrosion.BindIdentity(ctx, s.db, g, principal.Subject, realmName, bindID)
		}); {
		case berr == nil:
			s.audit(ctx, "auth.identity_bound", principal.Subject, "realm="+realmName+" id="+bindID, "ok")
		case errors.Is(berr, corrosion.ErrLoginPolicyGateClosed):
		case errors.Is(berr, corrosion.ErrIdentityBindingConflict):
			s.audit(ctx, "auth.identity_mismatch", principal.Subject,
				"realm="+realmName+" directory id "+bindID+" is bound to another account", "denied")
			return nil, status.Errorf(codes.PermissionDenied,
				"this directory entry is bound to another account; `lv user unbind <account> %s` clears that "+
					"binding (an administrator)", realmName)
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
	groups, dropped := corrosion.NormalizeSessionGroups(principal.Groups)
	if realmName == "local" {
		groups, dropped = nil, 0
	}
	if dropped > 0 {
		slog.Warn("login: directory groups not recorded (empty, over-long or over the limit)",
			"user", principal.Subject, "realm", realmName, "dropped", dropped, "limit", corrosion.MaxSessionGroups)
	}
	var authentication *corrosion.AutomationAccountAuthentication
	if realmName == "local" && hasPassword && !principal.Requires2FA && !required && presented == "" {
		var disposition corrosion.AutomationCredentialDisposition
		authentication, disposition, err = corrosion.PrepareAutomationLocalSession(ctx, s.db, principal.Subject, req.Password)
		if err != nil {
			return nil, automationCredentialUnavailable(err)
		}
		switch disposition {
		case corrosion.AutomationCredentialEligible:
			if authentication == nil {
				return nil, automationCredentialUnavailable(nil)
			}
		case corrosion.AutomationCredentialNoLocalProof, corrosion.AutomationCredentialUnsupportedFlow:
			authentication = nil
		default:
			return nil, automationCredentialUnavailable(nil)
		}
	}
	token, expiresAt, role, err := s.mintSessionWithAuthentication(ctx, principal.Subject, realmName, clientIP, req.UserAgent, presented, groups, authentication)
	if err != nil {
		return nil, err
	}
	s.auditGroupBindings(ctx, principal.Subject, realmName, token, groups)

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

// sessionCutoffRefusal is the refusal of a login made before the account's
// session cut-off and its skew margin have passed: it says when a login will
// work (re-review 4, m-2). A cut-off dated further ahead than the margin was
// written by a node whose clock ran ahead; nothing but root's reset-admin
// moves it back, so the refusal names that too.
func sessionCutoffRefusal(life corrosion.UserLifecycle, username string) error {
	at := life.SessionsRetryAt()
	if corrosion.CutoffAhead(life.SessionsNotBefore, time.Now()) {
		return status.Errorf(codes.Unavailable,
			"the account was changed with a cut-off dated %s, in the future, so no login works until after %s; "+
				"a node's clock is ahead (see the clock-skew health check). For an admin account, root corrects the "+
				"cut-off at once with `lv user reset-admin --user %s` on a node whose litevirtd is running",
			life.SessionsNotBefore, at, username)
	}
	return status.Errorf(codes.Unavailable,
		"the account was changed moments ago; log in again after %s (in at most %s)", at, corrosion.SessionCutoffSkewMargin)
}

// lastAdminPendingRefusal is the message of a last-admin refusal made because
// the only other admins that might log in are ones whose credential has not
// reached this node (corrosion.AdminCredentialPendingError): the guard fails
// closed, and the change can be retried once it has.
func lastAdminPendingRefusal(username string, pend *corrosion.AdminCredentialPendingError) string {
	return fmt.Sprintf("user %q may be the cluster's last admin account that can log in: %v, so the change is refused "+
		"for now. Retry in a moment, once it has replicated, or make the change on another node", username, pend)
}

// lastAdminRefusal is the message of a last-admin refusal. Every way out it
// names is one the refused caller — a logged-in admin — can take, with its
// arguments (re-review 3, I1b): create another admin, enable or un-expire a
// restricted one, or resolve a case-duplicate admin pair, which counts as no
// admin until one spelling is deleted by its id. An admin the admin floor
// reinstated without a credential counts as none either (re-review 4, m-1):
// root gives it one with `lv user reset-admin --user`.
func lastAdminRefusal(ctx context.Context, db *corrosion.Client, username, why string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "user %q is the cluster's last admin account that can log in, enabled with no expiry, and %s. "+
		"First make another admin usable: create one (`lv user create <username> --role admin`)", username, why)
	if rep, err := corrosion.AdminLoginState(ctx, db); err == nil {
		for _, u := range rep.AwaitingCredential {
			if u != username {
				fmt.Fprintf(&b, "; or give %s, which the admin floor reinstated with no credential, one: as root on "+
					"a node, `lv user reset-admin --user %s`", u, u)
			}
		}
	}
	users, err := corrosion.ListUsers(ctx, db)
	if err == nil {
		lifes, _ := corrosion.ListUserLifecycles(ctx, db)
		seen := map[string]int{}
		for _, u := range users {
			seen[corrosion.NormalizeUsername(u.Username)]++
		}
		pairs := map[string]bool{}
		for _, u := range users {
			if u.Role != "admin" || u.Username == username {
				continue
			}
			norm := corrosion.NormalizeUsername(u.Username)
			switch l := lifes[u.Username]; {
			case seen[norm] > 1 && !pairs[norm]:
				pairs[norm] = true
				fmt.Fprintf(&b, "; or resolve the duplicate admin accounts named like %q, which cannot log in "+
					"while both exist (`lv user delete --exact %s` lists them, then `lv user delete --exact %s --id <ID>`)",
					u.Username, norm, norm)
			case seen[norm] > 1:
			case l.Disabled:
				fmt.Fprintf(&b, "; or enable %s (`lv user enable %s`)", u.Username, u.Username)
			case l.ExpiresAt != "":
				fmt.Fprintf(&b, "; or lift %s's expiry (`lv user expire %s never`)", u.Username, u.Username)
			}
		}
	}
	return b.String()
}

// entryIDs is every immutable id the principal's entry carries, its primary
// ExternalID first.
func entryIDs(p *auth.Principal) []string {
	out := []string{p.ExternalID}
	for _, id := range p.ExternalIDs {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// otherOwner is the account other than subject that owns an id by res, ""
// when it is subject's or nobody's. A conflict between bindings of other
// accounts makes each of them an owner subject is refused for.
func otherOwner(res corrosion.IdentityResolution, subject string) string {
	norm := corrosion.NormalizeUsername(subject)
	if !res.Conflict {
		if res.Winner.Username != "" && corrosion.NormalizeUsername(res.Winner.Username) != norm {
			return res.Winner.Username
		}
		return ""
	}
	for _, b := range res.All {
		if corrosion.NormalizeUsername(b.Username) != norm {
			return b.Username
		}
	}
	return ""
}

// auditBindingConflict records that a login found more than one binding where
// one is the rule (re-review 3, m-1): a node bound an account or an entry
// without having received the binding another node made first.
func (s *Server) auditBindingConflict(ctx context.Context, subject, realm, what string, res corrosion.IdentityResolution) {
	verdict := "resolved: first binding " + res.Winner.Username + "=" + res.Winner.ExternalID + " holds"
	if res.Conflict {
		verdict = "unresolved: no binding was first by more than the skew margin; logins refused until `lv user unbind`"
	}
	var parts []string
	for _, b := range res.All {
		parts = append(parts, b.Username+"="+b.ExternalID+"@"+b.BoundAt)
	}
	slog.Warn("directory identity binding conflict", "user", subject, "realm", realm, "bindings", parts, "verdict", verdict)
	s.audit(ctx, "auth.identity_conflict", subject,
		"realm="+realm+" "+what+" "+strings.Join(parts, ",")+"; "+verdict, "detected")
}

// mintSession creates a session row for an already-authenticated user and
// returns the bearer token, hard-expiry (RFC3339), and the user's role. Shared
// by password Login and the WebAuthn login flow so both produce identical
// session semantics.
//
// factor is the second factor this login presented ("" for none); it is
// recorded with the session (corrosion.InsertSessionWithLoginData), and the
// second-factor policy reads it back for the session's whole life.
func (s *Server) mintSession(ctx context.Context, username, realm, clientIP, userAgent, factor string) (token, expiresAt, role string, err error) {
	return s.mintSessionWithGroups(ctx, username, realm, clientIP, userAgent, factor, nil)
}

// mintSessionWithGroups is mintSession for an external-realm login that
// verified directory groups: they are recorded in the session's own batch
// (corrosion.InsertSessionWithLoginData) when the login_policy release feature
// passes, so `group:<realm>/<g>` bindings apply to this session. Without it
// the session is minted without them, as before the release.
func (s *Server) mintSessionWithGroups(ctx context.Context, username, realm, clientIP, userAgent, factor string, groups []string) (token, expiresAt, role string, err error) {
	return s.mintSessionWithAuthentication(ctx, username, realm, clientIP, userAgent, factor, groups, nil)
}

func (s *Server) mintSessionWithAuthentication(ctx context.Context, username, realm, clientIP, userAgent, factor string, groups []string, a *corrosion.AutomationAccountAuthentication) (token, expiresAt, role string, err error) {
	if a != nil {
		defer func() {
			if err != nil && ctx.Err() != nil {
				err = automationCredentialUnavailable(ctx.Err())
			}
		}()
	}
	// Fail closed if a reseed ran while these credentials were being checked.
	// See refuseIfReseedMovedSinceEntry: the interceptor's gate cannot drain a
	// request that was already inside when the reseed started.
	if err := s.refuseIfReseedMovedSinceEntry(ctx); err != nil {
		return "", "", "", err
	}
	user, gerr := corrosion.GetUser(ctx, s.db, username)
	if gerr != nil || user == nil {
		if a != nil {
			return "", "", "", automationCredentialUnavailable(gerr)
		}
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
		return "", "", "", sessionCutoffRefusal(life, user.Username)
	}
	username = user.Username
	id, ierr := newSessionID()
	if ierr != nil {
		return "", "", "", status.Errorf(codes.Internal, "generate session id: %v", ierr)
	}
	now := time.Now().UTC()
	exp := now.Add(s.hardExpiry())
	rec := corrosion.SessionRecord{
		ID:         id,
		Username:   username,
		Realm:      realm,
		IP:         clientIP,
		UserAgent:  userAgent,
		CreatedAt:  now.Format(time.RFC3339),
		LastUsedAt: now.Format(time.RFC3339),
		ExpiresAt:  exp.Format(time.RFC3339),
	}
	if realm == "local" {
		groups = nil // the local realm has no directory
	}
	insert := func(ctx context.Context, g capabilities.FeatureGrant) error {
		// Fail closed (review M1): once login_policy is open on this node
		// (an acknowledged used record), a login that verified groups is never
		// minted without them. Such a session would fall back to the
		// account's legacy role, which can be WIDER than its group-scoped
		// access. The login is refused instead; retrying is safe.
		if len(groups) > 0 && g.Check(capabilities.FeatureLoginPolicy) != nil && s.loginPolicyInUseOrUnknown(ctx) {
			return errGroupsUnrecordable
		}
		if a != nil {
			return corrosion.InsertAutomationSessionWithLoginData(ctx, s.db, g, a, rec, factor, groups)
		}
		return corrosion.InsertSessionWithLoginData(ctx, s.db, g, rec, factor, groups)
	}
	// Only a login that presented a factor or verified groups has login-rule
	// data to record; any other never asks the release feature's gate.
	var serr error
	if factor == "" && len(groups) == 0 {
		serr = insert(ctx, capabilities.FeatureGrant{})
	} else {
		serr = s.withLoginPolicyIfAvailable(ctx, insert)
	}
	if errors.Is(serr, errGroupsUnrecordable) {
		return "", "", "", status.Error(codes.Unavailable,
			"retry: this node could not record the directory groups this login verified, and does not mint a session without them")
	}
	if serr != nil {
		if a != nil {
			return "", "", "", automationCredentialUnavailable(serr)
		}
		return "", "", "", status.Errorf(codes.Internal, "store session: %v", serr)
	}
	return SessionTokenPrefix + id, exp.Format(time.RFC3339), user.Role, nil
}

// errGroupsUnrecordable: a login verified directory groups after login_policy
// opened on this node, but its gate did not pass for this write.
var errGroupsUnrecordable = errors.New("directory groups not recordable")

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
	s.audit(ctx, "auth.logout", callerUsername(ctx), "session="+sessionHandle(sid), "ok")
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
	own := callerSessionID(ctx)
	for _, r := range rows {
		resp.Sessions = append(resp.Sessions, &pb.Session{
			// The handle, never the id: the id is the session's bearer
			// secret, and the handle is all RevokeSession needs.
			Id:         sessionHandle(r.ID),
			Current:    own != "" && r.ID == own,
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
//
// The id may also be an unambiguous prefix of at least sessionIDMinPrefix
// characters, the short form `lv session ls` shows. The full id is the
// session's bearer secret, so nothing returns it (ListSessions gives the
// 12-character handle, sessionHandle), and without a prefix an
// admin could not revoke another user's session from what it can see. A
// prefix resolves only among the sessions the caller may revoke — its own,
// or every live session for an admin — so a non-admin learns nothing about
// another user's sessions: theirs are NotFound, and never make its own
// prefix ambiguous.
func (s *Server) RevokeSession(ctx context.Context, req *pb.RevokeSessionRequest) (*emptypb.Empty, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "session id required")
	}
	// A refused revoke is audited too, by the handle of what was asked for and
	// a fixed reason — never the user-facing message, which can echo a long
	// prefix — so prefix probing and attempts on another user's session are
	// visible and the audit log still names no more than a handle.
	denied := func(target string, err error) (*emptypb.Empty, error) {
		asked := "session=" + sessionHandle(strings.ToLower(req.Id))
		if !isHexString(strings.ToLower(req.Id)) {
			asked = "session=(not a session id)"
		}
		s.audit(ctx, "session.revoke", target, asked+" reason="+revokeDenialReason(err, req.Id), "denied")
		return nil, err
	}
	sess, err := corrosion.GetSession(ctx, s.db, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup session: %v", err)
	}
	if sess == nil {
		if sess, err = s.resolveSessionPrefix(ctx, req.Id); err != nil {
			if status.Code(err) == codes.Internal {
				return nil, err
			}
			return denied("", err)
		}
	}
	if sess.Username != callerUsername(ctx) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return denied(sess.Username, err)
		}
	}
	if err := corrosion.RevokeSession(ctx, s.db, sess.ID); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke session: %v", err)
	}
	s.kickStreams()
	// The handle, never the id: the id is a bearer secret and the audit log
	// is replicated and read by every admin.
	slog.Info("session revoked", "session", sessionHandle(sess.ID), "username", sess.Username, "by", callerUsername(ctx))
	s.audit(ctx, "session.revoke", sess.Username, "session="+sessionHandle(sess.ID), "ok")
	return &emptypb.Empty{}, nil
}

// revokeDenialReason is the fixed audit reason for a refused revoke of id.
// resolveSessionPrefix refuses a short prefix and an ambiguous one with the
// same code; the id's length tells them apart.
func revokeDenialReason(err error, id string) string {
	switch status.Code(err) {
	case codes.NotFound:
		return "not-found"
	case codes.PermissionDenied:
		return "permission-denied"
	case codes.InvalidArgument:
		if len(id) < sessionIDMinPrefix {
			return "too-short"
		}
		return "ambiguous"
	}
	return status.Code(err).String()
}

// sessionHandle is a session's display handle: the first sessionShortLen
// characters of its id. The id itself is the bearer secret (lvs_<id>), so a
// handle is what ListSessions returns and what logs and audit rows name;
// RevokeSession resolves it as a prefix.
func sessionHandle(id string) string {
	return id[:min(sessionShortLen, len(id))]
}

// sessionIDMinPrefix is the shortest id prefix RevokeSession resolves. Ids
// are 64 random hex characters; 8 of them (32 bits) leave a collision among
// live sessions vanishingly unlikely, and an ambiguous one is refused anyway.
// `lv session ls` shows 12.
const sessionIDMinPrefix = 8

// sessionShortLen is how much of an id a message may show: what
// `lv session ls` shows.
const sessionShortLen = 12

// resolveSessionPrefix finds the one live session, among those the caller may
// revoke, whose id begins with prefix.
func (s *Server) resolveSessionPrefix(ctx context.Context, prefix string) (*corrosion.SessionRecord, error) {
	prefix = strings.ToLower(prefix)
	if !isHexString(prefix) || len(prefix) >= 64 {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if len(prefix) < sessionIDMinPrefix {
		return nil, status.Errorf(codes.InvalidArgument,
			"session id %q is too short: give at least %d characters of it (lv session ls shows %d)",
			prefix, sessionIDMinPrefix, sessionShortLen)
	}
	rows, err := corrosion.ListLiveSessionsByIDPrefix(ctx, s.db, prefix)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup session: %v", err)
	}
	if RequireRole(ctx, "admin") != nil {
		caller := callerUsername(ctx)
		own := rows[:0]
		for _, r := range rows {
			if r.Username == caller {
				own = append(own, r)
			}
		}
		rows = own
	}
	switch len(rows) {
	case 0:
		return nil, status.Error(codes.NotFound, "session not found")
	case 1:
		return &rows[0], nil
	}
	// Enough to tell the matches apart in the common case, never more than
	// 16 characters of a secret.
	show := min(max(sessionShortLen, len(prefix)+4), 16)
	matches := make([]string, len(rows))
	for i, r := range rows {
		matches[i] = fmt.Sprintf("%s… (%s)", r.ID[:min(show, len(r.ID))], r.Username)
	}
	return nil, status.Errorf(codes.InvalidArgument,
		"session id prefix %q matches %d sessions: %s; give more of the id",
		prefix, len(rows), strings.Join(matches, ", "))
}

func isHexString(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// verifyTOTP delegates to the auth package's TOTP verifier. A successful
// recovery-code submission also returns true; the code is marked used.
func (s *Server) verifyTOTP(ctx context.Context, username, code string) (bool, error) {
	return auth.VerifyTOTP(ctx, s.db, username, code)
}

// loginThrottleKey identifies a brute-force bucket. An empty username (OIDC
// code-flow, which carries no username) is the anonymous, address-only
// bucket.
func loginThrottleKey(username, ip string) loginKey {
	// Normalized like every account lookup, so `ALICE` and `alice ` share
	// alice's bucket instead of each getting a fresh allowance (I2). An IPv6
	// client counts by its /64 (auth.AddressBucket), so rotating addresses
	// inside one allocation is one bucket.
	return loginKey{account: corrosion.NormalizeUsername(username), addr: auth.AddressBucket(ip)}
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
	if err := s.withLoginPolicyIfAvailable(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return corrosion.ResetUserLifecycle(ctx, s.db, g, username, callerUsername(ctx))
	}); err != nil {
		if errors.Is(err, corrosion.ErrLoginPolicyGateClosed) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"%q belonged to an account with a disable or expiry, and this node cannot clear it until "+
					"the login_policy feature of %s opens here; retry shortly or create it on another node",
				username, capabilities.ReleaseToken)
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

// MarkUserExternal is an administrator's affirmative, audited statement that an
// existing user with no local password is an external-realm (LDAP/OIDC) user.
// It writes the positive evidence an external login needs once the old secret
// columns are cleared (corrosion.MarkUserExternal): an empty credential row at
// a timestamp decades back, which never replaces a real credential anywhere,
// and which holds only for the users row as it stands now.
//
// Refused for an account with any local-credential evidence in view (a
// password in its old column, or a credential row with one, live or
// tombstoned), and on a node whose replica has not caught up — there a missing
// credential row may only be one that has not arrived yet. Every refusal is
// audited.
func (s *Server) MarkUserExternal(ctx context.Context, req *pb.MarkUserExternalRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if !s.db.UsersSynced() {
		_, why := s.db.ReplicaCaughtUp()
		s.audit(ctx, "user.mark-external", req.Username, "replica not caught up: "+why, "denied")
		return nil, status.Errorf(codes.Unavailable,
			"retry: this node's replica has not caught up with its peers (%s), so it cannot tell "+
				"whether %q holds a local password elsewhere", why, req.Username)
	}
	err := corrosion.MarkUserExternal(ctx, s.db, req.Username)
	switch {
	case err == nil:
	case errors.Is(err, corrosion.ErrUserNotExternalCandidate):
		s.audit(ctx, "user.mark-external", req.Username, "has a local password or does not exist", "denied")
		return nil, status.Errorf(codes.FailedPrecondition,
			"user %q does not exist or holds a local password; only an account with no local "+
				"password can be marked external", req.Username)
	case errors.Is(err, corrosion.ErrAmbiguousUsername):
		s.audit(ctx, "user.mark-external", req.Username, "ambiguous name", "denied")
		return nil, status.Errorf(codes.FailedPrecondition, "mark %q external: %v", req.Username, err)
	case errors.Is(err, corrosion.ErrCredentialTablesNotLatched):
		s.audit(ctx, "user.mark-external", req.Username, "credentials_split_v1 not latched", "denied")
		return nil, status.Errorf(codes.FailedPrecondition,
			"credentials_split_v1 has not latched on this node; external users need no mark until it has")
	default:
		s.audit(ctx, "user.mark-external", req.Username, "error", "denied")
		return nil, status.Errorf(codes.Internal, "mark %q external: %v", req.Username, err)
	}
	s.audit(ctx, "user.mark-external", req.Username, "by="+callerUsername(ctx), "ok")
	return &emptypb.Empty{}, nil
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
		//
		// The id alone names the account (re-review 3, m-9): it is looked up
		// among every account named like the typed name, so typing the other
		// spelling with the right id deletes the account the id names.
		var vs []corrosion.UserVariant
		vs, err = corrosion.UserVariants(ctx, s.db, req.Username)
		if err == nil {
			for _, v := range vs {
				if v.ID == req.GetExactId() {
					target, err = corrosion.GetUserExact(ctx, s.db, v.Username)
					break
				}
			}
			if err == nil && target == nil {
				return nil, status.Errorf(codes.FailedPrecondition,
					"no account named like %q has id %s; list them again with `lv user delete --exact %s`",
					req.Username, req.GetExactId(), req.Username)
			}
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
		other, oerr := corrosion.OtherUnrestrictedAdminExists(ctx, s.db, target.Username, true)
		if oerr != nil {
			if pend := (*corrosion.AdminCredentialPendingError)(nil); errors.As(oerr, &pend) {
				return nil, status.Error(codes.Unavailable, lastAdminPendingRefusal(target.Username, pend))
			}
			return nil, status.Errorf(codes.Internal,
				"check for another admin before deleting %q: %v", req.Username, oerr)
		}
		if !other {
			return nil, status.Error(codes.FailedPrecondition, lastAdminRefusal(ctx, s.db, target.Username,
				"deleting it would leave the cluster with no administrator"))
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
	var ended, revokedTokens int
	err = s.withLoginPolicyIfAvailable(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		var derr error
		ended, revokedTokens, derr = corrosion.DeleteUserCounted(ctx, s.db, g, name)
		return derr
	})
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
		context.WithoutCancel(ctx), s.db, s.withLoginPolicyIfAvailable); rerr != nil {
		slog.Error("could not verify an admin survived the delete", "deleted", req.Username, "error", rerr)
	} else if reinstated != "" {
		note := corrosion.AdminReinstatementNote(context.WithoutCancel(ctx), s.db, reinstated)
		slog.Warn("deleting this user would have left the cluster with no administrator; "+
			"the most recently deleted admin was "+note,
			"deleted", req.Username, "reinstated", reinstated)
		s.audit(ctx, "user.admin_reinstated", reinstated, note, "ok")
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
	// A token made inside the skew margin after the account's token cut-off (a
	// re-create, a delete reinstated by the admin floor) would be refused by
	// TokenPredates from its first use (re-review 3, m-6). Refuse to mint it
	// rather than hand out a token that never works.
	if life, lerr := corrosion.GetUserLifecycle(ctx, s.db, user.Username); lerr != nil {
		return nil, status.Errorf(codes.Unavailable, "read the account state of %q: %v", user.Username, lerr)
	} else if corrosion.CutoffAhead(life.TokensNotBefore, time.Now()) {
		return nil, status.Errorf(codes.Unavailable, "cannot create a token for %q: %s",
			user.Username, tokenCutoffAheadText(life, user.Username))
	} else if life.TokenPredates(time.Now().UTC().Format(time.RFC3339)) {
		return nil, status.Errorf(codes.Unavailable,
			"the account %q was re-created moments ago; create the token again in %s",
			user.Username, corrosion.SessionCutoffSkewMargin)
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
