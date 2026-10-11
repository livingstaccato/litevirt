package grpcapi

// Follow-ups to the login rules (t1-auth-rereview-4.md m-1..m-7, n-4, n-5;
// switch-rereview-login.md m-A).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// m-1: an admin the floor reinstated has no credential until root runs
// reset-admin --user, so it cannot log in, and the last-admin guard does not
// count it: the only admin who can log in may not delete, disable or expire
// itself while that account is the "other" admin. The refusal names the way
// to give it a credential.
func TestFU_M1_LastAdminGuardSkipsAnUncredentialedReinstatedAdmin(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	seedUser(t, s, "alice", "admin", "alice-pw")
	seedUser(t, s, "oldops", "admin", "old-pw")
	rawDelete(t, s, "oldops")
	writeLifecycle(t, s, "alice", corrosion.UserAttrDisabled, "true")
	if who, err := corrosion.ReinstateAdminIfNoneRemain(ctx, s.db, s.withLoginPolicyIfAvailable); err != nil || who != "oldops" {
		t.Fatalf("floor reinstated %q, %v; want oldops", who, err)
	}
	writeLifecycle(t, s, "alice", corrosion.UserAttrDisabled, "false")
	if rep, err := corrosion.AdminLoginState(ctx, s.db); err != nil || !rep.Loggable {
		t.Fatalf("alice should be the admin who can log in: %+v %v", rep, err)
	}

	yes := true
	never := "2099-01-01T00:00:00Z"
	for what, call := range map[string]func() error{
		"delete": func() error {
			_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "alice"})
			return err
		},
		"disable": func() error {
			_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", Disabled: &yes})
			return err
		},
		"expire": func() error {
			_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", ExpiresAt: &never})
			return err
		},
	} {
		err := call()
		wantCode(t, what+" of the only admin who can log in, beside an uncredentialed reinstated one", err, codes.FailedPrecondition)
		wantMessage(t, what+" refusal", err, "lv user reset-admin --user oldops")
	}
	if u, _ := corrosion.GetUser(ctx, s.db, "alice"); u == nil {
		t.Fatal("alice was deleted")
	}

	// Once root gives oldops a credential, it counts again.
	if err := corrosion.ResetAdminPasswordFor(ctx, s.db, s.withLoginPolicy, "oldops", mustHash(t, "fresh-pw-0123456789"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", Disabled: &yes}); err != nil {
		t.Fatalf("disabling alice once oldops has a credential: %v", err)
	}
}

// m-2: a cut-off a node with a clock running ahead wrote (here 2 h) refuses
// every login until that time, and the refusal says until when and how to
// correct it; root's reset-admin replaces it, and the admin logs in at once.
// A cut-off ahead by no more than the skew margin is still never moved back
// (TestM5_CutoffNeverMovesBackwards).
func TestFU_M2_ResetAdminCorrectsAFutureDatedCutoff(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	seedAdmins(t, s)
	ahead := time.Now().Add(2 * time.Hour).UTC()
	writeLifecycle(t, s, "admin", corrosion.UserAttrSessionsNotBefore, ahead.Format(time.RFC3339))
	writeLifecycle(t, s, "admin", corrosion.UserAttrTokensNotBefore, ahead.Format(time.RFC3339))
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "admin", Password: "admin-pw"})
	wantCode(t, "a login under a 2 h future cut-off", err, codes.Unavailable)
	wantMessage(t, "the refusal", err, ahead.Add(corrosion.SessionCutoffSkewMargin).Format(time.RFC3339),
		"lv user reset-admin")

	if err := corrosion.ResetAdminPassword(ctx, s.db, s.withLoginPolicy, mustHash(t, "fresh-pw-0123456789"), false); err != nil {
		t.Fatalf("reset-admin: %v", err)
	}
	l, err := corrosion.GetUserLifecycle(ctx, s.db, "admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if l.SessionsNotBefore > now || l.TokensNotBefore > now {
		t.Fatalf("reset-admin kept a future-dated cut-off: %+v (now %s)", l, now)
	}
	if _, err := s.Login(ctx, &pb.LoginRequest{Username: "admin", Password: "fresh-pw-0123456789"}); err != nil {
		t.Fatalf("login right after reset-admin corrected the cut-off: %v", err)
	}
	if _, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{Username: "admin", Name: "after-fix"}); err != nil {
		t.Fatalf("a token right after reset-admin corrected the cut-off: %v", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT 1 FROM user_lifecycle WHERE username = 'admin' AND set_by = 'user.reset-admin'`)
	if len(rows) == 0 {
		t.Error("the correction is not attributed to reset-admin")
	}
}

// m-2: correcting a future cut-off needs the release feature; a reset-admin
// that cannot open it — its gate refuses, or litevirtd is down (no gate) —
// still resets the password, as before the login rules, and leaves the
// cut-off (secure, don't remove).
func TestFU_M2_ResetAdminWithoutTheGateStillResetsThePassword(t *testing.T) {
	refusing := corrosion.FeatureRun(func(context.Context, func(context.Context, capabilities.FeatureGrant) error) error {
		return errors.New("the cluster upgrade must finish first")
	})
	for name, run := range map[string]corrosion.FeatureRun{"gate refuses": refusing, "daemon down": nil} {
		t.Run(name, func(t *testing.T) {
			s := loginPolicyServer(t)
			ctx := context.Background()
			seedAdmins(t, s)
			ahead := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
			writeLifecycle(t, s, "admin", corrosion.UserAttrSessionsNotBefore, ahead)
			hash := mustHash(t, "fresh-pw-0123456789")
			if err := corrosion.ResetAdminPassword(ctx, s.db, run, hash, false); err != nil {
				t.Fatalf("reset-admin without the gate: %v", err)
			}
			if u, _ := corrosion.GetUser(ctx, s.db, "admin"); u == nil || u.PasswordHash != hash {
				t.Fatalf("the password was not reset: %+v", u)
			}
			if l, _ := corrosion.GetUserLifecycle(ctx, s.db, "admin"); l.SessionsNotBefore != ahead {
				t.Errorf("the cut-off changed without the grant: %q, want %q", l.SessionsNotBefore, ahead)
			}
		})
	}
}

// m-3: a session minted through a binding that later loses the conflict ends
// when a login through the winning binding clears it.
func TestFU_M3_WinnerLoginCutsTheLosingBindingsSessions(t *testing.T) {
	r := newIDRealm("ldap:corp", "alice", "entryUUID:u-evil")
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	ctx := context.Background()
	// A lagging node, holding only the recycled entry's binding, let it log in.
	bindingRow(t, s, "alice", "ldap:corp", "entryUUID:u-evil", time.Now())
	evil, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"})
	if err != nil {
		t.Fatalf("the losing entry's login before the first binding arrived: %v", err)
	}
	if _, err := s.authenticate(bearerCtx(evil.Token)); err != nil {
		t.Fatalf("the losing entry's session before the conflict is known: %v", err)
	}
	// The first binding arrives, and alice's own entry logs in.
	bindingRow(t, s, "alice", "ldap:corp", "entryUUID:u-1", time.Now().Add(-time.Hour))
	time.Sleep(2100 * time.Millisecond)
	r.id.Store("entryUUID:u-1")
	own, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"})
	if err != nil {
		t.Fatalf("the winning entry's login: %v", err)
	}
	_, err = s.authenticate(bearerCtx(evil.Token))
	wantCode(t, "the losing binding's session after the winner's login", err, codes.Unauthenticated)
	if _, err := s.authenticate(bearerCtx(own.Token)); err != nil {
		t.Fatalf("the winner's own new session: %v", err)
	}
}

// m-4: a token the cut-off refuses because it was minted within the skew
// margin of it — on a node the re-create had not reached — says why, and
// what to do, instead of looking like any revoked token.
func TestFU_M4_ATokenBornInsideTheCutoffMarginSaysWhy(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	tok := mintAPIToken(t, s, "bob")
	// The re-create's token cut-off, written on another node a moment
	// before this token was minted, arrives.
	writeLifecycle(t, s, "bob", corrosion.UserAttrTokensNotBefore, time.Now().UTC().Format(time.RFC3339))
	_, err := s.authenticate(bearerCtx(tok))
	wantCode(t, "a token minted inside the margin", err, codes.Unauthenticated)
	wantMessage(t, "the refusal", err, "within", "create a new token", "the node")
}

// m-6: the note for a reinstated external admin says what to do when its
// directory entry is gone.
func TestFU_M6_ExternalReinstatementNoteNamesResetAdmin(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	s.db.SetCredentialsSplitGate(func() bool { return true })
	if err := corrosion.InsertUser(ctx, s.db, "ext", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `INSERT INTO user_credentials (username, password_hash, updated_at) VALUES ('ext', '', ?)
		ON CONFLICT(username) DO UPDATE SET password_hash = ''`, s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	note := corrosion.AdminReinstatementNote(ctx, s.db, "ext")
	if !strings.Contains(note, "external") || !strings.Contains(note, "lv user reset-admin --user ext") {
		t.Fatalf("note %q: want it external and naming lv user reset-admin --user ext", note)
	}
}
