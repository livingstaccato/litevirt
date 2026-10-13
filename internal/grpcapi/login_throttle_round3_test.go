package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
)

// throttleAccounts lists the accounts the throttle holds entries for.
func throttleAccounts(s *Server) map[string]int {
	s.loginThrottle.mu.Lock()
	defer s.loginThrottle.mu.Unlock()
	out := map[string]int{}
	for k := range s.loginThrottle.entries {
		out[k.account]++
	}
	return out
}

// R2-M2 (round 3): an OIDC code flow proves no client-named account, so a
// failed exchange is charged to the anonymous bucket, never to the account
// a client put in the username field.
func TestLogin_OIDCCodeFailureNeverChargesTheNamedAccount(t *testing.T) {
	s, idp := oidcServer(t)
	code, state, binding := oidcCallback(t, s, idp)
	_, err := s.Login(context.Background(), &pb.LoginRequest{
		Realm: "oidc:corp", Username: "admin",
		OidcCode: code, OidcState: state, OidcBinding: binding,
		// Not the redirect the flow began with: a counted invalid-credentials
		// failure of the exchange.
		OidcRedirectUri: "https://elsewhere.example/oidc/callback",
	})
	if err == nil {
		t.Fatal("a tampered code logged in")
	}
	acc := throttleAccounts(s)
	if acc["admin"] != 0 {
		t.Fatalf("a failed OIDC exchange naming admin charged admin: %v", acc)
	}
	if acc[""] == 0 {
		t.Fatalf("the failed exchange was not counted at all (want the anonymous bucket): %v", acc)
	}
}

// R2-M1 (round 3): a WebAuthn finish with no ceremony in flight evaluated no
// guess, so it adds no throttle entry; otherwise fresh usernames would grow
// the table at request rate with no bcrypt cost behind them.
func TestFinishWebAuthnLogin_NoCeremonyAddsNoThrottleEntry(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	svc, err := auth.NewWebAuthnService(s.db, auth.WebAuthnConfig{
		RPDisplayName: "t", RPID: "litevirt.test", RPOrigins: []string{"https://litevirt.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.SetWebAuthnService(svc)
	for i := 0; i < 50; i++ {
		if _, err := s.FinishWebAuthnLogin(context.Background(), &pb.FinishWebAuthnLoginRequest{
			Username: fmt.Sprintf("ghost%d", i), AssertionJson: []byte(`{}`),
		}); err == nil {
			t.Fatal("a finish with no ceremony logged in")
		}
	}
	if n := len(throttleAccounts(s)); n != 0 {
		t.Fatalf("%d throttle accounts after finishes with no ceremony, want 0", n)
	}
}

// O2 (lab, round 3): a failed login's audit row records the client address,
// as the ok and locked-out rows do, so a brute force shows where it comes
// from before the lockout.
func TestLogin_FailedLoginAuditCarriesTheAddress(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	ui := uiCtx(t, s)
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "wrong", ClientAddress: "203.0.113.77"}); err == nil {
		t.Fatal("a wrong password logged in")
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "ghost", Password: "wrong", ClientAddress: "203.0.113.78"}); err == nil {
		t.Fatal("an unknown user logged in")
	}
	rows, err := s.db.Query(context.Background(),
		`SELECT detail FROM audit_log WHERE action = 'auth.login' AND result = 'denied'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d denied auth.login rows, want 2", len(rows))
	}
	for i, want := range []string{"ip=203.0.113.77", "ip=203.0.113.78"} {
		found := false
		for _, r := range rows {
			if strings.Contains(r.String("detail"), want) && strings.Contains(r.String("detail"), "invalid credentials") {
				found = true
			}
		}
		if !found {
			t.Errorf("failure %d: no denied row with %q in %v", i, want, rows)
		}
	}
}
