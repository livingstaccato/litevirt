package grpcapi

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// R1-I1 (round 2): a failure counts against the account the attempt named,
// exactly. Failing as "admin|1" .. "admin|30" from one address names thirty
// other (nonexistent) accounts and must leave admin open.
func TestLogin_PipeInAttemptedNameDoesNotChargeAnotherAccount(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	seedUser(t, s, "admin", "admin", "hunter2")
	ui := uiCtx(t, s)
	for i := 0; i < defaultLoginAccountMaxFailures; i++ {
		_, _ = s.Login(ui, &pb.LoginRequest{Username: fmt.Sprintf("admin|%d", i+1), Password: "wrong", ClientAddress: "203.0.113.50"})
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "admin", Password: "hunter2", ClientAddress: "203.0.113.51"}); err != nil {
		t.Fatalf("admin after failures as admin|1..admin|%d: %v", defaultLoginAccountMaxFailures, err)
	}
}

// Accounts whose names contain "|" (Auth0-style OIDC subjects) each have
// their own ceiling.
func TestLoginThrottle_PipeSubjectsDoNotShareACeiling(t *testing.T) {
	th := newLoginThrottle()
	for i := 0; i < defaultLoginAccountMaxFailures; i++ {
		th.fail(loginThrottleKey(fmt.Sprintf("auth0|user%d", i), fmt.Sprintf("10.0.0.%d", i+1)))
	}
	if w := th.retryAfter(loginThrottleKey("auth0|someone-else", "10.0.9.9")); w != 0 {
		t.Fatalf("auth0|someone-else is held %s by other auth0| subjects' failures", w)
	}
	// While one such account still meets its own ceiling.
	for i := 0; i < defaultLoginAccountMaxFailures; i++ {
		th.fail(loginThrottleKey("auth0|victim", fmt.Sprintf("10.1.0.%d", i+1)))
	}
	if w := th.retryAfter(loginThrottleKey("auth0|victim", "10.2.0.1")); w == 0 {
		t.Fatal("auth0|victim's own ceiling did not hold")
	}
}

// R1-M1 (round 2): over the threshold the table is swept at most once per
// interval, not on every failure.
func TestLoginThrottle_SweepIsRateLimited(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	th := newLoginThrottle()
	th.now = func() time.Time { return now }
	th.maxEntries = 2
	for i := 0; i < 20; i++ {
		th.fail(loginThrottleKey("alice", fmt.Sprintf("10.0.0.%d", i)))
	}
	if th.sweeps != 1 {
		t.Fatalf("%d sweeps over 20 failures within one interval, want 1", th.sweeps)
	}
	now = now.Add(loginThrottleSweepInterval + 1)
	th.fail(loginThrottleKey("alice", "10.0.1.1"))
	if th.sweeps != 2 {
		t.Fatalf("%d sweeps after the interval, want 2", th.sweeps)
	}
}

// R1-M2 (round 2): a denied revoke is audited with a fixed reason and the
// handle, never the user-facing message (which can echo a long prefix).
func TestRevokeSession_DeniedAuditCarriesAFixedReason(t *testing.T) {
	s := testServer(t)
	common := strings.Repeat("cd", 20) // 40 characters
	insertSessionWithID(t, s, common+strings.Repeat("1", 24), "alice")
	insertSessionWithID(t, s, common+strings.Repeat("2", 24), "bob")
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: common}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: "abc"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("too short: %v", err)
	}
	want := map[string]bool{"reason=ambiguous": false, "reason=too-short": false}
	for _, r := range sessionAudit(t, s, "session.revoke") {
		d := r.String("detail")
		if strings.Contains(d, common[:13]) {
			t.Errorf("denied audit %q carries more than a 12-character handle", d)
		}
		for k := range want {
			if strings.Contains(d, k) {
				want[k] = true
			}
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("no denied audit with %s", k)
		}
	}
}
