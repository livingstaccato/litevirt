package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
)

func lifecycleDB(t *testing.T) *Client {
	t.Helper()
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

// TestUserLifecycle_AttributesDoNotUndoEachOther: a disable and a later
// expiry change are separate rows with separate clocks, so the expiry change
// cannot re-enable the account — the failure one row per account would have.
func TestUserLifecycle_AttributesDoNotUndoEachOther(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	c.SetLoginPolicyGate(func() bool { return true })
	yes := true
	if err := SetUserLifecycle(ctx, c, "bob", &yes, nil, "a"); err != nil {
		t.Fatal(err)
	}
	exp := "2030-01-01T00:00:00Z"
	if err := SetUserLifecycle(ctx, c, "bob", nil, &exp, "b"); err != nil {
		t.Fatal(err)
	}
	l, err := GetUserLifecycle(ctx, c, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !l.Disabled || l.ExpiresAt != exp {
		t.Fatalf("lifecycle = %+v, want disabled AND the expiry", l)
	}
	if r := l.InactiveReason(time.Now()); r != "account disabled" {
		t.Fatalf("InactiveReason = %q", r)
	}
}

func TestUserLifecycle_GateFailsClosed(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	yes := true
	if err := SetUserLifecycle(ctx, c, "bob", &yes, nil, "a"); err != ErrLoginPolicyGateClosed {
		t.Fatalf("unwired gate: %v, want ErrLoginPolicyGateClosed", err)
	}
	c.SetLoginPolicyGate(func() bool { return false })
	if err := SetTwoFactorPolicy(ctx, c, TwoFactorPolicy{Value: "all", All: true}, "a"); err != ErrLoginPolicyGateClosed {
		t.Fatalf("closed gate, policy: %v, want ErrLoginPolicyGateClosed", err)
	}
	c.SetLoginPolicyGate(func() bool { return true })
	if err := SetTwoFactorPolicy(ctx, c, TwoFactorPolicy{Value: "all", All: true}, "a"); err != ErrClusterPolicyGateClosed {
		t.Fatalf("cluster_policies gate closed: %v, want ErrClusterPolicyGateClosed", err)
	}
	rows, _ := c.Query(ctx, `SELECT 1 FROM user_lifecycle UNION ALL SELECT 1 FROM cluster_policies`)
	if len(rows) != 0 {
		t.Fatalf("a refused write landed: %d rows", len(rows))
	}
}

func TestUserLifecycle_InactiveReason(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		l    UserLifecycle
		want bool // inactive
	}{
		{UserLifecycle{}, false},
		{UserLifecycle{Disabled: true}, true},
		{UserLifecycle{ExpiresAt: "2026-10-10T12:00:00Z"}, true}, // the instant itself
		{UserLifecycle{ExpiresAt: "2026-10-10T12:00:01Z"}, false},
		{UserLifecycle{ExpiresAt: "garbage"}, true},
		{UserLifecycle{Unreadable: "disabled=\"yes\""}, true},
	} {
		if got := tc.l.InactiveReason(now) != ""; got != tc.want {
			t.Errorf("%+v: inactive=%v, want %v", tc.l, got, tc.want)
		}
	}
}

func TestParseTwoFactorPolicy(t *testing.T) {
	for in, want := range map[string]string{
		"": "off", "OFF": "off", "all": "all", "local": "local",
		"ldap:corp, local,local": "ldap:corp,local", "oidc:okta": "oidc:okta",
	} {
		p, err := ParseTwoFactorPolicy(in)
		if err != nil || p.Value != want {
			t.Errorf("ParseTwoFactorPolicy(%q) = %q, %v; want %q", in, p.Value, err, want)
		}
	}
	for _, bad := range []string{"everyone", "ldap:", "local,,x", "ldap:a b", "LOCAL"} {
		if _, err := ParseTwoFactorPolicy(bad); err == nil {
			t.Errorf("ParseTwoFactorPolicy(%q) accepted", bad)
		}
	}
	p, _ := ParseTwoFactorPolicy("local,ldap:corp")
	if !p.Requires("local") || !p.Requires("ldap:corp") || p.Requires("oidc:x") || p.Off() {
		t.Errorf("realm list policy reads wrong: %+v", p)
	}
}

func TestGetTwoFactorPolicy_NoRowIsOff(t *testing.T) {
	c := lifecycleDB(t)
	p, err := GetTwoFactorPolicy(context.Background(), c)
	if err != nil || !p.Off() || p.Requires("local") {
		t.Fatalf("no row: %+v %v, want off", p, err)
	}
}

// TestDeleteUser_KeepsLifecycle: a delete leaves the account's disable in
// place (review m3) — the floor or a directory login that brings the name back
// must not bring it back enabled. ResetUserLifecycle (an explicit CreateUser)
// is what starts a name afresh.
func TestDeleteUser_KeepsLifecycle(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	c.SetLoginPolicyGate(func() bool { return true })
	if err := InsertUser(ctx, c, "bob", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	yes := true
	if err := SetUserLifecycle(ctx, c, "bob", &yes, nil, "a"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "bob"); err != nil {
		t.Fatal(err)
	}
	if l, err := GetUserLifecycle(ctx, c, "bob"); err != nil || !l.Disabled {
		t.Fatalf("after delete: %+v %v, want still disabled", l, err)
	}
	if err := ResetUserLifecycle(ctx, c, "bob", "admin"); err != nil {
		t.Fatal(err)
	}
	l, err := GetUserLifecycle(ctx, c, "bob")
	if err != nil || l.Disabled || l.ExpiresAt != "" || l.SessionsNotBefore == "" {
		t.Fatalf("after ResetUserLifecycle: %+v %v, want enabled with sessions_not_before set", l, err)
	}
	// With the gate closed it refuses rather than leave a peer's disable.
	c.SetLoginPolicyGate(nil)
	if err := ResetUserLifecycle(ctx, c, "bob", "admin"); err != ErrLoginPolicyGateClosed {
		t.Fatalf("gate closed with a row present: %v", err)
	}
	if err := ResetUserLifecycle(ctx, c, "nobody", "admin"); err != nil {
		t.Fatalf("gate closed, nothing to reset: %v", err)
	}
}

// TestNormalizeUsername: case and surrounding whitespace, ASCII only.
func TestNormalizeUsername(t *testing.T) {
	for in, want := range map[string]string{
		"Alice": "alice", " alice\t": "alice", "ALICE\n": "alice", "Émile": "Émile", "a b": "a b",
	} {
		if got := NormalizeUsername(in); got != want {
			t.Errorf("NormalizeUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGetUser_NormalizedAndAmbiguous: a lookup finds the stored spelling,
// and refuses, naming both, when two accounts normalize alike.
func TestGetUser_NormalizedAndAmbiguous(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertUser(ctx, c, "alice", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	u, err := GetUser(ctx, c, " ALICE ")
	if err != nil || u == nil || u.Username != "alice" {
		t.Fatalf("GetUser(\" ALICE \") = %+v %v", u, err)
	}
	if err := InsertUser(ctx, c, "Alice", "admin", "y"); err != nil {
		t.Fatal(err)
	}
	if _, err := GetUser(ctx, c, "alice"); err == nil || !strings.Contains(err.Error(), `"Alice"`) {
		t.Fatalf("GetUser with two accounts differing in case: %v, want ErrAmbiguousUsername naming both", err)
	}
}
