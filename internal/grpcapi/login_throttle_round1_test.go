package grpcapi

import (
	"fmt"
	"testing"
	"time"
)

// I2 (round 1): entries whose window and lockout have both passed are swept
// once the table is large, so rotating keys cannot grow it without bound.
func TestLoginThrottle_SweepsStaleEntries(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	th := newLoginThrottle()
	th.now = func() time.Time { return now }
	th.maxEntries = 10
	for i := 0; i < 10; i++ {
		th.fail(fmt.Sprintf("alice|10.0.0.%d", i))
	}
	now = now.Add(defaultLoginWindow + defaultLoginLockout + time.Minute)
	th.fail("alice|10.0.1.1")
	th.mu.Lock()
	n := len(th.entries)
	th.mu.Unlock()
	if n != 2 {
		t.Fatalf("%d entries after the sweep, want 2 (only the fresh pair and its account)", n)
	}
}

// A locked entry is never swept while its lockout runs.
func TestLoginThrottle_SweepKeepsLiveLockouts(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	th := newLoginThrottle()
	th.now = func() time.Time { return now }
	th.maxEntries = 2
	th.lockout = 2 * defaultLoginWindow
	for i := 0; i < defaultLoginMaxFailures; i++ {
		th.fail("alice|10.0.0.1")
	}
	now = now.Add(defaultLoginWindow + time.Minute) // window passed, lockout still running
	th.fail("bob|10.0.0.2")
	th.fail("carol|10.0.0.3")
	if th.retryAfter("alice|10.0.0.1") == 0 {
		t.Fatal("a running lockout was swept")
	}
}

// The anonymous OIDC bucket is not an account and has no ceiling: a stray
// flood of failed OIDC code redemptions must not lock every OIDC user out.
func TestAccountThrottleKey(t *testing.T) {
	cases := map[string]string{
		"alice|10.0.0.1":      "alice|*",
		"alice|2001:db8::/64": "alice|*",
		"_anon|10.0.0.1":      "",
		"nobar":               "",
	}
	for in, want := range cases {
		if got := accountThrottleKey(in); got != want {
			t.Errorf("accountThrottleKey(%q) = %q, want %q", in, got, want)
		}
	}
}
