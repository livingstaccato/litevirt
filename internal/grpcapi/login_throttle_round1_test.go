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
		th.fail(loginThrottleKey("alice", fmt.Sprintf("10.0.0.%d", i)))
	}
	now = now.Add(defaultLoginWindow + defaultLoginLockout + time.Minute)
	th.fail(loginThrottleKey("alice", "10.0.1.1"))
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
		th.fail(loginThrottleKey("alice", "10.0.0.1"))
	}
	now = now.Add(defaultLoginWindow + time.Minute) // window passed, lockout still running
	th.fail(loginThrottleKey("bob", "10.0.0.2"))
	th.fail(loginThrottleKey("carol", "10.0.0.3"))
	if th.retryAfter(loginThrottleKey("alice", "10.0.0.1")) == 0 {
		t.Fatal("a running lockout was swept")
	}
}

// The anonymous OIDC bucket is not an account and has no ceiling: a stray
// flood of failed OIDC code redemptions must not lock every OIDC user out.
func TestLoginThrottle_AnonymousHasNoAccountCeiling(t *testing.T) {
	th := newLoginThrottle()
	for i := 0; i < 2*defaultLoginAccountMaxFailures; i++ {
		th.fail(loginThrottleKey("", fmt.Sprintf("10.0.%d.%d", i/200, i%200+1)))
	}
	if w := th.retryAfter(loginThrottleKey("", "10.9.9.9")); w != 0 {
		t.Fatalf("the anonymous bucket from a fresh address is held %s by an account ceiling", w)
	}
}
