package grpcapi

import (
	"sync"
	"time"
)

// Brute-force lockout defaults. A lockout is per (username, client-IP) so a
// single attacker IP can't grind one account, and a single account can't be
// locked cluster-wide from one IP (the IP dimension keeps a shared-NAT office
// from locking everyone). The address is counted by auth.AddressBucket: an
// IPv6 client by its /64, so one allocation is one address.
//
// Per-address counting alone lets an attacker who rotates addresses (a
// botnet, a large IPv4 pool, or clients behind an over-broad trusted_proxies
// that can choose their X-Forwarded-For) guess without bound, so every
// account also has a ceiling across all addresses (defaultLoginAccountMaxFailures
// per window), counted under the account's own key (loginKey.ceilingKey). A
// failure is charged to exactly the account the attempt named, as a separate
// field of the key, never by parsing a joined string: an account name may
// contain any character ("auth0|abc" is an OIDC subject). It is larger than the per-address
// bound, so one browser's failures never lock the account for the others, and
// it is never cleared by a success, so an attacker cannot reset it by
// interleaving with the owner's logins. The anonymous OIDC bucket has no
// account ceiling (it is not an account). State is in-memory and per-node — an attacker who
// can spread guesses across every node in the cluster gets maxFailures tries
// per node, which is an acceptable trade for not needing a replicated counter
// on the hot login path. The window resets on any successful login.
const (
	defaultLoginMaxFailures = 5
	defaultLoginWindow      = 15 * time.Minute // failures older than this are forgotten
	defaultLoginLockout     = 15 * time.Minute // how long a tripped key stays locked

	defaultLoginAccountMaxFailures = 30 // failures per account per window, across all addresses
	// defaultLoginMaxEntries is a sweep THRESHOLD, not a cap: above it, stale
	// entries are swept at most once per loginThrottleSweepInterval. Live
	// entries are never evicted (that would let an attacker flush its own
	// record), so the table is bounded by login throughput over a window plus
	// a lockout, which the bcrypt cost of every attempt bounds in turn.
	defaultLoginMaxEntries     = 65536
	loginThrottleSweepInterval = time.Minute
)

// loginKey is a throttle bucket. It is a struct, never a joined string, so no
// account name — whatever characters it holds — can be read as another's.
type loginKey struct {
	// account is the normalized account name the attempt named, exactly;
	// "" for the anonymous OIDC code-flow bucket.
	account string
	// addr is the client's auth.AddressBucket; unused in a ceiling key.
	addr string
	// ceiling marks the account-wide key that counts every address.
	ceiling bool
}

// ceilingKey is the account-wide key k's failures also count against. The
// anonymous bucket is not an account and has none.
func (k loginKey) ceilingKey() (loginKey, bool) {
	if k.ceiling || k.account == "" {
		return loginKey{}, false
	}
	return loginKey{account: k.account, ceiling: true}, true
}

// loginThrottle is an in-memory failed-login counter with lockout. Safe for
// concurrent use. A nil *loginThrottle is a no-op (tests that don't wire one
// see unthrottled behaviour).
type loginThrottle struct {
	mu      sync.Mutex
	entries map[loginKey]*throttleEntry

	maxFailures int
	window      time.Duration
	lockout     time.Duration
	maxEntries  int
	accountMax  int
	sweeps      int       // sweeps run, for tests
	lastSweep   time.Time // when the table was last swept

	// now is a clock seam for tests; nil means time.Now.
	now func() time.Time
}

type throttleEntry struct {
	failures    int
	firstFail   time.Time
	lockedUntil time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{
		entries:     make(map[loginKey]*throttleEntry),
		maxFailures: defaultLoginMaxFailures,
		window:      defaultLoginWindow,
		lockout:     defaultLoginLockout,
		maxEntries:  defaultLoginMaxEntries,
		accountMax:  defaultLoginAccountMaxFailures,
	}
}

func (t *loginThrottle) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// retryAfter returns how long the key must wait before another attempt is
// allowed, or 0 if attempts are currently permitted. A locked key whose
// lockout has expired is reset here so the next failure starts a fresh window.
func (t *loginThrottle) retryAfter(key loginKey) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	wait := t.retryAfterLocked(key)
	if ck, ok := key.ceilingKey(); ok {
		wait = max(wait, t.retryAfterLocked(ck))
	}
	return wait
}

// accountRetryAfter is how long the account ceiling alone holds key's account.
func (t *loginThrottle) accountRetryAfter(key loginKey) time.Duration {
	ck, ok := key.ceilingKey()
	if t == nil || !ok {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.retryAfterLocked(ck)
}

func (t *loginThrottle) retryAfterLocked(key loginKey) time.Duration {
	e := t.entries[key]
	if e == nil {
		return 0
	}
	now := t.clock()
	if !e.lockedUntil.IsZero() {
		if now.Before(e.lockedUntil) {
			return e.lockedUntil.Sub(now)
		}
		// Lockout elapsed — forget the entry entirely.
		delete(t.entries, key)
		return 0
	}
	// Not locked, but drop a stale failure window so old failures don't
	// accumulate forever.
	if now.Sub(e.firstFail) > t.window {
		delete(t.entries, key)
	}
	return 0
}

// fail records a failed attempt and trips the lockout when the threshold is
// reached. Returns the lockout duration if this failure tripped it, else 0.
func (t *loginThrottle) fail(key loginKey) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	if t.maxEntries > 0 && len(t.entries) >= t.maxEntries && now.Sub(t.lastSweep) >= loginThrottleSweepInterval {
		t.sweepLocked(now)
		t.lastSweep = now
	}
	tripped := t.failLocked(key, t.maxFailures, now)
	if ck, ok := key.ceilingKey(); ok && t.accountMax > 0 {
		tripped = max(tripped, t.failLocked(ck, t.accountMax, now))
	}
	return tripped
}

func (t *loginThrottle) failLocked(key loginKey, limit int, now time.Time) time.Duration {
	e := t.entries[key]
	if e == nil || (now.Sub(e.firstFail) > t.window && (e.lockedUntil.IsZero() || !now.Before(e.lockedUntil))) {
		e = &throttleEntry{firstFail: now}
		t.entries[key] = e
	}
	e.failures++
	if e.failures >= limit {
		e.lockedUntil = now.Add(t.lockout)
		return t.lockout
	}
	return 0
}

// sweepLocked drops every entry whose failure window has passed and whose
// lockout, if any, has ended: such an entry no longer limits anything. Keys
// are otherwise forgotten only when retried, so rotating addresses or
// usernames would grow the table without bound.
func (t *loginThrottle) sweepLocked(now time.Time) {
	t.sweeps++
	for k, e := range t.entries {
		if now.Sub(e.firstFail) > t.window && (e.lockedUntil.IsZero() || !now.Before(e.lockedUntil)) {
			delete(t.entries, k)
		}
	}
}

// success clears any failure state for the key.
func (t *loginThrottle) success(key loginKey) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}
