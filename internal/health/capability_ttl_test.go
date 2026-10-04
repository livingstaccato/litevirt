package health

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestCapabilityCaches_ExpireOnTheCheckersClock: the three capability caches —
// the negative CapabilityActive result, the positive CapabilityActiveForHealth
// result, and each peer's advertised capabilities — expire on the Checker's own
// clock, so their TTLs can be tested at all.
//
// They used to stamp time.Now() and compare with time.Since, past the
// injectable clock every other timer in the Checker reads. Nothing could test
// their expiry short of sleeping for the TTL, so nothing did: a cache that
// never expired — a stamp refreshed on every hit, say — would have kept the HA
// monitor reporting a capability the cluster had lost, or the WAL proof filter
// trusting a downgraded peer, and every test would still have passed.
//
// Each case primes the cache at t0, then reads it once just inside the TTL
// (served from the cache, no Ping) and once just past t0+TTL (a fresh Ping that
// sees the peer's current answer). The read just inside the TTL comes first on
// purpose: a stamp refreshed on that hit would carry the entry past t0+TTL, and
// the last read would still be served from the cache.
func TestCapabilityCaches_ExpireOnTheCheckersClock(t *testing.T) {
	const tok = capabilities.SplitBrainGateV1
	ctx := context.Background()

	type rig struct {
		c          *Checker
		now        time.Time
		pings      int
		advertises bool
	}
	setup := func(t *testing.T) *rig {
		t.Helper()
		db := testCheckHostDB(t)
		gateHost(t, db, "host-a", "active", "worker")
		gateHost(t, db, "host-b", "active", "worker")
		r := &rig{
			c:          NewChecker("host-a", "/etc/litevirt/pki", db),
			now:        time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
			advertises: true,
		}
		var mu sync.Mutex
		r.c.clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return r.now }
		r.c.SetPeerPinger(func(_ context.Context, _ string) ([]string, time.Time, error) {
			mu.Lock()
			defer mu.Unlock()
			r.pings++
			if r.advertises {
				return []string{tok}, time.Time{}, nil
			}
			return []string{}, time.Time{}, nil
		})
		return r
	}

	cases := []struct {
		name string
		ttl  time.Duration
		// primeAdvertises is what the peer advertises when the cache is primed;
		// the peer then flips to the opposite.
		primeAdvertises bool
		// read returns what the cache-backed call answers now.
		read func(r *rig) bool
	}{
		{
			// A cached miss must not outlive its TTL: a just-healed cluster
			// activates on the first read after it.
			name:            "CapabilityActive negative / capActiveNegTTL",
			ttl:             capActiveNegTTL,
			primeAdvertises: false,
			read: func(r *rig) bool {
				ok, _ := r.c.CapabilityActive(ctx, tok)
				return ok
			},
		},
		{
			// A peer that stops advertising must surface on the HA monitor once
			// the positive cache lapses.
			name:            "CapabilityActiveForHealth positive / capActivePosTTL",
			ttl:             capActivePosTTL,
			primeAdvertises: true,
			read: func(r *rig) bool {
				ok, _ := r.c.CapabilityActiveForHealth(ctx, tok)
				return ok
			},
		},
		{
			// The WAL proof filter must refetch a peer's capabilities once
			// peerCapTTL has passed.
			name:            "PeerSupports / peerCapTTL",
			ttl:             peerCapTTL,
			primeAdvertises: true,
			read: func(r *rig) bool {
				return r.c.PeerSupports(ctx, "host-b", tok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := setup(t)
			t0 := r.now
			r.advertises = tc.primeAdvertises

			if got := tc.read(r); got != tc.primeAdvertises {
				t.Fatalf("prime: got %v, want %v", got, tc.primeAdvertises)
			}
			primed := r.pings
			if primed == 0 {
				t.Fatal("prime: the first read must Ping")
			}

			// The peer's answer changes; the cache does not know yet.
			r.advertises = !tc.primeAdvertises

			r.now = t0.Add(tc.ttl - time.Millisecond)
			if got := tc.read(r); got != tc.primeAdvertises {
				t.Fatalf("just inside the TTL: got %v, want the cached %v", got, tc.primeAdvertises)
			}
			if r.pings != primed {
				t.Fatalf("just inside the TTL the read Pinged (%d→%d); want it served from the cache", primed, r.pings)
			}

			r.now = t0.Add(tc.ttl + time.Millisecond)
			if got := tc.read(r); got != !tc.primeAdvertises {
				t.Fatalf("just past t0+TTL: got %v, want the peer's current answer %v — "+
					"the cache outlived its TTL on the Checker's clock", got, !tc.primeAdvertises)
			}
			if r.pings == primed {
				t.Fatal("just past t0+TTL the read was served from the cache; want a fresh Ping")
			}
		})
	}
}
