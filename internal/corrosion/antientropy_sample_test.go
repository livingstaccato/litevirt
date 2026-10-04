package corrosion

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"
)

func peerNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("peer-%02d", i)
	}
	return out
}

// Every pass contacts the relays it is given plus at most k others.
func TestAEPeerSampler_RelaysPlusK(t *testing.T) {
	peers := peerNames(49)
	relays := []string{"peer-00", "peer-01"}
	s := newAEPeerSampler(2, rand.New(rand.NewSource(1)))
	for pass := 0; pass < 100; pass++ {
		got := s.pick(peers, relays)
		for _, r := range relays {
			if !slices.Contains(got, r) {
				t.Fatalf("pass %d: relay %s not contacted (got %v)", pass, r, got)
			}
		}
		if len(got) > len(relays)+2 {
			t.Fatalf("pass %d: contacted %d peers, want at most %d relays + k=2: %v", pass, len(got), len(relays), got)
		}
		seen := map[string]bool{}
		for _, p := range got {
			if seen[p] {
				t.Fatalf("pass %d: %s contacted twice: %v", pass, p, got)
			}
			seen[p] = true
		}
	}
}

// The bound. With M non-relay peers and k per pass, the sampler walks a fresh
// random permutation of them k at a time, so one cycle is L = ⌈M/k⌉ passes and
// every peer is contacted exactly once per cycle. Hence:
//
//   - every peer is contacted within the first L passes, and
//   - every peer is contacted in ANY window of 2L−1 consecutive passes (the
//     worst case is a peer drawn first in one cycle and last in the next).
//
// A sampler that drew k peers independently at random each pass has no such
// bound — a peer can go unvisited for arbitrarily many passes — which is what
// this test would catch.
func TestAEPeerSampler_EveryPeerWithinABoundedNumberOfPasses(t *testing.T) {
	const k = 2
	for _, m := range []int{1, 2, 3, 7, 46, 47} {
		peers := peerNames(m + 3)
		relays := peers[:3]
		others := peers[3:]
		L := (m + k - 1) / k
		for seed := int64(0); seed < 20; seed++ {
			s := newAEPeerSampler(k, rand.New(rand.NewSource(seed)))
			var history [][]string
			for pass := 0; pass < 6*L+5; pass++ {
				history = append(history, s.pick(peers, relays))
			}
			contacted := func(p string, from, to int) bool {
				for i := from; i < to && i < len(history); i++ {
					if slices.Contains(history[i], p) {
						return true
					}
				}
				return false
			}
			for _, p := range others {
				if !contacted(p, 0, L) {
					t.Fatalf("M=%d seed=%d: %s not contacted in the first L=%d passes", m, seed, p, L)
				}
				for start := 0; start+2*L-1 <= len(history); start++ {
					if !contacted(p, start, start+2*L-1) {
						t.Fatalf("M=%d seed=%d: %s not contacted in passes [%d,%d) — a window of 2L-1=%d",
							m, seed, p, start, start+2*L-1, 2*L-1)
					}
				}
			}
		}
	}
}

// A peer that leaves is never contacted again, and one that joins mid-cycle is
// picked up no later than the end of the next cycle.
func TestAEPeerSampler_FollowsMembership(t *testing.T) {
	s := newAEPeerSampler(2, rand.New(rand.NewSource(3)))
	peers := peerNames(10)
	s.pick(peers, nil)
	gone := peers[9]
	peers = peers[:9]
	newcomer := "peer-new"
	peers = append(peers, newcomer)
	L := (len(peers) + 1) / 2
	seenNew := false
	for pass := 0; pass < 2*L; pass++ {
		got := s.pick(peers, nil)
		if slices.Contains(got, gone) {
			t.Fatalf("pass %d: contacted %s after it left: %v", pass, gone, got)
		}
		seenNew = seenNew || slices.Contains(got, newcomer)
	}
	if !seenNew {
		t.Fatalf("newcomer not contacted within 2L=%d passes of joining", 2*L)
	}
}

// Through the real pass: a scheduled pass on a leaf contacts its two assigned
// relays plus k others — not every member — and every member within L passes.
func TestCheckSampledPeers_ContactsRelaysPlusK(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	const n = 8
	fakes := map[string]*fakePeer{}
	var members []PeerInfo
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("peer-%d", i)
		p := &fakePeer{}
		startFakePeer(t, c, pkiDir, name, p)
		fakes[name] = p
		members = append(members, PeerInfo{Name: name})
	}
	c.SetMembersForTests(func() []PeerInfo { return members })

	// "self" has no hosts row, so it is ineligible and a leaf; the relays are
	// the first four eligible names and self's assigned pair is peer-0, peer-1.
	rs := ComputeRelays(members, "self", RelayConfig{}, RelayEligibleHosts(context.Background(), c))
	pair := rs.AssignedRelays("self")
	if rs.IsRelay("self") || pair[0] == "" || pair[1] == "" {
		t.Fatalf("precondition: self should be a leaf with two relays, got relays=%v pair=%v", rs.Relays(), pair)
	}

	ae := NewAntiEntropy(c, pkiDir, time.Minute)
	total := func() int {
		sum := 0
		for _, p := range fakes {
			sum += int(p.digestCalls.Load())
		}
		return sum
	}
	ae.checkSampledPeers(context.Background())
	if got := total(); got != 2+antiEntropySampleSize {
		t.Fatalf("one scheduled pass contacted %d of %d peers, want its 2 relays + k=%d", got, n, antiEntropySampleSize)
	}
	for _, r := range pair {
		if fakes[r].digestCalls.Load() != 1 {
			t.Errorf("assigned relay %s contacted %d times in one pass, want 1", r, fakes[r].digestCalls.Load())
		}
	}

	L := (n - 2 + antiEntropySampleSize - 1) / antiEntropySampleSize
	for pass := 1; pass < L; pass++ {
		ae.checkSampledPeers(context.Background())
	}
	for name, p := range fakes {
		if p.digestCalls.Load() == 0 {
			t.Errorf("%s never contacted within L=%d scheduled passes", name, L)
		}
	}
}

// The loop runs the SAMPLED pass. RunOnce stays a full sweep for `lv cluster
// converge`, so a loop wired to it would pass every test above and still cost
// N·(N−1) per interval.
func TestStart_RunsTheSampledPass(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	const n = 8
	var fakes []*fakePeer
	var members []PeerInfo
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("peer-%d", i)
		p := &fakePeer{}
		startFakePeer(t, c, pkiDir, name, p)
		fakes = append(fakes, p)
		members = append(members, PeerInfo{Name: name})
	}
	c.SetMembersForTests(func() []PeerInfo { return members })
	total := func() int {
		sum := 0
		for _, p := range fakes {
			sum += int(p.digestCalls.Load())
		}
		return sum
	}

	// A short interval; the 12s cooldown then holds the loop to one pass for
	// the life of the test.
	ae := NewAntiEntropy(c, pkiDir, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ae.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	want := 2 + antiEntropySampleSize
	deadline := time.Now().Add(10 * time.Second)
	for total() < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Let a full sweep, were that what ran, reach the rest.
	time.Sleep(500 * time.Millisecond)
	if got := total(); got != want {
		t.Fatalf("the scheduled loop contacted %d of %d peers in its pass, want relays + k = %d", got, n, want)
	}
}
