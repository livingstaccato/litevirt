package corrosion

import "math/rand"

// antiEntropySampleSize is k: how many members beyond this node's relays one
// scheduled anti-entropy pass contacts (#262). Small on purpose — a pass costs
// the cluster N·(relays+k) digest exchanges instead of N·(N−1) — and the
// sampler below still reaches every member within a bounded number of passes.
const antiEntropySampleSize = 2

// aePeerSampler chooses which non-relay members a scheduled pass contacts.
//
// It walks a fresh random permutation of the non-relay members k at a time and
// reshuffles when the permutation is used up. The randomness spreads the load:
// nodes do not converge on the same few peers each pass. The walk is what makes
// it bounded, which independent random draws are not. With M non-relay members
// a cycle is L = ⌈M/k⌉ passes and visits every member once, so every member is
// contacted within the first L passes and in ANY 2L−1 consecutive passes (the
// worst case is a member drawn first in one cycle and last in the next). With
// the 60s default interval and k=2, a 50-node cluster's leaf (M=45) reaches
// every member at least once every 45 passes, 45 minutes. The relays are
// contacted on every pass.
//
// Membership is re-read each pass: a member that leaves is dropped from the
// walk, and one that joins mid-cycle enters the next cycle's permutation, so it
// waits at most the rest of the current cycle plus one cycle.
type aePeerSampler struct {
	k     int
	rng   *rand.Rand
	queue []string // the rest of the current cycle's permutation
}

func newAEPeerSampler(k int, rng *rand.Rand) *aePeerSampler {
	return &aePeerSampler{k: k, rng: rng}
}

// pick returns the members to contact this pass: every relay that is a member,
// then up to k others from the walk. relays that are not in peers are ignored.
func (s *aePeerSampler) pick(peers, relays []string) []string {
	member := make(map[string]bool, len(peers))
	for _, p := range peers {
		member[p] = true
	}
	isRelay := make(map[string]bool, len(relays))
	out := make([]string, 0, len(relays)+s.k)
	for _, r := range relays {
		if member[r] && !isRelay[r] {
			isRelay[r] = true
			out = append(out, r)
		}
	}

	// Drop from the walk anything that left, or became a relay.
	kept := s.queue[:0]
	for _, p := range s.queue {
		if member[p] && !isRelay[p] {
			kept = append(kept, p)
		}
	}
	s.queue = kept

	if len(s.queue) == 0 {
		for _, p := range peers {
			if !isRelay[p] {
				s.queue = append(s.queue, p)
			}
		}
		s.rng.Shuffle(len(s.queue), func(i, j int) { s.queue[i], s.queue[j] = s.queue[j], s.queue[i] })
	}

	n := min(s.k, len(s.queue))
	out = append(out, s.queue[:n]...)
	s.queue = s.queue[n:]
	return out
}
