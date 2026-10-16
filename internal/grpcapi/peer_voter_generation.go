package grpcapi

import (
	"sync"
	"time"
)

// peerVoterGenReport is a voter generation a peer reported adopted
// (PingResponse.voter_generation), and when this node first received a
// report of it.
type peerVoterGenReport struct {
	gen int64
	at  time.Time
}

// peerVoterGenKeep is how many of a peer's reports are kept; the oldest go
// first.
const peerVoterGenKeep = 16

// peerVoterGens holds each peer's reported voter generations, in increasing
// order (notePeerVoterGeneration).
type peerVoterGens struct {
	mu   sync.Mutex
	seen map[string][]peerVoterGenReport
}

// notePeerVoterGeneration records that peer reported generation gen in a Ping
// this node received at at. 0 is no report: an older build, a node that has
// run no adoption pass since it started, or a host re-provisioned under the
// same name, whose adoption state starts empty. These cannot be told apart
// here, so a 0 forgets the peer's earlier reports, which fails closed: the
// bounded hold waits for a report again. A generation lower than the last
// reported one means the peer's adoption state was replaced (a re-added
// host), so the earlier reports no longer stand either.
func (s *Server) notePeerVoterGeneration(peer string, gen int64, at time.Time) {
	g := &s.peerVoterGens
	g.mu.Lock()
	defer g.mu.Unlock()
	if gen <= 0 {
		delete(g.seen, peer)
		return
	}
	if g.seen == nil {
		g.seen = map[string][]peerVoterGenReport{}
	}
	reps := g.seen[peer]
	if n := len(reps); n > 0 {
		switch last := reps[n-1].gen; {
		case gen == last:
			return
		case gen < last:
			reps = nil
		}
	}
	reps = append(reps, peerVoterGenReport{gen: gen, at: at})
	if len(reps) > peerVoterGenKeep {
		reps = reps[len(reps)-peerVoterGenKeep:]
	}
	g.seen[peer] = reps
}

// PeerVoterGeneration reports the highest voter generation peer reported
// adopted in a Ping this node received before `before`; ok is false when it
// reported none then. In memory: a restart forgets every report.
func (s *Server) PeerVoterGeneration(peer string, before time.Time) (int64, bool) {
	g := &s.peerVoterGens
	g.mu.Lock()
	defer g.mu.Unlock()
	var best int64
	for _, r := range g.seen[peer] {
		if r.at.Before(before) {
			best = r.gen
		}
	}
	return best, best > 0
}
