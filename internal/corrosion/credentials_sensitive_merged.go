package corrosion

import (
	"context"
	"log/slog"
	"sync"
)

// Which peers this process has merged the sensitive lane with.
//
// A completed sensitive-lane exchange with a peer — the digests agreed, or the
// differing tables were pulled and merged without error — leaves this node
// holding every credential row, live or retired, that the peer held. One copy
// of a host's old-column password depends on that: copying it where no
// credential row exists here (credentials_split.go, RETIRED HOST CREDENTIALS),
// because the row may be a tombstone this node has not pulled.
//
// One exchange is not enough: a peer that joined on an empty database at the
// same time holds nothing either, and agreeing with it proves nothing. So the
// copy waits until this node and the peers it has merged with are a majority
// of the voter set. Two fresh joiners are then a minority of any cluster they
// join, and at least one merged peer was there before them.
//
// Like replica freshness it has no durable form: a restarted process merges
// again, which costs an anti-entropy cycle.
type sensitiveMergeState struct {
	mu      sync.Mutex
	peers   map[string]bool
	assumed bool // test constructors: a harness cluster starts converged
}

func (s *sensitiveMergeState) mark(peer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peers[peer] {
		return false
	}
	if s.peers == nil {
		s.peers = map[string]bool{}
	}
	s.peers[peer] = true
	return true
}

func (s *sensitiveMergeState) snapshot() (peers map[string]bool, assumed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peers = make(map[string]bool, len(s.peers))
	for p := range s.peers {
		peers[p] = true
	}
	return peers, s.assumed
}

func (s *sensitiveMergeState) assumeForTests(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assumed, s.peers = on, nil
}

func (c *Client) markSensitiveLaneMerged(peer string) {
	if c.sensitiveMerges.mark(peer) {
		slog.Info("sensitive lane merged with a peer", "peer", peer)
	}
}

// MayCopyHostCredentials reports whether the split pass may copy a host's
// old-column password where no credential row exists: when this node and the
// voters it has merged the sensitive lane with are a majority of the voter
// set, or when it holds no live host but itself, so no peer holds a row it has
// not pulled.
func (c *Client) MayCopyHostCredentials(ctx context.Context) (bool, error) {
	return c.mayCopyHostCredentials(ctx)
}

func (c *Client) mayCopyHostCredentials(ctx context.Context) (bool, error) {
	merged, assumed := c.sensitiveMerges.snapshot()
	if assumed {
		return true, nil
	}
	self := c.HostName()
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM hosts WHERE deleted_at IS NULL AND name != ?`, self)
	if err != nil {
		return false, err
	}
	if len(rows) == 1 && rows[0].Int("n") == 0 {
		return true, nil
	}
	voters, err := VoterSet(ctx, c)
	if err != nil {
		return false, err
	}
	have := 0
	for v := range voters {
		if v == self || merged[v] {
			have++
		}
	}
	return len(voters) > 0 && 2*have > len(voters), nil
}
