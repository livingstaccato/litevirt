package grpcapi

import (
	"context"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// peerWALQAnswer is one peer's last Ping answer on wal_quarantined, or that
// it did not answer.
type peerWALQAnswer struct {
	quarantined bool
	noAnswer    bool
	at          time.Time
}

// How long a quarantined answer, and a "no answer", are trusted before the
// peer is asked again; how long one round of asks may take in all; and how
// many peers are asked at once. A "not quarantined" answer is never trusted
// from the cache: it may predate the peer's rollback restart.
var (
	peerWALQTTL         = 30 * time.Second
	peerWALQNoAnswerTTL = 10 * time.Second
	peerWALQAskTimeout  = 2 * time.Second
	peerWALQParallel    = 16
)

// notePeerWALQuarantined records a peer's Ping answer. Every path that reads
// a peer's Ping feeds it.
func (s *Server) notePeerWALQuarantined(peer string, quarantined bool) {
	s.notePeerWALQ(peer, peerWALQAnswer{quarantined: quarantined, at: time.Now()})
}

func (s *Server) notePeerWALQ(peer string, a peerWALQAnswer) {
	s.peerWALQMu.Lock()
	defer s.peerWALQMu.Unlock()
	if s.peerWALQ == nil {
		s.peerWALQ = map[string]peerWALQAnswer{}
	}
	s.peerWALQ[peer] = a
}

// Why PeerRecoveryExclusions leaves a peer out.
const (
	peerExcludedQuarantined = "reports itself WAL-quarantined"
	peerExcludedNoAnswer    = "did not answer whether it is WAL-quarantined"
)

// PeerRecoveryExclusions says which of peers must not be a VM recovery target
// while point-in-time overlays are in use, and why: a peer whose own Ping says
// it is WAL-quarantined (rolled back below a latched token, so possibly a
// build that knows nothing of overlays — it would define the VM on the bare
// disk), and a peer that does not answer (it may be mid-rollback, and a
// placement is durable: it would act on it when it comes back). Peers absent
// from the result are eligible.
//
// A quarantined answer read in the last peerWALQTTL, and a "no answer" in the
// last peerWALQNoAnswerTTL, are reused; every other peer is asked now, all of
// them in parallel (at most peerWALQParallel at once) under ONE shared
// peerWALQAskTimeout, so a round costs at most that, however many peers are
// dead. The failover coordinator calls it once per placement
// (failover.Coordinator.PeerRecoveryExclusions), and only once pit_overlay is
// used.
func (s *Server) PeerRecoveryExclusions(ctx context.Context, peers []string) map[string]string {
	out := map[string]string{}
	now := time.Now()
	var ask []string
	s.peerWALQMu.Lock()
	for _, p := range peers {
		if p == s.hostName {
			continue
		}
		last, ok := s.peerWALQ[p]
		switch {
		case ok && last.quarantined && now.Sub(last.at) < peerWALQTTL:
			out[p] = peerExcludedQuarantined
		case ok && last.noAnswer && now.Sub(last.at) < peerWALQNoAnswerTTL:
			out[p] = peerExcludedNoAnswer
		default:
			ask = append(ask, p)
		}
	}
	s.peerWALQMu.Unlock()
	if len(ask) == 0 {
		return out
	}
	actx, cancel := context.WithTimeout(ctx, peerWALQAskTimeout)
	defer cancel()
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, peerWALQParallel)
	)
	for _, p := range ask {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-actx.Done():
				mu.Lock()
				out[p] = peerExcludedNoAnswer
				mu.Unlock()
				s.notePeerWALQ(p, peerWALQAnswer{noAnswer: true, at: time.Now()})
				return
			}
			q, err := s.askPeerWALQuarantined(actx, p)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				out[p] = peerExcludedNoAnswer
				s.notePeerWALQ(p, peerWALQAnswer{noAnswer: true, at: time.Now()})
			case q:
				out[p] = peerExcludedQuarantined
			}
		}(p)
	}
	wg.Wait()
	return out
}

// askPeerWALQuarantined Pings peer and records its answer.
func (s *Server) askPeerWALQuarantined(ctx context.Context, peer string) (bool, error) {
	c, closeConn, err := s.dialPeer(ctx, peer)
	if err != nil {
		return false, err
	}
	defer closeConn()
	resp, err := c.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return false, err
	}
	s.notePeerWALQuarantined(peer, resp.GetWalQuarantined())
	return resp.GetWalQuarantined(), nil
}
