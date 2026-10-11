package grpcapi

import (
	"context"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// peerWALQAnswer is one peer's last Ping answer on wal_quarantined.
type peerWALQAnswer struct {
	quarantined bool
	at          time.Time
}

// peerWALQTTL is how long a peer's answer is trusted before it is asked
// again; peerWALQAskTimeout bounds that fresh Ping.
var (
	peerWALQTTL        = 30 * time.Second
	peerWALQAskTimeout = 2 * time.Second
)

// notePeerWALQuarantined records a peer's Ping answer. Every path that reads
// a peer's Ping feeds it.
func (s *Server) notePeerWALQuarantined(peer string, quarantined bool) {
	s.peerWALQMu.Lock()
	defer s.peerWALQMu.Unlock()
	if s.peerWALQ == nil {
		s.peerWALQ = map[string]peerWALQAnswer{}
	}
	s.peerWALQ[peer] = peerWALQAnswer{quarantined: quarantined, at: time.Now()}
}

// PeerReportsWALQuarantined reports whether peer's own Ping says it is
// WAL-quarantined: rolled back below a capability token this cluster latched,
// so possibly a build that knows nothing of point-in-time overlays. A
// quarantined answer any path read in the last peerWALQTTL is trusted; any
// other is asked again now (peerWALQAskTimeout) — a "not quarantined" from
// before the peer's rollback restart must not keep it a target. It is asked
// only on a VM recovery once pit_overlay is used, so the Ping costs little. A
// peer that cannot be asked keeps its last answer, and one never heard from
// is not reported: unreachable is not quarantined.
// The failover coordinator reads it (failover.Coordinator.PeerWALQuarantined)
// to keep VM recoveries off such a host once pit_overlay is used, from the
// first Ping after its rollback — cycles before the HA monitor records it
// isolated.
func (s *Server) PeerReportsWALQuarantined(ctx context.Context, peer string) bool {
	if peer == s.hostName {
		return s.walQuarantinedNow()
	}
	s.peerWALQMu.Lock()
	last, ok := s.peerWALQ[peer]
	s.peerWALQMu.Unlock()
	if ok && last.quarantined && time.Since(last.at) < peerWALQTTL {
		return true
	}
	actx, cancel := context.WithTimeout(ctx, peerWALQAskTimeout)
	defer cancel()
	c, closeConn, err := s.dialPeer(actx, peer)
	if err != nil {
		return ok && last.quarantined
	}
	defer closeConn()
	resp, err := c.Ping(actx, &pb.PingRequest{})
	if err != nil {
		return ok && last.quarantined
	}
	s.notePeerWALQuarantined(peer, resp.GetWalQuarantined())
	return resp.GetWalQuarantined()
}
