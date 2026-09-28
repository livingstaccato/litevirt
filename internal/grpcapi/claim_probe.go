package grpcapi

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// The owner probe (docs/design/recovery-claims.md §3.5.1).
//
// Before a voter accepts a workload value it has not accepted before, it
// probes the value's source host itself and refuses if it reaches it. It does
// not read replicated host_health rows to decide: those are only as fresh as
// replication, and a voter that trusted them would refuse, or accept, on
// another node's stale observation.
//
// It is consulted only for WORKLOAD keys (corrosion.ClaimAccept), which
// nothing in this release mints — recovery_claim_v1 (colonelpanik/litevirt#250)
// does. The mechanism is here so the voter's rules are complete the day a
// coordinator starts claiming.

const (
	// claimProbeTimeout bounds one probe, the order of health.checkTimeout.
	claimProbeTimeout = 2 * time.Second
	// claimProbeMaxAge is how long one probe's answer is reused for every
	// Accept naming the same source: a failed host with fifty workloads costs
	// each voter one probe, not fifty.
	claimProbeMaxAge = 5 * time.Second
)

type probeResult struct {
	reached bool
	detail  string
	at      time.Time
}

// ownerProbeCache holds the last answer per source and single-flights
// concurrent probes of one source.
type ownerProbeCache struct {
	mu       sync.Mutex
	results  map[string]probeResult
	inflight map[string]chan struct{}
	// dial replaces the real probe in tests: it reports the certificate CN
	// that answered, or an error.
	dial func(ctx context.Context, host string) (cn string, err error)
	now  func() time.Time
}

func (c *ownerProbeCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// probeOwner is the corrosion.OwnerProbe this voter consults.
func (s *Server) probeOwner(ctx context.Context, host string) (bool, string) {
	c := &s.claims.probe
	for {
		c.mu.Lock()
		if r, ok := c.results[host]; ok && c.clock().Sub(r.at) < claimProbeMaxAge {
			c.mu.Unlock()
			return r.reached, r.detail
		}
		if ch, busy := c.inflight[host]; busy {
			c.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				// Unknown is never "not reached": a voter that could not finish
				// its own check does not certify the eviction.
				return true, "probe interrupted: " + ctx.Err().Error()
			}
		}
		if c.inflight == nil {
			c.inflight = map[string]chan struct{}{}
		}
		ch := make(chan struct{})
		c.inflight[host] = ch
		c.mu.Unlock()

		reached, detail := s.probeOnce(ctx, host)

		c.mu.Lock()
		if c.results == nil {
			c.results = map[string]probeResult{}
		}
		c.results[host] = probeResult{reached: reached, detail: detail, at: c.clock()}
		delete(c.inflight, host)
		close(ch)
		c.mu.Unlock()
		return reached, detail
	}
}

// probeOnce dials host and Pings it. It counts as reached only if the
// handshake completes, the peer certificate's CN is host, and the RPC returns.
// Anything else — including a different host answering on a reused address —
// is not reached.
func (s *Server) probeOnce(ctx context.Context, host string) (bool, string) {
	pctx, cancel := context.WithTimeout(ctx, claimProbeTimeout)
	defer cancel()
	start := time.Now()
	dial := s.claims.probe.dial
	if dial == nil {
		dial = s.dialOwnerProbe
	}
	cn, err := dial(pctx, host)
	if err != nil {
		return false, fmt.Sprintf("not reached: %v", err)
	}
	if cn != host {
		return false, fmt.Sprintf("not reached: %q answered at %s's address", cn, host)
	}
	return true, fmt.Sprintf("Ping answered in %s", time.Since(start).Round(time.Millisecond))
}

// dialOwnerProbe Pings host at the address in THIS voter's hosts row, over
// the peer transport with this node's host certificate, and returns the CN
// the answering certificate carries. Not the gossip fallback: the probe asks
// whether the host the cluster recorded is up, at the address it recorded.
func (s *Server) dialOwnerProbe(ctx context.Context, host string) (string, error) {
	h, err := corrosion.GetHost(ctx, s.db, host)
	if err != nil {
		return "", err
	}
	if h == nil {
		return "", fmt.Errorf("no hosts row for %s", host)
	}
	conn, err := pki.PeerDial(s.pkiDir, peerTarget(h.Address, h.GRPCPort))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var p peer.Peer
	if _, err := pb.NewLiteVirtClient(conn).Ping(ctx, &pb.PingRequest{}, grpc.Peer(&p)); err != nil {
		return "", err
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate")
	}
	return tlsInfo.State.PeerCertificates[0].Subject.CommonName, nil
}
