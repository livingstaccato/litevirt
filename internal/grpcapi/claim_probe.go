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
	"github.com/litevirt/litevirt/internal/claims"
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
// It is consulted only for WORKLOAD keys (corrosion.ClaimAccept): the
// recoveries a coordinator claims under recovery_claim_v1 before it mints a
// reschedule, promote or relocate proof. A refusal names this voter and what
// it reached; the coordinator reports every refusing voter, records
// recovery_claim_owner_reachable, and retries at the same round on its next
// tick — nothing is contending, the source is up (§3.13 step 6).
//
// The probe runs detached from the RPC that wants it (§10 item 36). A dead
// host's dial can take longer than an Accept has left — an ARP timeout is
// about 3 s, and an Accept arrives with whatever phase 1 left of the claim's
// deadline — so a probe run under the Accept's context was cancelled before it
// could ever fail on its own, and nothing ever learned "not reached". Now a
// probe runs under its own claimProbeTimeout, one per source host, and only
// its finished answer is stored. An Accept that cannot wait for it reads as
// reached (§10 item 9); the next Accept finds the finished answer.
//
// Timing, with the proposer's per-call timeout C = claims.DefaultCallTimeout:
//
//   - a Prepare for a workload key starts the probe of the source this voter's
//     row names (or the last Accept at the key named), unless a result younger
//     than claimProbeRefreshAge = claimProbeMaxAge - C is cached or a probe is
//     in flight. The round's Accept follows within C (phase 1 is bounded by
//     it), so a result the Prepare did not refresh is still under
//     claimProbeMaxAge when the Accept reads it;
//   - a probe the Prepare started finishes within claimProbeTimeout (2 s) <
//     C. With the dead source a voter, phase 1 waits out its Prepare, C, so
//     the answer is waiting when the Accept arrives; with it not a voter, the
//     Accept arrives at once and waits up to C for the probe. Either way a
//     dead source's claim decides in its first round;
//   - a round that still misses — a claim deadline the lease cut short — is
//     retried on the coordinator's next tick, whose Prepare refreshes the
//     probe again, so it decides in the second.

const (
	// claimProbeTimeout bounds one probe, the order of health.checkTimeout.
	claimProbeTimeout = 2 * time.Second
	// claimProbeMaxAge is how long one probe's answer is reused for every
	// Accept naming the same source: a failed host with fifty workloads costs
	// each voter one probe, not fifty. A finished "not reached" is never used
	// past it, so a host that comes back is probed again.
	claimProbeMaxAge = 5 * time.Second
	// claimProbeRefreshAge is the age at which a Prepare starts a fresh probe
	// of a source whose cached answer is still valid: one proposer call
	// timeout before it expires, so the round's Accept never finds it expired.
	claimProbeRefreshAge = claimProbeMaxAge - claims.DefaultCallTimeout
	// maxClaimSources bounds the per-key memory of the last source an Accept
	// named; past it the memory starts again. It is only a probe hint.
	maxClaimSources = 4096
)

type probeResult struct {
	reached bool
	detail  string
	at      time.Time
}

// ownerProbeCache holds the last finished answer per source and runs at most
// one probe per source at a time.
type ownerProbeCache struct {
	mu       sync.Mutex
	results  map[string]probeResult
	inflight map[string]chan struct{}
	// sources is the source the last Accept at each workload key named: the
	// Prepare-time hint for a key whose row names no owner at its epoch.
	sources map[corrosion.ClaimKey]string
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

// freshLocked is host's cached answer if it is younger than age.
func (c *ownerProbeCache) freshLocked(host string, age time.Duration) (probeResult, bool) {
	r, ok := c.results[host]
	if !ok || c.clock().Sub(r.at) >= age {
		return probeResult{}, false
	}
	return r, true
}

// probeOwner is the corrosion.OwnerProbe this voter consults.
func (s *Server) probeOwner(ctx context.Context, host string) (bool, string) {
	c := &s.claims.probe
	c.mu.Lock()
	if r, ok := c.freshLocked(host, claimProbeMaxAge); ok {
		c.mu.Unlock()
		return r.reached, r.detail
	}
	done := s.startProbeLocked(host)
	c.mu.Unlock()
	select {
	case <-done:
		c.mu.Lock()
		r := c.results[host]
		c.mu.Unlock()
		return r.reached, r.detail
	case <-ctx.Done():
		// Unknown is never "not reached": a voter that could not finish its
		// own check does not certify the eviction (§10 item 9). The probe
		// keeps running, and the next Accept naming the source reads its
		// finished answer.
		return true, "probe in flight, unfinished at this Accept's deadline: " + ctx.Err().Error()
	}
}

// startProbeLocked starts a probe of host unless one is in flight, and returns
// the channel closed when it has finished and stored its answer. c.mu is held.
//
// The probe owns its context: no caller's cancellation reaches it, so it ends
// only on its own answer or claimProbeTimeout, which bounds the goroutine.
// Every answer it stores is therefore a finished one.
func (s *Server) startProbeLocked(host string) chan struct{} {
	c := &s.claims.probe
	if ch, busy := c.inflight[host]; busy {
		return ch
	}
	if c.inflight == nil {
		c.inflight = map[string]chan struct{}{}
	}
	ch := make(chan struct{})
	c.inflight[host] = ch
	dial := c.dial
	go func() {
		reached, detail := s.probeOnce(context.Background(), dial, host)
		c.mu.Lock()
		if c.results == nil {
			c.results = map[string]probeResult{}
		}
		c.results[host] = probeResult{reached: reached, detail: detail, at: c.clock()}
		delete(c.inflight, host)
		c.mu.Unlock()
		close(ch)
	}()
	return ch
}

// primeOwnerProbe starts, at Prepare, the probe the round's Accept will want:
// of the host this voter's row names at the key's epoch, and of the source
// the last Accept at the key named. A source whose answer is younger than
// claimProbeRefreshAge, or is being probed, or is this voter, is left alone.
// It decides nothing — the Accept probes the source its value names.
func (s *Server) primeOwnerProbe(ctx context.Context, key corrosion.ClaimKey) {
	if !key.IsWorkload() {
		return
	}
	hint, err := s.db.ClaimProbeHint(ctx, key)
	if err != nil {
		hint = ""
	}
	c := &s.claims.probe
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, h := range []string{hint, c.sources[key]} {
		if h == "" || h == s.hostName {
			continue
		}
		if _, ok := c.freshLocked(h, claimProbeRefreshAge); ok {
			continue
		}
		s.startProbeLocked(h)
	}
}

// rememberClaimSource records the source an Accept at key named, the
// Prepare-time hint for the key's next round.
func (s *Server) rememberClaimSource(key corrosion.ClaimKey, host string) {
	if !key.IsWorkload() || host == "" {
		return
	}
	c := &s.claims.probe
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sources == nil || len(c.sources) >= maxClaimSources {
		c.sources = map[corrosion.ClaimKey]string{}
	}
	c.sources[key] = host
}

// probeOnce dials host and Pings it, bounded by claimProbeTimeout under
// parent: context.Background() for the owner probe, which is detached from
// every caller, and the operator's context for a forced reconfiguration's
// fresh check (forcedProbe). It counts as reached only if the handshake completes, the
// peer certificate's CN is host, and the RPC returns. Anything else —
// including a different host answering on a reused address, or no answer
// within claimProbeTimeout — is not reached.
func (s *Server) probeOnce(parent context.Context, dial func(context.Context, string) (string, error), host string) (bool, string) {
	pctx, cancel := context.WithTimeout(parent, claimProbeTimeout)
	defer cancel()
	start := time.Now()
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
