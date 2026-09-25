package health

import (
	"context"
	"log/slog"
)

// StatusUnready is the host_health status for a peer that is REACHABLE and
// ANSWERING and nevertheless cannot serve.
//
// It is deliberately a third value beside "healthy" and "suspect" rather than a
// reuse of "suspect", because the two carry different evidence and license
// different actions. "suspect" is an inference from silence and is what fencing
// quorum counts — a power-off decision made about a node that cannot argue.
// "unready" is the node's own answer, and a node that is answering is not a
// node to power-cycle on an application-level signal; it is one to stop
// trusting with votes, placements and pushes. Every existing consumer compares
// against "healthy", so an unready peer degrades correctly without them
// knowing the value.
const StatusUnready = "unready"

// PeerReadiness asks a peer whether it can actually SERVE — not merely whether
// its TLS endpoint answers.
//
// The distinction is the whole point. Checker.probe completes a TLS handshake
// and calls that healthy, which a daemon holding a wedged database satisfies
// perfectly: the listener is up, the handshake is in the TLS stack, and nothing
// in it touches the DB. Such a peer keeps its voting weight, keeps being sent
// pushes it cannot apply, and is reported healthy to every operator surface,
// because no probe ever asked it to do any work.
//
// ready is the peer's own answer to "did a trivial local read of a replicated
// table just succeed". reason carries why not, for the operator; it is
// diagnostic and no decision path reads it.
//
// An error means UNREACHABLE — the RPC did not complete — and is a different
// verdict from (false, reason), which means reachable and answering and not
// able to serve. Injected from the daemon (grpcapi.Server.PeerReady); nil
// leaves the old TLS-only probe in place.
type PeerReadiness func(ctx context.Context, host string) (ready bool, reason string, err error)

// SetPeerReadiness injects the application-level readiness prober.
func (c *Checker) SetPeerReadiness(fn PeerReadiness) {
	c.mu.Lock()
	c.peerReady = fn
	c.mu.Unlock()
}

// readiness returns the injected prober under the lock.
func (c *Checker) readiness() PeerReadiness {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerReady
}

// probeResult is the three-valued verdict of one peer probe.
type probeResult int

const (
	// probeReady: the peer answered and reported that it can serve.
	probeReady probeResult = iota
	// probeNotReady: the peer answered and reported that it CANNOT serve.
	probeNotReady
	// probeUnreachable: no answer. Says nothing about readiness either way.
	probeUnreachable
)

// probeHost asks the peer whether it can serve, falling back to the TLS-only
// reachability probe when no readiness prober is wired.
//
// The readiness RPC SUBSUMES the TLS dial — it cannot complete without one — so
// when it is wired there is no second round trip. The fallback exists because
// SetPeerReadiness is injected by the daemon after construction; a Checker
// built without one behaves exactly as it did before. That is deliberately
// fail-OPEN on the new signal: the alternative, reporting every peer unready
// until the prober arrives, would strip the whole cluster of its voting weight
// during startup.
func (c *Checker) probeHost(ctx context.Context, name, addr string) probeResult {
	ready := c.readiness()
	if ready == nil {
		if c.probe(addr) {
			return probeReady
		}
		return probeUnreachable
	}
	rctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	ok, reason, err := ready(rctx, name)
	if err != nil {
		return probeUnreachable
	}
	if !ok {
		slog.Warn("peer is reachable but not ready to serve",
			"peer", name, "reason", reason)
		return probeNotReady
	}
	return probeReady
}
