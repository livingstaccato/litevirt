package grpcapi

import (
	"context"
	"fmt"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// readyReadTimeout bounds the trivial local read. It must be well under the
// health checker's checkTimeout, because a probe that hangs for the caller's
// whole budget is indistinguishable from an unreachable peer — and that is the
// one verdict this RPC exists to stop conflating.
const readyReadTimeout = 2 * time.Second

// Ready answers whether this daemon can actually serve, as opposed to merely
// accepting connections.
//
// The probe it replaces was a TLS handshake. A handshake is satisfied entirely
// inside the TLS stack: a daemon with a stalled WAL checkpoint, a deadlocked
// RPC path or a database returning busy for every query completes one exactly
// as a healthy node does, and was reported healthy — keeping its voting weight,
// keeping its placements, and continuing to receive pushes it could not apply.
//
// So this does the smallest piece of real work that the wedge would block: one
// read of one replicated table, bounded by readyReadTimeout. It reads this
// node's OWN row, which makes a second failure visible for free — a daemon
// whose own host record is absent from its own copy of the cluster state cannot
// authorize, own, or schedule anything, and is not ready either.
//
// It always returns a RESPONSE, never an error, for false. An error is
// indistinguishable on the wire from the RPC failing to arrive, which is the
// unreachable verdict; "I am here and I cannot serve" is a different fact and
// has to survive the trip as one.
func (s *Server) Ready(ctx context.Context, _ *pb.ReadyRequest) (*pb.ReadyResponse, error) {
	// not_ready_reason carries local error text, so it follows the rule Ping's
	// posture disclosure follows: Ready is in skipAuth and so reaches no
	// identity interceptor, and the distributable lv-cli certificate is issued
	// to every operator. A caller that cannot prove it is a peer gets the
	// verdict without the internals.
	disclose := callerCertHasServerAuth(ctx)
	rctx, cancel := context.WithTimeout(ctx, readyReadTimeout)
	defer cancel()

	resp := &pb.ReadyResponse{HostName: s.hostName, Ready: true}
	reason := ""
	rows, finished, err := s.boundedReadyQuery(rctx)
	switch {
	case !finished:
		resp.Ready = false
		reason = "local read did not return within " + readyReadTimeout.String()
	case err != nil:
		resp.Ready = false
		reason = "local read failed: " + err.Error()
	case len(rows) == 0:
		resp.Ready = false
		reason = "this node has no row in its own hosts table"
	}
	if disclose {
		resp.NotReadyReason = reason
	}
	return resp, nil
}

// PeerReady asks a peer whether it can serve. Injected into the health checker
// (SetPeerReadiness) so the peer probe is an application-level question rather
// than a TLS handshake.
func (s *Server) PeerReady(ctx context.Context, host, addr string) (bool, string, error) {
	// Self is answered locally. A node cannot dial itself to learn whether its
	// own database is wedged: the dial goes through the same daemon, and a
	// readiness probe that depends on the thing it is probing proves nothing.
	if host == s.hostName {
		resp, err := s.Ready(ctx, &pb.ReadyRequest{})
		if err != nil {
			return false, "", err
		}
		return resp.GetReady(), resp.GetNotReadyReason(), nil
	}
	c, closeConn, err := s.dialReadyTarget(ctx, host, addr)
	if err != nil {
		return false, "", err
	}
	defer closeConn()
	resp, err := c.Ready(ctx, &pb.ReadyRequest{})
	if err != nil {
		// Unimplemented means the RPC ARRIVED at a build that predates it. The
		// peer is reachable and has said nothing about its readiness, which is
		// neither of the two failing verdicts. Reading it as either would mark
		// every not-yet-upgraded node degraded for the length of a rolling
		// upgrade — the precise moment a cluster can least afford to lose its
		// voting weight.
		if status.Code(err) == codes.Unimplemented {
			return true, "", nil
		}
		return false, "", err
	}
	return resp.GetReady(), resp.GetNotReadyReason(), nil
}

// readyQuery is Ready's local read: this node's own hosts row.
func (s *Server) readyQuery(ctx context.Context) ([]corrosion.Row, error) {
	if s.readyRead != nil {
		return s.readyRead(ctx)
	}
	return s.db.Query(ctx, `SELECT name FROM hosts WHERE name = ?`, s.hostName)
}

// boundedReadyQuery runs readyQuery but returns when ctx does, whether or not
// the read has. corrosion.Client.Query takes the client lock before it honours
// any context, so a node whose writer is stuck inside a commit blocks the read
// past every timeout; waiting on it made Ready hang for the caller's whole
// budget, which the caller reads as unreachable — the fencing verdict — rather
// than as the not-ready answer it is.
//
// At most one read is outstanding, and callers SHARE it. Every observer probes
// on the same tick, so concurrent calls on a healthy node are the normal case;
// answering all but the first "not ready" for the length of an ordinary read
// cost a healthy node its vote (the checker and QuorumProof both believe a
// not-ready answer on first sight). A caller arriving while a read runs waits
// on that read, within its own budget, and gets its result.
//
// Only a read that has been outstanding longer than readyReadTimeout — one
// that has already overrun the budget every caller is held to, so is blocked,
// not slow — is answered not-ready at once, rather than parking another
// goroutine behind the same lock every probe interval.
//
// The shared read runs under its own readyReadTimeout context, not the first
// caller's: one caller hanging up must not fail the read the others are
// waiting on.
func (s *Server) boundedReadyQuery(ctx context.Context) (rows []corrosion.Row, finished bool, err error) {
	s.readyMu.Lock()
	f := s.readyFlight
	switch {
	case f != nil && time.Since(f.started) > readyReadTimeout:
		s.readyMu.Unlock()
		return nil, false, nil
	case f == nil:
		f = &readyFlight{started: time.Now(), done: make(chan struct{})}
		s.readyFlight = f
		go func() {
			rctx, cancel := context.WithTimeout(context.Background(), readyReadTimeout)
			defer cancel()
			f.rows, f.err = s.readyQuery(rctx)
			s.readyMu.Lock()
			if s.readyFlight == f {
				s.readyFlight = nil
			}
			s.readyMu.Unlock()
			close(f.done)
		}()
	}
	s.readyMu.Unlock()
	select {
	case <-f.done:
		return f.rows, true, f.err
	case <-ctx.Done():
		return nil, false, nil
	}
}

// readyFlight is one outstanding readyQuery, shared by every Ready caller that
// arrives while it runs. rows and err are written before done is closed and
// read only after.
type readyFlight struct {
	started time.Time
	done    chan struct{}
	rows    []corrosion.Row
	err     error
}

// dialReadyTarget reaches the peer at the address the health checker already
// resolved. Going through dialPeer re-resolved it via ResolvePeerTarget — a read
// of THIS node's hosts table, under its own lock, on every probe — so an
// observer whose store was stalled failed every probe before sending anything,
// and booked it as the peer being unreachable. With no address it falls back to
// resolving by name.
func (s *Server) dialReadyTarget(ctx context.Context, host, addr string) (pb.LiteVirtClient, func(), error) {
	if s.peerClientOverride != nil || addr == "" {
		return s.dialPeer(ctx, host)
	}
	conn, err := s.dialPeerAddr(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial host %s at %s: %w", host, addr, err)
	}
	return pb.NewLiteVirtClient(conn), func() { _ = conn.Close() }, nil
}
