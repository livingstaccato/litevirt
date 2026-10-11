package pki

import (
	"context"
	"crypto/x509"
	"log/slog"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/stats"
)

// Established connections and changed identities.
//
// Revocation and the peer pin are checked at the TLS handshake, and a gRPC
// connection is long-lived: without more, a certificate revoked or superseded
// after a connection was made keeps working on that connection until it
// happens to drop. The UI's loopback client is the plain case — after a
// renewal it went on presenting the old certificate, which the pin then
// classified as a bare client.
//
// A ConnTracker wraps the server's transport credentials, remembers every
// established TLS connection with the certificates it was made with, and closes
// the ones a judge says are no longer acceptable. The client reconnects with a
// fresh handshake — which a renewed client passes with its new certificate,
// and a revoked one fails.
//
// A judged connection DRAINS: from the moment it is judged, every new RPC on
// it is refused (the server's auth interceptors consult Draining, and also
// refuse a revoked or superseded identity themselves, per RPC, before any
// sweep has run). What a drain spares is only the RPCs already in flight on a
// connection superseded by a renewal — a cold-disk migration stream, a backup
// push that started legitimately before it — and only until they finish or
// StreamGrace runs out, whichever comes first; the connection is closed the
// moment its last RPC ends. That holds whether or not the replaced certificate
// has been revoked yet: `lv host renew-cert` revokes it at once, and a
// certificate with a standing CA-issued successor (SupersededBy) was revoked
// because it was renewed. A REVOKED identity with no successor gets no grace
// at all: that revocation is the emergency path (`lv host rm`, `lv host
// revoke-cert` of a live identity, a stolen key), and its connection is closed
// at once (Verdict.Immediate), in-flight RPCs included. The judge decides
// which; the tracker learns about RPCs through StatsHandler, which the server
// must install alongside ServerCreds.
type ConnTracker struct {
	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	byAddr map[string]*trackedConn
	// served returns the serial this process presents at handshake time.
	served func() string
	// StreamGrace is how long a judged connection with RPCs in flight is
	// left to finish. Zero means DefaultStreamGrace.
	StreamGrace time.Duration
	sweepMu     sync.Mutex
}

// DefaultStreamGrace bounds how long a connection that must be closed is left
// to finish the RPCs it is carrying.
const DefaultStreamGrace = 15 * time.Minute

// TrackedConn is what a judge sees.
type TrackedConn struct {
	// Peer is the certificate the client presented (nil if none).
	Peer *x509.Certificate
	// ServedSerial is the serial this side presented, lower-case hex.
	ServedSerial string
	// Since is when the handshake completed.
	Since time.Time
}

type trackedConn struct {
	net.Conn
	t        *ConnTracker
	info     TrackedConn
	key      string
	once     sync.Once
	active   atomic.Int64
	judgedAt time.Time // first sweep that wanted it closed; guarded by sweepMu
	// draining is set once the connection has been judged unacceptable; its
	// reason is drainWhy. New RPCs on it are refused, and it is closed when
	// the last RPC in flight ends.
	draining atomic.Bool
	drainWhy atomic.Value // string
}

// Verdict is a judge's answer for one connection.
type Verdict struct {
	// Close: the connection is no longer acceptable. It drains — no new RPC —
	// and is closed once its RPCs in flight end, or after StreamGrace.
	Close bool
	// Immediate closes it at once, RPCs in flight included (a revocation that
	// is not a renewal's).
	Immediate bool
	Reason    string
}

func (c *trackedConn) markDraining(why string) {
	if c.draining.CompareAndSwap(false, true) {
		c.drainWhy.Store(why)
	}
}

func (c *trackedConn) drainReason() string {
	s, _ := c.drainWhy.Load().(string)
	return s
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.t.remove(c) })
	return c.Conn.Close()
}

// NewConnTracker returns a tracker for a server serving pkiDir's host identity.
func NewConnTracker(pkiDir string) *ConnTracker {
	return &ConnTracker{conns: map[*trackedConn]struct{}{}, byAddr: map[string]*trackedConn{}, served: func() string {
		c, err := ServedHostCertificate(pkiDir)
		if err != nil {
			return ""
		}
		return strings.ToLower(c.SerialNumber.Text(16))
	}}
}

func addrKey(local, remote net.Addr) string {
	if local == nil || remote == nil {
		return ""
	}
	return local.String() + "|" + remote.String()
}

func (t *ConnTracker) remove(c *trackedConn) {
	t.mu.Lock()
	delete(t.conns, c)
	if t.byAddr[c.key] == c {
		delete(t.byAddr, c.key)
	}
	t.mu.Unlock()
}

func (t *ConnTracker) grace() time.Duration {
	if t.StreamGrace > 0 {
		return t.StreamGrace
	}
	return DefaultStreamGrace
}

// ServerCreds wraps base so every connection it accepts is tracked.
func (t *ConnTracker) ServerCreds(base credentials.TransportCredentials) credentials.TransportCredentials {
	return &trackingCreds{TransportCredentials: base, t: t}
}

type trackingCreds struct {
	credentials.TransportCredentials
	t *ConnTracker
}

func (c *trackingCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, ai, err := c.TransportCredentials.ServerHandshake(raw)
	if err != nil {
		return conn, ai, err
	}
	tc := &trackedConn{Conn: conn, t: c.t, info: TrackedConn{ServedSerial: c.t.served(), Since: time.Now()},
		key: addrKey(conn.LocalAddr(), conn.RemoteAddr())}
	if ti, ok := ai.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
		tc.info.Peer = ti.State.PeerCertificates[0]
	}
	c.t.mu.Lock()
	c.t.conns[tc] = struct{}{}
	if tc.key != "" {
		c.t.byAddr[tc.key] = tc
	}
	c.t.mu.Unlock()
	return tc, ai, nil
}

func (c *trackingCreds) Clone() credentials.TransportCredentials {
	return &trackingCreds{TransportCredentials: c.TransportCredentials.Clone(), t: c.t}
}

// StatsHandler counts the RPCs in flight on each tracked connection.
func (t *ConnTracker) StatsHandler() stats.Handler { return &connStats{t: t} }

type connStats struct{ t *ConnTracker }
type connKeyCtx struct{}
type rpcConnCtx struct{}

func (h *connStats) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return context.WithValue(ctx, connKeyCtx{}, addrKey(info.LocalAddr, info.RemoteAddr))
}

func (h *connStats) HandleConn(context.Context, stats.ConnStats) {}

func (h *connStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	key, _ := ctx.Value(connKeyCtx{}).(string)
	h.t.mu.Lock()
	tc := h.t.byAddr[key]
	h.t.mu.Unlock()
	if tc == nil {
		return ctx
	}
	tc.active.Add(1)
	return context.WithValue(ctx, rpcConnCtx{}, tc)
}

// ConnInfo is what the auth interceptors learn about the connection an RPC
// arrived on: the certificates it was made with, and whether it is draining.
type ConnInfo struct {
	TrackedConn
	Draining    bool
	DrainReason string
}

// ConnFromContext returns the tracked connection ctx's RPC arrived on.
// ok=false when the server has no tracker (or the connection predates it).
func ConnFromContext(ctx context.Context) (ConnInfo, bool) {
	tc, ok := ctx.Value(rpcConnCtx{}).(*trackedConn)
	if !ok || tc == nil {
		return ConnInfo{}, false
	}
	return ConnInfo{TrackedConn: tc.info, Draining: tc.draining.Load(), DrainReason: tc.drainReason()}, true
}

// DrainConnection marks the connection ctx's RPC arrived on as draining: an
// RPC the auth interceptor has just refused for its identity. Every later RPC
// on it is refused, and it is closed when the RPCs in flight end — this one,
// being refused, ends at once — or, when immediate, right after the refusal
// has had a moment to reach the client (immediateCloseDelay), RPCs in flight
// included.
func DrainConnection(ctx context.Context, why string, immediate bool) {
	tc, ok := ctx.Value(rpcConnCtx{}).(*trackedConn)
	if !ok || tc == nil {
		return
	}
	tc.markDraining(why)
	if immediate {
		time.AfterFunc(immediateCloseDelay, func() { _ = tc.Close() })
	}
}

// immediateCloseDelay lets the refusal that triggered an immediate close be
// written before the connection goes, so the client sees why. The connection
// accepts no new RPC meanwhile.
const immediateCloseDelay = 100 * time.Millisecond

func (h *connStats) HandleRPC(ctx context.Context, s stats.RPCStats) {
	if _, end := s.(*stats.End); !end {
		return
	}
	if tc, ok := ctx.Value(rpcConnCtx{}).(*trackedConn); ok {
		if tc.active.Add(-1) <= 0 && tc.draining.Load() {
			// The last RPC on a draining connection ended: close it now
			// rather than at the next sweep, so the client reconnects with a
			// fresh handshake at once — just after its last status has been
			// written, so a refusal reaches the client with its reason.
			time.AfterFunc(immediateCloseDelay, func() { _ = tc.Close() })
		}
	}
}

// Sweep closes every tracked connection judge rejects and returns how many.
// The judge runs on a snapshot, outside the lock new handshakes take, so a
// judge that reads the database never holds up the accept path. A rejected
// connection drains (no new RPC is accepted on it); one with RPCs in flight is
// left to finish them, up to StreamGrace, unless the verdict is Immediate.
func (t *ConnTracker) Sweep(judge func(TrackedConn) Verdict) int {
	t.sweepMu.Lock()
	defer t.sweepMu.Unlock()
	t.mu.Lock()
	snap := make([]*trackedConn, 0, len(t.conns))
	for c := range t.conns {
		snap = append(snap, c)
	}
	t.mu.Unlock()
	now := time.Now()
	closed := 0
	for _, c := range snap {
		v := judge(c.info)
		why := v.Reason
		if !v.Close {
			// Drained by the interceptor (an RPC refused for its identity)
			// stays drained: the identity does not become acceptable again.
			if !c.draining.Load() {
				c.judgedAt = time.Time{}
				continue
			}
			why = c.drainReason()
		}
		c.markDraining(why)
		peer := ""
		if c.info.Peer != nil {
			peer = c.info.Peer.Subject.CommonName + "/" + c.info.Peer.SerialNumber.Text(16)
		}
		if n := c.active.Load(); n > 0 && !v.Immediate {
			if c.judgedAt.IsZero() {
				c.judgedAt = now
				slog.Info("a connection made with a certificate that is no longer acceptable carries RPCs in flight; "+
					"closing it once they finish", "peer", peer, "reason", why, "in_flight", n, "grace", t.grace())
			}
			if now.Sub(c.judgedAt) < t.grace() {
				continue
			}
			slog.Warn("closing a connection whose RPCs outlasted the grace period; they fail and must be retried",
				"peer", peer, "reason", why, "in_flight", n)
		} else {
			slog.Info("closing a connection made with a certificate that is no longer acceptable; the client "+
				"reconnects with a fresh handshake", "peer", peer, "reason", why)
		}
		_ = c.Close()
		closed++
	}
	return closed
}

// Len is the number of tracked connections.
func (t *ConnTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// Run sweeps every `every` until ctx ends, with a fresh judge per sweep (so a
// judge may cache what it reads for exactly one sweep).
func (t *ConnTracker) Run(ctx context.Context, every time.Duration, newJudge func() func(TrackedConn) Verdict) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.Sweep(newJudge())
		}
	}
}

// RevocationChecker returns the cached, CA-verified CRL check the handshakes
// use, for judging established connections.
func RevocationChecker(pkiDir string) func(*big.Int) bool {
	caPEM, _ := readBounded(filepath.Join(pkiDir, "ca.crt"))
	chk := newCRLChecker(pkiDir, parseCACert(caPEM))
	return chk.isRevoked
}

var sharedRevocationCheckers sync.Map // pkiDir -> *crlChecker

// IsRevokedCached is the handshakes' revocation check — the CA-verified CRL
// installed in pkiDir, re-read only when the file changes — shared per pkiDir,
// for a check that runs on every RPC (the auth interceptors). Without a
// readable CA it falls back to IsCertRevoked.
func IsRevokedCached(pkiDir string, serial *big.Int) bool {
	if serial == nil {
		return false
	}
	if v, ok := sharedRevocationCheckers.Load(pkiDir); ok {
		return v.(*crlChecker).isRevoked(serial)
	}
	caPEM, err := readBounded(filepath.Join(pkiDir, "ca.crt"))
	ca := parseCACert(caPEM)
	if err != nil || ca == nil {
		return IsCertRevoked(pkiDir, serial)
	}
	v, _ := sharedRevocationCheckers.LoadOrStore(pkiDir, newCRLChecker(pkiDir, ca))
	return v.(*crlChecker).isRevoked(serial)
}
