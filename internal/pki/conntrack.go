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
	"time"

	"google.golang.org/grpc/credentials"
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
// and a revoked one fails. Sweeps run every few seconds, which bounds how long
// a revocation takes to reach a live connection.
type ConnTracker struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
	// served returns the serial this process presents at handshake time.
	served func() string
}

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
	t    *ConnTracker
	info TrackedConn
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.t.remove(c) })
	return c.Conn.Close()
}

// NewConnTracker returns a tracker for a server serving pkiDir's host identity.
func NewConnTracker(pkiDir string) *ConnTracker {
	return &ConnTracker{conns: map[*trackedConn]struct{}{}, served: func() string {
		c, err := ServedHostCertificate(pkiDir)
		if err != nil {
			return ""
		}
		return strings.ToLower(c.SerialNumber.Text(16))
	}}
}

func (t *ConnTracker) remove(c *trackedConn) {
	t.mu.Lock()
	delete(t.conns, c)
	t.mu.Unlock()
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
	tc := &trackedConn{Conn: conn, t: c.t, info: TrackedConn{ServedSerial: c.t.served(), Since: time.Now()}}
	if ti, ok := ai.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
		tc.info.Peer = ti.State.PeerCertificates[0]
	}
	c.t.mu.Lock()
	c.t.conns[tc] = struct{}{}
	c.t.mu.Unlock()
	return tc, ai, nil
}

func (c *trackingCreds) Clone() credentials.TransportCredentials {
	return &trackingCreds{TransportCredentials: c.TransportCredentials.Clone(), t: c.t}
}

// Sweep closes every tracked connection judge rejects and returns how many.
func (t *ConnTracker) Sweep(judge func(TrackedConn) (bool, string)) int {
	t.mu.Lock()
	var victims []*trackedConn
	var whys []string
	for c := range t.conns {
		if drop, why := judge(c.info); drop {
			victims = append(victims, c)
			whys = append(whys, why)
		}
	}
	t.mu.Unlock()
	for i, c := range victims {
		peer := ""
		if c.info.Peer != nil {
			peer = c.info.Peer.Subject.CommonName + "/" + c.info.Peer.SerialNumber.Text(16)
		}
		slog.Info("closing a connection made with a certificate that is no longer acceptable; the client "+
			"reconnects with a fresh handshake", "peer", peer, "reason", whys[i])
		_ = c.Close()
	}
	return len(victims)
}

// Len is the number of tracked connections.
func (t *ConnTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// Run sweeps every `every` until ctx ends.
func (t *ConnTracker) Run(ctx context.Context, every time.Duration, judge func(TrackedConn) (bool, string)) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.Sweep(judge)
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
