package pki

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

// freezeProxy forwards TCP to target until frozen; then it stops moving
// bytes in both directions but keeps the connections open — a peer that is
// alive at the TCP level and wedged above it.
type freezeProxy struct {
	ln     net.Listener
	mu     sync.Mutex
	frozen bool
	conns  []net.Conn
}

func newFreezeProxy(t *testing.T, target string) *freezeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezeProxy{ln: ln}
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			c.Close()
		}
		p.mu.Unlock()
	})
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				in.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, in, out)
			p.mu.Unlock()
			go p.pipe(out, in)
			go p.pipe(in, out)
		}
	}()
	return p
}

func (p *freezeProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		frozen := p.frozen
		p.mu.Unlock()
		if frozen {
			continue // swallowed: the peer never sees it
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (p *freezeProxy) freeze() { p.mu.Lock(); p.frozen = true; p.mu.Unlock() }

// A peer that stops answering while a stream to it is open is detected by
// keepalive: the stream fails, instead of waiting for as long as TCP keeps
// the connection (a wedged-but-alive host keeps it forever). The server side
// permits the pings (PeerServerOptions), so they are never rejected.
//
// Mutation: dial without the keepalive parameters — the stream's Recv
// waits past the test's bound, red.
func TestPeerDial_KeepaliveDetectsAWedgedPeer(t *testing.T) {
	dir := setupPKI(t)
	prev := peerKeepalive
	peerKeepalive = keepalive.ClientParameters{Time: 10 * time.Second, Timeout: time.Second}
	t.Cleanup(func() { peerKeepalive = prev })

	tlsCfg, err := PeerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(append(PeerServerOptions(), grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second}))...)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	proxy := newFreezeProxy(t, ln.Addr().String())
	conn, err := PeerDial(dir, proxy.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, err := healthpb.NewHealthClient(conn).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Recv(); err != nil {
		t.Fatalf("first health frame: %v", err)
	}
	proxy.freeze()
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := w.Recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err == io.EOF {
			t.Fatalf("the stream ended cleanly; want a keepalive failure")
		}
	case <-time.After(25 * time.Second):
		t.Fatal("a stream to a wedged peer was still open after 25s: no keepalive")
	}
}

// The client's keepalive interval is never shorter than what any server
// permits: the grpc default (5 minutes, an older daemon) and this build's
// (PeerServerOptions). A client pinging faster than a server permits is
// sent GOAWAY (too_many_pings), which would cut a long disk copy to an older
// daemon mid-way during a rolling upgrade.
func TestPeerKeepalive_IsPermittedByEveryServer(t *testing.T) {
	if peerKeepalive.Time <= 5*time.Minute {
		t.Fatalf("peer keepalive Time = %v; must exceed the grpc default server MinTime of 5m", peerKeepalive.Time)
	}
	if peerKeepalive.Time < peerServerKeepaliveMinTime {
		t.Fatalf("peer keepalive Time %v is below this build's server MinTime %v", peerKeepalive.Time, peerServerKeepaliveMinTime)
	}
	if peerKeepalive.PermitWithoutStream {
		t.Fatal("peer keepalive pings without a stream, which an older daemon's default policy rejects")
	}
}
