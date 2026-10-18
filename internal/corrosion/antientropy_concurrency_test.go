package corrosion

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Cross-peer concurrency and connection reuse for anti-entropy (#261).

// inflight tracks how many digest calls are in progress across every peer of
// one test, and the most there ever were at once.
type inflight struct {
	now, max atomic.Int32
}

func (f *inflight) enter() {
	n := f.now.Add(1)
	for {
		m := f.max.Load()
		if n <= m || f.max.CompareAndSwap(m, n) {
			return
		}
	}
}

func (f *inflight) leave() { f.now.Add(-1) }

// slowPeer answers GetStateDigest after delay, counting the calls in flight
// across every slowPeer that shares f. failNext makes its next digest fail.
type slowPeer struct {
	pb.UnimplementedLiteVirtServer
	delay    time.Duration
	f        *inflight
	calls    atomic.Int32
	failNext atomic.Bool
}

func (p *slowPeer) GetStateDigest(ctx context.Context, _ *emptypb.Empty) (*pb.StateDigestResponse, error) {
	p.calls.Add(1)
	if p.failNext.CompareAndSwap(true, false) {
		return nil, status.Error(codes.Internal, "injected failure")
	}
	if p.f != nil {
		p.f.enter()
		defer p.f.leave()
	}
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.StateDigestResponse{}, nil
}

// countingListener counts the TCP connections a peer accepted: one per dial.
type countingListener struct {
	net.Listener
	accepts atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return c, err
}

// servePeer serves p over mTLS on 127.0.0.1 and returns its port and its
// accept counter. It does not touch the hosts table.
func servePeer(t *testing.T, pkiDir string, p pb.LiteVirtServer) (int, *countingListener) {
	t.Helper()
	tlsCfg, err := pki.ServerTLSConfig(pkiDir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cl := &countingListener{Listener: ln}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	pb.RegisterLiteVirtServer(srv, p)
	go func() { _ = srv.Serve(cl) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().(*net.TCPAddr).Port, cl
}

// addPeerHost records a live host row for name at 127.0.0.1:port.
func addPeerHost(t *testing.T, c *Client, name string, port int, serial string) {
	t.Helper()
	if err := InsertHost(context.Background(), c, HostRecord{
		Name: name, Address: "127.0.0.1", SSHUser: "root", State: "active",
		GRPCPort: port, CertSerial: serial,
	}); err != nil {
		t.Fatalf("InsertHost %s: %v", name, err)
	}
}

func aeMembers(names ...string) func() []PeerInfo {
	return func() []PeerInfo {
		out := make([]PeerInfo, 0, len(names))
		for _, n := range names {
			out = append(out, PeerInfo{Name: n})
		}
		return out
	}
}

// newTestAE builds an AntiEntropy whose pooled connections are closed when the
// test ends.
func newTestAE(t *testing.T, c *Client, pkiDir string) *AntiEntropy {
	t.Helper()
	ae := NewAntiEntropy(c, pkiDir, time.Minute)
	t.Cleanup(ae.Close)
	return ae
}

// A pass checks peers concurrently, at most antiEntropyPeerConcurrency at a
// time. It visited them one at a time, so a pass over N peers cost the sum of
// their round trips: one slow peer delayed every peer behind it.
func TestCheckPeers_PeersAreCheckedConcurrentlyAndBounded(t *testing.T) {
	old := antiEntropyPeerConcurrency
	antiEntropyPeerConcurrency = 3
	t.Cleanup(func() { antiEntropyPeerConcurrency = old })

	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	f := &inflight{}
	const peers = 8
	const delay = 200 * time.Millisecond
	var names []string
	var all []*slowPeer
	for i := range peers {
		name := "peer-" + string(rune('a'+i))
		p := &slowPeer{delay: delay, f: f}
		port, _ := servePeer(t, pkiDir, p)
		addPeerHost(t, c, name, port, "")
		names = append(names, name)
		all = append(all, p)
	}
	c.SetMembersForTests(aeMembers(names...))
	ae := newTestAE(t, c, pkiDir)

	start := time.Now()
	ae.checkPeers(context.Background())
	took := time.Since(start)

	for i, p := range all {
		if p.calls.Load() != 1 {
			t.Errorf("%s: %d digest calls, want 1", names[i], p.calls.Load())
		}
	}
	got := f.max.Load()
	t.Logf("%d peers at %v each: pass took %v, at most %d digests in flight (limit %d)",
		peers, delay, took, got, antiEntropyPeerConcurrency)
	if got < 2 {
		t.Errorf("at most %d digest in flight: the pass checks peers one at a time", got)
	}
	if got > int32(antiEntropyPeerConcurrency) {
		t.Errorf("%d digests in flight, over the limit of %d: concurrency is unbounded", got, antiEntropyPeerConcurrency)
	}
}

// A pass reuses the connection it opened to a peer on the passes after it.
// Every check dialled afresh, so every pass paid a TCP and a TLS 1.3
// handshake per peer, in both directions' CPU.
func TestCheckPeers_ReusesPeerConnectionsAcrossPasses(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	var lns []*countingListener
	var names []string
	for _, name := range []string{"peer-a", "peer-b", "peer-c"} {
		port, ln := servePeer(t, pkiDir, &slowPeer{})
		addPeerHost(t, c, name, port, "")
		lns = append(lns, ln)
		names = append(names, name)
	}
	c.SetMembersForTests(aeMembers(names...))
	ae := newTestAE(t, c, pkiDir)

	const passes = 3
	for range passes {
		ae.checkPeers(context.Background())
	}
	for i, ln := range lns {
		if n := ln.accepts.Load(); n != 1 {
			t.Errorf("%s accepted %d connections over %d passes, want 1 (reused)", names[i], n, passes)
		}
	}
}

// A pooled connection is not reused once the peer's row says it is somewhere
// else, or is another incarnation of the host: a re-admission with a new
// certificate, or a move to a new address.
func TestCheckPeers_RedialsWhenThePeerRowChanges(t *testing.T) {
	ctx := context.Background()
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	oldPort, oldLn := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", oldPort, "aa01")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(ctx)
	if oldLn.accepts.Load() != 1 {
		t.Fatalf("precondition: first pass made %d connections, want 1", oldLn.accepts.Load())
	}

	// Re-admitted with a new certificate at the same address.
	if _, err := c.DB().Exec(`UPDATE hosts SET cert_serial = 'bb02' WHERE name = 'peer-a'`); err != nil {
		t.Fatal(err)
	}
	ae.checkPeers(ctx)
	if n := oldLn.accepts.Load(); n != 2 {
		t.Errorf("after the peer's certificate serial changed: %d connections, want 2 (redialled)", n)
	}

	// Moved to another address.
	newPort, newLn := servePeer(t, pkiDir, &slowPeer{})
	if _, err := c.DB().Exec(`UPDATE hosts SET grpc_port = ? WHERE name = 'peer-a'`, newPort); err != nil {
		t.Fatal(err)
	}
	ae.checkPeers(ctx)
	if n := newLn.accepts.Load(); n != 1 {
		t.Errorf("after the peer moved: its new address got %d connections, want 1", n)
	}

	// A new incarnation of the row (re-admission restamps created_at).
	if _, err := c.DB().Exec(`UPDATE hosts SET created_at = '2099-01-01T00:00:00.000000000Z' WHERE name = 'peer-a'`); err != nil {
		t.Fatal(err)
	}
	ae.checkPeers(ctx)
	if n := newLn.accepts.Load(); n != 2 {
		t.Errorf("after the peer's incarnation changed: %d connections, want 2 (redialled)", n)
	}
}

// A peer that leaves the membership has its pooled connection closed at the
// next pass, not held for as long as the daemon runs.
func TestCheckPeers_ClosesTheConnectionOfAPeerThatLeft(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	pa, _ := servePeer(t, pkiDir, &slowPeer{})
	pbp, _ := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", pa, "")
	addPeerHost(t, c, "peer-b", pbp, "")
	c.SetMembersForTests(aeMembers("peer-a", "peer-b"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(context.Background())
	gone := ae.conns.lookup("peer-b")
	if gone == nil {
		t.Fatal("precondition: no pooled connection to peer-b after a pass")
	}

	c.SetMembersForTests(aeMembers("peer-a"))
	ae.checkPeers(context.Background())
	if ae.conns.lookup("peer-b") != nil {
		t.Error("peer-b left the membership and is still in the pool")
	}
	if !gone.isClosed() {
		t.Error("peer-b left the membership and its connection is still open")
	}
	if ae.conns.lookup("peer-a") == nil {
		t.Error("peer-a is still a member and lost its pooled connection")
	}
}

// A connection whose digest failed is dropped, so the next pass dials afresh
// rather than waiting out gRPC's reconnect backoff on a peer that came back.
func TestCheckPeers_RedialsAfterAFailedDigest(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	p := &slowPeer{}
	port, ln := servePeer(t, pkiDir, p)
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	p.failNext.Store(true)
	ae.checkPeers(context.Background())
	ae.checkPeers(context.Background())
	if n := ln.accepts.Load(); n != 2 {
		t.Errorf("%d connections across a failed and a good pass, want 2 (the failed one dropped)", n)
	}
}

// A change to this node's own PKI material — a new CRL above all — drops every
// pooled connection: a revocation is enforced at the handshake, and a
// connection that never handshakes again would never see it.
func TestCheckPeers_RedialsWhenTheLocalPKIChanges(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, ln := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(context.Background())

	crl := filepath.Join(pkiDir, "crl.pem")
	if err := os.WriteFile(crl, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(crl) })
	ae.checkPeers(context.Background())
	if n := ln.accepts.Load(); n != 2 {
		t.Errorf("%d connections after the local CRL changed, want 2 (redialled)", n)
	}
}

// Close closes every pooled connection, and a pass after it still works.
func TestAntiEntropy_CloseClosesThePool(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, _ := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(context.Background())
	pc := ae.conns.lookup("peer-a")
	if pc == nil {
		t.Fatal("precondition: nothing pooled")
	}
	ae.Close()
	if !pc.isClosed() {
		t.Error("Close left a pooled connection open")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ae.checkPeers(context.Background()) }()
	wg.Wait()
	if ae.conns.lookup("peer-a") == nil {
		t.Error("a pass after Close did not dial again")
	}
}

// A pooled connection older than antiEntropyConnMaxAge is not reused, so a
// peer is re-handshaken, and its certificate re-verified, at least that often.
func TestAEConnPool_RedialsPastMaxAge(t *testing.T) {
	shrink(t, &antiEntropyConnMaxAge, time.Nanosecond)
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, ln := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(context.Background())
	ae.checkPeers(context.Background())
	if n := ln.accepts.Load(); n != 2 {
		t.Errorf("%d connections over two passes with a pooled connection past its age, want 2", n)
	}
}

// A peer isolated after its digests were read, while the pass was still
// merging from the peers before it, is not merged from: the merge half asks
// again. Its isolation can arrive by exactly such a merge.
func TestFinishExchange_RefusesAPeerIsolatedAfterItsDigest(t *testing.T) {
	ctx := context.Background()
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, _ := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)

	ex := ae.openExchange(ctx, "peer-a", nil, false)
	if ex == nil {
		t.Fatal("precondition: no exchange opened with a reachable, unisolated peer")
	}
	if !ae.finishExchange(ctx, ex, nil, false) {
		t.Fatal("precondition: an exchange with an agreeing peer did not complete")
	}
	if err := IsolateHost(ctx, c, "self", "peer-a", "manual"); err != nil {
		t.Fatalf("IsolateHost: %v", err)
	}
	if ae.finishExchange(ctx, ex, nil, false) {
		t.Error("an exchange with a peer isolated since its digest was read completed; it must not be merged from")
	}
}
