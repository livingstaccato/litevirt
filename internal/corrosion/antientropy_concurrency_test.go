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
	// failCode is the code failNext fails with; zero is Internal.
	failCode atomic.Int32
	// gate, when set, holds every digest until it is closed, instead of delay.
	gate chan struct{}
}

func (p *slowPeer) GetStateDigest(ctx context.Context, _ *emptypb.Empty) (*pb.StateDigestResponse, error) {
	p.calls.Add(1)
	if p.failNext.CompareAndSwap(true, false) {
		code := codes.Code(p.failCode.Load())
		if code == codes.OK {
			code = codes.Internal
		}
		return nil, status.Error(code, "injected failure")
	}
	if p.f != nil {
		p.f.enter()
		defer p.f.leave()
	}
	wait := time.After(p.delay)
	if p.gate != nil {
		wait = nil
	}
	select {
	case <-wait:
	case <-p.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.StateDigestResponse{}, nil
}

// countingListener counts the TCP connections a peer accepted (one per dial)
// and how many of them are still open.
type countingListener struct {
	net.Listener
	accepts atomic.Int32
	closes  atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	l.accepts.Add(1)
	return &countedConn{Conn: c, l: l}, nil
}

func (l *countingListener) open() int32 { return l.accepts.Load() - l.closes.Load() }

type countedConn struct {
	net.Conn
	l    *countingListener
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.l.closes.Add(1) })
	return c.Conn.Close()
}

// waitOpen waits for ln to have want connections open.
func waitOpen(t *testing.T, ln *countingListener, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for ln.open() != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := ln.open(); got != want {
		t.Errorf("%d connections open at the peer, want %d", got, want)
	}
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

// newTestAE builds an AntiEntropy whose pool persists across passes, as it
// does under Start's loop, and is closed when the test ends.
func newTestAE(t *testing.T, c *Client, pkiDir string) *AntiEntropy {
	t.Helper()
	ae := NewAntiEntropy(c, pkiDir, time.Minute)
	ae.owned.Store(true)
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

	// The row's insert stamp converging between replicas (the hosts tie
	// chain) is not a new incarnation: a re-admission always carries a new
	// certificate serial, which AdmitHost requires. The connection stands.
	if _, err := c.DB().Exec(`UPDATE hosts SET created_at = '2099-01-01T00:00:00.000000000Z' WHERE name = 'peer-a'`); err != nil {
		t.Fatal(err)
	}
	ae.checkPeers(ctx)
	if n := newLn.accepts.Load(); n != 1 {
		t.Errorf("after only the row's created_at changed: %d connections, want 1 (reused)", n)
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

// Close closes every pooled connection. A pass after it still checks its
// peers, and leaves no connection behind.
func TestAntiEntropy_CloseClosesThePool(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	p := &slowPeer{}
	port, ln := servePeer(t, pkiDir, p)
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
	ae.checkPeers(context.Background())
	if p.calls.Load() != 2 {
		t.Errorf("%d digest calls, want 2: a pass after Close must still check its peers", p.calls.Load())
	}
	if ae.conns.lookup("peer-a") != nil {
		t.Error("a pass after Close put a connection back into the closed pool")
	}
	waitOpen(t, ln, 0)
}

// An AntiEntropy whose pool no Start loop owns — a test's, or one built for a
// single pass — closes its connections when the pass ends. Each exchange used
// to close its own; a pool nobody closes holds an mTLS transport per peer,
// both ends' descriptors and their goroutines, until gRPC's idle timeout.
func TestAntiEntropy_APassWithoutStartLeavesNoConnection(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	var lns []*countingListener
	var names []string
	for _, name := range []string{"peer-a", "peer-b"} {
		port, ln := servePeer(t, pkiDir, &slowPeer{})
		addPeerHost(t, c, name, port, "")
		lns = append(lns, ln)
		names = append(names, name)
	}
	c.SetMembersForTests(aeMembers(names...))
	ae := NewAntiEntropy(c, pkiDir, time.Minute)
	if !ae.RunOnce(context.Background()) {
		t.Fatal("precondition: the pass did not run")
	}
	for i, ln := range lns {
		if ln.accepts.Load() != 1 {
			t.Fatalf("precondition: %s accepted %d connections, want 1", names[i], ln.accepts.Load())
		}
		waitOpen(t, ln, 0)
		if ae.conns.lookup(names[i]) != nil {
			t.Errorf("%s is still pooled after a pass no Start loop owns", names[i])
		}
	}
}

// A node that loses every gossip peer closes its pooled connections; they
// are all to peers it can no longer see.
func TestCheckPeers_NoMembersClosesThePool(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, ln := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(context.Background())
	if ae.conns.lookup("peer-a") == nil {
		t.Fatal("precondition: nothing pooled")
	}
	c.SetMembersForTests(aeMembers())
	ae.checkPeers(context.Background())
	if ae.conns.lookup("peer-a") != nil {
		t.Error("a pass that sees no members kept its pooled connections")
	}
	waitOpen(t, ln, 0)
}

// A peer this node refuses to merge from keeps no pooled connection: the pass
// never reaches the age and key checks for it, so the connection would
// otherwise stand for as long as the refusal does.
func TestCheckPeers_ARefusedPeerLosesItsConnection(t *testing.T) {
	ctx := context.Background()
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, ln := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(ctx)
	if ae.conns.lookup("peer-a") == nil {
		t.Fatal("precondition: nothing pooled")
	}
	if err := IsolateHost(ctx, c, "self", "peer-a", "manual"); err != nil {
		t.Fatalf("IsolateHost: %v", err)
	}
	ae.checkPeers(ctx)
	if ae.conns.lookup("peer-a") != nil {
		t.Error("an isolated peer kept its pooled connection")
	}
	waitOpen(t, ln, 0)
}

// A reused connection that answers Unavailable — a half-open transport to a
// peer that rebooted — is retried once on a fresh dial in the same pass,
// rather than losing the pass's exchange with that peer.
func TestCheckPeers_RetriesAReusedConnectionOnUnavailable(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	p := &slowPeer{}
	port, ln := servePeer(t, pkiDir, p)
	addPeerHost(t, c, "peer-a", port, "")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ae.checkPeers(context.Background())

	p.failCode.Store(int32(codes.Unavailable))
	p.failNext.Store(true)
	ae.checkPeers(context.Background())
	if n := p.calls.Load(); n != 3 {
		t.Errorf("%d digest calls over two passes, want 3: the Unavailable on a reused connection was not retried", n)
	}
	if n := ln.accepts.Load(); n != 2 {
		t.Errorf("%d connections, want 2: the retry must dial afresh", n)
	}
	if ae.conns.lookup("peer-a") == nil {
		t.Error("the retried exchange left nothing pooled")
	}
}

// pkiStamp changes when a file is replaced by one of the same size and
// modification time: two installs inside one mtime tick.
func TestPKIStamp_SeesAReplacementWithTheSameSizeAndTime(t *testing.T) {
	dir := t.TempDir()
	crl := filepath.Join(dir, "crl.pem")
	at := time.Unix(1_800_000_000, 0)
	write := func(body string) {
		tmp := crl + ".tmp"
		if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(tmp, at, at); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, crl); err != nil {
			t.Fatal(err)
		}
	}
	write("first-crl")
	keep, err := os.Open(crl) // pin the first inode so it cannot be reused
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	before := pkiStamp(dir)
	write("other-crl")
	if pkiStamp(dir) == before {
		t.Error("pkiStamp did not change when crl.pem was replaced by a file of the same size and mtime")
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

// A closed pool takes no connection back, even from a pass that was already
// running when Start's loop closed it: what that pass dials is the pass's to
// close.
func TestAEConnPool_AClosedPoolTakesNoConnection(t *testing.T) {
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, ln := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "")
	ae := newTestAE(t, c, pkiDir)
	ae.Close()
	pc, fresh, err := ae.pooledPeerClient(context.Background(), "peer-a")
	if err != nil || !fresh {
		t.Fatalf("pooledPeerClient on a closed pool: fresh=%v err=%v", fresh, err)
	}
	defer pc.close()
	if _, err := pc.client.GetStateDigest(context.Background(), &emptypb.Empty{}); err != nil {
		t.Fatalf("precondition: digest: %v", err)
	}
	if ae.conns.lookup("peer-a") != nil {
		t.Error("a closed pool took a connection back")
	}
	ae.conns.closeAll()
	if pc.isClosed() {
		t.Error("closing the pool closed a connection it never held")
	}
	_ = ln
}

// openAgreeingExchange opens an exchange with an agreeing peer-a, so that
// finishExchange completes unless something refuses it.
func openAgreeingExchange(t *testing.T) (*AntiEntropy, *Client, string, *peerExchange) {
	t.Helper()
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, _ := servePeer(t, pkiDir, &slowPeer{})
	addPeerHost(t, c, "peer-a", port, "aa01")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ex := ae.openExchange(context.Background(), "peer-a", nil, false)
	if ex == nil {
		t.Fatal("precondition: no exchange opened with a reachable, unisolated peer")
	}
	return ae, c, pkiDir, ex
}

// A peer re-admitted with a new certificate while the pass merged from the
// peers before it is not pulled from over the connection its digest used:
// that transport was verified against the old row. The merge half checks
// the connection's key again, as the digest half's dial did.
func TestFinishExchange_RefusesAPeerWhoseCertificateChangedSinceItsDigest(t *testing.T) {
	ae, c, _, ex := openAgreeingExchange(t)
	if _, err := c.DB().Exec(`UPDATE hosts SET cert_serial = 'bb02' WHERE name = 'peer-a'`); err != nil {
		t.Fatal(err)
	}
	if ae.finishExchange(context.Background(), ex, nil, false) {
		t.Error("merged from a peer whose certificate serial changed since its digest, over the old connection")
	}
	if !ex.pc.isClosed() || ae.conns.lookup("peer-a") != nil {
		t.Error("the stale connection was kept")
	}
}

// Likewise a CRL installed mid-pass: the connection's handshake predates it.
func TestFinishExchange_RefusesAfterTheLocalCRLChangedSinceTheDigest(t *testing.T) {
	ae, _, pkiDir, ex := openAgreeingExchange(t)
	if err := os.WriteFile(filepath.Join(pkiDir, "crl.pem"), []byte("newer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ae.finishExchange(context.Background(), ex, nil, false) {
		t.Error("merged over a connection whose handshake predates the local CRL")
	}
	if !ex.pc.isClosed() || ae.conns.lookup("peer-a") != nil {
		t.Error("the stale connection was kept")
	}
}

// A peer's pull and merge start as soon as its own digest is in, not after
// the slowest peer's: one slow digest held every merge in the pass back.
//
// The slow digest is held until the fast peer's merge half has finished, or
// for slowDigestHold at most, so the ordering is asserted without a wall-clock
// race: a pass that waits for every digest finishes the fast peer only once
// the hold has run out.
func TestCheckPeers_AMergeDoesNotWaitForASlowerDigest(t *testing.T) {
	const slowDigestHold = 20 * time.Second // under antiEntropyDigestTimeout
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	gate := make(chan struct{})
	var release sync.Once
	open := func() { release.Do(func() { close(gate) }) }
	t.Cleanup(open)
	slow := &slowPeer{gate: gate}
	fast := &slowPeer{}
	ps, _ := servePeer(t, pkiDir, slow)
	pf, _ := servePeer(t, pkiDir, fast)
	addPeerHost(t, c, "peer-slow", ps, "")
	addPeerHost(t, c, "peer-fast", pf, "")
	c.SetMembersForTests(aeMembers("peer-slow", "peer-fast"))
	ae := newTestAE(t, c, pkiDir)
	var fastBeforeSlowDigest atomic.Bool
	ae.onFinish = func(peer string) {
		if peer != "peer-fast" {
			return
		}
		select {
		case <-gate:
		default:
			fastBeforeSlowDigest.Store(true)
		}
		open()
	}
	hold := time.AfterFunc(slowDigestHold, open)
	defer hold.Stop()
	ae.checkPeers(context.Background())
	if slow.calls.Load() != 1 {
		t.Fatalf("precondition: slow peer asked %d times", slow.calls.Load())
	}
	if !fastBeforeSlowDigest.Load() {
		t.Error("the fast peer's exchange finished only after the slow peer's digest: merges wait for the slowest digest")
	}
}

// A peer removed while the pass merged from the peers before it is not pulled
// from over its old connection.
func TestFinishExchange_RefusesAPeerRemovedSinceItsDigest(t *testing.T) {
	ae, c, _, ex := openAgreeingExchange(t)
	if _, err := c.DB().Exec(`UPDATE hosts SET deleted_at = '2099-01-01T00:00:00Z' WHERE name = 'peer-a'`); err != nil {
		t.Fatal(err)
	}
	if ae.finishExchange(context.Background(), ex, nil, false) {
		t.Error("merged from a peer removed since its digest, over the old connection")
	}
}

// Replicas converging on one insert stamp for a peer's row move its
// created_at mid-pass on every node that held another (the hosts tie chain).
// That is not a new incarnation, and refusing it held every such exchange
// back for a pass.
func TestFinishExchange_AConvergedInsertStampDoesNotRefuse(t *testing.T) {
	ae, c, _, ex := openAgreeingExchange(t)
	if _, err := c.DB().Exec(`UPDATE hosts SET created_at = '2099-01-01T00:00:00.000000000Z' WHERE name = 'peer-a'`); err != nil {
		t.Fatal(err)
	}
	if !ae.finishExchange(context.Background(), ex, nil, false) {
		t.Error("refused an exchange because the peer row's created_at converged")
	}
}
