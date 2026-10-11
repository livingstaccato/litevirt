package fleet

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// Every fleet daemon listens on loopback, so every connection one node makes to
// another arrives from 127.0.0.1. The auth interceptor classifies a trusted host
// certificate arriving over loopback as LOCAL ROOT — the on-node `lv` run as
// root — and the same certificate from anywhere else as a cluster PEER
// (grpcapi.classifyBearerlessMTLS). In production a peer's call never comes
// from loopback. Here every one did, so every rule that treats a peer
// differently from the on-node root never ran in tests/fleet:
//
//   - forwarded identity (a peer's relayed user bearer is promoted to the user;
//     a local root's is ignored),
//   - the owner rules a forwarding peer is exempt from or bound by
//     (ownerStrict), a forwarded recreate's preflight and inherited mode,
//   - DeleteVM's LUN record and DeleteContainer's running-container refusal,
//     both skipped for a peer's forward,
//   - RestoreContainer's proofless-coordinator refusal,
//   - and the refusals of a peer outright: AcknowledgeLeaseTermTie and
//     ResetAdminPassword.
//
// The harness therefore presents each connection as production would see it.
// A connection presenting ANOTHER fleet node's certificate is a peer's, and its
// source address is rewritten, before any interceptor reads it, to that node's
// address on the network (fleetNetworkIP). A connection presenting the node's
// OWN certificate stays loopback: that is what SelfClient and the CLI's
// ConnectLocalRoot model, and what the daemon's own clients do in production.
// RemoteClient is the one way to present a node's own certificate from off the
// box — what a stolen host key would look like.
//
// Known gap: a daemon dialling ITSELF through its hosts row (a fan-out that
// includes its own name) also keeps loopback here, where production would see
// its own non-loopback address and classify it as a peer.

// loopbackPeers restores the old view — every connection arrives from
// loopback, so every peer is local root — for the whole run, when
// FLEET_LOOPBACK_PEERS=1. It exists to audit what the rewrite changes (run the
// suite both ways and compare), not for a scenario to depend on.
var loopbackPeers = os.Getenv("FLEET_LOOPBACK_PEERS") == "1"

// fleetNetworkIP is the address node i's daemon appears to connect from on the
// cluster network: 192.0.2.0/24 (TEST-NET-1), which is never routed, so it can
// collide with nothing. Only the server-side view of a connection is rewritten
// to it; nothing ever dials it.
func fleetNetworkIP(i int) net.IP { return net.IPv4(192, 0, 2, byte(10+i)) }

// remoteMarks are the client-side local addresses of connections RemoteClient
// dialled. The server sees the same address as the connection's remote one.
type remoteMarks struct {
	mu    sync.Mutex
	addrs map[string]int // local "ip:port" → index of the node whose address to present
}

func (m *remoteMarks) mark(addr string, i int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addrs == nil {
		m.addrs = map[string]int{}
	}
	m.addrs[addr] = i
}

// unmark forgets addr once its connection has closed, so a later loopback
// connection the kernel gives the same ephemeral port is not taken for it.
func (m *remoteMarks) unmark(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.addrs, addr)
}

// markedConn is a RemoteClient connection: closing it removes its mark.
type markedConn struct {
	net.Conn
	once   sync.Once
	unmark func()
}

func (c *markedConn) Close() error {
	c.once.Do(c.unmark)
	return c.Conn.Close()
}

func (m *remoteMarks) lookup(addr string) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.addrs[addr]
	return i, ok
}

// asSeenOnTheNetwork returns ctx with the caller's source address as
// production would see it (see above). A connection that is not a fleet node's
// is left alone: a client certificate is classified as a client wherever it
// comes from.
func (n *Node) asSeenOnTheNetwork(ctx context.Context) context.Context {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ctx
	}
	tcp, ok := p.Addr.(*net.TCPAddr)
	if !ok || !tcp.IP.IsLoopback() {
		return ctx
	}
	c := n.cluster
	if loopbackPeers {
		return ctx
	}
	idx, marked := c.remote.lookup(p.Addr.String())
	if !marked {
		cn := peerCertCN(ctx)
		if cn == "" || cn == n.Name {
			return ctx
		}
		idx = -1
		for i, o := range c.Nodes {
			if o.Name == cn {
				idx = i
				break
			}
		}
		if idx < 0 {
			return ctx
		}
	}
	rewritten := *p
	rewritten.Addr = &net.TCPAddr{IP: fleetNetworkIP(idx), Port: tcp.Port}
	return peer.NewContext(ctx, &rewritten)
}

func (n *Node) peerAddrUnaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return handler(n.asSeenOnTheNetwork(ctx), req)
}

func (n *Node) peerAddrStreamInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &ctxServerStream{ServerStream: ss, ctx: n.asSeenOnTheNetwork(ss.Context())})
}

type ctxServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *ctxServerStream) Context() context.Context { return s.ctx }

// RemoteClient dials target presenting target's OWN host certificate, from off
// the box: the server sees target's network address, not loopback, so the call
// classifies as a peer rather than local root. It is the caller a stolen host
// key makes, and the only way to reach a rule that refuses a peer even when the
// peer names the host it is calling.
func (c *Cluster) RemoteClient(target *Node) pb.LiteVirtClient {
	c.t.Helper()
	return pb.NewLiteVirtClient(c.remoteConn(target))
}

// remoteConn is RemoteClient's connection, closed at the end of the test.
func (c *Cluster) remoteConn(target *Node) *grpc.ClientConn {
	c.t.Helper()
	idx := -1
	for i, o := range c.Nodes {
		if o == target {
			idx = i
		}
	}
	if idx < 0 {
		c.t.Fatalf("fleet: RemoteClient: %s is not in this cluster", target.Name)
	}
	tlsCfg, err := pki.PeerTLSConfig(target.PKIDir)
	if err != nil {
		c.t.Fatalf("remote client TLS for %s: %v", target.Name, err)
	}
	cc, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", target.Address, target.Port),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			// Marked before the TLS handshake starts, so before the server
			// can have accepted a single RPC on it; unmarked when it closes.
			local := conn.LocalAddr().String()
			c.remote.mark(local, idx)
			return &markedConn{Conn: conn, unmark: func() { c.remote.unmark(local) }}, nil
		}),
	)
	if err != nil {
		c.t.Fatalf("dial %s remotely: %v", target.Name, err)
	}
	c.t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// marked reports how many connections are marked as dialled from off the box.
func (m *remoteMarks) marked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.addrs)
}
