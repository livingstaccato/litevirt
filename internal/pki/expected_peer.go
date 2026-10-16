package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ExpectedHostPeer owns one bounded unary exchange and its actual transport
// evidence. No caller transport options, dialer or TLS assertions are accepted.
// A fresh connection is required for each observation; callers must Close it.
type ExpectedHostPeer struct {
	mu                                sync.Mutex
	self                              *ExpectedHostPeer
	conn                              *grpc.ClientConn
	host, endpoint, pinned, connected string
	chain                             [][]byte
	used                              bool
}

func DialExpectedHostPeer(ctx context.Context, dir, host, endpoint string) (*ExpectedHostPeer, error) {
	if host == "" || len(host) > 253 || len(endpoint) > 512 {
		return nil, errors.New("invalid expected peer")
	}
	name, port, err := net.SplitHostPort(endpoint)
	if err != nil || name == "" {
		return nil, errors.New("invalid peer endpoint")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid peer port")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var ip net.IP
	if ip = net.ParseIP(name); ip == nil {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		if err != nil || len(ips) == 0 || len(ips) > 16 {
			return nil, fmt.Errorf("peer DNS unavailable or exceeds 16 addresses: %v", err)
		}
		ip = net.IP(ips[0].AsSlice())
	}
	pinned := net.JoinHostPort(ip.String(), port)
	cfg, err := PeerTLSConfig(dir)
	if err != nil {
		return nil, err
	}
	cfg.ServerName = name // Keep ordinary SAN/address verification, including DNS.
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("missing peer certificate")
		}
		leaf := state.PeerCertificates[0]
		if leaf.IsCA || leaf.Subject.CommonName != host || !hasUsage(leaf, x509.ExtKeyUsageClientAuth) || !hasUsage(leaf, x509.ExtKeyUsageServerAuth) {
			return errors.New("not the expected host identity")
		}
		return nil
	}
	conn, err := grpc.NewClient("passthrough:///"+endpoint,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", pinned)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, err
	}
	p := &ExpectedHostPeer{conn: conn, host: host, endpoint: endpoint, pinned: pinned}
	p.self = p
	return p, nil
}

func (p *ExpectedHostPeer) Invoke(ctx context.Context, method string, req, reply any, opts ...grpc.CallOption) error {
	if p == nil {
		return errors.New("nil expected peer")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.conn == nil || p.used {
		return errors.New("inactive expected peer")
	}
	p.used = true
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var observed peer.Peer
	opts = append(opts, grpc.Peer(&observed), grpc.MaxCallRecvMsgSize(2<<20), grpc.MaxCallSendMsgSize(64<<10))
	if err := p.conn.Invoke(ctx, method, req, reply, opts...); err != nil {
		return err
	}
	tlsInfo, ok := observed.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) == 0 || observed.Addr == nil {
		return errors.New("missing actual verified TLS peer")
	}
	remote, port, err := net.SplitHostPort(observed.Addr.String())
	if err != nil {
		return err
	}
	pin, pinPort, _ := net.SplitHostPort(p.pinned)
	if port != pinPort || !net.ParseIP(remote).Equal(net.ParseIP(pin)) {
		return errors.New("connected peer address differs from selected endpoint")
	}
	var chain [][]byte
	size := 0
	for _, c := range tlsInfo.State.PeerCertificates {
		size += len(c.Raw)
		if size > maxServingChainBytes || len(chain) == maxTrustCertificates {
			return errors.New("peer chain exceeds bound")
		}
		chain = append(chain, bytes.Clone(c.Raw))
	}
	leaf := tlsInfo.State.PeerCertificates[0]
	if leaf.IsCA || leaf.Subject.CommonName != p.host || !hasUsage(leaf, x509.ExtKeyUsageClientAuth) || !hasUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return errors.New("not the expected host identity")
	}
	p.connected = observed.Addr.String()
	p.chain = chain
	return nil
}

// Observation returns privately owned copies only after this connection's
// actual successful exchange. Storage must still bind its response/incarnation.
func (p *ExpectedHostPeer) Observation() (endpoint, connected string, chain [][]byte, err error) {
	if p == nil {
		return "", "", nil, errors.New("nil expected peer")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.conn == nil || len(p.chain) == 0 {
		return "", "", nil, errors.New("no successful peer exchange")
	}
	for _, c := range p.chain {
		chain = append(chain, bytes.Clone(c))
	}
	return p.endpoint, p.connected, chain, nil
}
func (p *ExpectedHostPeer) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("expected-host observation requires a unary exchange")
}
func (p *ExpectedHostPeer) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.conn == nil {
		return nil
	}
	err := p.conn.Close()
	p.conn = nil
	p.chain = nil
	return err
}
