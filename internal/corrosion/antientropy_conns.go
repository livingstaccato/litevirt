package corrosion

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// antiEntropyPeerConcurrency bounds how many peers one pass checks at once
// (#261). A var so tests can move it.
var antiEntropyPeerConcurrency = 8

// antiEntropyConnMaxAge is how long a pooled connection is reused before the
// pass dials afresh, so the peer is re-handshaken (and its certificate
// re-verified) at least this often whatever else changes.
var antiEntropyConnMaxAge = 10 * time.Minute

// aeConnPool keeps one gRPC connection per peer across anti-entropy passes
// (#261). Each pass dialled every peer it checked and closed the connection
// afterwards, so every pass paid a TCP and a TLS handshake per peer.
//
// A pooled connection is reused only while everything it was dialled against
// is unchanged: the peer's address, its recorded certificate serial and its
// row's incarnation (created_at, restamped by a re-admission), this node's own
// PKI files (ca.crt, host.crt, host.key, crl.pem — a revocation is enforced at
// the handshake, so a new CRL must force one), and antiEntropyConnMaxAge.
// A pass also drops the connection of every peer no longer a member, and of a
// peer whose digest failed, so the next pass dials afresh instead of waiting
// out gRPC's reconnect backoff.
type aeConnPool struct {
	mu    sync.Mutex
	conns map[string]*aePooledConn
}

type aePooledConn struct {
	key    string
	born   time.Time
	conn   *grpc.ClientConn
	client pb.LiteVirtClient

	closeOnce sync.Once
	closed    chan struct{}
}

func (p *aePooledConn) close() {
	p.closeOnce.Do(func() {
		_ = p.conn.Close()
		close(p.closed)
	})
}

func (p *aePooledConn) isClosed() bool {
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

// lookup returns the pooled connection to peer, or nil.
func (p *aeConnPool) lookup(peer string) *aePooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns[peer]
}

// get returns a connection to peer dialled against key, reusing the pooled one
// when it was dialled against the same key and is young enough.
func (p *aeConnPool) get(peer, key string, dial func() (*grpc.ClientConn, error)) (*aePooledConn, error) {
	p.mu.Lock()
	cur := p.conns[peer]
	if cur != nil && cur.key == key && time.Since(cur.born) < antiEntropyConnMaxAge && !cur.isClosed() {
		p.mu.Unlock()
		return cur, nil
	}
	delete(p.conns, peer)
	p.mu.Unlock()
	if cur != nil {
		cur.close()
	}
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	pc := &aePooledConn{key: key, born: time.Now(), conn: conn, client: pb.NewLiteVirtClient(conn), closed: make(chan struct{})}
	p.mu.Lock()
	if p.conns == nil {
		p.conns = make(map[string]*aePooledConn)
	}
	prev := p.conns[peer]
	p.conns[peer] = pc
	p.mu.Unlock()
	if prev != nil {
		prev.close()
	}
	return pc, nil
}

// drop closes and forgets pc, if it is still peer's pooled connection.
func (p *aeConnPool) drop(peer string, pc *aePooledConn) {
	p.mu.Lock()
	if p.conns[peer] == pc {
		delete(p.conns, peer)
	}
	p.mu.Unlock()
	pc.close()
}

// retain closes every pooled connection to a peer not in keep.
func (p *aeConnPool) retain(keep map[string]bool) {
	var gone []*aePooledConn
	p.mu.Lock()
	for name, pc := range p.conns {
		if !keep[name] {
			gone = append(gone, pc)
			delete(p.conns, name)
		}
	}
	p.mu.Unlock()
	for _, pc := range gone {
		pc.close()
	}
}

// closeAll closes every pooled connection.
func (p *aeConnPool) closeAll() { p.retain(nil) }

// Close closes the connections anti-entropy keeps to its peers. Start calls it
// when its loop ends; a pass run afterwards dials again.
func (ae *AntiEntropy) Close() { ae.conns.closeAll() }

// pooledPeerClient returns a client for peer from the pool, dialling when the
// pool holds none that is still valid (see aeConnPool).
func (ae *AntiEntropy) pooledPeerClient(ctx context.Context, peer string) (*aePooledConn, error) {
	target, host, err := resolvePeerEndpoint(ctx, ae.client, peer)
	if err != nil {
		return nil, err
	}
	key := target
	if host != nil {
		key = fmt.Sprintf("%s|%s|%s", target, host.CertSerial, host.CreatedAt)
	}
	key += "|" + pkiStamp(ae.pkiDir)
	return ae.conns.get(peer, key, func() (*grpc.ClientConn, error) { return ae.dialPeer(target) })
}

// pkiStamp identifies the state of this node's own PKI files: their sizes and
// modification times. A change to any of them changes the stamp.
func pkiStamp(dir string) string {
	s := ""
	for _, f := range []string{"ca.crt", "host.crt", "host.key", "crl.pem"} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil {
			s += fmt.Sprintf("%s:%d:%d;", f, fi.Size(), fi.ModTime().UnixNano())
		} else {
			s += f + ":-;"
		}
	}
	return s
}

// dialPeer dials target the way anti-entropy always has: mTLS, with the
// receive limit raised so the legacy unary GetStateDump fallback can pull a
// large full-state dump from an old peer. StreamStateDump chunks stay well
// under the 4 MiB default and don't need it.
func (ae *AntiEntropy) dialPeer(target string) (*grpc.ClientConn, error) {
	return pki.PeerDial(ae.pkiDir, target,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(antiEntropyMaxMsgSize)))
}
