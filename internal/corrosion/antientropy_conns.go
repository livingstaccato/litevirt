package corrosion

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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
//
// The pool persists across passes only under Start's loop (AntiEntropy.owned).
// A pass no loop owns, or one that runs after Close, closes every connection
// it used when it ends, so an AntiEntropy built for a pass or two leaks
// nothing; a closed pool never takes a connection back.
type aeConnPool struct {
	mu     sync.Mutex
	conns  map[string]*aePooledConn
	closed bool
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
// when it was dialled against the same key and is young enough. fresh is true
// when it was dialled now. On a closed pool the connection is not pooled, and
// the caller closes it.
func (p *aeConnPool) get(peer, key string, dial func() (*grpc.ClientConn, error)) (pc *aePooledConn, fresh bool, err error) {
	p.mu.Lock()
	cur := p.conns[peer]
	if cur != nil && cur.key == key && time.Since(cur.born) < antiEntropyConnMaxAge && !cur.isClosed() {
		p.mu.Unlock()
		return cur, false, nil
	}
	delete(p.conns, peer)
	p.mu.Unlock()
	if cur != nil {
		cur.close()
	}
	conn, err := dial()
	if err != nil {
		return nil, false, err
	}
	pc = &aePooledConn{key: key, born: time.Now(), conn: conn, client: pb.NewLiteVirtClient(conn), closed: make(chan struct{})}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return pc, true, nil
	}
	if p.conns == nil {
		p.conns = make(map[string]*aePooledConn)
	}
	prev := p.conns[peer]
	p.conns[peer] = pc
	p.mu.Unlock()
	if prev != nil {
		prev.close()
	}
	return pc, true, nil
}

// isClosed reports whether Close has closed the pool.
func (p *aeConnPool) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// dropPeer closes and forgets peer's pooled connection, if any.
func (p *aeConnPool) dropPeer(peer string) {
	p.mu.Lock()
	pc := p.conns[peer]
	delete(p.conns, peer)
	p.mu.Unlock()
	if pc != nil {
		pc.close()
	}
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

// Close closes the connections anti-entropy keeps to its peers, and the pool
// with them. Start calls it when its loop ends. A pass run afterwards still
// dials its peers, and closes those connections when it ends.
func (ae *AntiEntropy) Close() {
	ae.conns.mu.Lock()
	ae.conns.closed = true
	ae.conns.mu.Unlock()
	ae.conns.closeAll()
}

// poolPersists reports whether this pass's connections stay pooled after it:
// only under Start's loop, and never once the pool is closed.
func (ae *AntiEntropy) poolPersists() bool {
	return ae.owned.Load() && !ae.conns.isClosed()
}

// pooledPeerClient returns a client for peer from the pool, dialling when the
// pool holds none that is still valid (see aeConnPool). fresh is true when it
// was dialled now.
func (ae *AntiEntropy) pooledPeerClient(ctx context.Context, peer string) (pc *aePooledConn, fresh bool, err error) {
	target, host, err := resolvePeerEndpoint(ctx, ae.client, peer)
	if err != nil {
		return nil, false, err
	}
	key := target
	if host != nil {
		key = fmt.Sprintf("%s|%s|%s", target, host.CertSerial, host.CreatedAt)
	}
	key += "|" + pkiStamp(ae.pkiDir)
	return ae.conns.get(peer, key, func() (*grpc.ClientConn, error) { return ae.dialPeer(target) })
}

// pkiStamp identifies the state of this node's own PKI files: their inodes,
// sizes and modification times. A change to any of them changes the stamp —
// the inode included, so two installs of the same size inside one mtime tick
// are still told apart (crlChecker stamps the CRL the same way).
func pkiStamp(dir string) string {
	s := ""
	for _, f := range []string{"ca.crt", "host.crt", "host.key", "crl.pem"} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil {
			var ino uint64
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				ino = uint64(st.Ino) //nolint:unconvert // Ino is uint32 on some platforms
			}
			s += fmt.Sprintf("%s:%d:%d:%d;", f, ino, fi.Size(), fi.ModTime().UnixNano())
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
