package pki

import (
	"context"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// RecyclingConn is a grpc.ClientConnInterface for a long-lived client of this
// host's own daemon — the web UI's and the REST gateway's loopback — that
// moves to a fresh connection when this host's identity changes.
//
// A gRPC connection keeps the certificate it was made with. After `lv host
// renew-cert` the loopback connection was made with the REPLACED
// certificate, and the server refuses every new RPC on it (it drains:
// Server.connIdentityGate). While a browser held an event stream or a console
// open on it, the connection stayed up, and every UI request that needed a
// new RPC failed until the stream ended. So each call checks the identity
// this process presents (the same files ClientTLSConfig serves from, re-read
// only when they change) and, when it has changed, dials a new connection —
// which presents the renewed certificate — and sends this and every later
// RPC over it. The old connection is not cut: the streams open on it (a
// console, an event stream) finish, within the server's grace, and it is
// closed after that.
type RecyclingConn struct {
	dial   func() (*grpc.ClientConn, error)
	serial func() string
	retire time.Duration

	mu sync.Mutex
	cc *grpc.ClientConn
	at string // the identity serial cc was dialed under
}

// NewRecyclingConn dials once with dial and returns the recycling client for
// pkiDir's client identity (ClientTLSConfig's: host.crt, else client.crt).
func NewRecyclingConn(pkiDir string, dial func() (*grpc.ClientConn, error)) (*RecyclingConn, error) {
	r := &RecyclingConn{dial: dial, serial: func() string { return ClientIdentitySerial(pkiDir) },
		retire: DefaultStreamGrace + time.Minute}
	cc, err := dial()
	if err != nil {
		return nil, err
	}
	r.cc, r.at = cc, r.serial()
	return r, nil
}

// ClientIdentitySerial is the serial (lower-case hex) of the certificate
// ClientTLSConfig(pkiDir) presents now, or "" when none loads.
func ClientIdentitySerial(pkiDir string) string {
	var src *KeyPairSource
	switch {
	case fileExists(filepath.Join(pkiDir, "host.crt")):
		src = hostIdentitySource(pkiDir)
	case fileExists(filepath.Join(pkiDir, "client.crt")):
		src = sharedSource(pkiDir, "client", x509.ExtKeyUsageClientAuth)
	default:
		return ""
	}
	leaf, err := src.Leaf()
	if err != nil || leaf == nil || leaf.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(leaf.SerialNumber.Text(16))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// current returns the connection to use, dialing a new one first when this
// host's identity has changed since the current one was made.
func (r *RecyclingConn) current() *grpc.ClientConn {
	now := r.serial()
	r.mu.Lock()
	defer r.mu.Unlock()
	if now == "" || now == r.at {
		return r.cc
	}
	cc, err := r.dial()
	if err != nil {
		slog.Warn("this host's certificate changed, but the local client could not reconnect with it; "+
			"retrying on the next call", "error", err)
		return r.cc
	}
	old := r.cc
	slog.Info("this host's certificate changed; the local UI/REST client reconnects with it",
		"previous_serial", r.at, "serial", now)
	r.cc, r.at = cc, now
	time.AfterFunc(r.retire, func() { _ = old.Close() })
	return cc
}

// Invoke implements grpc.ClientConnInterface.
func (r *RecyclingConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	return r.current().Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements grpc.ClientConnInterface.
func (r *RecyclingConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return r.current().NewStream(ctx, desc, method, opts...)
}

// Close closes the current connection.
func (r *RecyclingConn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cc.Close()
}
