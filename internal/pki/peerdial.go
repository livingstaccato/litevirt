package pki

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// traceDialOptions is a hook PeerDial consults to attach tracing dial options
// (obs.ClientDialOptions) without pki importing obs directly — pki is a
// zero-internal-import leaf, and importing obs would pull the telemetry
// vendor into pki's (and corrosion's) dependency closure. Set once at boot,
// but PeerDial is called concurrently by the replicator and anti-entropy
// loops, so this needs atomic access, not a plain package var. Finding 8.
var traceDialOptions atomic.Pointer[func() []grpc.DialOption]

// SetTraceDialOptions installs (or, with nil, clears) the trace-dial-options
// hook. Call once at boot, after telemetry setup, so every PeerDial caller —
// including the corrosion replicator/anti-entropy dials, which pass none of
// their own today — picks up tracing dial options automatically.
func SetTraceDialOptions(fn func() []grpc.DialOption) {
	if fn == nil {
		traceDialOptions.Store(nil)
		return
	}
	traceDialOptions.Store(&fn)
}

// FwdBearerMDKey is the outgoing metadata key that relays a forwarded user's
// bearer from an entry node to the owning node. It is deliberately NOT
// "authorization": an old or not-yet-flipped receiver ignores this key, so its
// identity resolution is unchanged on rollout; only a receiver enforcing
// ForwardedIdentityV1 promotes it to the real user.
const FwdBearerMDKey = "x-litevirt-fwd-bearer"

// propagateFwdBearer copies the inbound authorization bearer (a forwarded user
// request) onto the outgoing context under FwdBearerMDKey. It APPENDS, so any
// existing outgoing metadata (repair-actor, relocate-token, console, proof
// tokens, …) is preserved. When there is no inbound bearer — a system
// continuation off a background context — nothing is propagated and the receiver
// sees a plain peer call (system identity).
func propagateFwdBearer(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	auth := md.Get("authorization")
	if len(auth) == 0 || auth[0] == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, FwdBearerMDKey, auth[0])
}

// RelayForwardedBearer is for a handler that continues a forwarded user's
// request on a third host: the call that reached it carries the user's bearer
// under FwdBearerMDKey and no authorization, so the dial's own propagation has
// nothing to copy and the continuation would reach its target as a plain peer.
// It puts the forwarded bearer on the outgoing context. It is a caller's
// request, not a property of every peer dial, so no other chain changes identity.
func RelayForwardedBearer(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	if a := md.Get("authorization"); len(a) != 0 && a[0] != "" {
		return ctx // the dial copies it
	}
	if f := md.Get(FwdBearerMDKey); len(f) != 0 && f[0] != "" {
		return metadata.AppendToOutgoingContext(ctx, FwdBearerMDKey, f[0])
	}
	return ctx
}

func fwdBearerUnaryInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(propagateFwdBearer(ctx), method, req, reply, cc, opts...)
}

func fwdBearerStreamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(propagateFwdBearer(ctx), desc, cc, method, opts...)
}

// PeerDial dials a peer daemon over host-to-host mTLS (PeerTLSConfig). The
// caller passes an already-resolved "host:port" target — build it with
// net.JoinHostPort so IPv6 addresses are bracketed correctly — plus any extra
// dial options.
//
// The peer-TLS transport credential is appended LAST so it is authoritative:
// a caller's extra option cannot accidentally swap the transport credentials
// (the last WithTransportCredentials wins). Extra opts are therefore expected
// to be non-transport options (e.g. grpc.WithDefaultCallOptions(...)).
//
// grpc.NewClient is lazy and does not connect here; the first RPC dials. The
// caller owns the returned connection and must Close it.
// peerServerKeepaliveMinTime is the shortest keepalive ping interval a
// daemon's peer server permits (PeerServerOptions).
const peerServerKeepaliveMinTime = time.Minute

// peerKeepalive is how a peer connection detects a peer that stopped
// answering while a call is open (a wedged-but-alive host, a partition): a
// ping after Time without traffic, failed after Timeout without an answer.
// Time exceeds both this build's server MinTime and grpc's default of five
// minutes, so neither a daemon of this build nor an older one (which sets no
// policy) ever sends GOAWAY too_many_pings — which would cut a long disk copy
// mid-way during a rolling upgrade. Pings only while a call is open: an
// older daemon's default policy rejects them otherwise. A var so a test can
// shorten it.
var peerKeepalive = keepalive.ClientParameters{Time: 6 * time.Minute, Timeout: 20 * time.Second}

// PeerServerOptions are the peer server's keepalive settings: it permits the
// pings PeerDial sends (peerKeepalive), and itself pings a client that went
// quiet with a call open, so a call from a peer that died does not hold a
// handler forever.
func PeerServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: peerServerKeepaliveMinTime}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 6 * time.Minute, Timeout: 20 * time.Second}),
	}
}

func PeerDial(pkiDir, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	tlsCfg, err := PeerTLSConfig(pkiDir)
	if err != nil {
		return nil, fmt.Errorf("peer TLS config: %w", err)
	}
	dialOpts := make([]grpc.DialOption, 0, len(opts)+4)
	// Forwarded-identity relay (send-side, always on + forward-compatible): copy
	// the inbound user bearer onto the peer call under FwdBearerMDKey.
	dialOpts = append(dialOpts,
		grpc.WithChainUnaryInterceptor(fwdBearerUnaryInterceptor),
		grpc.WithChainStreamInterceptor(fwdBearerStreamInterceptor),
	)
	// Trace propagation (when the hook is set — tracing active): every
	// PeerDial caller gets it automatically, including corrosion's
	// replicator/anti-entropy dials, which pass none of their own.
	if fn := traceDialOptions.Load(); fn != nil {
		dialOpts = append(dialOpts, (*fn)()...)
	}
	dialOpts = append(dialOpts, grpc.WithKeepaliveParams(peerKeepalive))
	dialOpts = append(dialOpts, opts...)
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return conn, nil
}
