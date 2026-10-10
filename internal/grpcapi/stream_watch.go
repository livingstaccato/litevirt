package grpcapi

// Open streams end when their credential does (t1-auth-review I1).
//
// Authentication runs once, when a stream opens. A console, a VNC proxy, an
// exec session, an event watch — and every UI websocket and REST SSE stream
// built on one — would otherwise keep running at the account's full authority
// after `lv user disable`, an expiry, a session revoke or a policy change, for
// as long as the client holds it open.
//
// So a stream authenticated by a USER credential (a session or an API token,
// directly or forwarded by a peer) is watched while it is open. Every
// StreamRecheckInterval, and at once whenever this node makes a change that
// can end a credential (kickStreams), the watcher re-checks it the way
// authentication would: the account is still active, a session is not revoked
// or past its hard expiry or from before the account's last disable, an API
// token is not revoked or expired, the node is not in WAL quarantine, and the
// session is not confined by the second-factor policy (a confined session may
// open no stream at all). The first failure cancels the stream's context and
// the stream ends with Unauthenticated.
//
// THE BOUND: an open stream ends within 5 s of the change reaching this node's
// replica — a recheck every StreamRecheckInterval (3 s), each with its own
// StreamRecheckTimeout (2 s) — and at once on the node where the change was
// made. A recheck that fails, or does not finish within its timeout (a stuck
// replica, a reseed holding the lock), ends the stream: it fails closed, so the
// bound holds whatever the replica is doing. A node the change has not reached
// yet keeps the stream — the same bound as every other refusal (docs/auth.md).
//
// ENDING IT FOR REAL (rereview N1). Cancelling a derived context ends nothing
// by itself: grpc-go's RecvMsg and SendMsg are bound to the transport, and the
// console and VNC handlers block in them and in reads of the PTY or socket. So
// the cut is made three ways: the handlers that hold a device (ConsoleVM,
// ProxyVNC) select on the stream context and close the PTY or socket when it
// ends; the stream handed to every handler refuses SendMsg and RecvMsg once
// cut; and the interceptor returns the cut error after streamCutGrace even if
// a handler is still blocked, which ends the RPC and so the transport.
//
// Bearerless mTLS streams (peer, local-root) are not user credentials and are
// not watched.

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// StreamRecheckInterval is how often an open user stream re-checks its
// credential when nothing on this node has changed, and StreamRecheckTimeout
// how long one recheck may take; together they are the documented 5 s.
const (
	StreamRecheckInterval = 3 * time.Second
	StreamRecheckTimeout  = 2 * time.Second
)

// streamCutGrace is how long the interceptor waits, after a cut, for the
// handler to return on its own before it ends the RPC regardless.
const streamCutGrace = 2 * time.Second

func (s *Server) streamRecheckInterval() time.Duration {
	if s.streamRecheckEvery > 0 {
		return s.streamRecheckEvery
	}
	return StreamRecheckInterval
}

// streamRecheckTimeout is one recheck's deadline: StreamRecheckTimeout, or
// the test interval when that is shorter.
func (s *Server) streamRecheckTimeout() time.Duration {
	if s.streamRecheckEvery > 0 && s.streamRecheckEvery < StreamRecheckTimeout {
		return s.streamRecheckEvery
	}
	return StreamRecheckTimeout
}

// userBearerIdentity reports whether ctx was authenticated by a user
// credential rather than by bearerless mTLS.
func userBearerIdentity(ctx context.Context) bool {
	switch callerAuthMethod(ctx) {
	case authMethodSession, authMethodToken:
		return true
	}
	return false
}

// kickChan returns the channel the next kickStreams closes.
func (s *Server) kickChan() <-chan struct{} {
	s.streamKickMu.Lock()
	defer s.streamKickMu.Unlock()
	if s.streamKick == nil {
		s.streamKick = make(chan struct{})
	}
	return s.streamKick
}

// kickStreams makes every open stream's watcher re-check now. Called by every
// change on this node that can end a credential.
func (s *Server) kickStreams() {
	s.streamKickMu.Lock()
	defer s.streamKickMu.Unlock()
	if s.streamKick != nil {
		close(s.streamKick)
	}
	s.streamKick = make(chan struct{})
}

// errStreamCut wraps the reason a watcher ended a stream.
type errStreamCut struct{ err error }

func (e errStreamCut) Error() string { return e.err.Error() }

// watchStream returns ctx with a watcher attached, and the function that
// stops the watcher when the stream ends.
func (s *Server) watchStream(ctx context.Context) (context.Context, func()) {
	wctx, cancel := context.WithCancelCause(ctx)
	stopped := make(chan struct{})
	go func() {
		t := time.NewTicker(s.streamRecheckInterval())
		defer t.Stop()
		for {
			kick := s.kickChan()
			select {
			case <-stopped:
				return
			case <-wctx.Done():
				return
			case <-t.C:
			case <-kick:
			}
			err := s.recheckWithTimeout(wctx)
			var transient errTransientRecheck
			switch {
			case err == nil:
			case errors.As(err, &transient):
				// Fail closed: a credential that cannot be confirmed within
				// the bound is not one.
				cancel(errStreamCut{status.Errorf(codes.Unauthenticated,
					"stream ended: its credential could not be re-checked: %v", transient.err)})
				return
			default:
				cancel(errStreamCut{err})
				return
			}
		}
	}()
	return wctx, func() {
		close(stopped)
		cancel(nil)
	}
}

// recheckWithTimeout runs one recheck under its own deadline. A recheck that
// has not answered by then is a failed one (errTransientRecheck), whatever it
// is blocked on.
func (s *Server) recheckWithTimeout(ctx context.Context) error {
	rctx, cancel := context.WithTimeout(ctx, s.streamRecheckTimeout())
	defer cancel()
	res := make(chan error, 1)
	go func() {
		if h := recheckHook.Load(); h != nil {
			(*h)(rctx)
		}
		res <- s.recheckStreamIdentity(rctx)
	}()
	select {
	case err := <-res:
		return err
	case <-rctx.Done():
		return errTransientRecheck{errors.New("recheck did not finish within " + s.streamRecheckTimeout().String())}
	}
}

// watchedStream is the stream a watched handler gets: its context is the
// watcher's, and once that is cut it refuses to send or receive, so a handler
// that loops on Send/Recv stops at its next call.
type watchedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *watchedStream) Context() context.Context { return w.ctx }

func (w *watchedStream) SendMsg(m any) error {
	if cut := streamCutCause(w.ctx); cut != nil {
		return cut
	}
	return w.ServerStream.SendMsg(m)
}

func (w *watchedStream) RecvMsg(m any) error {
	if cut := streamCutCause(w.ctx); cut != nil {
		return cut
	}
	return w.ServerStream.RecvMsg(m)
}

// serveWatched runs handler on a watched stream and ends it on a cut: the
// handler is given streamCutGrace to return on its own (the device-holding
// handlers close their PTY or socket and do), and then the cut error is
// returned regardless, which ends the RPC and with it the transport the
// handler is blocked on.
func (s *Server) serveWatched(ctx context.Context, srv any, ss grpc.ServerStream, handler grpc.StreamHandler) error {
	wctx, stop := s.watchStream(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- handler(srv, &watchedStream{ServerStream: ss, ctx: wctx}) }()
	select {
	case err := <-done:
		if cut := streamCutCause(wctx); cut != nil {
			return cut
		}
		return err
	case <-wctx.Done():
	}
	cut := streamCutCause(wctx)
	if cut == nil {
		// The transport ended, not a cut: wait for the handler as before.
		return <-done
	}
	select {
	case <-done:
	case <-time.After(streamCutGrace):
		slog.Warn("a stream handler did not return after its credential was cut; ending the RPC")
	}
	return cut
}

// streamEndError is what a handler returns when its stream context ended: the
// watcher's cut error, or the context's own.
func streamEndError(ctx context.Context) error {
	if cut := streamCutCause(ctx); cut != nil {
		return cut
	}
	return status.FromContextError(ctx.Err()).Err()
}

// streamCutCause returns the Unauthenticated error a watcher ended ctx with,
// or nil when it did not.
func streamCutCause(ctx context.Context) error {
	var cut errStreamCut
	if errors.As(context.Cause(ctx), &cut) {
		return cut.err
	}
	return nil
}

type errTransientRecheck struct{ err error }

func (e errTransientRecheck) Error() string { return e.err.Error() }

// recheckStreamIdentity is authentication's verdict on the credential behind
// an open stream, without its side effects (no last_used_at touch, no bcrypt
// sweep). A definite refusal is an Unauthenticated error; a read that failed
// is errTransientRecheck.
func (s *Server) recheckStreamIdentity(ctx context.Context) error {
	if err := s.refuseUserBearersInQuarantine(); err != nil {
		return status.Error(codes.Unauthenticated, status.Convert(err).Message())
	}
	user := callerUsername(ctx)
	life, err := corrosion.GetUserLifecycle(ctx, s.db, user)
	if err != nil {
		return errTransientRecheck{err}
	}
	if reason := life.InactiveReason(time.Now().UTC()); reason != "" {
		return status.Error(codes.Unauthenticated, "stream ended: "+reason)
	}
	switch callerAuthMethod(ctx) {
	case authMethodSession:
		// A deleted account's sessions end with it (rereview N2); the token
		// branch gets this from TokenLive's join.
		u, err := corrosion.GetUser(ctx, s.db, user)
		if err != nil {
			return errTransientRecheck{err}
		}
		if u == nil {
			return status.Error(codes.Unauthenticated, "stream ended: account deleted")
		}
		sid := callerSessionID(ctx)
		sess, err := corrosion.GetSession(ctx, s.db, sid)
		if err != nil {
			return errTransientRecheck{err}
		}
		if sess == nil || sess.RevokedAt != "" {
			return status.Error(codes.Unauthenticated, "stream ended: session revoked")
		}
		if exp, perr := time.Parse(time.RFC3339, sess.ExpiresAt); perr != nil || time.Now().After(exp) {
			return status.Error(codes.Unauthenticated, "stream ended: session expired")
		}
		if life.SessionPredates(sess.CreatedAt) {
			return status.Error(codes.Unauthenticated, "stream ended: session predates the account's last disable")
		}
		confined, err := s.sessionEnrollOnly(ctx, sid, sess.Realm)
		if err != nil {
			return errTransientRecheck{err}
		}
		if confined {
			return status.Error(codes.Unauthenticated,
				"stream ended: the second-factor policy now confines this session")
		}
	case authMethodToken:
		id, _ := ctx.Value(ctxKeyTokenID).(string)
		live, err := corrosion.TokenLive(ctx, s.db, id)
		if err != nil {
			return errTransientRecheck{err}
		}
		if !live {
			return status.Error(codes.Unauthenticated, "stream ended: API token revoked or expired")
		}
	}
	return nil
}

// recheckHook, when set (tests only), runs at the start of every stream
// recheck with that recheck's context.
var recheckHook atomic.Pointer[func(context.Context)]
