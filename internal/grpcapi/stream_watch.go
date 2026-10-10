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
// THE BOUND: an open stream ends within StreamRecheckInterval (5 s) of the
// change reaching this node's replica, and at once on the node where the
// change was made. A node the change has not reached yet keeps the stream —
// the same bound as every other refusal (docs/auth.md).
//
// Bearerless mTLS streams (peer, local-root) are not user credentials and are
// not watched. A read that fails while re-checking does not cut the stream on
// its own: it is retried at the next tick, and cut only after three in a row,
// so a busy replica does not drop every console.

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// StreamRecheckInterval is how often an open user stream re-checks its
// credential when nothing on this node has changed.
const StreamRecheckInterval = 5 * time.Second

// streamRecheckFailuresToCut is how many consecutive failed reads end a stream.
const streamRecheckFailuresToCut = 3

func (s *Server) streamRecheckInterval() time.Duration {
	if s.streamRecheckEvery > 0 {
		return s.streamRecheckEvery
	}
	return StreamRecheckInterval
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
		failures := 0
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
			err := s.recheckStreamIdentity(wctx)
			var transient errTransientRecheck
			switch {
			case err == nil:
				failures = 0
			case errors.As(err, &transient):
				failures++
				if failures < streamRecheckFailuresToCut {
					continue
				}
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
