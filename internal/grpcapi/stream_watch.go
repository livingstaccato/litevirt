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
// THE BOUND: an open stream ends within 5 s (StreamRecheckBound) of the change
// reaching this node's replica, and at once on the node where the change was
// made. A recheck runs every StreamRecheckInterval (2 s), each under its own
// StreamRecheckTimeout (1.5 s). One that fails or times out — a replica stall,
// a reseed holding the lock — is retried at once rather than ending the
// stream (rereview-2 m-1: a single stall must not cut every console and
// every running migration on the node); the stream ends only when no recheck
// has succeeded for StreamRecheckBound, so the credential's state is still
// unknown at the bound. A definite refusal ends it at once. A node the change
// has not reached yet keeps the stream — the same bound as every other
// refusal (docs/auth.md).
//
// ENDING IT FOR REAL (rereview N1, rereview-2 m-2). Cancelling a derived
// context ends nothing by itself: grpc-go's RecvMsg and SendMsg are bound to
// the transport, and the console and VNC handlers block in them and in reads
// of the PTY or socket. So the cut is made four ways: a handler that holds a
// device for its caller registers a closer (registerStreamCloser), which runs
// AT the cut whether or not the handler is looking at its context; the
// device-holding handlers also select on the stream context; the stream
// handed to every handler refuses SendMsg and RecvMsg once cut; and the
// interceptor returns the cut error after streamCutGrace even if a handler is
// still blocked, which ends the RPC and so the transport. streamHandlerAudit
// lists every streaming RPC and what it holds, and a test keeps it complete.
//
// Bearerless mTLS streams (peer, local-root) are not user credentials and are
// not watched.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
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
	StreamRecheckInterval = 2 * time.Second
	StreamRecheckTimeout  = 1500 * time.Millisecond
	// StreamRecheckBound is the longest a stream lives with its credential
	// unconfirmed: no successful recheck for this long ends it.
	StreamRecheckBound = 5 * time.Second
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

// streamNow is the clock the watcher measures its fail-closed bound on:
// streamClock in tests (nil: time.Now). A test drives "the credential could
// not be re-checked for the bound" by the time it says passed, not by how
// late this host fired a timer.
func (s *Server) streamNow() time.Time {
	if s.streamClock != nil {
		return s.streamClock()
	}
	return time.Now()
}

// streamRecheckBound is StreamRecheckBound, or 2.5 test intervals.
func (s *Server) streamRecheckBound() time.Duration {
	if s.streamRecheckEvery > 0 {
		return s.streamRecheckEvery * 5 / 2
	}
	return StreamRecheckBound
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
	// The channel the watcher waits on is taken BEFORE anything that reads
	// credential state, and before the goroutine exists: a kickStreams after
	// this returns closes it whether or not the goroutine has run yet.
	kick := s.kickChan()
	go func() {
		lastOK := s.streamNow()
		wait := s.streamRecheckInterval()
		for {
			timer := time.NewTimer(wait)
			select {
			case <-stopped:
				timer.Stop()
				return
			case <-wctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			case <-kick:
				timer.Stop()
			}
			// Retake the channel BEFORE the recheck reads state: a kick during
			// the recheck closes this one, and the next select returns at
			// once. (The transient-retry continue below keeps it, so it waits
			// on a live, unclosed channel and cannot spin.)
			kick = s.kickChan()
			remaining := s.streamRecheckBound() - s.streamNow().Sub(lastOK)
			err := s.recheckWithTimeout(wctx, remaining)
			var transient errTransientRecheck
			switch {
			case err == nil:
				lastOK = s.streamNow()
				wait = s.streamRecheckInterval()
			case errors.As(err, &transient):
				if s.streamNow().Sub(lastOK) < s.streamRecheckBound() {
					// Unknown, not refused: try again at once, inside the
					// bound (m-1).
					wait = s.streamRecheckInterval() / 8
					continue
				}
				// Fail closed AT the bound: a credential that could not be
				// confirmed for that long is not one.
				cancel(errStreamCut{status.Errorf(codes.Unauthenticated,
					"stream ended: its credential could not be re-checked for %s: %v",
					s.streamRecheckBound(), transient.err)})
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
func (s *Server) recheckWithTimeout(ctx context.Context, remaining time.Duration) error {
	timeout := s.streamRecheckTimeout()
	if remaining < timeout {
		timeout = remaining
	}
	if timeout <= 0 {
		return errTransientRecheck{errors.New("no time left inside the recheck bound")}
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := make(chan error, 1)
	go func() {
		if h := recheckHook.Load(); h != nil {
			if err := (*h)(rctx); err != nil {
				res <- errTransientRecheck{err}
				return
			}
		}
		res <- s.recheckStreamIdentity(rctx)
	}()
	select {
	case err := <-res:
		return err
	case <-rctx.Done():
		return errTransientRecheck{errors.New("recheck did not finish within " + timeout.String())}
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

// streamClosers holds the closers a handler registered for its stream.
type streamClosers struct {
	mu    sync.Mutex
	fns   []func()
	fired bool
}

type streamClosersKey struct{}

// fire runs every registered closer once; a closer registered later runs at
// once.
func (c *streamClosers) fire() {
	c.mu.Lock()
	fns := c.fns
	c.fns, c.fired = nil, true
	c.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// serveWatched runs handler on a watched stream and ends it on a cut: the
// handler is given streamCutGrace to return on its own (the device-holding
// handlers close their PTY or socket and do), and then the cut error is
// returned regardless, which ends the RPC and with it the transport the
// handler is blocked on.
func (s *Server) serveWatched(ctx context.Context, srv any, ss grpc.ServerStream, handler grpc.StreamHandler) error {
	wctx, stop := s.watchStream(ctx)
	defer stop()
	closers := &streamClosers{}
	hctx := context.WithValue(wctx, streamClosersKey{}, closers)
	done := make(chan error, 1)
	go func() { done <- handler(srv, &watchedStream{ServerStream: ss, ctx: hctx}) }()
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
	// Release what the handler holds for its caller NOW, whether or not it
	// is looking at its context (m-2).
	closers.fire()
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
		// branch gets this from TokenLive's join. Looked up by the EXACT
		// stored name (rereview-2 N6): a normalized lookup would find another
		// spelling once this one is deleted.
		u, err := corrosion.GetUserExact(ctx, s.db, user)
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
		// The exact stored name the session was minted for (rereview-2 N6):
		// once its spelling is deleted, a normalized lookup finds the
		// spelling that survives, which this session never belonged to.
		if u.Username != user || sess.Username != user {
			return status.Error(codes.Unauthenticated, "stream ended: account deleted")
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
		live, created, err := corrosion.TokenLive(ctx, s.db, id)
		if err != nil {
			return errTransientRecheck{err}
		}
		if !live {
			return status.Error(codes.Unauthenticated, "stream ended: API token revoked or expired")
		}
		if life.TokenPredates(created) {
			return status.Error(codes.Unauthenticated, tokenCutoffRefusal(life, user, created, "stream ended: "))
		}
	}
	return nil
}

// recheckHook, when set (tests only), runs at the start of every stream
// recheck with that recheck's context.
var recheckHook atomic.Pointer[func(context.Context) error]

// streamHandlerAudit is the reviewed list of every streaming RPC and what it
// holds open on behalf of its caller, so a cut credential releases it
// (rereview-2 m-2). TestM2_EveryStreamingRPCIsAudited fails when a streaming
// RPC is added without an entry here: decide, for the new one, whether it
// holds a device for its caller (then registerStreamCloser it) or not.
var streamHandlerAudit = map[string]string{
	"/litevirt.v1.LiteVirt/ConsoleVM": "holds the VM's serial-console PTY: closer registered (ptmx.Close), " +
		"and the handler selects on its context; a forwarded leg's outgoing stream derives from it",
	"/litevirt.v1.LiteVirt/ProxyVNC": "holds a TCP socket to the VM's VNC port: closer registered (conn.Close), " +
		"and the handler selects on its context; a forwarded leg's outgoing stream derives from it",
	"/litevirt.v1.LiteVirt/ProxySpice": "holds a TCP socket to the VM's SPICE port: closer registered (conn.Close), " +
		"and the handler selects on its context; a forwarded leg's outgoing stream derives from it",
	"/litevirt.v1.LiteVirt/GetVMLogs": "holds the VM log file in follow mode: closer registered (f.Close); " +
		"the follow loop also checks its context",
	"/litevirt.v1.LiteVirt/StreamEvents":       "holds an event-bus subscription only; its loop selects on the context",
	"/litevirt.v1.LiteVirt/ListRecoveryClaims": "a bounded read; holds no device",
	"/litevirt.v1.LiteVirt/RestoreBackupFiles": "holds a restore VM's connection for the extraction: closer registered " +
		"(conn.Close), and the extraction's context closes it too (context.AfterFunc)",

	// Operations that run to completion or observe their context: they hold
	// no device on the caller's behalf, and their progress Sends are refused
	// once the stream is cut.
	"/litevirt.v1.LiteVirt/DrainHost":             "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/FailbackHost":          "operation (a failback run it follows); holds no device for the caller",
	"/litevirt.v1.LiteVirt/ShutdownHostWorkloads": "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/UpgradeHost":           "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/PreStageUpgrade":       "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/DeployStack":           "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/DeleteStack":           "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/MigrateVM":             "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/MoveVolume":            "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/ReplicateVolume":       "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/MigrateStackVolumes":   "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/PullImage":             "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/PushImage":             "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/RestoreLive":           "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/BackupSnapshot":        "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/RestoreFromBackup":     "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/BackupContainer":       "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/RestoreContainer":      "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/MigrateContainer":      "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/CrossRegionMigrate":    "operation; holds no device for the caller",
	"/litevirt.v1.LiteVirt/PromoteReplica":        "operation; holds no device for the caller",

	// Client-streaming uploads: the handler reads the caller's frames; a cut
	// refuses the next RecvMsg, which ends the upload.
	"/litevirt.v1.LiteVirt/ImportImage":              "upload; RecvMsg refused after a cut ends it",
	"/litevirt.v1.LiteVirt/ImportVM":                 "upload; RecvMsg refused after a cut ends it",
	"/litevirt.v1.LiteVirt/UploadStoragePoolContent": "upload; RecvMsg refused after a cut ends it",

	// Peer-to-peer: authenticated by a host certificate, never by a user
	// credential, so never watched.
	"/litevirt.v1.LiteVirt/FetchBinary":              "peer mTLS only (requirePeerCert); not a user stream",
	"/litevirt.v1.LiteVirt/FetchISOLibraryFile":      "peer mTLS only (requirePeerCert); not a user stream",
	"/litevirt.v1.LiteVirt/PushBackup":               "peer-to-peer backup push; not a user stream",
	"/litevirt.v1.LiteVirt/PushReplicaIncrement":     "peer-to-peer replica push; not a user stream",
	"/litevirt.v1.LiteVirt/PushReplica":              "peer-to-peer replica push; not a user stream",
	"/litevirt.v1.LiteVirt/ReceiveMigrationDisk":     "peer-to-peer migration disk transfer; not a user stream",
	"/litevirt.v1.LiteVirt/StreamStateDump":          "peer anti-entropy; not a user stream",
	"/litevirt.v1.LiteVirt/StreamTableDump":          "peer anti-entropy; not a user stream",
	"/litevirt.v1.LiteVirt/StreamSensitiveStateDump": "peer anti-entropy; not a user stream",
	"/litevirt.v1.LiteVirt/StreamTableRows":          "peer anti-entropy; not a user stream",
	"/litevirt.v1.LiteVirt/StreamSensitiveTableRows": "peer anti-entropy; not a user stream",
}

// registerStreamCloser records fn, which releases what a handler holds for
// its stream's caller (a PTY, a socket, a file), to run at the moment the
// stream's credential is cut — before the grace, and even if the handler
// never looks at its context (rereview-2 m-2). Outside a watched stream (mTLS
// callers) it does nothing; after a cut it runs fn at once. fn must be safe to
// call alongside the handler's own close of the same thing (os.File and
// net.Conn Close are).
func registerStreamCloser(ctx context.Context, fn func()) {
	c, ok := ctx.Value(streamClosersKey{}).(*streamClosers)
	if !ok {
		return
	}
	c.mu.Lock()
	if c.fired {
		c.mu.Unlock()
		fn()
		return
	}
	c.fns = append(c.fns, fn)
	c.mu.Unlock()
}
