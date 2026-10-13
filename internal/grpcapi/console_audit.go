package grpcapi

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/randid"
)

// Console sessions in the audit log (docs/audit-log.md "Console sessions").
//
// Every host that carries a console session — VNC (ProxyVNC), SPICE
// (ProxySpice) or serial (ConsoleVM) — records it on its own sub-chain:
//
//   - vm.console.open, result ok, when the session starts;
//   - vm.console.close when it ends, with its duration;
//   - a refused open is a single vm.console.open row, result denied (the
//     caller lacks the permission) or error (anything else: no such VM, not
//     running, no such console, the owner unreachable).
//
// GetSpiceInfo hands out the SPICE password, so it is a vm.console.credential
// row of its own, saying whether a password went out, never what it was.
//
// WHO a row names is the identity THIS host authenticated, never one a peer
// asserted. The entry host names the user. A host carrying a session a peer
// relayed to it on its host certificate names the peer ("peer:<cn>",
// via_peer=<cn>): it never had the user's word, and the peer's "admin"
// principal is not a person. A forwarded identity this host verified itself
// (authenticateForwardedBearer) is a user it authenticated, and is named.
// So a relayed session is two pairs of rows, one on each host, each signed by
// the host that wrote it, joined by entry_session (the entry host's session
// id, which it sends on the forwarded stream as a correlation only).
//
// A SPICE client opens several channels, each its own ProxySpice stream.
// They are one session: the channels a caller has open on one VM through one
// credential are grouped, the open row is written when the first starts and
// the close row once the last has ended and none followed within
// consoleSessionLinger. Repeated identical refusals of one client's channels
// within the linger are one row. VNC and serial streams are a session each.
//
// No row carries a console password, a bearer token or a session id (which
// is a bearer): the grouping key that uses the caller's credential lives only
// in memory.

const (
	consoleKindVNC    = "vnc"
	consoleKindSPICE  = "spice"
	consoleKindSerial = "serial"
)

// consoleAuditSessionMD is the metadata key on a forwarded console stream
// carrying the entry host's console session id. The owner records it as
// entry_session, to join its rows to the entry's; it identifies no one and
// authorizes nothing, and an older owner ignores it.
const consoleAuditSessionMD = "x-litevirt-console-session"

// consoleSessionLinger is how long a SPICE session waits, after its last
// channel ended, for another before its close row is written. A variable for
// the tests.
var consoleSessionLinger = 2 * time.Second

// consoleAuditWriteTimeout bounds a console row's write, which runs on a
// context that outlives the (possibly already cancelled) stream's.
const consoleAuditWriteTimeout = 10 * time.Second

// consoleSessions is a host's open console sessions that group several
// streams (SPICE), and its recent SPICE refusals.
type consoleSessions struct {
	mu       sync.Mutex
	open     map[string]*consoleSession
	refusals map[string]time.Time
}

// consoleSession is one audited console session.
type consoleSession struct {
	id       string
	key      string // grouping key ("" for an ungrouped session)
	actor    string
	vm       string
	base     string // the detail every row of the session starts with
	opened   time.Time
	written  chan struct{} // closed once the open row is in
	active   int
	channels int
	lastEnd  time.Time
	endErr   error // the first stream end that was not a plain close
	timer    *time.Timer
	ctx      context.Context // for the close row's write (values only)
	s        *Server
}

// consoleAudit is one console stream's audit handle.
type consoleAudit struct {
	s       *Server
	ctx     context.Context
	kind    string
	vm      string
	owner   string
	actor   string
	viaPeer string
	entrySn string // the entry host's session id, on a relayed stream
	group   string // in-memory grouping key (SPICE)
	sess    *consoleSession
}

// beginConsoleAudit is the audit handle for a console stream of kind on vm.
// Its end must be called with the handler's result.
func (s *Server) beginConsoleAudit(ctx context.Context, kind, vm string) *consoleAudit {
	a := &consoleAudit{s: s, ctx: ctx, kind: kind, vm: vm}
	a.actor, a.viaPeer = consoleAuditActor(ctx)
	if a.viaPeer != "" {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get(consoleAuditSessionMD); len(v) > 0 {
				a.entrySn = v[0]
			}
		}
	}
	if kind == consoleKindSPICE {
		// Everything that tells one client's channels from another's: who,
		// through which credential, relayed by whom, in which entry session.
		a.group = strings.Join([]string{kind, vm, a.actor, callerAuthMethod(ctx), callerSessionID(ctx),
			callerTokenID(ctx), callerMTLSCommonName(ctx), a.viaPeer, a.entrySn}, "\x00")
	}
	return a
}

// consoleAuditActor is who a console row names (see the file comment), and
// the relaying peer's certificate CN when a peer carried the call.
func consoleAuditActor(ctx context.Context) (actor, viaPeer string) {
	if callerPrincipalKind(ctx) != principalKindPeer {
		return callerUsername(ctx), ""
	}
	cn := callerMTLSCommonName(ctx)
	if callerAuthMethod(ctx) == authMethodMTLS {
		return "peer:" + cn, cn
	}
	return callerUsername(ctx), cn
}

func callerTokenID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyTokenID).(string)
	return id
}

// setOwner records the VM's host, once the handler has read the VM.
func (a *consoleAudit) setOwner(host string) { a.owner = host }

// detail is the start of every row's detail for this stream.
func (a *consoleAudit) detail() string {
	entry := a.s.hostName
	if a.viaPeer != "" {
		entry = a.viaPeer
	}
	d := fmt.Sprintf("kind=%s entry=%s owner=%s", a.kind, entry, a.owner)
	if a.viaPeer != "" {
		d += " via_peer=" + a.viaPeer
		if a.entrySn != "" {
			d += " entry_session=" + auditValue(a.entrySn)
		}
	}
	if callerPrincipalKind(a.ctx) == principalKindLocalRoot {
		d += " principal=local-root"
	}
	return d
}

// start records that the session started (or, for a SPICE channel, joined
// its client's session) and returns the session id, which a forward sends
// to the owner under consoleAuditSessionMD.
func (a *consoleAudit) start() string {
	if a.sess != nil {
		return a.sess.id
	}
	reg := &a.s.consoleSessions
	now := time.Now()
	reg.mu.Lock()
	if a.group != "" {
		if sess, ok := reg.open[a.group]; ok {
			if sess.timer != nil {
				sess.timer.Stop()
				sess.timer = nil
			}
			sess.active++
			sess.channels++
			a.sess = sess
			reg.mu.Unlock()
			return sess.id
		}
	}
	sess := &consoleSession{
		id: randid.New(), key: a.group, actor: a.actor, vm: a.vm, base: a.detail(),
		opened: now, written: make(chan struct{}), active: 1, channels: 1,
		ctx: context.WithoutCancel(a.ctx), s: a.s,
	}
	if a.group != "" {
		if reg.open == nil {
			reg.open = map[string]*consoleSession{}
		}
		reg.open[a.group] = sess
	}
	a.sess = sess
	reg.mu.Unlock()

	a.s.writeConsoleAudit(sess.ctx, sess.actor, "vm.console.open", sess.vm, sess.base+" session="+sess.id, "ok")
	close(sess.written)
	return sess.id
}

// end records how the stream ended: the refusal, when it never started;
// else its part of the session's end.
func (a *consoleAudit) end(err error) {
	if a.sess == nil {
		a.refused(err)
		return
	}
	sess := a.sess
	reg := &a.s.consoleSessions
	reg.mu.Lock()
	sess.active--
	sess.lastEnd = time.Now()
	if sess.endErr == nil && !consoleEndedPlainly(err) {
		sess.endErr = err
	}
	if sess.active > 0 {
		reg.mu.Unlock()
		return
	}
	if sess.key == "" {
		reg.mu.Unlock()
		sess.close()
		return
	}
	var t *time.Timer
	t = time.AfterFunc(consoleSessionLinger, func() {
		reg.mu.Lock()
		if sess.timer != t || sess.active > 0 {
			reg.mu.Unlock()
			return // a channel joined in the meantime
		}
		delete(reg.open, sess.key)
		reg.mu.Unlock()
		sess.close()
	})
	sess.timer = t
	reg.mu.Unlock()
}

// close writes the session's close row. Its fields no longer change: the
// session has no active stream and has left the registry.
func (sess *consoleSession) close() {
	<-sess.written
	result, ended := "ok", "closed"
	if sess.endErr != nil {
		ended = status.Convert(sess.endErr).Message()
		if !consoleEndedWithoutFault(sess.endErr) {
			result = "error"
		}
	}
	d := fmt.Sprintf("%s session=%s duration=%s", sess.base, sess.id, sess.lastEnd.Sub(sess.opened).Round(time.Millisecond))
	if sess.key != "" {
		d += " channels=" + strconv.Itoa(sess.channels)
	}
	d += " ended=" + auditValue(ended)
	sess.s.writeConsoleAudit(sess.ctx, sess.actor, "vm.console.close", sess.vm, d, result)
}

// refused writes the row for a stream that never started.
func (a *consoleAudit) refused(err error) {
	if err == nil {
		return
	}
	result := "error"
	if c := status.Code(err); c == codes.PermissionDenied || c == codes.Unauthenticated {
		result = "denied"
	}
	reason := status.Convert(err).Message()
	if a.group != "" {
		// One row for a burst of identical refusals of one client's channels.
		reg := &a.s.consoleSessions
		key := a.group + "\x00" + result + "\x00" + reason
		now := time.Now()
		reg.mu.Lock()
		if last, ok := reg.refusals[key]; ok && now.Sub(last) < consoleSessionLinger {
			reg.mu.Unlock()
			return
		}
		if reg.refusals == nil {
			reg.refusals = map[string]time.Time{}
		}
		for k, at := range reg.refusals {
			if now.Sub(at) >= consoleSessionLinger {
				delete(reg.refusals, k)
			}
		}
		reg.refusals[key] = now
		reg.mu.Unlock()
	}
	a.s.writeConsoleAudit(context.WithoutCancel(a.ctx), a.actor, "vm.console.open", a.vm,
		a.detail()+" reason="+auditValue(reason), result)
}

// auditConsoleCredential writes GetSpiceInfo's row.
func (s *Server) auditConsoleCredential(ctx context.Context, vm, owner string, password bool, err error) {
	a := s.beginConsoleAudit(ctx, consoleKindSPICE, vm)
	a.owner = owner
	d, result := a.detail(), "ok"
	switch {
	case err == nil:
		d += " password=" + map[bool]string{true: "yes", false: "no"}[password]
	case status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.Unauthenticated:
		result, d = "denied", d+" reason="+auditValue(status.Convert(err).Message())
	default:
		result, d = "error", d+" reason="+auditValue(status.Convert(err).Message())
	}
	s.writeConsoleAudit(context.WithoutCancel(ctx), a.actor, "vm.console.credential", vm, d, result)
}

func (s *Server) writeConsoleAudit(ctx context.Context, actor, action, vm, detail, result string) {
	ctx, cancel := context.WithTimeout(ctx, consoleAuditWriteTimeout)
	defer cancel()
	s.auditAs(ctx, actor, action, vm, detail, result)
}

// consoleEndedPlainly: the stream closed with no error, or the client went
// away (its context cancelled).
func consoleEndedPlainly(err error) bool {
	return err == nil || status.Code(err) == codes.Canceled
}

// consoleEndedWithoutFault: ended plainly, or cut because the caller's
// credential was revoked, disabled or deleted (stream_watch.go) — the
// session ran and was ended on purpose.
func consoleEndedWithoutFault(err error) bool {
	return consoleEndedPlainly(err) || status.Code(err) == codes.Unauthenticated
}

// auditValue is v as one detail value: as it is when it has no space or
// quote, else quoted.
func auditValue(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\n\"\\=") {
		return v
	}
	return strconv.Quote(v)
}
