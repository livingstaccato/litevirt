package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
)

// Console sessions in the audit log (docs/audit-log.md "Console sessions").
//
// Every host that carries a console session — VNC (ProxyVNC), SPICE
// (ProxySpice) or serial (ConsoleVM) — records it on its own sub-chain:
//
//   - vm.console.open, result ok, once the session is ACCEPTED: on the VM's
//     host when its console socket or PTY is open; on a host relaying to the
//     VM's host only once that host has accepted the stream (it sends the
//     stream's header — consoleAcceptedMD — when it does; an older one sends
//     its header with its first message);
//   - vm.console.close when it ends, with its duration and how it ended;
//   - a stream that never got that far is a single vm.console.open row,
//     result denied (PermissionDenied or Unauthenticated, here or on the VM's
//     host) or error (anything else: no such VM, not running, no such
//     console, the VM's host unreachable, the client gone).
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
// id, which it sends on the forwarded call as a correlation only).
//
// A SPICE client opens several channels, each its own ProxySpice stream.
// They are one session: the channels a caller has open on one VM through one
// credential are grouped, the open row is written when the first is accepted
// and the close row once the last has ended and none followed within
// consoleSessionLinger. VNC and serial streams are a session each.
//
// Refusal rows are bounded: each echoed value is cut to a fixed size, and a
// caller gets at most consoleRefusalBurst refusal rows, and one per distinct
// (console, VM, result, reason), per consoleRefusalWindow. What is held back
// is counted, and the window ends with one vm.console.suppressed row naming
// the count. The first refusal of every window is always written.
//
// A graceful stop (MarkConsoleShutdown, FlushConsoleAudit) writes every open
// session's close row, ended=daemon-stop, before the database closes.
//
// No row carries a console password, a bearer token or a session id (which
// is a bearer): the grouping key that uses the caller's credential lives only
// in memory.

const (
	consoleKindVNC    = "vnc"
	consoleKindSPICE  = "spice"
	consoleKindSerial = "serial"
)

// consoleAuditSessionMD is the metadata key on a forwarded console call
// carrying the entry host's session (or request) id. The VM's host records it
// as entry_session, to join its rows to the entry's; it identifies no one and
// authorizes nothing, and an older host ignores it.
const consoleAuditSessionMD = "x-litevirt-console-session"

// consoleAcceptedMD is the header a host sends on a console stream the moment
// it has accepted it (its open row is written), before any console byte. A
// relaying host records its own open only once it has a header from the VM's
// host, so a stream the VM's host refused — or never saw — is a refusal on
// both hosts, not a session.
const consoleAcceptedMD = "x-litevirt-console-accepted"

// consoleSessionLinger is how long a SPICE session waits, after its last
// channel ended, for another before its close row is written. A variable for
// the tests.
var consoleSessionLinger = 2 * time.Second

// Refusal rows per caller: at most consoleRefusalBurst in each
// consoleRefusalWindow, and one per distinct refusal. Variables for the tests.
var (
	consoleRefusalWindow = time.Minute
	consoleRefusalBurst  = 10
)

// Caps on what a row echoes from a request.
const (
	consoleAuditMaxTarget = safename.MaxNameLen
	consoleAuditMaxReason = 300
	consoleAuditMaxID     = 64
)

// consoleAuditWriteTimeout bounds a console row's write, which runs on a
// context that outlives the (possibly already cancelled) stream's.
const consoleAuditWriteTimeout = 10 * time.Second

// How a session ended, in its close row's ended field.
const (
	consoleEndedClosed     = "closed"
	consoleEndedDaemonStop = "daemon-stop"
)

// consoleSessions is a host's console audit state.
type consoleSessions struct {
	mu       sync.Mutex
	open     map[string]*consoleSession   // grouped (SPICE) sessions by key, pending or open
	live     map[*consoleSession]struct{} // sessions with an open row and no close yet
	refusals map[string]*refusalWindow    // per actor
	stopping bool                         // the daemon is stopping (MarkConsoleShutdown)
	flushed  bool                         // FlushConsoleAudit ran: write nothing more
}

// consoleSession is one audited console session.
type consoleSession struct {
	s      *Server
	ctx    context.Context // for the row writes (values only)
	id     string
	key    string // grouping key ("" for an ungrouped session)
	actor  string
	vm     string
	base   string // the detail every row of the session starts with
	opened time.Time

	streams  int  // streams attached: pending or accepted, not yet ended
	active   int  // accepted streams not yet ended
	channels int  // streams ever accepted
	openRow  bool // the open row is (being) written
	written  chan struct{}
	closed   bool
	lastEnd  time.Time
	endClass string // "" until a stream ends other than plainly
	endMsg   string
	timer    *time.Timer
}

// refusalWindow is one caller's refusal budget.
type refusalWindow struct {
	start      time.Time
	written    int
	seen       map[string]bool // refusals written in this window
	suppressed int
	denied     int // of the suppressed
	timer      *time.Timer
}

// consoleAudit is one console stream's audit handle.
type consoleAudit struct {
	s        *Server
	ctx      context.Context
	kind     string
	vm       string
	owner    string
	actor    string
	viaPeer  string
	entrySn  string // the entry host's session id, on a relayed stream
	group    string // in-memory grouping key (SPICE)
	sess     *consoleSession
	accepted bool
	ended    bool
}

// beginConsoleAudit is the audit handle for a console stream of kind on vm.
// Its end must be called with the handler's result.
func (s *Server) beginConsoleAudit(ctx context.Context, kind, vm string) *consoleAudit {
	a := &consoleAudit{s: s, ctx: ctx, kind: kind, vm: vm}
	a.actor, a.viaPeer = consoleAuditActor(ctx)
	if a.viaPeer != "" {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get(consoleAuditSessionMD); len(v) > 0 {
				a.entrySn = boundAuditValue(v[0], consoleAuditMaxID)
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

// attach joins the stream to its session — the caller's open SPICE session
// on this VM, or a new one — without recording anything yet, and returns the
// session id, which a forward sends to the VM's host.
func (a *consoleAudit) attach() string {
	reg := &a.s.consoleSessions
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if a.sess != nil {
		return a.sess.id
	}
	if a.group != "" {
		if sess, ok := reg.open[a.group]; ok && !sess.closed {
			sess.streams++
			a.sess = sess
			return sess.id
		}
	}
	sess := &consoleSession{
		s: a.s, ctx: context.WithoutCancel(a.ctx), id: randid.New(), key: a.group,
		actor: a.actor, vm: boundAuditValue(a.vm, consoleAuditMaxTarget), base: a.detail(),
		streams: 1, written: make(chan struct{}),
	}
	if a.group != "" {
		if reg.open == nil {
			reg.open = map[string]*consoleSession{}
		}
		reg.open[a.group] = sess
	}
	a.sess = sess
	return sess.id
}

// accept records that this host accepted the stream: the session's open row
// (once per session) and, through stream, the header that tells a relaying
// host so. A stream that has already ended is not accepted.
func (a *consoleAudit) accept(stream grpc.ServerStream) {
	a.attach()
	reg := &a.s.consoleSessions
	reg.mu.Lock()
	if a.ended || a.accepted {
		reg.mu.Unlock()
		return
	}
	sess := a.sess
	a.accepted = true
	sess.active++
	sess.channels++
	if sess.timer != nil {
		sess.timer.Stop()
		sess.timer = nil
	}
	first := !sess.openRow
	if first {
		sess.openRow = true
		sess.opened = time.Now()
		if reg.live == nil {
			reg.live = map[*consoleSession]struct{}{}
		}
		reg.live[sess] = struct{}{}
	}
	flushed := reg.flushed
	reg.mu.Unlock()

	if first {
		if !flushed {
			a.s.writeConsoleAudit(sess.ctx, sess.actor, "vm.console.open", sess.vm, sess.base+" session="+sess.id, "ok")
		}
		close(sess.written)
	}
	if stream != nil {
		// Before any console byte, so a relaying host sees it first. Fails
		// harmlessly when the header already went (it cannot, here).
		_ = stream.SendHeader(metadata.Pairs(consoleAcceptedMD, "1"))
	}
}

// acceptRelayed waits for the VM's host's header on a forwarded stream and
// accepts this stream when it has one: a current host sends it when it
// accepts, an older one with its first message. A stream that ended without
// one was refused there (or never reached it), and is not accepted.
func (a *consoleAudit) acceptRelayed(remote grpc.ClientStream, incoming grpc.ServerStream) {
	if md, err := remote.Header(); err == nil && md != nil {
		a.accept(incoming)
	}
}

// end records how the stream ended: the refusal, when it was never accepted;
// else its part of the session's end.
func (a *consoleAudit) end(err error) {
	reg := &a.s.consoleSessions
	reg.mu.Lock()
	if a.ended {
		reg.mu.Unlock()
		return
	}
	if a.sess != nil && !a.accepted && err == nil {
		// A relayed stream that ended cleanly without a header: an older VM
		// host on a console that never wrote a byte. It ran; record it.
		reg.mu.Unlock()
		a.accept(nil)
		reg.mu.Lock()
	}
	a.ended = true
	sess := a.sess
	if sess == nil {
		reg.mu.Unlock()
		a.refused(err)
		return
	}
	sess.streams--
	var finish func()
	if !a.accepted {
		finish = reg.settleLocked(sess)
		reg.mu.Unlock()
		if finish != nil {
			finish()
		}
		a.refused(err)
		return
	}
	sess.active--
	sess.lastEnd = time.Now()
	if sess.endClass == "" {
		switch {
		case reg.stopping:
			sess.endClass = consoleEndedDaemonStop
		case err == nil || status.Code(err) == codes.Canceled:
		case streamCutCause(a.ctx) != nil:
			// This host's own watcher cut the caller's credential: the
			// session ran and was ended on purpose.
			sess.endClass, sess.endMsg = "cut", status.Convert(err).Message()
		default:
			sess.endClass, sess.endMsg = "error", status.Convert(err).Message()
		}
	}
	finish = reg.settleLocked(sess)
	reg.mu.Unlock()
	if finish != nil {
		finish()
	}
}

// settleLocked decides what follows a stream's end: nothing while the
// session has streams, its close row (now, or after the linger for a grouped
// one), or — a session nothing accepted — its removal. reg.mu is held; the
// returned func, if any, runs after it is released.
func (reg *consoleSessions) settleLocked(sess *consoleSession) func() {
	if sess.closed || sess.streams > 0 || sess.active > 0 {
		return nil
	}
	if !sess.openRow {
		if sess.key != "" && reg.open[sess.key] == sess {
			delete(reg.open, sess.key)
		}
		sess.closed = true
		return nil
	}
	if sess.key == "" {
		reg.closeLocked(sess)
		return sess.writeClose
	}
	var t *time.Timer
	t = time.AfterFunc(consoleSessionLinger, func() {
		reg.mu.Lock()
		if sess.timer != t || sess.closed || sess.streams > 0 || sess.active > 0 {
			reg.mu.Unlock()
			return // a channel joined in the meantime
		}
		reg.closeLocked(sess)
		reg.mu.Unlock()
		sess.writeClose()
	})
	sess.timer = t
	return nil
}

// closeLocked takes sess out of the registry; its close row is the caller's
// to write, after releasing reg.mu.
func (reg *consoleSessions) closeLocked(sess *consoleSession) {
	sess.closed = true
	if sess.timer != nil {
		sess.timer.Stop()
		sess.timer = nil
	}
	if sess.key != "" && reg.open[sess.key] == sess {
		delete(reg.open, sess.key)
	}
	delete(reg.live, sess)
}

// writeClose writes the session's close row. Its fields no longer change:
// the session has left the registry.
func (sess *consoleSession) writeClose() {
	<-sess.written
	result, ended := "ok", consoleEndedClosed
	switch sess.endClass {
	case consoleEndedDaemonStop:
		ended = consoleEndedDaemonStop
	case "cut":
		ended = sess.endMsg
	case "error":
		result, ended = "error", sess.endMsg
	}
	d := fmt.Sprintf("%s session=%s duration=%s", sess.base, sess.id, sess.lastEnd.Sub(sess.opened).Round(time.Millisecond))
	if sess.key != "" {
		d += " channels=" + strconv.Itoa(sess.channels)
	}
	d += " ended=" + auditValue(boundAuditValue(ended, consoleAuditMaxReason))
	sess.s.writeConsoleAudit(sess.ctx, sess.actor, "vm.console.close", sess.vm, d, result)
}

// refused writes the row for a stream that was never accepted.
func (a *consoleAudit) refused(err error) {
	if err == nil {
		return
	}
	a.s.refusalRow(a.ctx, a.actor, "vm.console.open", a.kind, a.vm, a.detail(), err)
}

// refusalRow writes one refusal row, within the caller's budget (see the
// file comment).
func (s *Server) refusalRow(ctx context.Context, actor, action, kind, vm, detail string, err error) {
	result := "error"
	if c := status.Code(err); c == codes.PermissionDenied || c == codes.Unauthenticated {
		result = "denied"
	}
	reason := status.Convert(err).Message()
	if status.Code(err) == codes.Canceled {
		reason = "aborted by the client"
	}
	reg := &s.consoleSessions
	reg.mu.Lock()
	if reg.stopping && status.Code(err) == codes.Canceled {
		reason = consoleEndedDaemonStop
	}
	if reg.flushed {
		reg.mu.Unlock()
		return
	}
	w := reg.refusals[actor]
	if w == nil {
		if reg.refusals == nil {
			reg.refusals = map[string]*refusalWindow{}
		}
		w = &refusalWindow{start: time.Now(), seen: map[string]bool{}}
		reg.refusals[actor] = w
		w.timer = time.AfterFunc(consoleRefusalWindow, func() { s.endRefusalWindow(context.Background(), actor, w) })
	}
	sig := strings.Join([]string{action, kind, vm, result, reason}, "\x00")
	if w.seen[sig] || w.written >= consoleRefusalBurst {
		w.suppressed++
		if result == "denied" {
			w.denied++
		}
		reg.mu.Unlock()
		return
	}
	w.seen[sig] = true
	w.written++
	reg.mu.Unlock()
	s.writeConsoleAudit(context.WithoutCancel(ctx), actor, action, boundAuditValue(vm, consoleAuditMaxTarget),
		detail+" reason="+auditValue(boundAuditValue(reason, consoleAuditMaxReason)), result)
}

// endRefusalWindow closes actor's refusal window w and writes its summary
// row when it held anything back.
func (s *Server) endRefusalWindow(ctx context.Context, actor string, w *refusalWindow) {
	reg := &s.consoleSessions
	reg.mu.Lock()
	if reg.refusals[actor] != w {
		reg.mu.Unlock()
		return
	}
	delete(reg.refusals, actor)
	flushed := reg.flushed
	reg.mu.Unlock()
	if !flushed {
		s.writeRefusalSummary(ctx, actor, w)
	}
}

func (s *Server) writeRefusalSummary(ctx context.Context, actor string, w *refusalWindow) {
	if w.suppressed == 0 {
		return
	}
	result := "error"
	if w.denied > 0 {
		result = "denied"
	}
	d := fmt.Sprintf("suppressed=%d denied=%d error=%d since=%s window=%s", w.suppressed, w.denied,
		w.suppressed-w.denied, w.start.UTC().Format(time.RFC3339), consoleRefusalWindow)
	s.writeConsoleAudit(context.WithoutCancel(ctx), actor, "vm.console.suppressed", "", d, result)
}

// MarkConsoleShutdown tells console auditing the daemon is stopping: a
// session that ends from now on ended because of the stop, not its client.
// Call it before stopping the gRPC server.
func (s *Server) MarkConsoleShutdown() {
	reg := &s.consoleSessions
	reg.mu.Lock()
	reg.stopping = true
	reg.mu.Unlock()
}

// FlushConsoleAudit writes, before the database closes, the close row of
// every session still open or lingering (ended=daemon-stop for one that was
// still running) and every pending refusal summary. Nothing is written after
// it. Call it after the gRPC server has stopped and before the database
// closes.
func (s *Server) FlushConsoleAudit() {
	reg := &s.consoleSessions
	reg.mu.Lock()
	reg.stopping = true
	var closes []*consoleSession
	for sess := range reg.live {
		if sess.active > 0 {
			// Still running: the stop ended it, whatever its handler later says.
			sess.lastEnd = time.Now()
			if sess.endClass == "" {
				sess.endClass = consoleEndedDaemonStop
			}
		}
		reg.closeLocked(sess)
		closes = append(closes, sess)
	}
	type summary struct {
		actor string
		w     *refusalWindow
	}
	var sums []summary
	for actor, w := range reg.refusals {
		if w.timer != nil {
			w.timer.Stop()
		}
		sums = append(sums, summary{actor, w})
	}
	reg.refusals = nil
	reg.mu.Unlock()

	for _, sess := range closes {
		sess.writeClose()
	}
	for _, sm := range sums {
		s.writeRefusalSummary(context.Background(), sm.actor, sm.w)
	}
	reg.mu.Lock()
	reg.flushed = true
	reg.mu.Unlock()
}

// auditConsoleCredential writes GetSpiceInfo's row. request is the id this
// host sent with a forwarded call ("" when it served the call itself).
func (s *Server) auditConsoleCredential(ctx context.Context, vm, owner, request string, password bool, err error) {
	a := s.beginConsoleAudit(ctx, consoleKindSPICE, vm)
	a.owner = owner
	d := a.detail()
	if request != "" {
		d += " session=" + request
	}
	if err != nil {
		s.refusalRow(ctx, a.actor, "vm.console.credential", consoleKindSPICE, vm, d, err)
		return
	}
	d += " password=" + map[bool]string{true: "yes", false: "no"}[password]
	s.writeConsoleAudit(context.WithoutCancel(ctx), a.actor, "vm.console.credential", boundAuditValue(vm, consoleAuditMaxTarget), d, "ok")
}

func (s *Server) writeConsoleAudit(ctx context.Context, actor, action, vm, detail, result string) {
	if s.consoleAuditFlushed() {
		slog.Debug("console audit row after the flush, not written", "action", action, "vm", vm)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, consoleAuditWriteTimeout)
	defer cancel()
	s.auditAs(ctx, actor, action, vm, detail, result)
}

func (s *Server) consoleAuditFlushed() bool {
	reg := &s.consoleSessions
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.flushed
}

// boundAuditValue is v cut to at most max bytes (never inside a rune), with
// a marker saying how much was cut.
func boundAuditValue(v string, max int) string {
	if len(v) <= max {
		return v
	}
	cut := strings.ToValidUTF8(v[:max], "")
	return fmt.Sprintf("%s…(+%d bytes)", cut, len(v)-len(cut))
}

// auditValue is v as one detail value: as it is when it has no space or
// quote, else quoted.
func auditValue(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\n\"\\=") {
		return v
	}
	return strconv.Quote(v)
}
