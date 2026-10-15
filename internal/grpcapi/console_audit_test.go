package grpcapi

// Console opens are audited (docs/audit-log.md "Console sessions"): every
// VNC, SPICE and serial console session a host carries is an open row and a
// close row on that host's own sub-chain, and every refused open is a row.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// auditVirt is libvirtfake with a real serial console (a FIFO), VNC and
// SPICE listeners, and a SPICE password.
type auditVirt struct {
	*libvirtfake.Fake
	pty       string
	vnc       int
	spice     int
	spicePass string
}

func (v auditVirt) ConsolePTYPath(string) (string, error) { return v.pty, nil }
func (v auditVirt) GetVMVNCPort(string) (int, error)      { return v.vnc, nil }
func (v auditVirt) GetVMSpicePort(string) (int, error)    { return v.spice, nil }

// StateReader and SecureStateReader are none: the console reads go to the
// overrides above, not to the embedded fake's own readers.
func (v auditVirt) StateReader() *libvirt.StateReader       { return nil }
func (v auditVirt) SecureStateReader() *libvirt.StateReader { return nil }
func (v auditVirt) ConsolePassword(_, kind string) (string, error) {
	if kind == "spice" {
		return v.spicePass, nil
	}
	return "", nil
}

// holdListener accepts connections and keeps them open (reading and
// discarding) until the test ends.
func holdListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// consoleAuditServer is a server whose running VM "desk" (project acme) has
// all three consoles behind real endpoints.
func consoleAuditServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.5", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "desk", HostName: s.hostName, State: "running", Spec: "{}", Project: "acme",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fifo := filepath.Join(t.TempDir(), "console")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// A writer held open, so the console never reads EOF on its own.
	w, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	s.virt = auditVirt{
		Fake: libvirtfake.New(), pty: fifo,
		vnc: holdListener(t), spice: holdListener(t), spicePass: "spice-secret-0123456789ab",
	}
	shortLinger(t)
	return s
}

func shortLinger(t *testing.T) {
	t.Helper()
	old := consoleSessionLinger
	consoleSessionLinger = 300 * time.Millisecond
	t.Cleanup(func() { consoleSessionLinger = old })
}

// openConsole starts the real handler for kind ("vnc", "spice", "serial")
// on "desk" as the caller in ctx. It returns at once if the handler refused
// (with its error), else after 300 ms with the session still open and a
// function that ends it and returns the handler's result.
func openConsole(t *testing.T, s *Server, ctx context.Context, kind string) (refused error, end func() error) {
	t.Helper()
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-vm-name", "desk"))
	ts := &transportStream{ctx: ctx, transport: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		switch kind {
		case "vnc":
			done <- s.ProxyVNC(&grpc.GenericServerStream[pb.VNCData, pb.VNCData]{ServerStream: ts})
		case "spice":
			done <- s.ProxySpice(&grpc.GenericServerStream[pb.SpiceData, pb.SpiceData]{ServerStream: ts})
		case "serial":
			done <- s.ConsoleVM(&grpc.GenericServerStream[pb.ConsoleInput, pb.ConsoleOutput]{ServerStream: ts})
		}
	}()
	select {
	case err := <-done:
		close(ts.transport)
		if err == nil {
			t.Fatalf("%s: the handler ended at once with no error", kind)
		}
		return err, nil
	case <-time.After(300 * time.Millisecond):
	}
	var once sync.Once
	return nil, func() error {
		once.Do(func() { close(ts.transport) })
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			// Errorf, not Fatalf: end may run on a goroutine a test spawned,
			// where Fatalf would end only that goroutine and leave the test
			// waiting on it until the package timeout.
			t.Errorf("%s: the handler did not end 5s after its stream did", kind)
			return errHandlerDidNotEnd
		}
	}
}

// errHandlerDidNotEnd is what an openConsole end returns when the handler
// has not ended 5s after its stream did.
var errHandlerDidNotEnd = errors.New("the console handler did not end")

// awaitEnd waits for an end() a test ran on a goroutine of its own, and fails
// the test, from the test goroutine, if that end failed or never returned:
// a regression fails the test at once instead of hanging the package.
func awaitEnd(t *testing.T, ended <-chan error) {
	t.Helper()
	select {
	case err := <-ended:
		if errors.Is(err, errHandlerDidNotEnd) {
			t.Fatal("the console handler did not end")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("end() did not return within 10s")
	}
}

type consoleAuditRow struct {
	user, host, action, target, detail, result string
}

func consoleAuditRows(t *testing.T, s *Server) []consoleAuditRow {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT username, host_name, action, target, detail, result FROM audit_log
		 WHERE action LIKE 'vm.console.%' ORDER BY seq`)
	if err != nil {
		t.Fatalf("read audit_log: %v", err)
	}
	var out []consoleAuditRow
	for _, r := range rows {
		out = append(out, consoleAuditRow{r.String("username"), r.String("host_name"), r.String("action"),
			r.String("target"), r.String("detail"), r.String("result")})
	}
	return out
}

func rowsWith(rows []consoleAuditRow, action, kind string) []consoleAuditRow {
	var out []consoleAuditRow
	for _, r := range rows {
		if r.action == action && auditField(r.detail, "kind") == kind {
			out = append(out, r)
		}
	}
	return out
}

// auditField is key's value in a console row's detail (key=value pairs, a
// value quoted when it has a space).
func auditField(detail, key string) string {
	m := regexp.MustCompile(`(?:^| )` + regexp.QuoteMeta(key) + `=("(?:[^"\\]|\\.)*"|\S*)`).FindStringSubmatch(detail)
	if m == nil {
		return ""
	}
	if v, err := strconv.Unquote(m[1]); err == nil {
		return v
	}
	return m[1]
}

func waitRows(t *testing.T, s *Server, what string, ok func([]consoleAuditRow) bool) []consoleAuditRow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows := consoleAuditRows(t, s)
		if ok(rows) {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s; console audit rows:\n%+v", what, rows)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A refused open is a row: the caller, the VM, the console, and "denied".
//
// Mutation "no row for a refused open" — red.
func TestConsoleAudit_ARefusedOpenIsADeniedRow(t *testing.T) {
	for _, kind := range []string{"vnc", "spice", "serial"} {
		t.Run(kind+" without vm.console on the VM", func(t *testing.T) {
			s := consoleAuditServer(t)
			ctx := boundAtCtx(t, s, "mallory", "operator", "Operator", "/projects/beta")
			if err, _ := openConsole(t, s, ctx, kind); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("open as mallory: %v, want PermissionDenied", err)
			}
			rows := waitRows(t, s, "no denied row", func(r []consoleAuditRow) bool { return len(r) > 0 })
			if len(rows) != 1 {
				t.Fatalf("want exactly one row, got %+v", rows)
			}
			r := rows[0]
			if r.action != "vm.console.open" || r.result != "denied" || r.user != "mallory" || r.target != "desk" ||
				r.host != s.hostName || auditField(r.detail, "kind") != kind || auditField(r.detail, "owner") != s.hostName {
				t.Fatalf("denied row = %+v", r)
			}
		})
	}
	t.Run("vnc below the operator role", func(t *testing.T) {
		s := consoleAuditServer(t)
		if err, _ := openConsole(t, s, userCtx("vic", "viewer"), "vnc"); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("open as a viewer: %v, want PermissionDenied", err)
		}
		rows := waitRows(t, s, "no denied row", func(r []consoleAuditRow) bool { return len(r) > 0 })
		if len(rows) != 1 || rows[0].result != "denied" || rows[0].user != "vic" || rows[0].target != "desk" {
			t.Fatalf("rows = %+v", rows)
		}
	})
	t.Run("a stopped VM is an error row", func(t *testing.T) {
		s := consoleAuditServer(t)
		if err := corrosion.UpdateVMState(context.Background(), s.db, "desk", "stopped", ""); err != nil {
			t.Fatal(err)
		}
		ctx := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
		if err, _ := openConsole(t, s, ctx, "serial"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("open on a stopped VM: %v, want FailedPrecondition", err)
		}
		rows := waitRows(t, s, "no error row", func(r []consoleAuditRow) bool { return len(r) > 0 })
		if len(rows) != 1 || rows[0].action != "vm.console.open" || rows[0].result != "error" ||
			!strings.Contains(auditField(rows[0].detail, "reason"), "not running") {
			t.Fatalf("rows = %+v", rows)
		}
	})
}

// A session is an open row when it starts and a close row when it ends,
// joined by the session id, the close carrying how long it lasted.
//
// Mutation "no open row" — red. Mutation "no close row" — red.
func TestConsoleAudit_ASessionIsAnOpenAndACloseRow(t *testing.T) {
	for _, kind := range []string{"vnc", "spice", "serial"} {
		t.Run(kind, func(t *testing.T) {
			s := consoleAuditServer(t)
			ctx := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
			err, end := openConsole(t, s, ctx, kind)
			if err != nil {
				t.Fatalf("open as alice: %v", err)
			}
			rows := waitRows(t, s, "no open row while the session is open", func(r []consoleAuditRow) bool {
				return len(rowsWith(r, "vm.console.open", kind)) == 1
			})
			if n := len(rowsWith(rows, "vm.console.close", kind)); n != 0 {
				t.Fatalf("a close row while the session is still open: %+v", rows)
			}
			if err := end(); err != nil {
				t.Fatalf("the session ended with %v", err)
			}
			rows = waitRows(t, s, "no close row after the session ended", func(r []consoleAuditRow) bool {
				return len(rowsWith(r, "vm.console.close", kind)) == 1
			})
			open, closed := rowsWith(rows, "vm.console.open", kind)[0], rowsWith(rows, "vm.console.close", kind)[0]
			for _, r := range []consoleAuditRow{open, closed} {
				if r.user != "alice" || r.target != "desk" || r.result != "ok" || r.host != s.hostName ||
					auditField(r.detail, "entry") != s.hostName || auditField(r.detail, "owner") != s.hostName {
					t.Errorf("row = %+v", r)
				}
			}
			if id := auditField(open.detail, "session"); id == "" || auditField(closed.detail, "session") != id {
				t.Errorf("open and close are not one session: %q / %q", open.detail, closed.detail)
			}
			d, err := time.ParseDuration(auditField(closed.detail, "duration"))
			if err != nil || d < 250*time.Millisecond {
				t.Errorf("close duration = %q (%v), want at least the 300ms the session was open", auditField(closed.detail, "duration"), err)
			}
			if len(rows) != 2 {
				t.Errorf("want exactly an open and a close, got %+v", rows)
			}
		})
	}
}

// A SPICE client opens several channels, each its own ProxySpice stream.
// They are one session: one open row when the first starts, one close row
// once the last has ended and none followed within the linger. Another
// user's channels are a session of their own, and so is a reconnect after
// the linger. Repeated refusals of one client's channels are one row.
//
// Mutation "no grouping: every channel is a session" — red.
func TestConsoleAudit_SpiceChannelsOfOneClientAreOneSession(t *testing.T) {
	s := consoleAuditServer(t)
	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	bob := boundAtCtx(t, s, "bob", "operator", "Operator", "/projects/acme")

	var ends []func() error
	for i := 0; i < 4; i++ {
		err, end := openConsole(t, s, alice, "spice")
		if err != nil {
			t.Fatalf("alice's channel %d: %v", i, err)
		}
		ends = append(ends, end)
	}
	_, bobEnd := openConsole(t, s, bob, "spice")
	// Two of alice's channels end, a fifth opens: still the same session.
	_ = ends[0]()
	_ = ends[1]()
	_, fifth := openConsole(t, s, alice, "spice")
	ends = append(ends[2:], fifth)
	for _, end := range ends {
		_ = end()
	}
	_ = bobEnd()

	rows := waitRows(t, s, "no close rows for the two sessions", func(r []consoleAuditRow) bool {
		return len(rowsWith(r, "vm.console.close", "spice")) >= 2
	})
	time.Sleep(2 * consoleSessionLinger)
	rows = consoleAuditRows(t, s)
	byUser := map[string][2]int{}
	for _, r := range rows {
		c := byUser[r.user]
		if r.action == "vm.console.open" {
			c[0]++
		} else if r.action == "vm.console.close" {
			c[1]++
			if r.user == "alice" && auditField(r.detail, "channels") != "5" {
				t.Errorf("alice's close row: channels = %q, want 5: %q", auditField(r.detail, "channels"), r.detail)
			}
		}
		byUser[r.user] = c
	}
	if byUser["alice"] != [2]int{1, 1} || byUser["bob"] != [2]int{1, 1} {
		t.Fatalf("open/close rows per user = %v, want one of each for alice and for bob:\n%+v", byUser, rows)
	}

	// A reconnect after the linger is a new session.
	_, again := openConsole(t, s, alice, "spice")
	_ = again()
	waitRows(t, s, "no second session for alice after the linger", func(r []consoleAuditRow) bool {
		n := 0
		for _, x := range r {
			if x.user == "alice" && x.action == "vm.console.close" {
				n++
			}
		}
		return n == 2
	})

	// Three refused channels in a burst: one row.
	mallory := boundAtCtx(t, s, "mallory", "operator", "Operator", "/projects/beta")
	for i := 0; i < 3; i++ {
		if err, _ := openConsole(t, s, mallory, "spice"); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("mallory's channel %d: %v", i, err)
		}
	}
	n := 0
	for _, r := range consoleAuditRows(t, s) {
		if r.user == "mallory" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("mallory's three refused channels wrote %d rows, want 1", n)
	}
}

// GetSpiceInfo hands out the console's password, so it is a row of its own
// — saying whether a password went out, never what it was.
//
// Mutation "no row for GetSpiceInfo" — red.
func TestConsoleAudit_SpiceInfoIsACredentialRow(t *testing.T) {
	s := consoleAuditServer(t)
	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	resp, err := s.GetSpiceInfo(alice, &pb.GetSpiceInfoRequest{VmName: "desk"})
	if err != nil || resp.Password == "" {
		t.Fatalf("GetSpiceInfo as alice: %v (password %q)", err, resp.GetPassword())
	}
	mallory := boundAtCtx(t, s, "mallory", "operator", "Operator", "/projects/beta")
	if _, err := s.GetSpiceInfo(mallory, &pb.GetSpiceInfoRequest{VmName: "desk"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetSpiceInfo as mallory: %v, want PermissionDenied", err)
	}
	rows := consoleAuditRows(t, s)
	if len(rows) != 2 {
		t.Fatalf("want two rows, got %+v", rows)
	}
	for _, r := range rows {
		if strings.Contains(r.detail, resp.Password) {
			t.Fatalf("a row carries the SPICE password: %+v", r)
		}
		if r.action != "vm.console.credential" || r.target != "desk" || auditField(r.detail, "kind") != "spice" {
			t.Errorf("row = %+v", r)
		}
	}
	if r := rows[0]; r.user != "alice" || r.result != "ok" || auditField(r.detail, "password") != "yes" {
		t.Errorf("alice's row = %+v", r)
	}
	if r := rows[1]; r.user != "mallory" || r.result != "denied" {
		t.Errorf("mallory's row = %+v", r)
	}
}

// A SPICE client that closes every channel and opens another within the
// linger (a reconnect) is still one session.
//
// Mutation "close a grouped session as soon as its last channel ends" — red.
func TestConsoleAudit_SpiceRejoinWithinTheLingerIsTheSameSession(t *testing.T) {
	s := consoleAuditServer(t)
	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	// openConsole holds a stream 300ms before returning; the linger is
	// stretched so the rejoin lands well inside it.
	consoleSessionLinger = 2 * time.Second
	_, end := openConsole(t, s, alice, "spice")
	_ = end()
	_, end = openConsole(t, s, alice, "spice")
	_ = end()
	rows := waitRows(t, s, "no close row", func(r []consoleAuditRow) bool {
		return len(rowsWith(r, "vm.console.close", "spice")) > 0
	})
	time.Sleep(500 * time.Millisecond)
	rows = consoleAuditRows(t, s)
	open, closed := rowsWith(rows, "vm.console.open", "spice"), rowsWith(rows, "vm.console.close", "spice")
	if len(open) != 1 || len(closed) != 1 || auditField(closed[0].detail, "channels") != "2" {
		t.Fatalf("a rejoin within the linger: want one session of 2 channels, got\n%+v", rows)
	}
}

// A session cut because its user's session was revoked ran and was ended on
// purpose: its close row is ok, and says why it ended.
//
// Mutation "a cut is an error close" — red.
func TestConsoleAudit_ACutSessionClosesOkNamingTheCut(t *testing.T) {
	s, v := consoleServer(t)
	v.vnc = holdListener(t)
	s.virt = v
	token := login(t, s, "bob", "bob-pw").Token
	done, _ := runRealStream(t, s, token, "/litevirt.v1.LiteVirt/ProxyVNC", "web1", func(ss grpc.ServerStream) error {
		return s.ProxyVNC(&grpc.GenericServerStream[pb.VNCData, pb.VNCData]{ServerStream: ss})
	})
	waitRows(t, s, "no open row", func(r []consoleAuditRow) bool { return len(rowsWith(r, "vm.console.open", "vnc")) == 1 })
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: strings.TrimPrefix(token, SessionTokenPrefix)}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("VNC ended with %v, want Unauthenticated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the VNC session was not cut")
	}
	rows := waitRows(t, s, "no close row", func(r []consoleAuditRow) bool { return len(rowsWith(r, "vm.console.close", "vnc")) == 1 })
	c := rowsWith(rows, "vm.console.close", "vnc")[0]
	if c.result != "ok" || c.user != "bob" || auditField(c.detail, "ended") == "closed" || auditField(c.detail, "ended") == "" {
		t.Fatalf("close row of a cut session = %+v", c)
	}
}

// A graceful stop writes every open session's close row before it returns —
// the database closes right after (daemon.Run) — and a session the stop
// ended says so. Nothing is written after the flush.
//
// Mutation "FlushConsoleAudit writes nothing" — red.
// Mutation "MarkConsoleShutdown does nothing" — red (serial ended=closed).
func TestConsoleAudit_DaemonStopClosesEverySession(t *testing.T) {
	s := consoleAuditServer(t)
	consoleSessionLinger = time.Hour // the SPICE close would never come on its own
	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	_, endVNC := openConsole(t, s, alice, "vnc")
	_, endSerial := openConsole(t, s, alice, "serial")
	_, endSpice := openConsole(t, s, alice, "spice")
	_ = endSpice() // ended by its client, lingering

	s.MarkConsoleShutdown()
	_ = endSerial() // its handler returns during the stop
	s.FlushConsoleAudit()

	rows := consoleAuditRows(t, s)
	for kind, want := range map[string]string{"vnc": "daemon-stop", "serial": "daemon-stop", "spice": "closed"} {
		c := rowsWith(rows, "vm.console.close", kind)
		if len(c) != 1 || c[0].result != "ok" || auditField(c[0].detail, "ended") != want {
			t.Errorf("%s: close rows after the flush = %+v, want one, ended=%s", kind, c, want)
		}
	}
	_ = endVNC() // after the flush: nothing more
	time.Sleep(100 * time.Millisecond)
	if n := len(consoleAuditRows(t, s)); n != len(rows) {
		t.Errorf("%d rows written after the flush", n-len(rows))
	}
}

// Refusal rows are bounded: an echoed VM name is cut, a caller gets at most
// consoleRefusalBurst refusal rows per window, and the window ends with one
// row counting what was held back. The next window starts with a row again.
//
// Mutation "no per-caller budget" — red. Mutation "no truncation" — red.
// Mutation "no summary row" — red.
func TestConsoleAudit_RefusalsAreBoundedPerCaller(t *testing.T) {
	s := consoleAuditServer(t)
	oldW, oldB := consoleRefusalWindow, consoleRefusalBurst
	// A window that never ends on its own: the test ends it (no timing).
	consoleRefusalWindow, consoleRefusalBurst = time.Hour, 3
	t.Cleanup(func() { consoleRefusalWindow, consoleRefusalBurst = oldW, oldB })

	refuse := func(name string) {
		ctx := metadata.NewIncomingContext(userCtx("vic", "viewer"), metadata.Pairs("x-vm-name", name))
		ts := &transportStream{ctx: ctx, transport: make(chan struct{})}
		close(ts.transport)
		if err := s.ProxyVNC(&grpc.GenericServerStream[pb.VNCData, pb.VNCData]{ServerStream: ts}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a viewer's ProxyVNC: %v, want PermissionDenied", err)
		}
	}
	for i := 0; i < 8; i++ {
		refuse(strconv.Itoa(i) + strings.Repeat("x", 100<<10)) // distinct within the kept prefix
	}
	rows := consoleAuditRows(t, s)
	if len(rows) != 3 {
		t.Fatalf("8 refusals in one window wrote %d rows, want 3", len(rows))
	}
	for _, r := range rows {
		if len(r.target) > consoleAuditMaxTarget+32 || len(r.detail) > 1024 || !strings.Contains(r.target, "bytes)") {
			t.Fatalf("a refusal row is not bounded: target %d bytes, detail %d bytes", len(r.target), len(r.detail))
		}
	}
	s.consoleSessions.mu.Lock()
	w := s.consoleSessions.refusals["vic"]
	s.consoleSessions.mu.Unlock()
	if w == nil {
		t.Fatal("no refusal window for vic")
	}
	w.timer.Stop()
	s.endRefusalWindow("vic", w)
	rows = consoleAuditRows(t, s)
	if len(rows) != 4 {
		t.Fatalf("no summary row: %+v", rows)
	}
	sum := rows[3]
	if sum.action != "vm.console.suppressed" || sum.user != "vic" || sum.result != "denied" ||
		auditField(sum.detail, "suppressed") != "5" || auditField(sum.detail, "kinds") != "vnc" ||
		!strings.Contains(auditField(sum.detail, "vms"), "bytes)") || len(sum.detail) > 1024 {
		t.Fatalf("summary row = %+v", sum)
	}
	refuse("again")
	if rows := consoleAuditRows(t, s); len(rows) != 5 || rows[4].target != "again" {
		t.Fatalf("the first refusal of a new window was not written: %+v", rows)
	}
}

// The flush waits for a close row its handler is already writing: a session
// whose handler is mid-close when the stop begins has exactly one close row
// when FlushConsoleAudit returns, and nothing is written after it.
//
// Mutation "the flush does not wait for rows in flight" — red.
func TestConsoleAudit_FlushWaitsForACloseItsHandlerIsWriting(t *testing.T) {
	s := consoleAuditServer(t)
	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	_, end := openConsole(t, s, alice, "vnc")
	entered := make(chan struct{})
	var once sync.Once
	consoleCloseWriteHook = func() {
		once.Do(func() {
			close(entered)
			time.Sleep(300 * time.Millisecond) // the handler is mid-close
		})
	}
	t.Cleanup(func() { consoleCloseWriteHook = nil })

	s.MarkConsoleShutdown()
	ended := make(chan error, 1)
	go func() { ended <- end() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never began its close row")
	}
	s.FlushConsoleAudit()
	closes := rowsWith(consoleAuditRows(t, s), "vm.console.close", "vnc")
	if len(closes) != 1 || auditField(closes[0].detail, "ended") != "daemon-stop" {
		t.Fatalf("close rows when the flush returned = %+v, want exactly one, ended=daemon-stop", closes)
	}
	awaitEnd(t, ended)
	time.Sleep(200 * time.Millisecond)
	if n := len(rowsWith(consoleAuditRows(t, s), "vm.console.close", "vnc")); n != 1 {
		t.Fatalf("%d close rows after the flush, want still 1", n)
	}
}

// During the stop, a session that ends with an error keeps its error: only a
// plain or cancelled end reads as daemon-stop.
//
// Mutation "stopping outranks the error" — red.
func TestConsoleAudit_AnErrorDuringTheStopStaysAnError(t *testing.T) {
	s := consoleAuditServer(t)
	a := s.beginConsoleAudit(userCtx("alice", "admin"), consoleKindSerial, "desk")
	a.setOwner(s.hostName)
	a.accept(nil)
	s.MarkConsoleShutdown()
	a.end(status.Error(codes.Internal, "console error: boom"))
	c := rowsWith(consoleAuditRows(t, s), "vm.console.close", "serial")
	if len(c) != 1 || c[0].result != "error" || auditField(c[0].detail, "ended") != "console error: boom" {
		t.Fatalf("close rows = %+v, want one error row ended=\"console error: boom\"", c)
	}
}

// The stop wakes every console handler at once (grpc.Server.Stop cancels
// their streams), so the flush writes a running session's close while that
// session's handler is ending it. The close row is built from what the
// session was when the flush took it, under the registry lock — never from
// fields the handler is still writing. Run under -race: the hook makes the
// handler end between the flush's sweep and its write.
//
// Mutation "the close row reads the live session outside the lock" — DATA RACE.
func TestConsoleAudit_TheFlushDoesNotRaceAHandlerTheStopWoke(t *testing.T) {
	s := consoleAuditServer(t)
	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	_, end := openConsole(t, s, alice, "vnc")
	handlerDone := make(chan error, 1)
	var once sync.Once
	consoleCloseWriteHook = func() {
		once.Do(func() {
			go func() { handlerDone <- end() }()
			// No synchronisation with the handler: it ends on its own
			// while this write is under way, as after a real Stop.
			time.Sleep(200 * time.Millisecond)
		})
	}
	t.Cleanup(func() { consoleCloseWriteHook = nil })

	s.MarkConsoleShutdown()
	s.FlushConsoleAudit()
	awaitEnd(t, handlerDone)
	closes := rowsWith(consoleAuditRows(t, s), "vm.console.close", "vnc")
	if len(closes) != 1 || auditField(closes[0].detail, "ended") != "daemon-stop" {
		t.Fatalf("close rows = %+v, want exactly one, ended=daemon-stop", closes)
	}
}

// The flush is bounded: a close row a handler is stuck writing (a stalled
// database) holds it for consoleFlushTimeout, no longer. It then says so in
// the log and takes on no row after.
//
// Mutation "the flush waits for rows in flight without a deadline" — red.
func TestConsoleAudit_TheFlushGivesUpAtItsDeadline(t *testing.T) {
	s := consoleAuditServer(t)
	old := consoleFlushTimeout
	consoleFlushTimeout = 200 * time.Millisecond
	t.Cleanup(func() { consoleFlushTimeout = old })
	logs := &lockedLog{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	_, end := openConsole(t, s, alice, "vnc")
	entered := make(chan struct{})
	var once sync.Once
	consoleCloseWriteHook = func() {
		once.Do(func() {
			close(entered)
			time.Sleep(1500 * time.Millisecond) // the database is stalled
		})
	}
	t.Cleanup(func() { consoleCloseWriteHook = nil })
	ended := make(chan error, 1)
	go func() { ended <- end() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never began its close row")
	}

	start := time.Now()
	s.FlushConsoleAudit()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the flush took %s with a %s deadline", d, consoleFlushTimeout)
	}
	if !strings.Contains(logs.String(), "console audit flush timed out") || !strings.Contains(logs.String(), "rows=1") {
		t.Errorf("the flush did not log the row it gave up on:\n%s", logs.String())
	}
	s.consoleSessions.mu.Lock()
	claimed := s.consoleSessions.claimLocked()
	s.consoleSessions.mu.Unlock()
	if claimed {
		t.Error("a row was taken on after the flush")
	}
	awaitEnd(t, ended)
}

// lockedLog is a goroutine-safe log sink.
type lockedLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A session accepted after the flush's first sweep — a relay that got the
// VM host's header just after the stop — is still closed by the flush: it
// sweeps again before it lets nothing more be written.
//
// Mutation "the flush sweeps once" — red (an open row with no close).
func TestConsoleAudit_ASessionAcceptedDuringTheFlushIsClosedByIt(t *testing.T) {
	s := consoleAuditServer(t)
	alice := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
	// A VNC session whose close is being written keeps the flush waiting.
	_, end := openConsole(t, s, alice, "vnc")
	entered := make(chan struct{})
	var once sync.Once
	consoleCloseWriteHook = func() {
		once.Do(func() {
			close(entered)
			time.Sleep(400 * time.Millisecond)
		})
	}
	t.Cleanup(func() { consoleCloseWriteHook = nil })
	s.MarkConsoleShutdown()
	ended := make(chan error, 1)
	go func() { ended <- end() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never began its close row")
	}
	flushed := make(chan struct{})
	go func() { s.FlushConsoleAudit(); close(flushed) }()
	time.Sleep(100 * time.Millisecond) // the flush has swept and is waiting

	late := s.beginConsoleAudit(alice, consoleKindSerial, "desk")
	late.setOwner(s.hostName)
	late.accept(nil)
	select {
	case <-flushed:
	case <-time.After(10 * time.Second):
		t.Fatal("the flush did not return within 10s")
	}
	awaitEnd(t, ended)
	rows := consoleAuditRows(t, s)
	open, closes := rowsWith(rows, "vm.console.open", "serial"), rowsWith(rows, "vm.console.close", "serial")
	if len(open) != 1 || len(closes) != 1 || auditField(closes[0].detail, "ended") != "daemon-stop" {
		t.Fatalf("a session accepted during the flush: open %+v, close %+v; want one of each, ended=daemon-stop", open, closes)
	}
}
