// Fleet scenario: console sessions relayed through another host are audited
// (docs/audit-log.md "Console sessions").
//
// A user's console for a VM on another host enters on one daemon and is
// carried to the VM's host over peer mTLS. The entry host is the only one
// that authenticated the user, so ITS row names the user; the VM's host
// records the session too, on its own sub-chain, but under the relaying
// peer — never a user it only has the peer's word for, and never the
// peer's "admin" principal.
package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type consoleRow struct {
	user, host, action, target, detail, result string
}

func consoleRows(t *testing.T, n *Node) []consoleRow {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT username, host_name, action, target, detail, result FROM audit_log
		 WHERE action LIKE 'vm.console.%' ORDER BY host_name, seq`)
	if err != nil {
		t.Fatalf("read audit_log on %s: %v", n.Name, err)
	}
	var out []consoleRow
	for _, r := range rows {
		out = append(out, consoleRow{r.String("username"), r.String("host_name"), r.String("action"),
			r.String("target"), r.String("detail"), r.String("result")})
	}
	return out
}

func rowField(detail, key string) string {
	m := regexp.MustCompile(`(?:^| )` + regexp.QuoteMeta(key) + `=("(?:[^"\\]|\\.)*"|\S*)`).FindStringSubmatch(detail)
	if m == nil {
		return ""
	}
	if v, err := strconv.Unquote(m[1]); err == nil {
		return v
	}
	return m[1]
}

// sessionRows is host's open and close rows for console kind.
func sessionRows(rows []consoleRow, host, kind string) (open, closed []consoleRow) {
	for _, r := range rows {
		if r.host != host || rowField(r.detail, "kind") != kind {
			continue
		}
		switch r.action {
		case "vm.console.open":
			open = append(open, r)
		case "vm.console.close":
			closed = append(closed, r)
		}
	}
	return open, closed
}

// TestFleet_ConsoleAudit_ARelayedSessionIsAuditedAsTheUserOnTheEntryHost:
// bob logs in on relay and, through it, opens a SPICE console (three
// channels), a VNC console and a serial console for a VM on owner, and asks
// for the SPICE connection info.
//
//   - relay's rows: one open and one close per console, as bob, naming relay
//     as the entry and owner as the VM's host; one credential row.
//   - owner's rows: the same sessions, as "peer:<relay>", with the entry's
//     session id — never as bob or as admin.
//   - no row anywhere carries bob's token, his session id or a console
//     password.
//
// Mutation "no row on a forward (entry host)" — red.
// Mutation "owner rows under callerUsername" — red (admin).
func TestFleet_ConsoleAudit_ARelayedSessionIsAuditedAsTheUserOnTheEntryHost(t *testing.T) {
	c := consoleCluster(t)
	relay, owner := c.Nodes[0], c.Nodes[1]
	signNode(t, relay)
	signNode(t, owner)
	createConsoleVM(t, c, relay, "desk", owner.Name, true)
	sl := startSpiceListener(t)
	owner.Virt.SetSpicePort("desk", sl.port())
	relay.Virt.SetSpicePort("desk", 1)
	vncPW := consolePassword(t, owner, "desk", "vnc")
	spicePW := consolePassword(t, owner, "desk", "spice")
	vl := startVNCListener(t, vncPW)
	owner.Virt.SetVNCPort("desk", vl.port())
	fifo := filepath.Join(t.TempDir(), "console")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	owner.Virt.SetConsolePTYPath("desk", fifo)

	ctx := context.Background()
	admin := c.SelfClient(relay)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "bob", Password: "bobs-password-0123456789", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	login, err := admin.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bobs-password-0123456789"})
	if err != nil {
		t.Fatalf("bob's login on %s: %v", relay.Name, err)
	}
	bob := c.bearerClient(relay, login.Token)

	// SPICE: three channels open at once, then all close.
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var chans []interface{ CloseSend() error }
	for i := 0; i < 3; i++ {
		st, err := bob.ProxySpice(metadata.NewOutgoingContext(sctx, metadata.Pairs("x-vm-name", "desk")))
		if err != nil {
			t.Fatalf("ProxySpice as bob: %v", err)
		}
		greet := make([]byte, len(spiceGreeting))
		if _, err := io.ReadFull(&spiceStreamReader{st: st}, greet); err != nil {
			t.Fatalf("bob's SPICE channel %d: %v", i, err)
		}
		chans = append(chans, st)
	}
	for _, st := range chans {
		_ = st.CloseSend()
	}

	// VNC.
	if _, init, err := viewVNCVia(t, bob, "desk"); err != nil || len(init) == 0 {
		t.Fatalf("bob's VNC console through %s: init %q, %v", relay.Name, init, err)
	}

	// Serial: what is typed comes back through the FIFO.
	cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
	con, err := bob.ConsoleVM(metadata.NewOutgoingContext(cctx, metadata.Pairs("x-vm-name", "desk")))
	if err != nil {
		t.Fatalf("ConsoleVM as bob: %v", err)
	}
	if err := con.Send(&pb.ConsoleInput{Data: []byte("hello\n")}); err != nil {
		t.Fatalf("serial send: %v", err)
	}
	var got []byte
	for !strings.Contains(string(got), "hello") {
		m, err := con.Recv()
		if err != nil {
			t.Fatalf("serial echo: %v (so far %q)", err, got)
		}
		got = append(got, m.Data...)
	}
	_ = con.CloseSend()
	ccancel()

	// The SPICE info, which hands out the password.
	if _, err := bob.GetSpiceInfo(ctx, &pb.GetSpiceInfoRequest{VmName: "desk"}); err != nil {
		t.Fatalf("GetSpiceInfo as bob: %v", err)
	}

	var rows []consoleRow
	eventually(t, 15*time.Second, "an open and a close row per console on both hosts", func() bool {
		rows = consoleRows(t, relay)
		for _, kind := range []string{"spice", "vnc", "serial"} {
			for _, h := range []*Node{relay, owner} {
				o, cl := sessionRows(rows, h.Name, kind)
				if len(o) == 0 || len(cl) == 0 {
					return false
				}
			}
		}
		return true
	})
	// Give a straggling duplicate (an ungrouped SPICE channel) time to land.
	time.Sleep(3 * time.Second)
	rows = consoleRows(t, relay)

	for _, kind := range []string{"spice", "vnc", "serial"} {
		open, closed := sessionRows(rows, relay.Name, kind)
		if len(open) != 1 || len(closed) != 1 {
			t.Errorf("%s on %s: %d open and %d close rows, want one of each:\n%+v", kind, relay.Name, len(open), len(closed), rows)
			continue
		}
		entrySession := rowField(open[0].detail, "session")
		for _, r := range []consoleRow{open[0], closed[0]} {
			if r.user != "bob" || r.target != "desk" || r.result != "ok" ||
				rowField(r.detail, "entry") != relay.Name || rowField(r.detail, "owner") != owner.Name ||
				rowField(r.detail, "session") != entrySession {
				t.Errorf("%s: entry row = %+v", kind, r)
			}
		}
		if kind == "spice" && rowField(closed[0].detail, "channels") != "3" {
			t.Errorf("spice: entry close row channels = %q, want 3: %q", rowField(closed[0].detail, "channels"), closed[0].detail)
		}

		oOpen, oClosed := sessionRows(rows, owner.Name, kind)
		if len(oOpen) != 1 || len(oClosed) != 1 {
			t.Errorf("%s on %s: %d open and %d close rows, want one of each:\n%+v", kind, owner.Name, len(oOpen), len(oClosed), rows)
			continue
		}
		for _, r := range []consoleRow{oOpen[0], oClosed[0]} {
			if r.user != "peer:"+relay.Name || rowField(r.detail, "via_peer") != relay.Name ||
				rowField(r.detail, "entry") != relay.Name || rowField(r.detail, "owner") != owner.Name ||
				rowField(r.detail, "entry_session") != entrySession {
				t.Errorf("%s: owner row = %+v (entry session %s)", kind, r, entrySession)
			}
		}
	}

	var cred []consoleRow
	for _, r := range rows {
		if r.action == "vm.console.credential" {
			cred = append(cred, r)
		}
	}
	if len(cred) != 2 {
		t.Errorf("credential rows = %+v, want one on each host", cred)
	}
	// The two credential rows are joined: the owner's names the entry's id.
	var entryReq, ownerReq string
	for _, r := range cred {
		if r.host == relay.Name {
			entryReq = rowField(r.detail, "session")
		} else {
			ownerReq = rowField(r.detail, "entry_session")
		}
	}
	if entryReq == "" || ownerReq != entryReq {
		t.Errorf("credential rows not joined: entry session %q, owner entry_session %q", entryReq, ownerReq)
	}
	for _, r := range cred {
		want := "bob"
		if r.host == owner.Name {
			want = "peer:" + relay.Name
		}
		if r.user != want || rowField(r.detail, "password") != "yes" {
			t.Errorf("credential row on %s = %+v", r.host, r)
		}
	}

	sid := strings.TrimPrefix(login.Token, "lvs_")
	for _, r := range rows {
		if r.host == owner.Name && (r.user == "bob" || r.user == "admin") {
			t.Errorf("owner wrote a row under %q, an identity it did not authenticate: %+v", r.user, r)
		}
		for _, secret := range []string{login.Token, sid, vncPW, spicePW} {
			if secret != "" && strings.Contains(r.user+r.target+r.detail, secret) {
				t.Errorf("a console row carries a secret: %+v", r)
			}
		}
	}
	_ = os.Remove(fifo)

	// Signed, and the chain verifies, on both hosts' sub-chains.
	if n := rowCount(t, relay, `SELECT count(*) AS n FROM audit_log
		WHERE action LIKE 'vm.console.%' AND (signature IS NULL OR signature = '')`); n != 0 {
		t.Errorf("%d console rows are unsigned", n)
	}
	if res := verifyOn(t, relay); res.BrokenAt != "" || len(res.BadSignature) != 0 || len(res.SeqGaps) != 0 || len(res.UnsignedAfterSigned) != 0 {
		t.Errorf("the audit chain does not verify: %+v", res)
	}
}

// openRelayed opens kind's console stream for vm as client and returns the
// error the stream ends with (nil when it is still open after 2s).
func openRelayed(t *testing.T, client pb.LiteVirtClient, kind, vm string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-vm-name", vm)), 2*time.Second)
	defer cancel()
	var recv func() error
	switch kind {
	case "vnc":
		st, err := client.ProxyVNC(ctx)
		if err != nil {
			return err
		}
		recv = func() error { _, err := st.Recv(); return err }
	case "spice":
		st, err := client.ProxySpice(ctx)
		if err != nil {
			return err
		}
		recv = func() error { _, err := st.Recv(); return err }
	case "serial":
		st, err := client.ConsoleVM(ctx)
		if err != nil {
			return err
		}
		recv = func() error { _, err := st.Recv(); return err }
	}
	for {
		if err := recv(); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

// noHeaderStream is a VM host on an older build: it sends no accept header,
// so its header goes with its first message.
type noHeaderStream struct{ grpc.ServerStream }

func (noHeaderStream) SendHeader(metadata.MD) error { return nil }

// TestFleet_ConsoleAudit_ARelayTheVMHostRefusedIsARefusalOnTheEntryHost: a
// console entering on relay for a VM on owner is a session on relay only
// once owner has accepted it. Refused on owner — by its handler, by its
// interceptor (a rejected forwarded bearer), or unreachable — it is one
// refusal row on relay, never an open ok and a close. An older owner, which
// sends no accept header, still gives a session (its header comes with its
// first message).
//
// Mutation "a relay accepts when the peer client is obtained" — red.
func TestFleet_ConsoleAudit_ARelayTheVMHostRefusedIsARefusalOnTheEntryHost(t *testing.T) {
	c := consoleCluster(t)
	relay, owner := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, relay, "desk", owner.Name, true)
	owner.Virt.SetConsolePTYPath("desk", filepath.Join(t.TempDir(), "no-such-pty"))
	vl := startVNCListener(t, consolePassword(t, owner, "desk", "vnc"))
	owner.Virt.SetVNCPort("desk", vl.port())
	ctx := context.Background()
	admin := c.SelfClient(relay)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "bob", Password: "bobs-password-0123456789", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	login, err := admin.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bobs-password-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	bob := c.bearerClient(relay, login.Token)

	// The VM's host's handler refuses (no PTY).
	if err := openRelayed(t, bob, "serial", "desk"); err == nil {
		t.Fatal("a serial console with no PTY on the VM's host was not refused")
	}
	// The VM's host's interceptor refuses, as it does a revoked forwarded bearer.
	owner.HookStream("ProxyVNC", func(any, grpc.ServerStream, grpc.StreamHandler) error {
		return status.Error(codes.Unauthenticated, "forwarded identity: session revoked")
	})
	if err := openRelayed(t, bob, "vnc", "desk"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a relayed VNC the VM's host refused: %v, want Unauthenticated", err)
	}
	// The VM's host unreachable.
	owner.HookStream("ProxySpice", func(any, grpc.ServerStream, grpc.StreamHandler) error {
		return status.Error(codes.Unavailable, "connection refused")
	})
	if err := openRelayed(t, bob, "spice", "desk"); status.Code(err) != codes.Unavailable {
		t.Fatalf("a relayed SPICE to an unreachable host: %v, want Unavailable", err)
	}

	var rows []consoleRow
	eventually(t, 10*time.Second, "a refusal row per console on relay", func() bool {
		rows = consoleRows(t, relay)
		n := 0
		for _, r := range rows {
			if r.host == relay.Name && r.action == "vm.console.open" && r.result != "ok" {
				n++
			}
		}
		return n == 3
	})
	time.Sleep(500 * time.Millisecond)
	rows = consoleRows(t, relay)
	want := map[string]string{"serial": "error", "vnc": "denied", "spice": "error"}
	for kind, result := range want {
		open, closed := sessionRows(rows, relay.Name, kind)
		if len(open) != 1 || len(closed) != 0 || open[0].result != result || open[0].user != "bob" {
			t.Errorf("%s on %s: open %+v, close %+v; want one open %s row and no close", kind, relay.Name, open, closed, result)
		}
	}
	if o, _ := sessionRows(rows, owner.Name, "serial"); len(o) != 1 || o[0].result != "error" || o[0].user != "peer:"+relay.Name {
		t.Errorf("serial on %s: %+v, want one open error row under peer:%s", owner.Name, o, relay.Name)
	}

	// An older VM host: no accept header. Its header comes with its first
	// message (the RFB greeting), and the session is open on relay from then
	// — while it runs, not only once it has ended.
	owner.HookStream("ProxyVNC", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		return h(srv, noHeaderStream{ss})
	})
	vctx, vcancel := context.WithTimeout(metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", "desk")), 15*time.Second)
	defer vcancel()
	st, err := bob.ProxyVNC(vctx)
	if err != nil {
		t.Fatalf("ProxyVNC through an older VM host: %v", err)
	}
	ver := make([]byte, 12)
	if _, err := io.ReadFull(&vncStreamReader{st: st}, ver); err != nil {
		t.Fatalf("the RFB greeting through an older VM host: %v", err)
	}
	eventually(t, 10*time.Second, "an open ok row on relay while the VNC session through the older host runs", func() bool {
		open, _ := sessionRows(consoleRows(t, relay), relay.Name, "vnc")
		for _, r := range open {
			if r.result == "ok" {
				return true
			}
		}
		return false
	})
	_ = st.CloseSend()
	vcancel()
}
