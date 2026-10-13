// Fleet scenarios: per-VM console passwords (docs/ui.md "Console passwords").
//
// A VM's VNC and SPICE consoles listen on the host's 127.0.0.1, which any
// local process or user on that host could reach. Each console now carries a
// per-VM password that only the daemon on the VM's own host presents: it
// authenticates to the listener and offers the viewer security type None, so
// the viewer — and every daemon relaying the stream to it — never sees it.
//
// What only a fleet can show:
//   - a viewer entering on ANOTHER host gets through, because the relay host
//     needs nothing and the owning host does the authentication;
//   - the password is set only once console_password_v1 has latched across
//     the cluster AND the defining host's flag is on — the latch is real
//     peer Pings over mTLS;
//   - a live migration keeps the console working: the password travels in
//     the migratable definition and the destination reads it from there;
//   - SPICE, whose stream ProxySpice relays unchanged (the client presents
//     the password), hands the password to a caller that passed vm.console,
//     through whichever host it entered on.
package fleet

import (
	"bytes"
	"context"
	"crypto/des"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// serverInit is what the fake listener sends once a viewer is through: a
// viewer that reads it got all the way past authentication.
var serverInit = []byte("fake-qemu-server-init")

// vncListener is a VM's VNC listener as QEMU runs one: RFB 3.8 on
// 127.0.0.1, security type 2 (VNC authentication) when it has a password and
// None when it has not, checked against the password the guest STARTED with.
type vncListener struct {
	ln       net.Listener
	password string

	mu      sync.Mutex
	refused int
}

func startVNCListener(t *testing.T, password string) *vncListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &vncListener{ln: ln, password: password}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go l.serve(conn)
		}
	}()
	return l
}

func (l *vncListener) port() int { return l.ln.Addr().(*net.TCPAddr).Port }

func (l *vncListener) refusals() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refused
}

func (l *vncListener) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return
	}
	sec := byte(1)
	if l.password != "" {
		sec = 2
	}
	if _, err := conn.Write([]byte{1, sec}); err != nil {
		return
	}
	pick := make([]byte, 1)
	if _, err := io.ReadFull(conn, pick); err != nil || pick[0] != sec {
		return
	}
	if sec == 2 {
		challenge := []byte("fleet-challenge!")
		if _, err := conn.Write(challenge); err != nil {
			return
		}
		resp := make([]byte, 16)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return
		}
		var key [8]byte
		copy(key[:], l.password)
		for i := range key {
			key[i] = bits.Reverse8(key[i])
		}
		c, _ := des.NewCipher(key[:])
		want := make([]byte, 16)
		c.Encrypt(want[:8], challenge[:8])
		c.Encrypt(want[8:], challenge[8:])
		if !bytes.Equal(resp, want) {
			l.mu.Lock()
			l.refused++
			l.mu.Unlock()
			_, _ = conn.Write([]byte{0, 0, 0, 1, 0, 0, 0, 0})
			return
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return
	}
	shared := make([]byte, 1) // ClientInit
	if _, err := io.ReadFull(conn, shared); err != nil {
		return
	}
	_, _ = conn.Write(serverInit)
	_, _ = io.Copy(io.Discard, conn)
}

// vncStreamReader reads the bytes of a ProxyVNC client stream.
type vncStreamReader struct {
	st  grpc.BidiStreamingClient[pb.VNCData, pb.VNCData]
	buf []byte
}

func (r *vncStreamReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		m, err := r.st.Recv()
		if err != nil {
			return 0, err
		}
		r.buf = m.Data
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// viewVNC is noVNC: it opens ProxyVNC for vm at entry and runs an RFB 3.8
// handshake with NO password. It returns the security types it was offered
// and, when None was among them, the ServerInit it then received.
func viewVNC(t *testing.T, c *Cluster, entry *Node, vm string) (offered []byte, init []byte, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", vm))
	st, err := c.SelfClient(entry).ProxyVNC(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = st.CloseSend() }()
	r := &vncStreamReader{st: st}
	send := func(b []byte) error { return st.Send(&pb.VNCData{Data: b}) }

	ver := make([]byte, 12)
	if _, err := io.ReadFull(r, ver); err != nil {
		return nil, nil, err
	}
	if err := send([]byte("RFB 003.008\n")); err != nil {
		return nil, nil, err
	}
	n := make([]byte, 1)
	if _, err := io.ReadFull(r, n); err != nil {
		return nil, nil, err
	}
	offered = make([]byte, n[0])
	if _, err := io.ReadFull(r, offered); err != nil {
		return nil, nil, err
	}
	if !bytes.Contains(offered, []byte{1}) {
		return offered, nil, nil // a password prompt: the viewer has nothing to answer it with
	}
	if err := send([]byte{1}); err != nil {
		return offered, nil, err
	}
	var res [4]byte
	if _, err := io.ReadFull(r, res[:]); err != nil {
		return offered, nil, err
	}
	if binary.BigEndian.Uint32(res[:]) != 0 {
		return offered, nil, errors.New("security result not OK")
	}
	if err := send([]byte{1}); err != nil { // ClientInit, shared
		return offered, nil, err
	}
	init = make([]byte, len(serverInit))
	if _, err := io.ReadFull(r, init); err != nil {
		return offered, nil, err
	}
	return offered, init, nil
}

// consoleCluster is two nodes with enforcement.console_password on and the
// console_password_v1 latch formed across both.
func consoleCluster(t *testing.T) *Cluster {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetConsolePassword(true)
	}
	latchConsolePassword(t, c)
	return c
}

func latchConsolePassword(t *testing.T, c *Cluster) {
	t.Helper()
	// A real gate, quorum held (a migration needs it), split_brain_gate_v1
	// latched — then console_password_v1 through the real Ping path.
	gates := enforceGate(t, c)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(context.Background(), capabilities.ConsolePasswordV1) {
			t.Fatalf("%s: console_password_v1 did not latch on a uniform build", n.Name)
		}
	}
}

func createConsoleVM(t *testing.T, c *Cluster, at *Node, name, host string, spice bool) {
	t.Helper()
	spec := &pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256, EnableSpice: spice,
		Placement: &pb.PlacementSpec{Host: host}}
	if _, err := c.SelfClient(at).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: spec}); err != nil {
		t.Fatalf("create %s on %s: %v", name, host, err)
	}
}

func consolePassword(t *testing.T, n *Node, vm, kind string) string {
	t.Helper()
	pw, err := n.Virt.ConsolePassword(vm, kind)
	if err != nil {
		t.Fatalf("%s: ConsolePassword(%s, %s): %v", n.Name, vm, kind, err)
	}
	return pw
}

// TestFleet_ConsolePassword_ViewerThroughAPeerNeverNeedsIt: the VM runs on
// owner, the viewer enters on relay. The listener demands the password; the
// viewer is offered None only and still reaches ServerInit, because owner
// authenticated for it.
//
// Mutation "ProxyVNC relays raw even with a password" — red (offered [2]).
// Mutation "no policy applied at define" — red (no password set).
func TestFleet_ConsolePassword_ViewerThroughAPeerNeverNeedsIt(t *testing.T) {
	c := consoleCluster(t)
	relay, owner := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, relay, "web", owner.Name, false)

	pw := consolePassword(t, owner, "web", "vnc")
	if len(pw) != lv.VNCPasswordLen {
		t.Fatalf("the VM's VNC console password is %q, want %d characters", pw, lv.VNCPasswordLen)
	}
	l := startVNCListener(t, pw)
	owner.Virt.SetVNCPort("web", l.port())

	offered, init, err := viewVNC(t, c, relay, "web")
	if err != nil {
		t.Fatalf("view the console through %s: %v", relay.Name, err)
	}
	if !bytes.Equal(offered, []byte{1}) {
		t.Fatalf("the viewer was offered security types %v, want only None: it would be asked for a password it cannot know", offered)
	}
	if !bytes.Equal(init, serverInit) {
		t.Fatalf("the viewer got %q after the handshake, want the listener's ServerInit", init)
	}
	if l.refusals() != 0 {
		t.Errorf("the listener refused %d authentication(s)", l.refusals())
	}
}

// TestFleet_ConsolePassword_NoneUntilLatchedAndOn: no password is set before
// console_password_v1 latches (an older peer could not present one), nor on a
// host whose flag is off. A console without one still works, relayed raw.
//
// Mutation "policy ignores the latch" — red on the first VM.
// Mutation "policy ignores the flag" — red on the second.
func TestFleet_ConsolePassword_NoneUntilLatchedAndOn(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	relay, owner := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetConsolePassword(true)
	}

	// Flag on, nothing latched.
	createConsoleVM(t, c, relay, "early", owner.Name, false)
	if pw := consolePassword(t, owner, "early", "vnc"); pw != "" {
		t.Fatalf("a console password was set before console_password_v1 latched (%d chars)", len(pw))
	}

	// Latched, but the defining host's flag is off.
	latchConsolePassword(t, c)
	owner.Server.SetConsolePassword(false)
	createConsoleVM(t, c, relay, "optout", owner.Name, false)
	if pw := consolePassword(t, owner, "optout", "vnc"); pw != "" {
		t.Fatalf("a console password was set on a host whose enforcement.console_password is off (%d chars)", len(pw))
	}

	// A console without a password is relayed exactly as before.
	l := startVNCListener(t, "")
	owner.Virt.SetVNCPort("optout", l.port())
	offered, init, err := viewVNC(t, c, relay, "optout")
	if err != nil || !bytes.Equal(offered, []byte{1}) || !bytes.Equal(init, serverInit) {
		t.Fatalf("a console with no password: offered %v, init %q, err %v; want it relayed as before", offered, init, err)
	}
}

// TestFleet_ConsolePassword_LiveMigrationKeepsTheConsole: the guest keeps
// the password it started with across a live migration — libvirt hands the
// destination the secure migratable XML — and the destination's daemon reads
// it from the running domain, so the console still opens, through the
// source (now only a relay) too. A redefine on the destination while the
// guest runs gives the NEXT start a new password and leaves the console alone.
func TestFleet_ConsolePassword_LiveMigrationKeepsTheConsole(t *testing.T) {
	c := consoleCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, src, "web", src.Name, false)
	pw := consolePassword(t, src, "web", "vnc")
	if pw == "" {
		t.Fatal("fixture: the VM has no console password")
	}
	l := startVNCListener(t, pw) // the QEMU process, which migrates with its password

	// As libvirt's live migration does: the destination gets the secure
	// migratable definition as it is (no define of ours runs there), and the
	// source domain is gone (VIR_MIGRATE_UNDEFINE_SOURCE).
	src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
		x, err := src.Virt.DumpXMLSecure(name)
		if err != nil {
			return err
		}
		dst.Virt.LandMigrated(x)
		return src.Virt.UndefineDomain(name, false)
	}
	if err := migrateAt(t, c, src, "web", dst.Name); err != nil {
		t.Fatalf("live migrate: %v", err)
	}
	if got := consolePassword(t, dst, "web", "vnc"); got != pw {
		t.Fatalf("after the migration the destination reads console password %q, want the one the guest started with", got)
	}
	dst.Virt.SetVNCPort("web", l.port())

	// A redefine while the guest runs (an update applied at next start).
	x, err := dst.Virt.DumpXMLInactive("web")
	if err != nil {
		t.Fatal(err)
	}
	if err := dst.Virt.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	if got := consolePassword(t, dst, "web", "vnc"); got != pw {
		t.Fatalf("a redefine of the running guest changed the password the console proxy presents (%q -> %q)", pw, got)
	}

	for _, entry := range []*Node{src, dst} {
		offered, init, err := viewVNC(t, c, entry, "web")
		if err != nil || !bytes.Equal(offered, []byte{1}) || !bytes.Equal(init, serverInit) {
			t.Errorf("console via %s after the migration: offered %v, init %q, err %v", entry.Name, offered, init, err)
		}
	}
	if l.refusals() != 0 {
		t.Errorf("the listener refused %d authentication(s) after the migration", l.refusals())
	}
}

// TestFleet_ConsolePassword_SpiceInfoCarriesItAcrossHosts: SPICE is relayed
// unchanged, so GetSpiceInfo hands the password to the caller (who passed
// vm.console), forwarded from the owning host through whichever host the
// caller entered on.
//
// Mutation "GetSpiceInfo omits the password" — red.
func TestFleet_ConsolePassword_SpiceInfoCarriesItAcrossHosts(t *testing.T) {
	c := consoleCluster(t)
	relay, owner := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, relay, "desk", owner.Name, true)
	pw := consolePassword(t, owner, "desk", "spice")
	if len(pw) != lv.SPICEPasswordLen {
		t.Fatalf("the VM's SPICE password is %d characters, want %d", len(pw), lv.SPICEPasswordLen)
	}
	resp, err := c.SelfClient(relay).GetSpiceInfo(context.Background(), &pb.GetSpiceInfoRequest{VmName: "desk"})
	if err != nil {
		t.Fatalf("GetSpiceInfo via %s: %v", relay.Name, err)
	}
	if resp.GetPassword() != pw {
		t.Fatalf("GetSpiceInfo via %s returned a password of %d chars that is not the console's", relay.Name, len(resp.GetPassword()))
	}
	if vnc := consolePassword(t, owner, "desk", "vnc"); vnc == "" || vnc == pw[:lv.VNCPasswordLen] {
		t.Errorf("the VNC and SPICE consoles must have independent passwords")
	}
}
