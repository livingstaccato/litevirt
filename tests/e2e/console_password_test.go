package e2e

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Console passwords against real libvirt and QEMU (docs/ui.md "Console
// passwords"). The fleet tests run on internal/libvirtfake, which cannot show
// that libvirt keeps the password out of an ordinary dump, that QEMU really
// asks for it, or that a live migration carries it. This does, on a cluster
// node (virsh and the guest's 127.0.0.1 listener must be local):
//
//  1. an ordinary `virsh dumpxml` has no passwd; `--security-info` has an
//     8-character one;
//  2. a raw RFB connection to the listener is offered VNC authentication
//     (type 2) only — no password, no way in;
//  3. `lv vnc --listen` (ProxyVNC, the web UI's path) reaches ServerInit with
//     no password;
//  4. after a live migration away and back, the password is unchanged and the
//     console still opens — through another host while the guest is away.
//
// It skips, rather than fails, when the cluster has no console passwords in
// force (console_password_v1 not latched, or the flag off on this host).

var reVNCPasswd = regexp.MustCompile(`<graphics type='vnc'[^>]*passwd='([^']*)'`)

func virshDump(t *testing.T, domain string, secure bool) string {
	t.Helper()
	args := []string{"-c", "qemu:///system", "dumpxml", domain}
	if secure {
		args = append(args, "--security-info")
	}
	out, err := exec.Command("virsh", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// vncLocalPort is the domain's VNC port on this host's 127.0.0.1.
func vncLocalPort(t *testing.T, domain string) int {
	t.Helper()
	out, err := exec.Command("virsh", "-c", "qemu:///system", "vncdisplay", domain).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh vncdisplay %s: %v\n%s", domain, err, out)
	}
	s := strings.TrimSpace(string(out))
	_, disp, ok := strings.Cut(s, ":")
	n, cerr := strconv.Atoi(disp)
	if !ok || cerr != nil {
		t.Fatalf("parse vncdisplay %q", s)
	}
	return 5900 + n
}

// rfbOffered connects to addr as a VNC viewer and returns the security types
// it is offered (RFB 3.8).
func rfbOffered(t *testing.T, addr string) (net.Conn, []byte) {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ { // `lv vnc --listen` may still be starting
		if conn, err = net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect %s: %v", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		t.Fatalf("read RFB version from %s: %v", addr, err)
	}
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatal(err)
	}
	n := make([]byte, 1)
	if _, err := io.ReadFull(conn, n); err != nil {
		t.Fatalf("read security types from %s: %v", addr, err)
	}
	types := make([]byte, n[0])
	if _, err := io.ReadFull(conn, types); err != nil {
		t.Fatal(err)
	}
	return conn, types
}

// viewWithoutPassword completes the handshake through addr with None and
// returns the ServerInit name.
func viewWithoutPassword(t *testing.T, addr string) string {
	t.Helper()
	conn, types := rfbOffered(t, addr)
	defer conn.Close()
	if !bytes.Equal(types, []byte{1}) {
		t.Fatalf("through %s the viewer was offered %v, want only None (1)", addr, types)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var res [4]byte
	if _, err := io.ReadFull(conn, res[:]); err != nil || binary.BigEndian.Uint32(res[:]) != 0 {
		t.Fatalf("security result through %s: %v %v", addr, res, err)
	}
	if _, err := conn.Write([]byte{1}); err != nil { // ClientInit, shared
		t.Fatal(err)
	}
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("no ServerInit through %s: %v", addr, err)
	}
	name := make([]byte, binary.BigEndian.Uint32(hdr[20:24]))
	if _, err := io.ReadFull(conn, name); err != nil {
		t.Fatal(err)
	}
	return string(name)
}

// listenVNC runs `lv vnc <vm> --listen <addr>` until the test ends.
func listenVNC(t *testing.T, vm string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, lvBin, "vnc", vm, "--listen", addr)
	cmd.Env = lvEnv()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("lv vnc --listen: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("lv vnc --listen output:\n%s", out.String())
		}
	})
	return addr
}

func TestVM_ConsolePassword(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	if !virshAvailable() {
		t.Skip("needs virsh and the guest's 127.0.0.1 listener: run on a cluster node")
	}
	requireHosts(t, 2)
	requireImage(t)
	name := uniqueName("vncpw")
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })
	var other string
	for _, h := range hostNames {
		if h != localHost {
			other = h
			break
		}
	}
	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", "1024", "--disk", "5G", "--host", localHost)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	// 1. The password is in the definition, and only in a secure dump.
	m := reVNCPasswd.FindStringSubmatch(virshDump(t, name, true))
	if m == nil {
		t.Skip("the VM's VNC console has no password: console passwords are not in force on this cluster " +
			"(console_password_v1 not latched, or enforcement.console_password off on " + localHost + ")")
	}
	pw := m[1]
	if len(pw) != 8 {
		t.Errorf("VNC password is %d characters, want 8", len(pw))
	}
	if strings.Contains(virshDump(t, name, false), "passwd=") {
		t.Error("an ordinary virsh dumpxml shows the console password")
	}
	if out, _ := exec.Command("pgrep", "-af", "guest="+name).Output(); strings.Contains(string(out), pw) {
		t.Error("the console password is on QEMU's command line")
	}

	// 2. Direct to the listener: VNC authentication only.
	port := vncLocalPort(t, name)
	conn, types := rfbOffered(t, fmt.Sprintf("127.0.0.1:%d", port))
	conn.Close()
	if !bytes.Equal(types, []byte{2}) {
		t.Fatalf("a direct connection to 127.0.0.1:%d was offered %v, want VNC authentication (2) only", port, types)
	}

	// 3. Through litevirt: no password, all the way to ServerInit.
	if init := viewWithoutPassword(t, listenVNC(t, name)); init == "" {
		t.Error("ServerInit through lv vnc --listen carried no desktop name")
	}

	// 4. Live migration away: the console still opens (now through this
	// host, which only relays), and back: the password is unchanged.
	lv(t, "migrate", name, other, "--with-storage")
	waitVM(t, name, "RUNNING", 3*time.Minute)
	if out := lv(t, "inspect", name); !strings.Contains(out, other) {
		t.Fatalf("VM not on %s after the migration", other)
	}
	viewWithoutPassword(t, listenVNC(t, name))
	lv(t, "migrate", name, localHost, "--with-storage")
	waitVM(t, name, "RUNNING", 3*time.Minute)
	m = reVNCPasswd.FindStringSubmatch(virshDump(t, name, true))
	if m == nil {
		t.Fatalf("after migrating away and back the VNC password went")
	}
	if m[1] != pw {
		t.Fatalf("after migrating away and back the VNC password changed")
	}
	conn, types = rfbOffered(t, fmt.Sprintf("127.0.0.1:%d", vncLocalPort(t, name)))
	conn.Close()
	if !bytes.Equal(types, []byte{2}) {
		t.Errorf("after the migrations a direct connection was offered %v, want 2 only", types)
	}
	viewWithoutPassword(t, listenVNC(t, name))
}
