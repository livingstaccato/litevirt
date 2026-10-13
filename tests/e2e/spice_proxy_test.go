package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// SPICE through litevirt against a real spice-server (docs/ui.md "SPICE
// Console"). The VM's SPICE listener is bound to its host's 127.0.0.1, so
// `lv spice --launch` and the UI's .vv used to point a client at the host's
// address and get "connection refused" (N2 in vnc-password-lab.md). The
// fleet tests prove ProxySpice relays bytes over libvirtfake; only a real
// QEMU can show that a SPICE link made through `lv spice --listen`, from a
// node other than the VM's host, reaches spice-server and that its ticket
// (the console password, RSA-OAEP-encrypted to the key spice-server sends)
// is checked there:
//
//  1. the right password: link result OK (0);
//  2. a wrong one: link refused (non-zero), so the relay adds no access.
//
// It skips on a FIPS-mode VM host (spice-server cannot make its RSA key;
// docs/ui.md) and when the console has no password in force.

const spiceLinkOK = 0

// spiceLink runs a SPICE main-channel link with password through addr (the
// legacy ticket path: no capabilities offered) and returns spice-server's
// link result.
func spiceLink(t *testing.T, addr, password string) uint32 {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ { // `lv spice --listen` may still be starting
		if conn, err = net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// SpiceLinkHeader {magic "REDQ", major 2, minor 2, size} + SpiceLinkMess
	// {connection_id 0, channel_type 1 (main), channel_id 0, 0 common caps,
	// 0 channel caps, caps_offset 18}, little-endian and packed.
	var mess bytes.Buffer
	_ = binary.Write(&mess, binary.LittleEndian, uint32(0))
	mess.Write([]byte{1, 0})
	_ = binary.Write(&mess, binary.LittleEndian, []uint32{0, 0, 18})
	var hdr bytes.Buffer
	hdr.WriteString("REDQ")
	_ = binary.Write(&hdr, binary.LittleEndian, []uint32{2, 2, uint32(mess.Len())})
	if _, err := conn.Write(append(hdr.Bytes(), mess.Bytes()...)); err != nil {
		t.Fatalf("send the SPICE link through %s: %v", addr, err)
	}

	rh := make([]byte, 16)
	if _, err := io.ReadFull(conn, rh); err != nil {
		t.Fatalf("no SPICE link reply through %s: %v (a FIPS host closes every link here)", addr, err)
	}
	if string(rh[:4]) != "REDQ" {
		t.Fatalf("through %s the reply is not SPICE: % x", addr, rh)
	}
	reply := make([]byte, binary.LittleEndian.Uint32(rh[12:16]))
	if _, err := io.ReadFull(conn, reply); err != nil || len(reply) < 4+162 {
		t.Fatalf("short SPICE link reply through %s: %d bytes, %v", addr, len(reply), err)
	}
	if code := binary.LittleEndian.Uint32(reply[:4]); code != spiceLinkOK {
		t.Fatalf("spice-server refused the link before the ticket: error %d", code)
	}
	pub, err := x509.ParsePKIXPublicKey(reply[4 : 4+162])
	if err != nil {
		t.Fatalf("parse spice-server's ticket key: %v", err)
	}
	rpub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("spice-server's ticket key is %T, want RSA", pub)
	}
	ticket, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rpub, append([]byte(password), 0), nil)
	if err != nil {
		t.Fatalf("encrypt the ticket: %v", err)
	}
	if _, err := conn.Write(ticket); err != nil {
		t.Fatalf("send the ticket: %v", err)
	}
	var res [4]byte
	if _, err := io.ReadFull(conn, res[:]); err != nil {
		t.Fatalf("no link result through %s: %v", addr, err)
	}
	return binary.LittleEndian.Uint32(res[:])
}

// listenSpice runs `lv spice <vm> --listen <addr>` until the test ends.
func listenSpice(t *testing.T, vm string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, lvBin, "spice", vm, "--listen", addr)
	cmd.Env = lvEnv()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("lv spice --listen: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("lv spice --listen output:\n%s", out.String())
		}
	})
	return addr
}

func TestVM_SpiceThroughLitevirt(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	requireImage(t)
	// Put the VM on a host other than this one when there is one, so the
	// SPICE stream really crosses hosts (entry daemon → the VM's daemon).
	host := ""
	for _, h := range hostNames {
		if h != localHost {
			host = h
			break
		}
	}
	if host == "" {
		host = hostWithCapacity(t, 1, 1024)
	}
	stack, vm := uniqueName("spx"), uniqueName("spv")
	cleanup(t, func() { lvErr(t, "compose", "down", "--name", stack, "-y") })
	y := fmt.Sprintf(`name: %s
vms:
  %s:
    image: %s
    cpu: 1
    memory: 1024
    disks:
      root:
        size: 5G
    graphics:
      vnc: true
      spice: true
    placement:
      host: %s
`, stack, vm, testImage, host)
	f := fmt.Sprintf("/tmp/e2e-spice-%d.yaml", os.Getpid())
	if err := os.WriteFile(f, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f) })
	lv(t, "compose", "up", "-f", f, "-y")
	waitVM(t, vm, "RUNNING", 2*time.Minute)

	// Poll the info call itself, not `lv inspect`: the entry host's own row
	// can still read "creating" for a moment after inspect (answered by the
	// VM's host) reports RUNNING, and GetSpiceInfo refuses until it does
	// not (lab-1 F1). The output carries the password: never log it whole.
	var info string
	deadline := time.Now().Add(60 * time.Second)
	for {
		out, err := lvErr(t, "spice", vm, "--show-password")
		if err == nil {
			info = out
			break
		}
		if time.Now().After(deadline) || !strings.Contains(out, "is not running") {
			// A failed info call printed no password, only its error.
			t.Fatalf("lv spice %s: %v\n%s", vm, err, out)
		}
		time.Sleep(time.Second)
	}
	password, shown := "", []string{}
	for _, line := range strings.Split(info, "\n") {
		if p, ok := strings.CutPrefix(line, "Password: "); ok {
			password = strings.TrimSpace(p)
			continue
		}
		shown = append(shown, line)
	}
	if strings.Contains(info, "Warning:") {
		t.Skipf("SPICE cannot connect on %s: %s", host, strings.Join(shown, "\n"))
	}
	if !strings.Contains(info, "bound to that host's 127.0.0.1") {
		t.Errorf("lv spice does not say where the listener is:\n%s", strings.Join(shown, "\n"))
	}
	if password == "" {
		t.Skip("the VM's SPICE console has no password: console passwords are not in force on this cluster")
	}

	addr := listenSpice(t, vm)
	if got := spiceLink(t, addr, password); got != spiceLinkOK {
		t.Fatalf("a SPICE link with the right password through lv spice --listen got result %d, want OK (0)", got)
	}
	if got := spiceLink(t, addr, password+"x"); got == spiceLinkOK {
		t.Fatal("a SPICE link with a WRONG password through lv spice --listen was accepted: the relay must add no access")
	}
}
