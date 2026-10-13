package rfb

import (
	"bytes"
	"crypto/des"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// qemuListener is a VNC server as QEMU runs one with a password: RFB 3.8,
// security type 2 only, and a DES challenge it checks itself. It is written
// from RFC 6143 independently of the code under test (its own key reversal),
// so the two cannot agree on a wrong answer.
func qemuListener(t *testing.T, conn net.Conn, password string) error {
	t.Helper()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return err
	}
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{1, 2}); err != nil { // one type: VNC auth
		return err
	}
	pick := make([]byte, 1)
	if _, err := io.ReadFull(conn, pick); err != nil {
		return err
	}
	if pick[0] != 2 {
		return errors.New("client did not pick VNC auth")
	}
	challenge := []byte("0123456789abcdef")
	if _, err := conn.Write(challenge); err != nil {
		return err
	}
	resp := make([]byte, 16)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	key := make([]byte, 8)
	copy(key, password)
	for i, b := range key {
		var r byte
		for j := 0; j < 8; j++ {
			if b&(1<<j) != 0 {
				r |= 0x80 >> j
			}
		}
		key[i] = r
	}
	c, _ := des.NewCipher(key)
	want := make([]byte, 16)
	c.Encrypt(want[:8], challenge[:8])
	c.Encrypt(want[8:], challenge[8:])
	if !bytes.Equal(resp, want) {
		reason := "Authentication failed"
		var b [8]byte
		binary.BigEndian.PutUint32(b[:4], 1)
		binary.BigEndian.PutUint32(b[4:], uint32(len(reason)))
		_, _ = conn.Write(append(b[:], reason...))
		return errors.New("wrong password")
	}
	_, err := conn.Write([]byte{0, 0, 0, 0})
	return err
}

func TestAuthenticate_AnswersTheChallenge(t *testing.T) {
	proxy, qemu := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- qemuListener(t, qemu, "Zq3xR8pA") }()
	if err := Authenticate(proxy, "Zq3xR8pA"); err != nil {
		t.Fatalf("Authenticate with the right password: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the listener refused: %v", err)
	}
}

func TestAuthenticate_WrongPasswordIsRefused(t *testing.T) {
	proxy, qemu := net.Pipe()
	go func() { _ = qemuListener(t, qemu, "Zq3xR8pA") }()
	err := Authenticate(proxy, "notright")
	if err == nil {
		t.Fatal("Authenticate with a wrong password succeeded")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
}

// viewer drives the client half of an RFB handshake at the given minor
// version against a server that should offer only security type None, and
// returns the types it was offered.
func viewer(conn net.Conn, minor int) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return nil, err
	}
	if string(ver) != "RFB 003.008\n" {
		return nil, errors.New("server version " + string(ver))
	}
	if _, err := conn.Write([]byte("RFB 003.00" + string(rune('0'+minor)) + "\n")); err != nil {
		return nil, err
	}
	if minor < 7 {
		var typ [4]byte
		if _, err := io.ReadFull(conn, typ[:]); err != nil {
			return nil, err
		}
		return []byte{byte(binary.BigEndian.Uint32(typ[:]))}, nil
	}
	n := make([]byte, 1)
	if _, err := io.ReadFull(conn, n); err != nil {
		return nil, err
	}
	types := make([]byte, n[0])
	if _, err := io.ReadFull(conn, types); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return nil, err
	}
	if minor >= 8 {
		var res [4]byte
		if _, err := io.ReadFull(conn, res[:]); err != nil {
			return nil, err
		}
		if binary.BigEndian.Uint32(res[:]) != 0 {
			return nil, errors.New("security result not OK")
		}
	}
	return types, nil
}

func TestServeNoAuth_EveryVersionGetsNone(t *testing.T) {
	for _, minor := range []int{3, 7, 8} {
		proxy, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- ServeNoAuth(proxy, nil) }()
		types, err := viewer(client, minor)
		if err != nil {
			t.Fatalf("3.%d viewer: %v", minor, err)
		}
		if !bytes.Equal(types, []byte{1}) {
			t.Errorf("3.%d viewer was offered %v, want only None (1)", minor, types)
		}
		if err := <-done; err != nil {
			t.Errorf("3.%d: ServeNoAuth: %v", minor, err)
		}
		proxy.Close()
		client.Close()
	}
}

func TestServeNoAuth_ViewerPickingAnotherTypeIsRefused(t *testing.T) {
	proxy, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeNoAuth(proxy, nil) }()
	go func() {
		ver := make([]byte, 12)
		_, _ = io.ReadFull(client, ver)
		_, _ = client.Write([]byte("RFB 003.008\n"))
		hdr := make([]byte, 2)
		_, _ = io.ReadFull(client, hdr)
		_, _ = client.Write([]byte{2})
		_, _ = io.Copy(io.Discard, client)
	}()
	if err := <-done; err == nil {
		t.Fatal("ServeNoAuth accepted a viewer that picked VNC auth, which it never offered")
	}
	client.Close()
}

// The backend (the proxy's authentication to the listener) runs only once the
// viewer has chosen None, and a refusal there reaches a 3.8 viewer as a failed
// security result, not a silently dropped connection.
//
// Mutation "authenticate before the viewer handshake" — red (ran too early).
// Mutation "ignore the backend's error" — red.
func TestServeNoAuth_BackendRunsAfterThePickAndItsRefusalIsReported(t *testing.T) {
	proxy, client := net.Pipe()
	defer client.Close()
	picked := make(chan struct{})
	var ranEarly bool
	done := make(chan error, 1)
	go func() {
		done <- ServeNoAuth(proxy, func() error {
			select {
			case <-picked:
			default:
				ranEarly = true
			}
			return ErrAuthFailed
		})
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	ver := make([]byte, 12)
	if _, err := io.ReadFull(client, ver); err != nil {
		t.Fatal(err)
	}
	_, _ = client.Write([]byte("RFB 003.008\n"))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	close(picked)
	_, _ = client.Write([]byte{1})
	var res [4]byte
	if _, err := io.ReadFull(client, res[:]); err != nil {
		t.Fatalf("no security result after a refused backend: %v", err)
	}
	if binary.BigEndian.Uint32(res[:]) == 0 {
		t.Fatal("the viewer was told OK although the listener refused")
	}
	go func() { _, _ = io.Copy(io.Discard, client) }()
	if err := <-done; !errors.Is(err, ErrAuthFailed) {
		t.Errorf("ServeNoAuth returned %v, want the backend's error", err)
	}
	if ranEarly {
		t.Error("the backend ran before the viewer had chosen a security type")
	}
}

// A listener with TLS or SASL configured gets an error that names the cause.
func TestAuthenticate_UnsupportedTypesAreNamed(t *testing.T) {
	proxy, qemu := net.Pipe()
	go func() {
		defer qemu.Close()
		_, _ = qemu.Write([]byte("RFB 003.008\n"))
		ver := make([]byte, 12)
		_, _ = io.ReadFull(qemu, ver)
		_, _ = qemu.Write([]byte{1, 19})
		_, _ = io.Copy(io.Discard, qemu)
	}()
	err := Authenticate(proxy, "x")
	if err == nil || !strings.Contains(err.Error(), "VeNCrypt (19)") || !strings.Contains(err.Error(), "vnc_tls") {
		t.Fatalf("err = %v, want it to name VeNCrypt and vnc_tls", err)
	}
}
