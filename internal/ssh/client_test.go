package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestParseTarget_UserAndHost(t *testing.T) {
	tests := []struct {
		input    string
		wantUser string
		wantHost string
		wantPort string
	}{
		{"root@10.0.50.10", "root", "10.0.50.10", "22"},
		{"admin@myhost", "admin", "myhost", "22"},
		{"deploy@10.0.50.10:2222", "deploy", "10.0.50.10", "2222"},
		{"10.0.50.10", "root", "10.0.50.10", "22"},
		{"myhost", "root", "myhost", "22"},
		{"user@host:22", "user", "host", "22"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			user, host, port := parseTarget(tt.input)
			if user != tt.wantUser {
				t.Errorf("user = %s, want %s", user, tt.wantUser)
			}
			if host != tt.wantHost {
				t.Errorf("host = %s, want %s", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %s, want %s", port, tt.wantPort)
			}
		})
	}
}

func TestBytesReader_ReadAll(t *testing.T) {
	data := []byte("hello world")
	r := bytesReader(data)

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if string(out) != "hello world" {
		t.Errorf("got %q, want %q", string(out), "hello world")
	}
}

func TestBytesReader_ReadInChunks(t *testing.T) {
	data := []byte("abcdefghij") // 10 bytes
	r := bytesReader(data)

	buf := make([]byte, 3)
	var result []byte

	for {
		n, err := r.Read(buf)
		result = append(result, buf[:n]...)
		if err != nil {
			break
		}
	}

	if string(result) != "abcdefghij" {
		t.Errorf("got %q, want %q", string(result), "abcdefghij")
	}
}

func TestBytesReader_Empty(t *testing.T) {
	r := bytesReader([]byte{})

	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
	if err == nil {
		t.Error("expected EOF error for empty reader")
	}
}

func TestBytesReader_DoubleRead(t *testing.T) {
	r := bytesReader([]byte("abc"))

	buf := make([]byte, 10)
	n, _ := r.Read(buf)
	if string(buf[:n]) != "abc" {
		t.Errorf("first read: got %q", string(buf[:n]))
	}

	// Second read should return EOF
	n, err := r.Read(buf)
	if n != 0 || err == nil {
		t.Errorf("second read: n=%d, err=%v, expected 0 and EOF", n, err)
	}
}

// fd re-review 2 N2-m3: `lv host rm` dials a joining host, often one that
// died mid-add, to clean up after it. ssh.Dial has no handshake limit, so a
// host that accepts TCP and never sends a banner held the command for good.
// dialTimeout bounds the connect and the handshake together.
//
// Mutation: dial with ssh.Dial (no deadline) — the call does not return
// within the bound.
func TestDialTimeout_BoundsASilentHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accept, then say nothing
		}
	}()
	cfg := &gossh.ClientConfig{User: "root", HostKeyCallback: gossh.InsecureIgnoreHostKey()}
	done := make(chan error, 1)
	go func() {
		_, err := dialTimeout(ln.Addr().String(), cfg, 300*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a handshake with a silent server succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dial did not return within its bound")
	}
}

// NewClientTimeout goes through the bounded dial: with a key to offer, a
// silent server still returns within the bound.
//
// Mutation: NewClientTimeout dialling with ssh.Dial — no return in time.
func TestNewClientTimeout_BoundsASilentHandshake(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	done := make(chan error, 1)
	go func() {
		_, err := NewClientTimeout("root@"+ln.Addr().String(), 300*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a handshake with a silent server succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NewClientTimeout did not return within its bound")
	}
}
