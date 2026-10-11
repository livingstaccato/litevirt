package nbd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type memDev []byte

func (m memDev) ReadAt(p []byte, off int64) (int, error) { return bytes.NewReader(m).ReadAt(p, off) }
func (m memDev) Size() int64                             { return int64(len(m)) }

// R2-I1: a restore session's export serves exactly one vetted client; the
// socket is gone the moment it is taken, and a refused client gets nothing.
func TestSinglePeer_OneVettedConnection(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nbd.sock")
	allow := make(chan bool, 4)
	s := &Server{ExportName: "backup", Dev: memDev(make([]byte, 4096)), SinglePeer: true,
		PeerCheck: func(net.Conn) error {
			if <-allow {
				return nil
			}
			return errors.New("not the session's qemu")
		}}
	if err := s.ListenUnix(sock); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(context.Background()) }()
	defer s.Stop()

	// A refused client: closed without a byte served; the socket stays.
	allow <- false
	c1, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c1.Read(make([]byte, 16)); n != 0 {
		t.Fatal("a refused client was served the handshake")
	}
	c1.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Fatal("the socket went away after a refused client")
	}

	// The vetted client is served, and the socket is unlinked at once.
	allow <- true
	c2, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c2.Read(make([]byte, 16)); n == 0 {
		t.Fatal("the vetted client was not served")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sock); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the socket still exists after the single peer was taken")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := net.Dial("unix", sock); err == nil {
		t.Fatal("a second client connected to a single-peer export")
	}
}
