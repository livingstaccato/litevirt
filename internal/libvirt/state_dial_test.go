package libvirt

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// A libvirtd that accepts a connection and never answers the handshake costs
// a reader's dial its timeout, not forever: the dial fails, and the caller
// falls back to its usual connection. go-libvirt bounds neither the
// handshake nor (its reader retries a timeout) a read deadline.
//
// Mutation: the handshake unbounded: the dial does not return: red.
func TestDialLibvirtBounded_AHandshakeThatIsNotAnsweredFails(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "libvirt-sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	acceptDone := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		<-acceptDone
		select {
		case c := <-accepted:
			c.Close()
		default:
		}
	})
	go func() {
		defer close(acceptDone)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c // held open, never answered
	}()

	type answer struct{ err error }
	ch := make(chan answer, 1)
	go func() {
		v, err := dialLibvirtBounded(sock, 200*time.Millisecond)
		if v != nil {
			_ = v.Disconnect()
		}
		ch <- answer{err}
	}()
	select {
	case a := <-ch:
		if a.err == nil {
			t.Fatal("a handshake libvirtd never answered succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dial did not return: the handshake is unbounded")
	}
}
