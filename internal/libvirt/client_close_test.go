package libvirt

import (
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// libvirt's remote protocol procedures the handshake uses
// (REMOTE_PROC_CONNECT_OPEN, REMOTE_PROC_AUTH_LIST).
const (
	procConnectOpen = 1
	procAuthList    = 66
)

// silentLibvirtd is a libvirtd on a unix socket that answers a client's
// handshake (auth-list, connect-open) and nothing after it: every later
// request is read and never answered, as libvirtd does to a connection
// whose max_client_requests calls it does not answer. ConnectClose among
// them.
func silentLibvirtd(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "libvirt-sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveHandshakeOnly(c)
			}()
		}
	}()
	return sock
}

// serveHandshakeOnly answers auth-list (no auth) and connect-open, and reads
// every other request without answering it.
func serveHandshakeOnly(c net.Conn) {
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n < 28 || n > 1<<20 {
			return
		}
		pkt := make([]byte, n-4)
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		prog := binary.BigEndian.Uint32(pkt[0:4])
		vers := binary.BigEndian.Uint32(pkt[4:8])
		proc := binary.BigEndian.Uint32(pkt[8:12])
		serial := binary.BigEndian.Uint32(pkt[16:20])
		var payload []byte
		switch proc {
		case procAuthList:
			payload = []byte{0, 0, 0, 1, 0, 0, 0, 0} // one entry: no auth
		case procConnectOpen:
		default:
			continue // never answered
		}
		reply := make([]byte, 28+len(payload))
		binary.BigEndian.PutUint32(reply[0:4], uint32(len(reply)))
		binary.BigEndian.PutUint32(reply[4:8], prog)
		binary.BigEndian.PutUint32(reply[8:12], vers)
		binary.BigEndian.PutUint32(reply[12:16], proc)
		binary.BigEndian.PutUint32(reply[16:20], 1) // reply
		binary.BigEndian.PutUint32(reply[20:24], serial)
		binary.BigEndian.PutUint32(reply[24:28], 0) // ok
		copy(reply[28:], payload)
		if _, err := c.Write(reply); err != nil {
			return
		}
	}
}

// Review r1-m1 (lsunknown-rereview-1): Close took the client's lock and
// called the main connection's Disconnect unbounded. Disconnect asks
// libvirtd to close first, and a connection libvirtd stopped reading never
// answers; the reconnect loop's liveness check, waiting on that connection,
// holds the lock for reading meanwhile. The daemon's shutdown then never got
// past Close to its database's. Close now returns within its bound, closes
// the socket under the connection, and the calls waiting on it fail.
//
// Mutation: Close waiting for the lock and Disconnect unbounded: it does not
// return: red.
func TestClientClose_AConnectionLibvirtdDoesNotAnswerClosesInTime(t *testing.T) {
	sock := silentLibvirtd(t)
	c, err := newClientOn(sock)
	if err != nil {
		t.Fatalf("dial the fake libvirtd: %v", err)
	}
	prev := clientCloseTimeout
	clientCloseTimeout = 200 * time.Millisecond
	t.Cleanup(func() { clientCloseTimeout = prev })

	// The reconnect loop's liveness check: it holds the lock for reading
	// and waits on a call libvirtd does not answer.
	checking := make(chan struct{})
	checked := make(chan bool, 1)
	go func() {
		c.mu.RLock()
		defer c.mu.RUnlock()
		close(checking)
		checked <- c.isAlive()
	}()
	<-checking

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err == nil {
			t.Error("Close reported a clean close of a connection libvirtd never answered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return: it waits on a connection libvirtd does not answer")
	}
	select {
	case alive := <-checked:
		if alive {
			t.Error("the liveness check answered alive on a closed connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call waiting on the connection did not fail once Close closed its socket")
	}
}

// Review mainconn m-2: a reader asked for after Close was dialled and never
// closed. Once closed, the client hands out a closed reader, whose calls fail
// without dialling, and says it is closing.
//
// Mutation: no closed check in SecureStateReader: it dials: red.
func TestClientClose_NoReaderIsDialledAfterClose(t *testing.T) {
	sock := silentLibvirtd(t)
	c, err := newClientOn(sock)
	if err != nil {
		t.Fatalf("dial the fake libvirtd: %v", err)
	}
	prev := clientCloseTimeout
	clientCloseTimeout = 200 * time.Millisecond
	t.Cleanup(func() { clientCloseTimeout = prev })
	_ = c.Close()
	if !c.Closing() {
		t.Error("Closing after Close: false")
	}
	for _, r := range []*StateReader{c.StateReader(), c.SecureStateReader()} {
		if _, err := r.VNCPort("x"); err == nil {
			t.Error("a reader asked for after Close answered")
		}
		if r.Dials() != 0 {
			t.Errorf("a reader asked for after Close dialled %d connections", r.Dials())
		}
	}
}
