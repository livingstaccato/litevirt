package fleet

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// wantRefused fails unless a dial to addr is refused outright: a held port
// must look like a closed one, and a dial that only timed out proves nothing.
func wantRefused(t *testing.T, what, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		_ = c.Close()
		t.Fatalf("%s: a dial to %s connected; it must be refused", what, addr)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("%s: a dial to %s failed with %v, want connection refused", what, addr, err)
	}
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// The hold Stop keeps on a node's port must not make a stopped node look any
// different to its peers (a dial is refused, as with nothing there), and must
// not stop the node from listening there again (port_hold.go).
func TestPortHold_StoppedNodeRefusesAndRebinds(t *testing.T) {
	if !portHoldSupported {
		t.Skip("this platform holds no port (holdPort unsupported)")
	}
	l := listenLocal(t)
	n := &Node{Name: "node-x", Address: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Listener: l}
	addr := net.JoinHostPort(n.Address, strconv.Itoa(n.Port))

	n.Stop()
	if n.portHold == nil {
		t.Fatal("Stop took no hold on the node's port")
	}
	t.Cleanup(n.releasePortHold)
	wantRefused(t, "stopped node", addr)

	n.rebindPort(t)
	defer n.Listener.Close()
	if n.portHold != nil {
		t.Fatal("rebindPort kept the hold")
	}
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial the rebound node: %v", err)
	}
	_ = c.Close()
}

// A crashed node's machine may come back on its port, so Crash holds it too,
// and its peers still see it refuse.
func TestPortHold_CrashHoldsThePort(t *testing.T) {
	if !portHoldSupported {
		t.Skip("this platform holds no port (holdPort unsupported)")
	}
	c := New(t, Options{Nodes: 2})
	n := c.Nodes[1]
	c.Crash(n)
	if n.portHold == nil || n.heldPort != n.Port {
		t.Fatalf("Crash left %s's port %d unheld (held %d)", n.Name, n.Port, n.heldPort)
	}
	wantRefused(t, "crashed node", net.JoinHostPort(n.Address, strconv.Itoa(n.Port)))
}

// A node moved to a new port (voter_chain_test's reimage) drops the hold on its
// old one, so a later Stop holds the port it is on now.
func TestPortHold_MovedNodeHoldsItsNewPort(t *testing.T) {
	if !portHoldSupported {
		t.Skip("this platform holds no port (holdPort unsupported)")
	}
	old := listenLocal(t)
	n := &Node{Name: "node-x", Address: "127.0.0.1", Port: old.Addr().(*net.TCPAddr).Port, Listener: old}
	t.Cleanup(n.releasePortHold)
	n.Stop()
	if n.heldPort != old.Addr().(*net.TCPAddr).Port {
		t.Fatalf("Stop held port %d, want the old port", n.heldPort)
	}

	n.movePort(listenLocal(t))
	n.Stop()
	if n.portHold == nil || n.heldPort != n.Port {
		t.Fatalf("after a move to port %d, Stop holds port %d", n.Port, n.heldPort)
	}
}
