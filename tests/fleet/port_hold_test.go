package fleet

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// The hold Stop keeps on a node's port must not make a stopped node look any
// different to its peers (a dial is refused, as with nothing there), and must
// not stop the node from listening there again (port_hold.go).
func TestPortHold_StoppedNodeRefusesAndRebinds(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	n := &Node{Name: "node-x", Address: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Listener: l}
	addr := net.JoinHostPort(n.Address, strconv.Itoa(n.Port))

	if !portHoldSupported {
		t.Skip("this platform holds no port (holdPort unsupported)")
	}
	n.Stop()
	if n.portHold == nil {
		t.Fatal("Stop took no hold on the node's port")
	}
	t.Cleanup(n.releasePortHold)
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a dial to a stopped node's held port connected; it must be refused")
	}

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
