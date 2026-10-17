package fleet

import (
	"log/slog"
	"net"
	"strconv"
	"testing"
)

// A stopped node keeps its gRPC port. Every peer dials the port in the node's
// hosts row, so a node that comes back (restartNode, rebuildWithEmptyDB, …)
// must listen on that same port again. Its port came from the ephemeral range,
// though, and once the listener closes the kernel hands it to the next socket
// that asks: an outbound connection anywhere on the machine, or another test's
// listener on port 0. The rebind then fails with "address already in use".
//
// So Stop holds the port: a socket bound to it with SO_REUSEADDR and never
// listening (holdPort). A connection to the stopped node is still refused, as
// with no socket there, and the ephemeral allocator skips the bound port for
// both an outbound connection and a port-0 listener. rebindPort listens on the
// port while the hold is still in place (both sockets have SO_REUSEADDR and
// the hold is not listening), then lets the hold go, so the port is never free
// in between.

// holdStoppedPort reserves n's port after its listener has closed. A failure
// leaves the port unheld, which is what the harness had before, and is logged:
// a rebind that then collides should not be a mystery.
func (n *Node) holdStoppedPort() {
	if n.portHold != nil || n.Port == 0 {
		return
	}
	release, err := holdPort(n.Address, n.Port)
	if err != nil {
		slog.Warn("fleet: could not hold a stopped node's port; a later rebind on it may collide",
			"node", n.Name, "port", n.Port, "error", err)
		return
	}
	n.portHold, n.heldPort = release, n.Port
}

// releasePortHold lets go of the hold Stop took, if any.
func (n *Node) releasePortHold() {
	if n.portHold != nil {
		n.portHold()
		n.portHold, n.heldPort = nil, 0
	}
}

// movePort gives n the new listener l, on a port of its own, and lets go of
// any hold on the old one: nothing will rebind that port, and a later Stop
// must be free to hold the new one.
func (n *Node) movePort(l net.Listener) {
	n.Port, n.Listener = l.Addr().(*net.TCPAddr).Port, l
	n.releasePortHold()
}

// rebindPort listens on n's port again, as a restarted daemon does on the
// port its peers know, and then releases the hold Stop kept on it.
func (n *Node) rebindPort(t *testing.T) {
	t.Helper()
	addr := net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
	l, err := net.Listen("tcp", addr)
	if err != nil && n.portHold != nil {
		// A platform whose SO_REUSEADDR does not let a listener bind beside
		// the hold: release it and bind at once.
		n.releasePortHold()
		l, err = net.Listen("tcp", addr)
	}
	n.releasePortHold()
	if err != nil {
		t.Fatalf("rebind %s on port %d: %v", n.Name, n.Port, err)
	}
	n.Listener = l
}
