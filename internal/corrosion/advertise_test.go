package corrosion

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

// freePort reserves an ephemeral port and releases it, so two gossip clients in
// one test process can bind without colliding.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newGossipClient starts a gossip client bound to bind:port. With port 0 it
// takes a free port and retries the bind: freePort only proves a port was free
// for TCP on 127.0.0.1 a moment ago, and memberlist binds TCP and UDP on the
// configured address afterwards, so another socket -- this binary's other
// nodes, a parallel package, anything on the machine -- can hold either one
// by then. The port the client got is c.list.LocalNode().Port.
func newGossipClient(t *testing.T, name, bind, advertise string, port int, join []string) *Client {
	t.Helper()
	cfg := Config{
		HostName:      name,
		BindAddr:      bind,
		AdvertiseAddr: advertise,
		BindPort:      port,
		JoinPeers:     join,
	}
	var c *Client
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		cfg.DataDir = t.TempDir()
		if port == 0 {
			cfg.BindPort = freePort(t)
		}
		c, err = NewClient(cfg, hlc.NewClock(name))
		if err == nil || port != 0 || !strings.Contains(err.Error(), "address already in use") {
			break
		}
	}
	if err != nil {
		t.Fatalf("NewClient %s: %v", name, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestAdvertiseAddr_IsWhatPeersSee is the plumbing test for the half that was
// actually broken: Config.AdvertiseAddr must reach memberlist's AdvertiseAddr,
// because that — not the host record, and not the routing table — is the address
// other nodes learn and dial.
//
// It has to be observed from a PEER: Members() deliberately skips self, and more
// to the point, a node's own view is not what matters. Auto-detection picks the
// first private IP by interface enumeration order, so on a multi-homed host it
// can advertise an address that is real but wrong, and the only place that shows
// up is in what the peer received.
func TestAdvertiseAddr_IsWhatPeersSee(t *testing.T) {
	// node-a binds ALL interfaces so memberlist's auto-detection would pick this
	// host's real private IP, then overrides it with an advertise address that
	// auto-detection could never produce. Binding 127.0.0.1 instead would make
	// this test vacuous: auto-detect derives the advertise address from a
	// specific BindAddr, so it would report 127.0.0.1 with the wiring removed too.
	a := newGossipClient(t, "node-a", "0.0.0.0", "127.0.0.1", 0, nil)
	portA := int(a.list.LocalNode().Port)
	b := newGossipClient(t, "node-b", "127.0.0.1", "127.0.0.1", 0,
		[]string{net.JoinHostPort("127.0.0.1", itoa(portA))})

	// Gossip converges asynchronously.
	var peers []PeerInfo
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if peers = b.Members(); len(peers) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(peers) == 0 {
		t.Fatal("node-b never saw node-a through gossip")
	}

	var addr string
	for _, p := range peers {
		if p.Name == "node-a" {
			addr = p.Addr
		}
	}
	if addr == "" {
		t.Fatalf("node-a absent from node-b's members: %+v", peers)
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("node-a advertised %q, want the configured 127.0.0.1 — the "+
			"configured advertise address did not reach memberlist", addr)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
