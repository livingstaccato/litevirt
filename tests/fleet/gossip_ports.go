package fleet

import (
	"math/rand"
	"net"
	"strconv"
	"sync"
	"testing"
)

// gossipPorts hands out gossip ports for this test process. They come from
// below the kernel's ephemeral range (ip_local_port_range, 32768-60999 on
// Linux), which is never assigned implicitly. A port the kernel chose with :0
// IS from that range, so in the seconds before a node binds it — and across a
// node's restart into the same port — any process's outgoing connection could
// take it as its source port. Each port is handed out once per process, so
// tests running in parallel never get the same one.
var gossipPorts struct {
	sync.Mutex
	next int
	used map[int]bool
}

func freeGossipPort(t *testing.T) int {
	t.Helper()
	const lo, hi = 20000, 32000
	gossipPorts.Lock()
	defer gossipPorts.Unlock()
	if gossipPorts.used == nil {
		gossipPorts.used = map[int]bool{}
		// Different test binaries start at different points, so two packages
		// probing at once rarely race for the same port.
		gossipPorts.next = lo + rand.Intn(hi-lo)
	}
	for i := 0; i < hi-lo; i++ {
		port := gossipPorts.next
		gossipPorts.next++
		if gossipPorts.next >= hi {
			gossipPorts.next = lo
		}
		if gossipPorts.used[port] {
			continue
		}
		l, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		u, err := net.ListenPacket("udp", "0.0.0.0:"+strconv.Itoa(port))
		l.Close()
		if err != nil {
			continue
		}
		u.Close()
		gossipPorts.used[port] = true
		return port
	}
	t.Fatal("no port free for both TCP and UDP below the ephemeral range")
	return 0
}
