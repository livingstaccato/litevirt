package fleet

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestFreeGossipPort_OutsideTheEphemeralRange: a gossip node's port must stay
// free from the moment it is chosen until the node (re)binds it, sometimes
// seconds later, and it is reused across a restart. A port from the kernel's
// ephemeral range is handed out as the source port of any outgoing
// connection by any process in that window, so under `go test -p 16` another
// package took one: "listen tcp 0.0.0.0:36251: bind: address already in use"
// (TestGossipKeyring_RotationKeepsMembership, kvm003-f3, 2026-10-01). Ports
// below the range are never assigned implicitly.
//
// Mutation: return to listening on :0 — the port lands in the range.
func TestFreeGossipPort_OutsideTheEphemeralRange(t *testing.T) {
	lo := 32768
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 {
			if v, err := strconv.Atoi(f[0]); err == nil {
				lo = v
			}
		}
	}
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		p := freeGossipPort(t)
		if p >= lo {
			t.Fatalf("port %d is inside the ephemeral range (starts at %d)", p, lo)
		}
		if seen[p] {
			t.Fatalf("port %d handed out twice in one process", p)
		}
		seen[p] = true
	}
}
