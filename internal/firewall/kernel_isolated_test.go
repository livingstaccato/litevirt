//go:build linux

package firewall

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
)

// routedGuest is one guest network stack behind a bridge of a routedLab. An
// empty gw gives it no default route.
type routedGuest struct {
	name, bridge, addr, gw string
}

// newRoutedLab builds bridges (name → the host's address on it, as a CIDR)
// and guests behind them, each in its own network namespace with a default
// route through its bridge's host address, and the host routing between them.
// Guest g's bridge port is p<g>. Reverse-path filtering is off, so only the
// firewall decides what a forged source reaches.
func newRoutedLab(t *testing.T, bridges map[string]string, guests []routedGuest) *guestLab {
	t.Helper()
	mountRun.Do(func() {
		sh(t, "mount", "-t", "tmpfs", "tmpfs", "/run")
		sh(t, "mkdir", "-p", "/run/netns")
	})
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", TableName).Run()
		for _, g := range guests {
			_ = exec.Command("ip", "netns", "del", g.name).Run()
			_ = exec.Command("ip", "link", "del", "p"+g.name).Run()
		}
		for br := range bridges {
			_ = exec.Command("ip", "link", "del", br).Run()
		}
	})
	sh(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	sh(t, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
	sh(t, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=0")
	for br, cidr := range bridges {
		sh(t, "ip", "link", "add", br, "type", "bridge", "stp_state", "0", "forward_delay", "0")
		sh(t, "ip", "addr", "add", cidr, "dev", br)
		sh(t, "ip", "link", "set", br, "up")
	}
	for _, g := range guests {
		sh(t, "ip", "netns", "add", g.name)
		sh(t, "ip", "link", "add", "p"+g.name, "type", "veth", "peer", "name", "eth0", "netns", g.name)
		sh(t, "ip", "link", "set", "p"+g.name, "master", g.bridge)
		sh(t, "ip", "link", "set", "p"+g.name, "up")
		sh(t, "ip", "-n", g.name, "addr", "add", g.addr+"/24", "dev", "eth0")
		sh(t, "ip", "-n", g.name, "link", "set", "eth0", "up")
		sh(t, "ip", "-n", g.name, "link", "set", "lo", "up")
		if g.gw != "" {
			sh(t, "ip", "-n", g.name, "route", "add", "default", "via", g.gw)
		}
	}
	return &guestLab{}
}

type pathCase struct {
	name     string
	from, to string
	want     bool
}

func checkPaths(t *testing.T, l *guestLab, phase string, cases []pathCase) {
	t.Helper()
	failed := false
	for _, c := range cases {
		if got := l.ping(c.from, c.to); got != c.want {
			failed = true
			t.Errorf("%s: %s (%s -> %s): reached=%v, want %v", phase, c.name, c.from, c.to, got, c.want)
		}
	}
	if failed {
		t.Logf("ruleset:\n%s", sh(t, "nft", "list", "ruleset"))
	}
}

func applyPlan(t *testing.T, p Plan) {
	t.Helper()
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), p); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// TestKernelChild_IsolatedNetworkStaysOnHost pushes real traffic between
// guests on two isolated bridges (in compose.IsolatedBridgeGroup, as litevirt
// creates them), a `bridge` network's bridge that happens to be named
// br-iso-usr (main allowed that; it must keep routing), and an ordinary uplink
// bridge, with the host routing between all of them. Nothing is routed off or
// onto an isolated bridge; guests on one isolated bridge still reach each
// other and the host (its dnsmasq), and the host reaches them. Then the same
// with no bridge named in the plan — the group alone holds them — then a
// bridge not yet in the group, held by its name in the plan alone, and
// finally every blocked path works with the table removed, so it was the
// table dropping them.
//
// Mutation: drop the group lines from renderIsolatedForward — the
// "group alone" phase goes red; drop the per-bridge lines — the
// isolated-to-isolated and not-yet-grouped cases go red; match br-iso-* by
// name — the br-iso-usr cases go red.
func TestKernelChild_IsolatedNetworkStaysOnHost(t *testing.T) {
	inNetns(t)
	l := newRoutedLab(t, map[string]string{
		"br-iso-ka":  "10.30.0.254/24",
		"br-iso-kb":  "10.31.0.254/24",
		"br-iso-usr": "10.33.0.254/24",
		"lvup0":      "10.32.0.254/24",
	}, []routedGuest{
		{"ia1", "br-iso-ka", "10.30.0.1", "10.30.0.254"},
		{"ia2", "br-iso-ka", "10.30.0.2", "10.30.0.254"},
		{"ib", "br-iso-kb", "10.31.0.1", "10.31.0.254"},
		{"gus", "br-iso-usr", "10.33.0.1", "10.33.0.254"},
		{"gu", "lvup0", "10.32.0.1", "10.32.0.254"},
	})
	group := strconv.Itoa(compose.IsolatedBridgeGroup)
	sh(t, "ip", "link", "set", "br-iso-ka", "group", group)
	sh(t, "ip", "link", "set", "br-iso-kb", "group", group)

	allowed := []pathCase{
		{"guest to guest on one isolated bridge", "ia1", "10.30.0.2", true},
		{"guest to the host on its isolated bridge (DHCP, DNS)", "ia1", "10.30.0.254", true},
		{"host to a guest on an isolated bridge", "", "10.30.0.1", true},
		{"uplink guest to the host", "gu", "10.32.0.254", true},
		{"a bridge network named br-iso-usr routes out", "gus", "10.32.0.1", true},
		{"a bridge network named br-iso-usr is routed into", "gu", "10.33.0.1", true},
	}

	applyPlan(t, Plan{IsolatedBridges: []string{"br-iso-ka", "br-iso-kb"}})
	checkPaths(t, l, "named", append([]pathCase{
		{"routed out of an isolated bridge", "ia1", "10.32.0.1", false},
		{"routed into an isolated bridge", "gu", "10.30.0.1", false},
		{"routed between two isolated bridges", "ia1", "10.31.0.1", false},
		{"routed from the other isolated bridge", "ib", "10.30.0.1", false},
		{"routed from br-iso-usr into an isolated bridge", "gus", "10.30.0.1", false},
	}, allowed...))

	applyPlan(t, Plan{})
	checkPaths(t, l, "group alone (no bridge named)", append([]pathCase{
		{"routed out of an isolated bridge", "ia1", "10.32.0.1", false},
		{"routed into an isolated bridge", "gu", "10.30.0.1", false},
		{"routed out of the other isolated bridge", "ib", "10.32.0.1", false},
	}, allowed...))

	// A bridge not in the group yet (made by a build before the group) is
	// held by its name in the plan alone.
	sh(t, "ip", "link", "set", "br-iso-ka", "group", "default")
	applyPlan(t, Plan{IsolatedBridges: []string{"br-iso-ka"}})
	checkPaths(t, l, "named, not yet in the group", []pathCase{
		{"routed out of an isolated bridge", "ia1", "10.32.0.1", false},
		{"routed into an isolated bridge", "gu", "10.30.0.1", false},
		{"guest to guest on one isolated bridge", "ia1", "10.30.0.2", true},
	})
	sh(t, "ip", "link", "set", "br-iso-ka", "group", group)

	sh(t, "nft", "delete", "table", "inet", TableName)
	checkPaths(t, l, "no table", []pathCase{
		{"routed out of an isolated bridge", "ia1", "10.32.0.1", true},
		{"routed into an isolated bridge", "gu", "10.30.0.1", true},
		{"routed between two isolated bridges", "ia1", "10.31.0.1", true},
	})
}

// udpListener receives on addr and reports whether a datagram carrying
// payload arrives within wait.
type udpListener struct{ c *net.UDPConn }

func listenUDP(t *testing.T, addr string) *udpListener {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp4", ua)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &udpListener{c: c}
}

func (u *udpListener) got(payload string, wait time.Duration) bool {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		_ = u.c.SetReadDeadline(deadline)
		n, _, err := u.c.ReadFromUDP(buf)
		if err != nil {
			return false
		}
		if strings.Contains(string(buf[:n]), payload) {
			return true
		}
	}
	return false
}

// TestKernelChild_HostIsolationAnswersTheHost: a host-isolated bridge drops
// what its guests send the host, but not their replies to connections the
// host opened onto that bridge — haproxy's health checks and proxied
// connections to backends there (lab 1 LBAndSNAT: Layer4 timeout once the VIP
// was on the bridge). A guest still cannot open anything to the host, and
// cannot ride a connection the host has on another link: a datagram forged
// from a peer host's address into an established gossip flow (UDP 7946) is
// dropped. With the table removed the forgery arrives, so it was the table.
//
// Mutation: accept `ct state established,related` on the bridge without the
// direction and mark match — the forged datagram arrives, red; drop the
// output mark — the host-to-guest case goes red.
func TestKernelChild_HostIsolationAnswersTheHost(t *testing.T) {
	inNetns(t)
	l := newRoutedLab(t, map[string]string{"lvhi0": "10.40.0.254/24", "lvup0": "10.32.0.254/24"},
		[]routedGuest{{"hi1", "lvhi0", "10.40.0.1", "10.40.0.254"}, {"pr", "lvup0", "10.32.0.1", "10.32.0.254"}})
	applyPlan(t, Plan{HostIsolation: []IsolationChain{{Bridge: "lvhi0"}}})

	if !l.ping("", "10.40.0.1") {
		t.Error("the host gets no reply from a guest on a host-isolated bridge")
	}
	if l.ping("hi1", "10.40.0.254") {
		t.Error("a guest on a host-isolated bridge reached the host")
	}

	// The host's gossip flow with a peer on the uplink: the host sends
	// first, the peer answers, so the peer's datagrams are its replies.
	host := listenUDP(t, "10.32.0.254:7946")
	if _, err := host.c.WriteToUDP([]byte("hello"), &net.UDPAddr{IP: net.ParseIP("10.32.0.1"), Port: 7946}); err != nil {
		t.Fatal(err)
	}
	sendUDPFrom(t, "pr", "10.32.0.1", 7946, "10.32.0.254", 7946, "peer-reply")
	if !host.got("peer-reply", time.Second) {
		t.Fatal("precondition: the peer's reply did not reach the host")
	}
	sendUDPFrom(t, "hi1", "10.32.0.1", 7946, "10.32.0.254", 7946, "forged")
	if host.got("forged", time.Second) {
		t.Error("a guest on a host-isolated bridge forged its way into the host's gossip flow")
	}
	if t.Failed() {
		t.Logf("ruleset:\n%s", sh(t, "nft", "list", "ruleset"))
	}

	sh(t, "nft", "delete", "table", "inet", TableName)
	if !l.ping("hi1", "10.40.0.254") {
		t.Error("a guest cannot reach the host with no table loaded")
	}
	sendUDPFrom(t, "hi1", "10.32.0.1", 7946, "10.32.0.254", 7946, "forged-open")
	if !host.got("forged-open", time.Second) {
		t.Error("with no table the forged datagram does not arrive either: the case proves nothing")
	}
}

// TestKernelChild_HostIsolatedGatewayRoutesWithSNAT: a host-isolated bridge
// that carries its guests' gateway (as litevirt now gives a bridge it made
// for a host-isolated `bridge` network) keeps the guests off that address,
// and routes them out through an LB's SNAT. The peer has no route back to the
// guests' subnet, so only the SNAT brings the replies home.
//
// Mutation: drop the SNAT rule — the routed-out case goes red.
func TestKernelChild_HostIsolatedGatewayRoutesWithSNAT(t *testing.T) {
	inNetns(t)
	if missing := missingModules("nf_nat", "nft_chain_nat", "nft_nat"); len(missing) > 0 {
		t.Skipf("SNAT would make the kernel load %v, which is not loaded on this host", missing)
	}
	l := newRoutedLab(t, map[string]string{"lvhi0": "10.40.0.1/24", "lvup0": "10.32.0.254/24"},
		[]routedGuest{{"hi1", "lvhi0", "10.40.0.10", "10.40.0.1"}, {"pr", "lvup0", "10.32.0.1", ""}})
	plan := Plan{
		HostIsolation: []IsolationChain{{Bridge: "lvhi0"}},
		NAT:           []NATRule{{OutIface: "lvup0", Subnet: "10.40.0.0/24", SNATTo: "10.32.0.254"}},
	}
	applyPlan(t, plan)
	checkPaths(t, l, "SNAT", []pathCase{
		{"guest to its gateway address", "hi1", "10.40.0.1", false},
		{"guest to the host's uplink address", "hi1", "10.32.0.254", false},
		{"guest routed out through SNAT", "hi1", "10.32.0.1", true},
	})
	plan.NAT = nil
	applyPlan(t, plan)
	checkPaths(t, l, "no SNAT", []pathCase{
		{"guest routed out with no SNAT (the peer cannot answer)", "hi1", "10.32.0.1", false},
	})
}
