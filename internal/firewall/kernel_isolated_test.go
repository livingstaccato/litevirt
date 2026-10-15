//go:build linux

package firewall

import (
	"context"
	"os/exec"
	"testing"
)

// routedGuest is one guest network stack behind a bridge of a routedLab.
type routedGuest struct {
	name, bridge, addr, gw string
}

// newRoutedLab builds bridges (name → the host's address on it, as a CIDR)
// and guests behind them, each in its own network namespace with a default
// route through its bridge's host address, and the host routing between them.
// Guest g's bridge port is p<g>.
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
		sh(t, "ip", "-n", g.name, "route", "add", "default", "via", g.gw)
	}
	return &guestLab{}
}

// TestKernelChild_IsolatedNetworkStaysOnHost pushes real traffic between
// guests on two isolated bridges and one ordinary bridge (the uplink a host
// forwards to the internet through) with the host routing between all three,
// and checks that nothing is routed off or onto an isolated bridge, while
// guests on one isolated bridge reach each other and the host (its dnsmasq)
// and the host reaches them. Then the same with no bridge named in the plan —
// the wildcard alone holds them — and finally that every blocked path works
// with the table removed, so it was the table dropping them.
//
// Mutation: drop the wildcard lines from renderIsolatedForward — the
// fail-closed phase goes red; drop the per-bridge lines — the
// isolated-to-isolated case goes red.
func TestKernelChild_IsolatedNetworkStaysOnHost(t *testing.T) {
	inNetns(t)
	l := newRoutedLab(t, map[string]string{
		"br-iso-ka": "10.30.0.254/24",
		"br-iso-kb": "10.31.0.254/24",
		"lvup0":     "10.32.0.254/24",
	}, []routedGuest{
		{"ia1", "br-iso-ka", "10.30.0.1", "10.30.0.254"},
		{"ia2", "br-iso-ka", "10.30.0.2", "10.30.0.254"},
		{"ib", "br-iso-kb", "10.31.0.1", "10.31.0.254"},
		{"gu", "lvup0", "10.32.0.1", "10.32.0.254"},
	})
	type pathCase struct {
		name     string
		from, to string
		want     bool
	}
	check := func(phase string, cases []pathCase) {
		t.Helper()
		for _, c := range cases {
			if got := l.ping(c.from, c.to); got != c.want {
				t.Errorf("%s: %s (%s -> %s): reached=%v, want %v", phase, c.name, c.from, c.to, got, c.want)
			}
		}
		if t.Failed() {
			t.Logf("ruleset:\n%s", sh(t, "nft", "list", "ruleset"))
		}
	}
	apply := func(p Plan) {
		t.Helper()
		if _, err := NewApplier(NftBinary{}).Apply(context.Background(), p); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	allowed := []pathCase{
		{"guest to guest on one isolated bridge", "ia1", "10.30.0.2", true},
		{"guest to the host on its isolated bridge (DHCP, DNS)", "ia1", "10.30.0.254", true},
		{"host to a guest on an isolated bridge", "", "10.30.0.1", true},
		{"uplink guest to the host", "gu", "10.32.0.254", true},
	}

	apply(Plan{IsolatedBridges: []string{"br-iso-ka", "br-iso-kb"}})
	check("named", append([]pathCase{
		{"routed out of an isolated bridge", "ia1", "10.32.0.1", false},
		{"routed into an isolated bridge", "gu", "10.30.0.1", false},
		{"routed between two isolated bridges", "ia1", "10.31.0.1", false},
		{"routed from the other isolated bridge", "ib", "10.30.0.1", false},
	}, allowed...))

	apply(Plan{})
	check("fail closed (no bridge named)", append([]pathCase{
		{"routed out of an isolated bridge", "ia1", "10.32.0.1", false},
		{"routed into an isolated bridge", "gu", "10.30.0.1", false},
		{"routed out of the other isolated bridge", "ib", "10.32.0.1", false},
	}, allowed...))

	sh(t, "nft", "delete", "table", "inet", TableName)
	check("no table", []pathCase{
		{"routed out of an isolated bridge", "ia1", "10.32.0.1", true},
		{"routed into an isolated bridge", "gu", "10.30.0.1", true},
		{"routed between two isolated bridges", "ia1", "10.31.0.1", true},
	})
	if t.Failed() {
		t.Logf("links:\n%s", sh(t, "ip", "-br", "addr"))
	}
}
