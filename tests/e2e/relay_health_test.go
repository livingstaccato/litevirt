package e2e

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/failover"
)

// relayRole reads litevirt_relay_role{member=<member>} from host's own
// metrics endpoint: 1 relay, 0 leaf, ok=false when the series is absent.
func (l *lab) relayRole(host, member string) (float64, bool) {
	out, err := l.ssh(host, 30*time.Second, "curl -s --max-time 10 http://127.0.0.1:7444/metrics | grep '^litevirt_relay_role{'")
	if err != nil {
		return 0, false
	}
	re := regexp.MustCompile(`member="` + regexp.QuoteMeta(member) + `"[^}]*\}\s+(\S+)`)
	for _, line := range strings.Split(out, "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseFloat(m[1], 64)
			return v, err == nil
		}
	}
	return 0, false
}

// waitRelayRole waits until every host's own election reports member with
// role want, sampling every 10 s, and returns how long it took.
func (l *lab) waitRelayRole(member string, want float64, within time.Duration, what string) time.Duration {
	l.t.Helper()
	start := time.Now()
	last := ""
	for time.Since(start) < within {
		var off []string
		for _, h := range l.hosts {
			if v, ok := l.relayRole(h, member); !ok || v != want {
				off = append(off, fmt.Sprintf("%s=%v(present %v)", h, v, ok))
			}
		}
		if len(off) == 0 {
			return time.Since(start)
		}
		last = strings.Join(off, " ")
		time.Sleep(10 * time.Second)
	}
	l.t.Fatalf("%s: not within %s; last disagreeing: %s", what, within, last)
	return 0
}

// TestRelayHealth_DegradedLinkBecomesALeafEverywhere (colonelpanik/litevirt#175):
// the lab node that sorts first is a relay by name. Its link is degraded with
// tc netem (E2E_RELAY_NETEM, default "loss 30%"); the failover lease holder
// demotes it and litevirt_relay_role then reads 0 for it on EVERY node. The
// netem qdisc is removed and, after RelayRestoreWindow with no failing
// observer, it reads 1 on every node again.
//
// The judgement is each node's own metrics endpoint, which reports the
// replicator's live election, not a row in the database.
//
// Needs relay_health_v1 latched on the lab (every node on this build).
func TestRelayHealth_DegradedLinkBecomesALeafEverywhere(t *testing.T) {
	l := newLab(t)
	victim := l.hosts[0]
	netem := os.Getenv("E2E_RELAY_NETEM")
	if netem == "" {
		netem = "loss 30%"
	}
	l.waitRelayRole(victim, 1, 2*time.Minute, "precondition: "+victim+" a relay on every node (it sorts first)")

	dev := strings.TrimSpace(l.mustSSH(victim, 30*time.Second,
		fmt.Sprintf(`ip -o -4 addr show | awk '$4 ~ /^%s\// {print $2; exit}'`, regexp.QuoteMeta(l.ip[victim]))))
	if dev == "" {
		t.Fatalf("no interface on %s carries %s", victim, l.ip[victim])
	}
	clearNetem := func() { _, _ = l.ssh(victim, 30*time.Second, "tc qdisc del dev "+dev+" root 2>/dev/null; true") }
	t.Cleanup(clearNetem)
	l.mustSSH(victim, 30*time.Second, fmt.Sprintf("tc qdisc replace dev %s root netem %s", dev, netem))
	l.mark("netem %q on %s (%s)", netem, victim, dev)

	// The demotion window, the probes' own build-up and a backstop relay
	// re-election (30 s) on every node, with room.
	took := l.waitRelayRole(victim, 0, failover.RelayDemoteWindow+5*time.Minute, victim+" a leaf on every node")
	l.mark("%s a leaf on every node after %s", victim, took.Round(time.Second))
	if took < failover.RelayDemoteWindow {
		t.Errorf("%s demoted after %s, inside the %s window", victim, took, failover.RelayDemoteWindow)
	}

	clearNetem()
	l.mark("netem cleared on %s", victim)
	took = l.waitRelayRole(victim, 1, failover.RelayRestoreWindow+5*time.Minute, victim+" restored to relay on every node")
	l.mark("%s a relay again on every node after %s", victim, took.Round(time.Second))
	if took < failover.RelayRestoreWindow {
		t.Errorf("%s restored after %s, inside the %s window", victim, took, failover.RelayRestoreWindow)
	}
}
