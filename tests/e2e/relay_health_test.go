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
	"github.com/litevirt/litevirt/tests/e2e/hostls"
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
// the lab node that sorts first is a relay by name. A tc filter on it drops
// all of its traffic to TWO of its peers: their probes of it fail on every
// probe (2 of 4 observers, a third — and short of the 3 a fence needs), while
// the rest of the cluster reaches it. The failover lease holder demotes it,
// and litevirt_relay_role then reads 0 for it on EVERY node. The filter is
// removed and, after RelayRestoreWindow below the bar, it reads 1 on every
// node again — with the production windows, so the healed observers' one
// healthy verdict each is long past healthFreshness when the restore comes.
//
// Uniform netem loss does not fit the rule: TCP retransmission hides moderate
// loss from a 3 s probe, so no evaluation sees a third of the observers
// failing for 2 minutes, and loss heavy enough to fail every observer makes
// the node a fence candidate instead. E2E_RELAY_NETEM still overrides the
// impairment with a uniform `tc netem <args>` on the node's interface.
//
// The judgement is each node's own metrics endpoint, which reports the
// replicator's live election, not a row in the database.
//
// Needs relay_health_v1 latched on the lab (every node on this build).
func TestRelayHealth_DegradedLinkBecomesALeafEverywhere(t *testing.T) {
	l := newLab(t)
	l.requireRelayDemotionRoom()
	victim := l.hosts[0]
	l.waitRelayRole(victim, 1, 2*time.Minute, "precondition: "+victim+" a relay on every node (it sorts first)")

	dev := strings.TrimSpace(l.mustSSH(victim, 30*time.Second,
		fmt.Sprintf(`ip -o -4 addr show | awk '$4 ~ /^%s\// {print $2; exit}'`, regexp.QuoteMeta(l.ip[victim]))))
	if dev == "" {
		t.Fatalf("no interface on %s carries %s", victim, l.ip[victim])
	}
	clearImpairment := func() { _, _ = l.ssh(victim, 30*time.Second, "tc qdisc del dev "+dev+" root 2>/dev/null; true") }
	t.Cleanup(clearImpairment)

	var impair string
	if netem := os.Getenv("E2E_RELAY_NETEM"); netem != "" {
		impair = fmt.Sprintf("tc qdisc replace dev %s root netem %s", dev, netem)
	} else {
		// A fourth prio band that loses everything, and a u32 filter per
		// cut peer steering the victim's traffic to it there; every other
		// packet keeps the default priomap's three bands.
		cut := l.hosts[1:3]
		cmds := []string{
			fmt.Sprintf("tc qdisc replace dev %s root handle 1: prio bands 4 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1", dev),
			fmt.Sprintf("tc qdisc add dev %s parent 1:4 handle 40: netem loss 100%%", dev),
		}
		for _, p := range cut {
			cmds = append(cmds, fmt.Sprintf("tc filter add dev %s parent 1:0 protocol ip prio 1 u32 match ip dst %s/32 flowid 1:4", dev, l.ip[p]))
		}
		impair = strings.Join(cmds, " && ")
		l.mark("cutting %s's traffic to %v", victim, cut)
	}
	l.mustSSH(victim, 30*time.Second, impair)
	l.mark("impairment on %s (%s): %s", victim, dev, impair)

	// The demotion window, the probes' own build-up and a backstop relay
	// re-election (30 s) on every node, with room.
	took := l.waitRelayRole(victim, 0, failover.RelayDemoteWindow+5*time.Minute, victim+" a leaf on every node")
	l.mark("%s a leaf on every node after %s", victim, took.Round(time.Second))
	if took < failover.RelayDemoteWindow {
		t.Errorf("%s demoted after %s, inside the %s window", victim, took, failover.RelayDemoteWindow)
	}
	// Demoted, not fenced: two of four observers is below fence quorum. The
	// victim must still print HOST_ACTIVE (a fenced host prints HOST_OFFLINE).
	if out, err := l.lv(l.hosts[len(l.hosts)-1], "host", "ls"); err == nil {
		if line, bad := hostls.TakenDown(out, victim); bad {
			t.Errorf("%s was taken out of service, not just demoted: %s", victim, line)
		}
	}

	clearImpairment()
	l.mark("impairment cleared on %s", victim)
	took = l.waitRelayRole(victim, 1, failover.RelayRestoreWindow+5*time.Minute, victim+" restored to relay on every node")
	l.mark("%s a relay again on every node after %s", victim, took.Round(time.Second))
	if took < failover.RelayRestoreWindow {
		t.Errorf("%s restored after %s, inside the %s window", victim, took, failover.RelayRestoreWindow)
	}
}

// requireRelayDemotionRoom skips unless one demotion can take effect: at least
// 5 hosts active (so 2 failing observers of 4 is the bar and short of fence
// quorum), none a witness, and more active hosts than the election's relay
// count R = min(N, 3 + ceil(N/50)), so the floor lets one host go. Otherwise
// the evaluator correctly declines, and the test would fail after minutes as
// if the feature were broken.
func (l *lab) requireRelayDemotionRoom() {
	l.t.Helper()
	out, err := l.lv(l.hosts[0], "host", "ls")
	if err != nil {
		l.t.Fatalf("lv host ls: %v", err)
	}
	total, active, notActive := hostls.CountActive(out)
	rows, err := l.sql(l.hosts[0], "SELECT name FROM hosts WHERE deleted_at IS NULL AND role = 'witness'")
	if err != nil {
		l.t.Fatalf("read witnesses: %v", err)
	}
	r := 3 + (total+49)/50
	if r > total {
		r = total
	}
	switch {
	case active < 5:
		l.t.Skipf("relay demotion needs at least 5 active hosts; %d of %d are active (not active: %v)", active, total, notActive)
	case len(rows) > 0:
		l.t.Skipf("relay demotion needs no witness among the hosts (a witness is never a relay); witnesses: %v", rows)
	case active <= r:
		l.t.Skipf("relay demotion needs more active hosts (%d) than the relay count R = %d", active, r)
	}
}
