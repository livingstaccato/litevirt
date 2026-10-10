package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/health"
)

// TestLab_ReleaseTokenRollbackRule proves the release token's rollback rule on
// real nodes, with the real binary reading real files:
//
//  1. every node's marker for the release token carries `rollback:
//     safe_if_unused`, and `lv cluster upgrade-status` agrees with the used
//     records in state.db about whether the token blocks a rollback;
//  2. a node holding a marker for a LATER release token (one this build does
//     not know) that carries the rule, with none of that token's features
//     recorded used, starts in release probation, asks a voter majority, and
//     leaves probation — never quarantined, which one token per feature was —
//     and a second boot below the same marker is a probation again;
//  3. the same node, once that marker carries no rule, starts WAL-quarantined
//     and says so in upgrade-status — today's behaviour for every token.
//
// Steps 2–3 stop the victim's daemon, write a marker into its data directory
// while it is down, and on cleanup remove it — and any probation-lift record an
// earlier build of this branch left — restart, and check the victim ends with
// neither a WAL quarantine nor a probation. A RECORDED USE is deliberately not
// planted here: a used row in one node's state.db would reach its peers by
// anti-entropy and quarantine them too, which is the mechanism working, on the
// whole lab. The used-set decision over a real state.db is covered by
// internal/daemon TestPreflightCapabilityRollback_ReadsTheReplicatedUsedSet and
// the replication trip by tests/fleet TestFleet_ReleaseFeature_*.
func TestLab_ReleaseTokenRollbackRule(t *testing.T) {
	l := newLab(t)
	q := l.hosts[0]
	tok := capabilities.ReleaseToken
	marker := health.ActivationMarkerPath("/var/lib/litevirt", tok)
	for _, h := range l.hosts {
		out, err := l.ssh(h, 20*time.Second, "cat "+shellQuote(marker))
		if err != nil {
			t.Skipf("%s has not latched on %s (roll every node to this build first): %v", tok, h, err)
		}
		if !strings.Contains(out, "rollback: "+capabilities.RollbackSafeIfUnused) {
			t.Errorf("%s marker on %s = %q, want the safe_if_unused rule", tok, h, out)
		}
	}

	used := l.mustSQL(q, "SELECT count(*) FROM cluster_policies WHERE key >= 'release_feature/"+tok+
		"/' AND key < 'release_feature/"+tok+"0' AND deleted_at IS NULL")
	status := l.mustLV(q, "cluster", "upgrade-status")
	l.saveEvidence("upgrade-status-before.txt", status)
	// Every build below the first release token predates rules: it always
	// blocks. A rule-aware build would be blocked only once a feature is used.
	wantRuleAware := "no"
	if len(used) == 1 && used[0][0] != "0" {
		wantRuleAware = "yes"
	}
	if !upgradeStatusRow(status, tok, "safe_if_unused", "yes", wantRuleAware) {
		t.Errorf("upgrade-status on %s has no %s row with rule safe_if_unused, BLOCKS ROLLBACK yes and "+
			"IF RULE-AWARE %s (%v used records):\n%s", q, tok, wantRuleAware, used, status)
	}

	victim := l.hosts[len(l.hosts)-1]
	const future = "release_2099_01_v1"
	futureMarker := health.ActivationMarkerPath("/var/lib/litevirt", future)
	// What a round-3 build of this branch left behind after a lift; this
	// build reads nothing of it, and the cleanup removes it with the marker.
	staleLift := "/var/lib/litevirt/release_probation_lifted." + future
	planted := shellQuote(futureMarker) + " " + shellQuote(staleLift)
	t.Cleanup(func() {
		if _, err := l.ssh(victim, time.Minute, "systemctl stop litevirt; rm -f "+planted+"; systemctl start litevirt"); err != nil {
			t.Errorf("cleanup on %s: %v", victim, err)
			return
		}
		if err := l.waitDaemon(victim, 3*time.Minute); err != nil {
			t.Errorf("cleanup: %s did not come back: %v", victim, err)
			return
		}
		if out, _ := l.ssh(victim, 20*time.Second, "ls "+planted+" 2>/dev/null || true"); strings.TrimSpace(out) != "" {
			t.Errorf("cleanup left on %s: %s", victim, out)
		}
		var st string
		deadline := time.Now().Add(2 * time.Minute)
		for {
			st = l.mustLV(victim, "cluster", "upgrade-status")
			if !strings.Contains(st, "WAL quarantine: yes") && !strings.Contains(st, "Release probation: yes") {
				break
			}
			if time.Now().After(deadline) {
				l.saveEvidence("upgrade-status-after-cleanup.txt", st)
				t.Errorf("%s did not end clean after the cleanup:\n%s", victim, st)
				return
			}
			time.Sleep(5 * time.Second)
		}
		l.saveEvidence("upgrade-status-after-cleanup.txt", st)
	})

	// 2. A later release's marker, rule on, nothing used: it starts in release
	// probation (its own replica's "nothing used" is not proof), asks a voter
	// majority, finds nothing, and leaves probation — never quarantined. A
	// second boot below the same marker is a probation again (I-R3-1): nothing
	// about the lift is remembered.
	now := func() string {
		return strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "date -u '+%Y-%m-%d %H:%M:%S'"))
	}
	since := now()
	l.mustSSH(victim, time.Minute, "systemctl stop litevirt && printf '1\\nrollback: safe_if_unused\\n' > "+
		shellQuote(futureMarker)+" && chmod 600 "+shellQuote(futureMarker)+" && systemctl start litevirt")
	for boot := 1; boot <= 2; boot++ {
		if boot == 2 {
			since = now()
			l.mustSSH(victim, time.Minute, "systemctl restart litevirt")
		}
		if err := l.waitDaemon(victim, 3*time.Minute); err != nil {
			t.Fatal(err)
		}
		var st string
		deadline := time.Now().Add(2 * time.Minute)
		for {
			st = l.mustLV(victim, "cluster", "upgrade-status")
			if strings.Contains(st, "WAL quarantine: yes") {
				l.saveEvidence("upgrade-status-unused.txt", st)
				t.Fatalf("boot %d: %s quarantined for an unused release token's marker:\n%s", boot, victim, st)
			}
			if !strings.Contains(st, "Release probation: yes") {
				break
			}
			if time.Now().After(deadline) {
				l.saveEvidence("upgrade-status-unused.txt", st)
				t.Fatalf("boot %d: %s did not leave release probation:\n%s", boot, victim, st)
			}
			time.Sleep(5 * time.Second)
		}
		l.saveEvidence("upgrade-status-unused.txt", st)
		cmd := "journalctl -u litevirt --since " + shellQuote(since) + " --no-pager | grep -c "
		if out := l.mustSSH(victim, time.Minute, cmd+"'entering release probation' || true"); strings.TrimSpace(out) == "0" {
			t.Errorf("boot %d: %s did not enter release probation below the marker", boot, victim)
		}
		if out := l.mustSSH(victim, time.Minute, cmd+"'release probation lifted' || true"); strings.TrimSpace(out) == "0" {
			t.Errorf("boot %d: %s logged no probation lift", boot, victim)
		}
	}

	// 3. The same marker with no rule: quarantined at startup.
	l.mustSSH(victim, time.Minute, "systemctl stop litevirt && printf '1\\n' > "+shellQuote(futureMarker)+
		" && systemctl start litevirt")
	if err := l.waitDaemon(victim, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	st := l.mustLV(victim, "cluster", "upgrade-status")
	l.saveEvidence("upgrade-status-norule.txt", st)
	if !strings.Contains(st, "WAL quarantine: yes") || !strings.Contains(st, future) {
		t.Fatalf("%s is not quarantined below an unknown token with no rollback rule:\n%s", victim, st)
	}
	logs := l.mustSSH(victim, time.Minute, "journalctl -u litevirt --since '-5 min' --no-pager | grep -c 'ROLLBACK below capability tokens' || true")
	if strings.TrimSpace(logs) == "0" {
		t.Errorf("%s logged no rollback quarantine at startup", victim)
	}
}

// upgradeStatusRow reports whether out has a token row whose rule, BLOCKS
// ROLLBACK and IF RULE-AWARE columns are rule, blocks and ruleAware.
func upgradeStatusRow(out, token, rule, blocks, ruleAware string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 6 && f[0] == token && f[3] == rule && f[4] == blocks && f[5] == ruleAware {
			return true
		}
	}
	return false
}
