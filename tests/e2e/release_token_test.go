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
//     not know) that carries the rule starts unquarantined while none of that
//     token's features is recorded used — the case one token per feature used
//     to quarantine;
//  3. the same node, once that marker carries no rule, starts WAL-quarantined
//     and says so in upgrade-status — today's behaviour for every token.
//
// Steps 2–3 stop the victim's daemon, write a marker into its data directory
// while it is down, and remove it on cleanup. A RECORDED USE is deliberately not
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
	wantBlocks := "no"
	if len(used) == 1 && used[0][0] != "0" {
		wantBlocks = "yes"
	}
	if !upgradeStatusRow(status, tok, "safe_if_unused", wantBlocks) {
		t.Errorf("upgrade-status on %s has no %s row with rule safe_if_unused and BLOCKS ROLLBACK %s "+
			"(%v used records):\n%s", q, tok, wantBlocks, used, status)
	}

	victim := l.hosts[len(l.hosts)-1]
	const future = "release_2099_01_v1"
	futureMarker := health.ActivationMarkerPath("/var/lib/litevirt", future)
	cleanup := func() {
		_, _ = l.ssh(victim, time.Minute, "systemctl stop litevirt; rm -f "+shellQuote(futureMarker)+"; systemctl start litevirt")
		_ = l.waitDaemon(victim, 3*time.Minute)
	}
	t.Cleanup(cleanup)

	// 2. A later release's marker, rule on, nothing used: not quarantined.
	l.mustSSH(victim, time.Minute, "systemctl stop litevirt && printf '1\\nrollback: safe_if_unused\\n' > "+
		shellQuote(futureMarker)+" && chmod 600 "+shellQuote(futureMarker)+" && systemctl start litevirt")
	if err := l.waitDaemon(victim, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	st := l.mustLV(victim, "cluster", "upgrade-status")
	l.saveEvidence("upgrade-status-unused.txt", st)
	if strings.Contains(st, "WAL quarantine: yes") {
		t.Fatalf("%s quarantined for an unused release token's marker:\n%s", victim, st)
	}

	// 3. The same marker with no rule: quarantined at startup.
	l.mustSSH(victim, time.Minute, "systemctl stop litevirt && printf '1\\n' > "+shellQuote(futureMarker)+
		" && systemctl start litevirt")
	if err := l.waitDaemon(victim, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	st = l.mustLV(victim, "cluster", "upgrade-status")
	l.saveEvidence("upgrade-status-norule.txt", st)
	if !strings.Contains(st, "WAL quarantine: yes") || !strings.Contains(st, future) {
		t.Fatalf("%s is not quarantined below an unknown token with no rollback rule:\n%s", victim, st)
	}
	logs := l.mustSSH(victim, time.Minute, "journalctl -u litevirt --since '-5 min' --no-pager | grep -c 'ROLLBACK below capability tokens' || true")
	if strings.TrimSpace(logs) == "0" {
		t.Errorf("%s logged no rollback quarantine at startup", victim)
	}
}

// upgradeStatusRow reports whether out has a token row whose rule and
// BLOCKS ROLLBACK columns are rule and blocks.
func upgradeStatusRow(out, token, rule, blocks string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 5 && f[0] == token && f[3] == rule && f[4] == blocks {
			return true
		}
	}
	return false
}
