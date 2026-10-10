package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/health"
)

// TestDrill_SSHFenceRecordsOffline (colonelpanik/litevirt#253): with
// fence_state_v1 latched, an SSH fence records its host 'offline', never
// 'fenced' — nothing verified the power-off — and still recovers the host's
// workloads exactly once.
//
// The victim's daemon is SIGSTOPped, so its peers see it down while sshd still
// answers: the coordinator's SSH fence reaches it and powers it off for real
// (systemctl poweroff --force --force). Where its VMs run is judged from virsh
// on every node (the sampler), never from litevirt; its state and the fence row
// are read from a survivor's state.db.
func TestDrill_SSHFenceRecordsOffline(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	marker := health.ActivationMarkerPath("/var/lib/litevirt", capabilities.FenceStateV1)
	if out, err := l.ssh(q, 20*time.Second, "test -f "+shellQuote(marker)+" && echo LATCHED"); err != nil || !strings.Contains(out, "LATCHED") {
		t.Skipf("%s has not latched on %s (roll every node to this build first): %v", capabilities.FenceStateV1, q, err)
	}

	victim := l.leastLoaded(q, l.except(q))
	l.createVMs(q, "fs", victim)
	keys := l.relocatableOn(q, b, victim)
	l.mustLV(q, "host", "config", victim, "--fence-strategy", "ssh")
	l.mark("drill fence-state: victim %s (fence ssh), recoverable on victim %v", victim, keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, keys, victim)

	thaw := l.freezeDaemon(victim)
	t.Cleanup(func() { thaw() })
	frozen := time.Now()
	if !l.waitHostNot(q, victim, "HOST_ACTIVE", hostDownBy+time.Minute) {
		t.Fatalf("%s was never marked down after its daemon froze", victim)
	}

	recovered := waitEach(s, frozen, recoverBy, keys, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != victim
	})
	for _, k := range keys {
		if _, ok := recovered[k]; !ok {
			t.Errorf("%s not recovered off %s within %v of an SSH fence\n  %s", k, victim, recoverBy, s.last())
		}
	}

	state := l.mustSQL(q, "SELECT COALESCE((SELECT state FROM host_membership WHERE host_name='"+victim+
		"'), (SELECT state FROM hosts WHERE name='"+victim+"' AND deleted_at IS NULL))")
	if len(state) != 1 || state[0][0] != "offline" {
		t.Errorf("%s is recorded %v after its SSH fence, want offline", victim, state)
	}
	fences := l.mustSQL(q, "SELECT method, result FROM fencing_log WHERE host_name='"+victim+"' AND timestamp >= '"+since+"'")
	sshFenced := false
	for _, f := range fences {
		if len(f) == 2 && f[0] == "ssh" && f[1] == "fenced" {
			sshFenced = true
		}
	}
	if !sshFenced {
		t.Errorf("no ssh/fenced fencing_log row for %s since %s: %v", victim, since, fences)
	}

	// Its return: the victim boots, records itself active, and no second
	// copy appears anywhere.
	_ = thaw()
	if err := l.powerOn(victim); err != nil {
		t.Errorf("power on %s: %v", victim, err)
	}
	l.waitAllActive(q, 6*time.Minute)
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, s, keys)
	s.Stop()
	assertNeverTwice(t, s.snapshot())
}
