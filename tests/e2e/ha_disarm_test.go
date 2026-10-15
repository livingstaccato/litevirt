package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// HA disarm on the lab (docs/migration-failover.md, "Disarming HA for planned
// maintenance"). Both drills leave the lab armed, with every host active.

// heldWatch is how long a disarmed cluster is watched with a host down: well
// past the time an armed cluster takes to fence it and start its workloads
// elsewhere (recoverBy covers the slowest of those).
const heldWatch = recoverBy

// rearmOnCleanup arms HA again when the drill ends, however it ends, before
// the baseline is restored (cleanups run last-registered first).
func (l *lab) rearmOnCleanup(via string) {
	l.t.Cleanup(func() {
		if out, err := l.lv(via, "cluster", "ha", "arm", "--fence-down-hosts", "--reason", "e2e cleanup"); err != nil {
			l.t.Errorf("re-arm HA after the drill: %v\n%s", err, out)
		}
	})
}

// TestDrillHADisarm_PowerOffNothingFenced: with HA disarmed, a host is powered
// off; nothing fences it and nothing of its starts elsewhere. Arm is refused
// while it is down and names it; armed with --fence-down-hosts, it is fenced
// and its workloads recover. It comes back, and the lab ends armed.
func TestDrillHADisarm_PowerOffNothingFenced(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.fenceableWhenOff(q, l.except(q)))
	l.createVMs(q, "had", victim)
	keys := l.relocatableOn(q, b, victim)
	if len(keys) == 0 {
		t.Fatalf("nothing recoverable on %s", victim)
	}
	l.rearmOnCleanup(q)
	l.mustLV(q, "cluster", "ha", "disarm", "--reason", "e2e: power-off drill")
	st := l.mustLV(q, "cluster", "ha")
	if !strings.Contains(st, "HA:        disarmed") {
		t.Fatalf("lv cluster ha after the disarm:\n%s", st)
	}
	l.mark("ha-disarm: disarmed; victim %s, recoverable %v", victim, keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, keys, victim)
	off := l.powerOff(victim)

	time.Sleep(time.Until(off.Add(heldWatch)))
	if rows := l.mustSQL(q, "SELECT host_name,method,result,timestamp FROM fencing_log WHERE timestamp >= '"+since+"'"); len(rows) > 0 {
		t.Errorf("fences recorded while HA was disarmed: %v", rows)
	}
	for _, r := range s.snapshot() {
		for _, k := range keys {
			for _, h := range r.executing(k) {
				if h != victim {
					t.Errorf("%s executed on %s at %s while HA was disarmed", k, h, r.At.UTC().Format("15:04:05.000"))
				}
			}
		}
	}
	for _, row := range l.conditions(q, corrosion.CondHADisarmed, since) {
		l.mark("ha-disarm: condition %v", row)
	}
	if st := l.mustLV(q, "cluster", "ha"); !strings.Contains(st, "Arming would fence: "+victim) {
		t.Errorf("lv cluster ha does not name %s as fenced on arm:\n%s", victim, st)
	}

	out, err := l.lv(q, "cluster", "ha", "arm")
	if err == nil || !strings.Contains(out+err.Error(), victim) {
		t.Fatalf("arm with %s down: err=%v\n%s\nwant a refusal naming it", victim, err, out)
	}
	armed := l.mark("ha-disarm: arm refused, arming with --fence-down-hosts")
	l.mustLV(q, "cluster", "ha", "arm", "--fence-down-hosts", "--reason", "e2e: power-off drill done")
	recovered := waitEach(s, armed, recoverBy, keys, func(r round, k string) bool {
		for _, h := range r.executing(k) {
			if h != victim {
				return true
			}
		}
		return false
	})
	for _, k := range keys {
		if _, ok := recovered[k]; !ok {
			t.Errorf("%s did not recover within %v of the arm\n  %s", k, recoverBy, s.last())
		}
	}
	if err := l.powerOn(victim); err != nil {
		t.Errorf("power on %s: %v", victim, err)
	}
	l.waitAllActive(q, 6*time.Minute)
	s.Stop()
	assertNeverTwice(t, s.snapshot())
}

// TestDrillHADisarm_FleetWideBlipPausesAndResumes: with HA disarmed, a
// fleet-wide nftables drop longer than T_pause still pauses every recoverable
// workload (partition pause is kept), every one resumes after the heal, and
// nothing is fenced or recovered.
func TestDrillHADisarm_FleetWideBlipPausesAndResumes(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	q := l.hosts[0]

	l.createVMs(q, "hab", l.leastLoaded(q, l.hosts))
	keys := l.recoverableOn(q, l.hosts...)
	home := map[string]string{}
	for _, v := range l.vms(q) {
		home["vm/"+v.Name] = v.HostName
	}
	for _, c := range l.containers(q) {
		home["ct/"+c.Name] = c.Host
	}
	l.rearmOnCleanup(q)
	l.mustLV(q, "cluster", "ha", "disarm", "--reason", "e2e: fleet-wide blip")

	since := l.nodeNow(q)
	s := l.startSampler()
	var alone [][]string
	for _, h := range append(append([]string{}, l.hosts...), l.outsiderHosts()...) {
		alone = append(alone, []string{h})
	}
	start, _ := l.partition(alone...)
	pausedAt := waitEach(s, start, 2*minorityPauseBy, keys, func(r round, k string) bool {
		return pausedState(r.state(home[k], k))
	})
	for _, k := range keys {
		if _, ok := pausedAt[k]; !ok {
			t.Errorf("%s never paused on %s with HA disarmed\n  %s", k, home[k], s.last())
		}
	}
	time.Sleep(time.Until(start.Add(longBlip)))
	healed := l.heal()
	resumedAt := waitEach(s, healed, resumeBy, keys, func(r round, k string) bool {
		return r.state(home[k], k) == "running"
	})
	for _, k := range keys {
		if _, ok := resumedAt[k]; !ok {
			t.Errorf("%s did not resume on %s within %v of the heal\n  %s", k, home[k], resumeBy, s.last())
		}
	}
	time.Sleep(time.Minute)
	s.Stop()
	assertNeverTwice(t, s.snapshot())
	if rows := l.mustSQL(q, "SELECT host_name,method,result,timestamp FROM fencing_log WHERE timestamp >= '"+since+"'"); len(rows) > 0 {
		t.Errorf("fences recorded during the blip: %v", rows)
	}
	for _, k := range keys {
		kind, name, _ := strings.Cut(k, "/")
		if kind == "ct" {
			kind = "container"
		}
		if ps := l.proofsSince(q, kind, name, since); len(ps) > 0 {
			t.Errorf("%s has recovery proofs minted during the blip: %+v", k, ps)
		}
	}
	if states, err := l.hostStates(q); err != nil {
		t.Errorf("host states: %v", err)
	} else {
		for _, h := range l.hosts {
			if states[h] != "HOST_ACTIVE" {
				t.Errorf("%s is %s after the blip", h, states[h])
			}
		}
	}
}
