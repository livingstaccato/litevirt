package e2e

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/notify"
)

// Witness and partition-pause drills
// (.superpowers/sdd/plan-residuals-2026-10-05/witness-drill-design.md). They
// reach what TestDrill1b_WitnessReachesBothSides cannot: a bridge on the
// MAJORITY side of a host the majority cannot fence (its SSH cut), a lease
// that changes hands mid-outage, a claim retry across two outages of one
// host, and stepped node clocks.
//
// Every drill checks the lab is the one the design reasons about
// (requireWitnessTopology: five workers voting, one witness outside them that
// does not vote, the tokens latched) and skips, saying why, when it is not.
// Every fault registers its undo before it goes in; every drill samples where
// each workload executes once a second and checks assertNeverTwice over every
// sample in a cleanup, however it ends (startCheckedSampler). Log lines and
// condition codes asserted here are quoted from the code at 03fe9868, with
// their file:line.

// TestDrillW1_WitnessBridgedStall is scenarios 1, 2 and 6.2 of the design: on a
// DERIVED voter set (lv cluster voter reset), a victim the majority cannot
// SSH-fence is held, visibly, while observers outside the majority see it
// answer, and recovered within two coordinator polls once the last of them
// stops seeing it.
//
//   - P0, the before-fence form: V cut from M, SSH cut from everyone. V pauses;
//     only M (3 of the derived 6) fail it, under the derived quorum of 4, so
//     nothing fences it, and ha.recovery.bridged opens with "has kept its
//     workloads paused since" (failover/bridged_stall.go:94), observers ⊇
//     {B, W}, derived_voter_set=true.
//   - P1, the deadline form: V also cut from B. Four voters fail it, the
//     best-effort fence fails and becomes a self-pause (partition_pause.go:154),
//     and at the deadline W's fresh answer refuses the recovery
//     (partition_pause.go:227, coordinator.go:2389). The condition says "the
//     partition-pause deadline of V passed" (bridged_stall.go:59), observers
//     [W]; the stall alert names the refusal (partition_pause.go:229,
//     fence_wake.go:367) 60–90 s after the fence row and reaches Mailpit as
//     "error: host.recovery.stalled V" (notify/email.go EmailSubject);
//     `lv host fence-confirm V` is refused (grpcapi/fence_confirm_liveness.go:78).
//     For four minutes nothing is minted and the VM stays paused on V only.
//   - P2: V also cut from W. W's row turns failing; the deadline goes ahead
//     (partition_pause.go:193) within two polls of that row reaching the
//     holder's replica, ha.recovery.bridged resolves with "the partition-pause
//     deadline went ahead" (partition_pause.go:192, bridged_stall.go:246), and
//     the VM executes on the majority — never before P2.
//
// The baseline voter generation is put back with `lv cluster voter init` once
// the replacement's proof completed (restore does it too, on failure).
func TestDrillW1_WitnessBridgedStall(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	w := l.requireWitnessTopology(l.hosts[0])
	V, B, M, W := l.hosts[0], l.hosts[1], l.hosts[2:], w.witness
	q := M[0]
	// V and B must be on best-effort, whose failed power-off is a self-pause;
	// restore puts their baseline strategies back.
	for _, h := range []string{V, B} {
		if !bestEffort(l.fenceStrategy(q, h)) {
			l.setStrategy(q, h, "best-effort")
		}
	}
	mp := mailpitFromEnv()
	mail := l.mailpitReachable(q, mp)
	if !mail {
		l.mark("w1: Mailpit does not answer at %s from %s (E2E_MAILPIT); the stall notification is not checked", mp.api, q)
	}
	test := l.createVMsWhereRoom(q, "w1", V)[V]
	if test == "" {
		t.Skipf("no room on %s for the test VM", V)
	}
	key := "vm/" + test
	keys := []string{key}
	vrec := l.vms(q)[test]
	if mail {
		l.addMailpitRoute(q, mp, notify.KindHostRecoveryStalled)
	}
	gen := l.voterReset(q)
	time.Sleep(capRefreshWait)
	l.mark("w1: V=%s B=%s M=%v W=%s, derived voter set at generation %d, test VM %s", V, B, M, W, gen, test)

	since := l.nodeNow(q)
	s := l.startCheckedSampler()
	waitAllAt(t, s, keys, V)
	lw := l.watchLease(l.allBut(V))
	others := l.allBut(V)
	majority := append([]string{B}, M...)

	// ── P0: the before-fence form ───────────────────────────────────────────
	tP0 := l.cutEdges(edgesFrom(V, M...)...)
	l.sshCut(q, V, append([]string{B, W}, M...))
	pausedAt := waitEach(s, tP0, 2*minorityPauseBy, keys, func(r round, k string) bool { return pausedState(r.state(V, k)) })
	if at, ok := pausedAt[key]; !ok {
		t.Fatalf("P0: %s never paused on %s within %v (it reaches 3 of 6)\n  %s", key, V, 2*minorityPauseBy, s.last())
	} else if d := at.Sub(tP0); d > minorityPauseBy+sampleSlop {
		t.Errorf("P0: %s paused %v after the cut; bound %v (+%v sampling)", key, d, minorityPauseBy, sampleSlop)
	}
	pausedRow := fmt.Sprintf("SELECT 1 FROM health_conditions WHERE evaluator='%s' AND code='%s' AND subject_kind='host' AND subject_id IN ('%s','host/%s') AND lifecycle != 'resolved' AND deleted_at IS NULL",
		corrosion.PartitionPauseEvaluator, corrosion.CondPartitionPaused, V, V)
	arrival := l.sampleRowArrival(corrosion.CondPartitionPaused+"/"+V, func() string { return lw.current().Holder }, pausedRow)
	if c, _, ok := l.waitBridged(q, V, V+" has kept its workloads paused since", 5*time.Minute); !ok {
		t.Errorf("P0: no %s for %s in its before-fence form within 5m (bridged_stall.go:94)", condBridged, V)
	} else {
		for _, o := range []string{B, W} {
			if !contains(c.Bridged.Observers, o) {
				t.Errorf("P0: %s observers %v lack %s", condBridged, c.Bridged.Observers, o)
			}
		}
		if !c.Bridged.DerivedVoterSet {
			t.Errorf("P0: %s says derived_voter_set=false after a voter reset", condBridged)
		}
		if !contains(c.Bridged.Workloads, key) {
			t.Errorf("P0: %s workloads %v lack %s", condBridged, c.Bridged.Workloads, key)
		}
	}
	if at, on, ok := arrival.result(); ok {
		l.mark("w1: P0 %s/%s reached the holder %s's replica at +%v (the minority row's crossing through W/B)", corrosion.CondPartitionPaused, V, on, at.Sub(tP0).Round(time.Second))
	} else {
		l.mark("w1: P0 %s/%s not seen in the holder's replica", corrosion.CondPartitionPaused, V)
	}
	if _, _, ok := l.waitLogLine(others, since, journalPair("failover: a paused host's workloads are held while observers outside the majority see it answer", "host", V), time.Time{}, nil, time.Minute); !ok {
		t.Errorf("P0: no holder logged the bridged hold of %s (bridged_stall.go:188)", V)
	}
	if _, row, ok := l.newestFenceRow(q, V, since); ok {
		t.Errorf("P0: %s was fenced (%s) with only %v failing it, under the derived quorum", V, row, M)
	}
	for _, h := range others {
		if j := strings.TrimSpace(l.journalSince(h, since, stallPattern(V))); j != "" {
			t.Errorf("P0: %s raised the stall alert for %s, which is no fenced or offline host:\n%s", h, V, j)
		}
	}

	// ── P1: the deadline form, bridged by the witness ───────────────────────
	tP1 := l.cutEdges([2]string{V, B})
	decider, ql, ok := l.waitLogLine(others, since, journalPair("host exceeded failure threshold", "host", V), tP1.Add(-clockSlack), nil, 90*time.Second)
	if !ok {
		t.Fatalf("P1: no coordinator reached a fence quorum for %s within 90 s of cutting it from %s (coordinator.go:1155)", V, B)
	}
	if !strings.Contains(ql.Text, "observers=4") || !strings.Contains(ql.Text, "quorum=4") {
		t.Errorf("P1: the fence decision is not 4 failing voters against the derived quorum 4: %s", ql.Text)
	}
	if d := ql.At.Sub(tP1); d > 25*time.Second+clockSlack {
		t.Errorf("P1: fence quorum for %s at +%v; design bound +25 s", V, d.Round(time.Second))
	}
	if _, _, ok := l.waitLogLine([]string{decider}, since, journalPair("relying on the host's partition pause", "host", V), time.Time{}, nil, 30*time.Second); !ok {
		t.Errorf("P1: %s never relied on %s's partition pause (partition_pause.go:154): the fence was not a self-pause", decider, V)
	}
	fenceAt := l.waitSelfPauseFence(q, V, since)
	c, _, ok := l.waitBridged(q, V, "the partition-pause deadline of "+V+" passed", time.Until(tP1.Add(90*time.Second)))
	if !ok {
		t.Errorf("P1: no %s for %s in its deadline form by +90 s (bridged_stall.go:59)", condBridged, V)
	} else {
		if strings.Join(c.Bridged.Observers, ",") != W {
			t.Errorf("P1: %s observers %v, want [%s]", condBridged, c.Bridged.Observers, W)
		}
		if !contains(c.Bridged.Workloads, key) {
			t.Errorf("P1: %s workloads %v lack %s", condBridged, c.Bridged.Workloads, key)
		}
	}
	if _, _, ok := l.waitLogLine(others, since, journalPair("partition-pause deadline passed, but the host may not have paused", "host", V), tP1.Add(-clockSlack), []string{"observer " + W + " saw the host answer after the fence"}, 30*time.Second); !ok {
		t.Errorf("P1: no deadline refusal for %s naming observer %s (partition_pause.go:227)", V, W)
	}
	if _, sl, ok := l.waitStallLine(others, since, V, "recovery refused at the partition-pause deadline", time.Time{}, time.Until(fenceAt.Add(recoveryStallAfter+30*time.Second+clockSlack))); !ok {
		t.Errorf("P1: no stall alert for %s naming the deadline refusal by fence row + 90 s (fence_wake.go:367)", V)
	} else {
		if d := sl.At.Sub(fenceAt); d < recoveryStallAfter-clockSlack || d > recoveryStallAfter+30*time.Second+clockSlack {
			t.Errorf("P1: stall alert %v after the fence row; want 60–90 s", d.Round(time.Second))
		}
		if !strings.Contains(sl.Text, "lv host fence-confirm "+V) {
			t.Errorf("P1: the stall alert's reason does not name the remedy 'lv host fence-confirm %s': %s", V, sl.Text)
		}
	}
	if !mail {
		l.mark("w1: P1 notification not checked (no Mailpit)")
	} else if subj, ok := l.mailpitWait(q, mp, notify.KindHostRecoveryStalled+" "+V, tP1, 90*time.Second); !ok {
		t.Errorf("P1: Mailpit never received %s %s", notify.KindHostRecoveryStalled, V)
	} else if !strings.Contains(subj, "error: "+notify.KindHostRecoveryStalled+" "+V) {
		t.Errorf("P1: notification subject %q, want it to contain %q", subj, "error: "+notify.KindHostRecoveryStalled+" "+V)
	}
	l.requireFenceConfirmRefused(q, W, V, "Power it off first", W)
	time.Sleep(time.Until(tP1.Add(4 * time.Minute)))
	l.mark("w1: P1 held 4 minutes")
	if ps := l.proofsSince(q, "vm", test, since); len(ps) > 0 {
		t.Errorf("P1: recovery proofs minted during the bridged hold: %+v", ps)
	}
	if c, ok, _ := l.condition(q, evalFailover, condBridged, V); !ok || c.Lifecycle != "confirmed" {
		t.Errorf("P1: %s for %s is %q after the hold, want confirmed", condBridged, V, c.Lifecycle)
	}
	if at, ok := pausedAt[key]; ok {
		assertPausedOn(t, s.snapshot(), key, V, at.Add(sampleSlop), time.Now(), "P0–P1")
	}
	if hs := holdersBetween(lw, tP1, time.Now()); len(hs) == 1 {
		n := 0
		for _, ln := range l.journalLines(hs[0], since, journalPair("partition-pause deadline passed, but the host may not have paused", "host", V)) {
			if !ln.At.Before(tP1.Add(-clockSlack)) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("P1: %s logged the deadline refusal of %s %d times at Warn; the same refusal re-checked every cycle logs at Debug (partition_pause.go:218), want 1", hs[0], V, n)
		}
	} else {
		l.mark("w1: the lease moved during P1 (%v); the one-Warn-per-refusal count is not checked", hs)
	}

	// ── P2: the stall clears when the bridge goes ───────────────────────────
	holder := lw.current().Holder
	tP2 := l.cutEdges([2]string{V, W})
	tw, _, ok := l.waitHealthRow(holder, W, V, failing, 30*time.Second)
	if !ok {
		t.Errorf("P2: %s's failing row about %s never reached the holder %s's replica within 30 s", W, V, holder)
	}
	recAt := waitEach(s, tP2, 90*time.Second, keys, func(r round, k string) bool {
		for _, h := range r.executing(k) {
			if contains(majority, h) {
				return true
			}
		}
		return false
	})
	if at, ok := recAt[key]; !ok {
		t.Errorf("P2: %s not executing on the majority within 90 s of cutting %s from %s\n  %s", key, V, W, s.last())
	} else {
		l.mark("w1: P2 %s executing at +%v on %v", key, at.Sub(tP2).Round(time.Second), s.last().executing(key))
	}
	assertOnlyOn(t, s.snapshot(), key, V, tP0, tP2, "P0–P1")
	ps := l.waitProofs(q, "vm", test, since, 1, time.Minute)
	if len(ps) != 1 {
		t.Errorf("P2: %d recovery proofs for %s, want 1: %+v", len(ps), test, ps)
	} else {
		if !l.waitProofStatus(q, ps[0].ID, "completed", 2*time.Minute) {
			t.Errorf("P2: proof %s never completed (status %q)", ps[0].ID, l.proofStatus(q, ps[0].ID))
		}
		if created, ok := corrosion.ParseUpdatedAt(ps[0].Created); ok && !tw.IsZero() {
			lat := created.Sub(tw)
			l.mark("w1: recovery decided %v after %s's failing row reached the holder", lat.Round(time.Second), W)
			if lat > 2*coordinatorPoll+clockSlack {
				t.Errorf("P2: the recovery came %v after the last answering observer's row turned failing in the holder's replica; the deadline is re-checked every cycle, want ≤ 2 polls (%v)", lat, 2*coordinatorPoll)
			}
		}
	}
	if _, _, ok := l.waitLogLine(others, since, journalPair("partition-pause deadline passed; recovering the host's workloads", "host", V), tP2.Add(-clockSlack), nil, 30*time.Second); !ok {
		t.Errorf("P2: no holder logged the deadline going ahead for %s (partition_pause.go:193)", V)
	}
	if _, ok := l.waitBridgedResolved(q, V, time.Minute); !ok {
		t.Errorf("P2: %s for %s not resolved within a minute of the recovery", condBridged, V)
	}
	if _, _, ok := l.waitLogLine(others, since, journalPair("failover: "+condBridged+" resolved", "host", V), tP2.Add(-clockSlack), []string{"the partition-pause deadline went ahead"}, 30*time.Second); !ok {
		t.Errorf("P2: no '%s resolved' line for %s with reason 'the partition-pause deadline went ahead' (bridged_stall.go:246)", condBridged, V)
	}
	recovered := time.Now()
	if at, ok := recAt[key]; ok {
		recovered = at
	}

	// ── heal and settle ─────────────────────────────────────────────────────
	healed := l.heal()
	if at, ok := waitEach(s, healed, settleBy, keys, func(r round, k string) bool {
		st := r.state(V, k)
		_, down := r.Down[V]
		return !down && st != "running" && st != "paused" && st != "frozen"
	})[key]; !ok {
		t.Errorf("%s: the superseded copy on %s was not stopped within %v of the heal\n  %s", key, V, settleBy, s.last())
	} else {
		l.mark("w1: %s settled on %s at heal+%v", key, V, at.Sub(healed).Round(time.Second))
		for _, d := range vrec.Disks {
			if !l.fileExists(V, d.Path) {
				t.Errorf("%s: settle on %s deleted disk %s", key, V, d.Path)
			}
		}
	}
	time.Sleep(tPause + 10*time.Second)
	assertExactlyOnceNow(t, s, keys)
	for _, h := range others {
		for _, ln := range l.journalLines(h, since, stallPattern(V)) {
			if ln.At.After(recovered.Add(clockSlack)) {
				t.Errorf("a stall alert for %s after its recovery completed (fence_wake.go:328 drops the stall clock once nothing is pending): %s: %s", V, h, ln.Text)
			}
		}
	}
	l.waitAllActive(q, 8*time.Minute)
	if err := l.voterInit(q, b.allVoters); err != nil {
		t.Errorf("voter init back to %v: %v", b.allVoters, err)
	}
	s.Stop() // the exactly-once check runs in startCheckedSampler's cleanup
	assertNoDualRun(t, l, q, since, healed)
}

// TestDrillW3_LeaseChurnDuringAPausedManualHold is scenario 3 (and 6.1): a
// victim on the MANUAL fence, fully isolated (the witness too), paused and
// held awaiting `lv host fence-confirm`, while the failover lease is moved
// round the majority — once by stopping the holder's daemon, then by freezing
// each holder past its lease — until a node takes the lease back IN THE SAME
// PROCESS that held it before.
//
//   - the hold: "MANUAL FENCE REQUIRED" (fence/fence.go:495), V offline, and
//     the stall alert "manual fence awaiting" (coordinator.go:3345) 60 s
//     after the fence row; the witness's failing row about V reaches the holder
//     fresh but does not vote: the decision says observers=4 quorum=3;
//   - each new tenure re-alerts for V (fence_wake.go:367) and has a higher
//     lease term than the last;
//   - the regain: the regaining node re-alerts within 2 polls + 5 s, less
//     than recoveryStallRepeat (10 min) after its own previous alert — which
//     only forgetEpisodes clearing stallAlerted on a new tenure allows
//     (coordinator.go:1286);
//   - throughout, nothing is minted and the VM stays paused on V; after the
//     heal it resumes in place (health/partition_pause.go:1051).
//
// Every host, the witness included, is on the manual fence for the drill (a
// stopped or frozen holder looks dead to its peers); restore puts each back.
// No regain within six rounds ends the drill as skipped (inconclusive), with
// the evidence.
func TestDrillW3_LeaseChurnDuringAPausedManualHold(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	w := l.requireWitnessTopology(l.hosts[0])
	V, W := l.hosts[0], w.witness
	q := l.hosts[1]
	test := l.createVMsWhereRoom(q, "w3", V)[V]
	if test == "" {
		t.Skipf("no room on %s for the test VM", V)
	}
	key := "vm/" + test
	keys := []string{key}
	for _, h := range l.allBut() {
		if l.fenceStrategy(q, h) != "manual" {
			l.setStrategy(q, h, "manual")
		}
	}
	others := l.allBut(V)
	frozen := map[string]bool{}
	via := func() string {
		for _, h := range others {
			if !frozen[h] {
				return h
			}
		}
		return q
	}

	since := l.nodeNow(q)
	s := l.startCheckedSampler()
	waitAllAt(t, s, keys, V)
	lw := l.watchLease(others)
	start, _ := l.partition([]string{V}, l.hosts[1:])
	pausedAt := waitEach(s, start, 2*minorityPauseBy, keys, func(r round, k string) bool { return pausedState(r.state(V, k)) })
	if _, ok := pausedAt[key]; !ok {
		t.Fatalf("%s never paused on the isolated %s\n  %s", key, V, s.last())
	}
	fencer, _, ok := l.waitLogLine(others, since, journalPair("MANUAL FENCE REQUIRED", "host", V), time.Time{}, nil, 3*time.Minute)
	if !ok {
		t.Fatalf("no holder logged MANUAL FENCE REQUIRED for %s within 3m (fence/fence.go:495)", V)
	}
	if _, dl, ok := l.waitLogLine(others, since, journalPair("host exceeded failure threshold", "host", V), time.Time{}, nil, 30*time.Second); !ok {
		t.Errorf("no fence decision line for %s", V)
	} else if !strings.Contains(dl.Text, "observers=4") || !strings.Contains(dl.Text, "quorum=3") {
		t.Errorf("the fence decision for %s does not count the 4 worker voters against quorum 3 (the witness must not vote): %s", V, dl.Text)
	}
	// 6.1: the witness's failing row reaches the holder, fresh, and does not vote.
	if _, r, ok := l.waitHealthRow(fencer, W, V, func(r healthRow) bool { return r.Failures >= 5 && r.Status == "suspect" }, time.Minute); !ok {
		t.Errorf("the holder %s's replica holds no suspect row (failures ≥ 5) from the witness %s about %s", fencer, W, V)
	} else if now, ok := corrosion.ParseUpdatedAt(l.nodeNow(fencer)); ok && now.Sub(r.Updated) > 30*time.Second {
		t.Errorf("the witness's row about %s in %s's replica is %v old, want ≤ 30 s: %s", V, fencer, now.Sub(r.Updated), r.Raw)
	}
	if !l.waitHostNot(q, V, "HOST_ACTIVE", hostDownBy) {
		t.Errorf("%s still active %v after its isolation", V, hostDownBy)
	}
	fenceAt, row, ok := l.newestFenceRow(q, V, since)
	if !ok {
		t.Fatalf("no fencing_log row for %s since %s", V, since)
	}
	l.mark("w3: fence row %s", row)
	stallBy := time.Until(fenceAt.Add(recoveryStallAfter + 30*time.Second + clockSlack))
	if _, _, ok := l.waitStallLine(others, since, V, "manual fence awaiting", time.Time{}, stallBy); !ok {
		t.Errorf("no stall alert for %s naming the manual fence by fence row + 90 s", V)
	}

	// ── churn the lease ─────────────────────────────────────────────────────
	pids := map[string]string{} // a holder → its daemon's PID when it held the lease
	prevTerm := lw.current().Term
	checkTenure := func(c leaseChange) {
		t.Helper()
		if c.Term <= prevTerm {
			t.Errorf("lease: %s took the lease at term %d, not above the previous %d", c.Holder, c.Term, prevTerm)
		} else if c.Term != prevTerm+1 {
			l.mark("lease: term moved %d → %d on one change", prevTerm, c.Term)
		}
		prevTerm = c.Term
		_, ln, ok := l.waitStallLine([]string{c.Holder}, since, V, "", c.At.Add(-clockSlack), recoveryStallAfter+2*coordinatorPoll+5*time.Second+clockSlack)
		if !ok {
			t.Errorf("new tenure: %s never alerted the stall of %s after taking the lease at term %d", c.Holder, V, c.Term)
			return
		}
		d := ln.At.Sub(c.At)
		l.mark("tenure: %s (term %d) re-alerted %s %v after taking the lease (within 2 polls + 5 s: %v)", c.Holder, c.Term, V, d.Round(time.Second), d <= 2*coordinatorPoll+5*time.Second+clockSlack)
	}
	thawCheck := func(h string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for {
			if st, err := l.hostStates(via()); err == nil && st[h] == "HOST_ACTIVE" {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("the thawed holder %s is not HOST_ACTIVE 2 minutes after its thaw: a frozen holder must not end up fenced", h)
				l.waitActive(via(), []string{h}, 5*time.Minute)
				return
			}
			time.Sleep(5 * time.Second)
		}
	}
	h1 := lw.current().Holder
	if h1 == "" || h1 == V {
		t.Fatalf("lease holder %q after %s's isolation", h1, V)
	}
	next, ok := l.handoverByStop(via(), h1, lw)
	if !ok {
		t.Fatalf("round 1: the lease did not leave %s within %v of stopping it", h1, failoverLeaseTTL+15*time.Second)
	}
	checkTenure(next)
	pids[next.Holder] = l.mainPID(next.Holder)
	regain := ""
	var regainAt time.Time
	for round := 2; round <= 6 && regain == ""; round++ {
		cur := lw.current()
		if _, ok := pids[cur.Holder]; !ok {
			pids[cur.Holder] = l.mainPID(cur.Holder)
		}
		l.mark("round %d: freezing the holder %s (pid %s, term %d)", round, cur.Holder, pids[cur.Holder], cur.Term)
		frozen[cur.Holder] = true
		next, ok := l.handoverByFreeze(via(), cur.Holder, lw)
		frozen[cur.Holder] = false
		thawCheck(cur.Holder)
		if !ok {
			t.Errorf("round %d: the lease did not leave the frozen %s within %v", round, cur.Holder, holderFreeze)
			break
		}
		checkTenure(next)
		if pid, held := pids[next.Holder]; held && pid != "" && pid == l.mainPID(next.Holder) {
			regain, regainAt = next.Holder, next.At
			l.mark("round %d: %s took the lease back in the same process (pid %s)", round, regain, pid)
		} else {
			pids[next.Holder] = l.mainPID(next.Holder)
		}
	}
	if regain != "" {
		var prev, again logLine
		for _, ln := range l.journalLines(regain, since, stallPattern(V)) {
			switch {
			case ln.At.Before(regainAt.Add(-clockSlack)):
				prev = ln
			case again.At.IsZero():
				again = ln
			}
		}
		switch {
		case again.At.IsZero():
			t.Errorf("regain: %s took the lease back and never re-alerted the stall of %s", regain, V)
		case prev.At.IsZero():
			t.Errorf("regain: %s has no stall alert for %s from its earlier tenure to compare with", regain, V)
		default:
			if d := again.At.Sub(regainAt); d > 2*coordinatorPoll+5*time.Second+clockSlack {
				t.Errorf("regain: %s re-alerted %v after retaking the lease; want within 2 polls + 5 s (a fresh tenure re-derives the stall clock from the old fence row)", regain, d.Round(time.Second))
			}
			if gap := again.At.Sub(prev.At); gap >= recoveryStallRepeat {
				l.mark("regain: %v between %s's two stall alerts, not under %v: this regain cannot discriminate", gap.Round(time.Second), regain, recoveryStallRepeat)
				regain = "" // inconclusive, as no regain is
			} else {
				l.mark("regain: %s re-alerted %v after its previous alert (< %v: forgetEpisodes cleared stallAlerted)", regain, gap.Round(time.Second), recoveryStallRepeat)
			}
		}
	}
	var lost strings.Builder
	for _, h := range others {
		if j := strings.TrimSpace(l.journalSince(h, since, "lease lost, unshown or renewed as a new tenure mid-cycle, aborting")); j != "" {
			fmt.Fprintf(&lost, "== %s\n%s\n", h, j)
		}
	}
	l.saveEvidence("lease-lost.txt", lost.String())
	if ps := l.proofsSince(via(), "vm", test, since); len(ps) > 0 {
		t.Errorf("recovery proofs minted for %s on the unconfirmed manual hold: %+v", test, ps)
	}
	l.saveEvidence("lease-history.txt", fmt.Sprintf("%+v\n", lw.history()))

	// ── heal: V resumes in place ────────────────────────────────────────────
	healed := l.heal()
	assertPausedOn(t, s.snapshot(), key, V, pausedAt[key].Add(sampleSlop), healed, "the manual hold")
	if _, ok := waitEach(s, healed, resumeBy+time.Minute, keys, func(r round, k string) bool { return r.state(V, k) == "running" })[key]; !ok {
		t.Errorf("%s did not resume on %s after the heal\n  %s", key, V, s.last())
	}
	if _, _, ok := l.waitLogLine([]string{V}, since, journalPair("partition-pause: resumed workload", "name", test), time.Time{}, nil, time.Minute); !ok {
		t.Errorf("%s never logged resuming %s (health/partition_pause.go:1051)", V, test)
	}
	l.waitAllActive(via(), 6*time.Minute)
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, s, keys)
	s.Stop() // the exactly-once check runs in startCheckedSampler's cleanup
	if regain == "" && !t.Failed() {
		t.Skipf("inconclusive: no discriminating regain (a node retaking the lease in the same process within 10 min of its last alert) in 6 rounds (holders %v); the regain reset was not exercised", lw.holders())
	}
}

// w4Setup is W4a's and W4b's start: drill 4's owner-reachable claim refusal
// (TestDrill4_OwnerReachableVetoesTheClaim), on a best-effort owner, with the
// owner's partition pause off.
type w4Setup struct {
	owner, keep, q, test, key, since, decider string
	s                                         *sampler
}

func (l *lab) w4Begin(prefix string, watch time.Duration) w4Setup {
	l.t.Helper()
	coord := l.leaseHolder(l.hosts[0], "failover")
	var cands []string
	for _, h := range l.except(coord) {
		if bestEffort(l.fenceStrategy(l.hosts[0], h)) {
			cands = append(cands, h)
		}
	}
	if len(cands) == 0 {
		l.t.Skipf("no best-effort host but the lease holder %s to own the test VM", coord)
	}
	var w w4Setup
	w.owner = l.leastLoaded(l.hosts[0], cands)
	w.keep = l.pick(func(h string) bool { return h != coord && h != w.owner }, true)
	w.q = l.pick(func(h string) bool { return h != w.owner && h != w.keep }, false)
	w.test = l.createVMs(w.q, prefix, w.owner)[w.owner]
	w.key = "vm/" + w.test
	// Booting a best-effort host again with plain lab.sh after the drill
	// powered it off must not race a fence of it: put it on manual first.
	l.t.Cleanup(func() {
		if !l.isUp(w.owner) {
			if v := l.liveHost(); v != "" {
				l.lv(v, "host", "config", w.owner, "--fence-strategy", "manual")
			}
		}
	})
	if err := l.setEnforcement(w.owner, "partition_pause", "false"); err != nil {
		l.t.Fatalf("partition_pause off on %s: %v", w.owner, err)
	}
	time.Sleep(capRefreshWait)
	l.mark("%s: owner %s (best-effort, partition_pause off), keep %s", prefix, w.owner, w.keep)
	w.since = l.nodeNow(w.q)
	w.s = l.startCheckedSampler()
	waitAllAt(l.t, w.s, []string{w.key}, w.owner)
	w.decider, _ = l.ownerReachableClaimRefusal(w.owner, w.keep, w.since, watch)
	return w
}

// outage1Value reads the claim after outage 1: no attempt is decided, and it
// returns the proof of a value some voter accepted (P1), the voters that hold
// it and their attempt, or "" when none did.
func (l *lab) outage1Value(w w4Setup, via string) (p1 string, acceptors []string, attempt int) {
	l.t.Helper()
	att, out := l.claimView(via, w.key, "claim-outage1.txt")
	for _, a := range att {
		if a.Decided {
			l.t.Errorf("outage 1: attempt %d of %s is decided although its owner was reachable:\n%s", a.N, w.key, out)
		}
		if acc := a.acceptedUndecided(); len(acc) > 0 && p1 == "" {
			p1, attempt = acc[0].Proof, a.N
			for _, v := range acc {
				if v.Proof == p1 {
					acceptors = append(acceptors, v.Voter)
				}
			}
		}
	}
	if _, _, ok := l.waitLogLine([]string{w.decider}, w.since, journalPair("recovery claim formed no certificate", "name", w.test), time.Time{}, nil, 10*time.Second); !ok {
		l.t.Errorf("outage 1: %s never logged the claim for %s forming no certificate (failover/claims.go:501)", w.decider, w.test)
	}
	l.mark("outage 1: accepted value proof %q at attempt %d by %v", p1, attempt, acceptors)
	return p1, acceptors, attempt
}

// powerOnOwnerManual boots the owner again on the manual fence, waits it
// active, then gives it its baseline fence strategy two minutes later.
func (l *lab) powerOnOwnerManual(via, owner, strategy string) {
	l.t.Helper()
	l.setStrategy(via, owner, "manual")
	if err := l.powerOn(owner); err != nil {
		l.t.Errorf("power on %s: %v", owner, err)
	}
	l.waitActive(via, []string{owner}, 6*time.Minute)
	time.Sleep(2 * time.Minute)
	if strategy != "" {
		l.setStrategy(via, owner, strategy)
	}
}

// TestDrillW4a_PartialAcceptAdoptedAfterALeaseChange is scenario 4a: a value
// one voter accepted in a refused claim (drill 4's outage: only the deciding
// coordinator is cut from the reachable owner) survives the heal and a lease
// term change, and the owner's next outage — a power-off, with one other voter
// frozen so every promise majority includes that acceptor — must still
// recover the VM exactly once.
//
//   - A (pass): the decided proof is P1, adopted, and it executed;
//   - B (pass, "not adopted"): a fresh proof was decided and executed;
//   - C (FAIL, design question Q5): the decided proof is P1, the VM does not
//     run by recoverBy, and the destination logs "reconciler: pending proof
//     refused by the lease-term gate" for it (health/reconciler.go:1634).
//
// A run in which no voter accepted a value in outage 1 is skipped as
// inconclusive, with the claim view saved.
func TestDrillW4a_PartialAcceptAdoptedAfterALeaseChange(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	l.requireWitnessTopology(l.hosts[0])
	w := l.w4Begin("w4a", claimWatch)
	via := l.pick(func(h string) bool { return h != w.owner && h != w.decider }, false)
	p1, acceptors, attempt := l.outage1Value(w, via)
	if p1 == "" {
		l.clearDrops(w.owner)
		t.Skipf("inconclusive: the stale-value path was not produced this run (no voter accepted a value for %s in outage 1; claim-outage1.txt)", w.key)
	}
	if attempt != 0 {
		l.mark("w4a: the accepted value is at attempt %d, not 0", attempt)
	}
	t1 := l.leaseTerm(via, "failover")

	// Heal: the owner comes back, with its partition pause on again.
	if err := l.clearDrops(w.owner); err != nil {
		t.Fatal(err)
	}
	l.mark("w4a: healed outage 1")
	l.waitActive(via, []string{w.owner}, 8*time.Minute)
	if _, err := l.restoreConfig(w.owner); err != nil {
		t.Errorf("restore %s's config: %v", w.owner, err)
	}
	time.Sleep(capRefreshWait)
	att, out := l.claimView(via, w.key, "claim-after-heal.txt")
	kept := false
	for _, a := range att {
		for _, v := range a.Voters {
			kept = kept || (contains(acceptors, v.Voter) && v.Accepted != "-" && v.Proof == p1)
		}
	}
	if !kept {
		t.Errorf("after the heal no voter of %v still holds the accepted value with proof %s (acceptor state is durable):\n%s", acceptors, p1, out)
	}

	// A lease-term change.
	lw := l.watchLease(l.allBut(w.owner))
	h := l.leaseHolder(via, "failover")
	v2 := l.pick(func(x string) bool { return x != h && x != w.owner }, false)
	l.setStrategy(v2, h, "manual")
	if _, ok := l.handoverByStop(v2, h, lw); !ok {
		t.Fatalf("the lease did not leave %s within %v of stopping it", h, failoverLeaseTTL+15*time.Second)
	}
	l.waitActive(v2, []string{h}, 3*time.Minute)
	if s := b.strategies[h]; s != "" {
		l.setStrategy(v2, h, s)
	}
	if t2 := l.leaseTerm(v2, "failover"); t2 <= t1 {
		t.Fatalf("the lease term is %d after the handover, not above outage 1's %d", t2, t1)
	} else {
		l.mark("w4a: lease term %d → %d", t1, t2)
	}

	// Outage 2: one voter frozen, so every promise majority includes the acceptor.
	holder := l.leaseHolder(v2, "failover")
	x := ""
	for _, c := range l.hosts {
		if c != w.owner && c != w.decider && c != holder && !contains(acceptors, c) {
			x = c
			break
		}
	}
	if x == "" {
		t.Skipf("no voter to freeze outside owner %s, decider %s, holder %s and acceptors %v", w.owner, w.decider, holder, acceptors)
	}
	l.setStrategy(v2, x, "manual")
	thaw := l.freezeDaemon(x)
	lw.avoid(x, true)
	timer := time.AfterFunc(3*time.Minute, func() { thaw() })
	t.Cleanup(func() { timer.Stop(); thaw() })
	off := l.powerOff(w.owner)
	recAt := waitEach(w.s, off, recoverBy, []string{w.key}, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != w.owner
	})
	_, recovered := recAt[w.key]
	timer.Stop()
	if err := thaw(); err != nil {
		t.Errorf("thaw %s: %v", x, err)
	}
	lw.avoid(x, false)
	v3 := l.pick(func(c string) bool { return c != w.owner && c != x }, false)
	att, out = l.claimView(v3, w.key, "claim-outage2.txt")
	var decided *claimAttempt
	for i := range att {
		if att[i].Decided {
			decided = &att[i]
		}
	}
	dp := ""
	if decided != nil {
		dp = decided.decidedProof()
	}
	switch {
	case recovered && dp == p1:
		l.mark("w4a: outcome A — the accepted value (proof %s) was adopted and decided at attempt %d", p1, decided.N)
		if !l.waitProofStatus(v3, p1, "completed", 2*time.Minute) {
			t.Errorf("outcome A: the adopted proof %s did not complete (status %q)", p1, l.proofStatus(v3, p1))
		}
	case recovered:
		l.mark("w4a: outcome B — not adopted: decided proof %q, outage 1's was %s", dp, p1)
		if decided == nil {
			t.Errorf("%s recovered, but no attempt reads decided:\n%s", w.key, out)
		}
	case dp == p1 && decided != nil:
		j := l.journalSince(decided.DecidedDest, w.since, journalPair("reconciler: pending proof refused by the lease-term gate", "proof", p1))
		if strings.TrimSpace(j) != "" {
			t.Errorf("outcome C (design Q5): the adopted value's proof %s is refused by the lease-term gate on %s and the VM is stranded:\n%s", p1, decided.DecidedDest, j)
		} else {
			t.Errorf("%s not recovered within %v; the decided proof is outage 1's %s, with no lease-term refusal logged on %s", w.key, recoverBy, p1, decided.DecidedDest)
		}
	default:
		t.Errorf("%s not recovered within %v of its owner losing power (decided proof %q):\n%s", w.key, recoverBy, dp, out)
	}
	if j := strings.TrimSpace(l.journalSince(v3, w.since, "a decided recovery will never execute; moving the claim to the next attempt")); j != "" {
		l.mark("w4a: claims.go:230 on %s:\n%s", v3, j)
	}

	// Restore under the sampler.
	l.waitActive(v3, []string{x}, 5*time.Minute)
	l.powerOnOwnerManual(v3, w.owner, b.strategies[w.owner])
	l.waitNoOwnershipConditions(v3, 6*time.Minute)
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, w.s, []string{w.key})
	w.s.Stop() // the exactly-once check runs in startCheckedSampler's cleanup
	assertOneDestination(t, w.s.snapshot(), []string{w.key})
}

// TestDrillW4b_ClaimRetryOwedToTheLastOutage is scenario 4b's lab-drivable
// part: a claim refused in outage 1 (drill 4's owner-reachable veto, 60 s) is
// retried in outage 2 — the owner powered off within four minutes of outage
// 1's fence, while it is still offline — by the same holder at the same lease
// term ("failover: retrying the recovery claims refused on an earlier tick",
// failover/claims.go:832), with the proof of a value accepted in outage 1 when
// there was one (sameClaimIntent), and exactly once. The hazardous form (a
// partition with the owner's pause on in outage 2) needs a pause flip without
// a restart and belongs in tests/fleet (design Q3).
func TestDrillW4b_ClaimRetryOwedToTheLastOutage(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	l.requireWitnessTopology(l.hosts[0])
	w := l.w4Begin("w4b", 60*time.Second)
	via := l.pick(func(h string) bool { return h != w.owner && h != w.decider }, false)
	p1, _, _ := l.outage1Value(w, via)
	fenceAt, row, ok := l.newestFenceRow(via, w.owner, w.since)
	if !ok {
		t.Fatalf("outage 1 left no fencing_log row for %s", w.owner)
	}
	l.mark("w4b: outage 1 fence row %s", row)
	if err := l.clearDrops(w.owner); err != nil {
		t.Fatal(err)
	}
	l.mark("w4b: healed outage 1 for 30 s; %s's config is left as is (a restart would re-admit it)", w.owner)
	time.Sleep(30 * time.Second)
	if st, err := l.hostStates(via); err != nil || st[w.owner] == "HOST_ACTIVE" {
		t.Skipf("inconclusive: %s is %q 30 s after the heal (err %v); re-admitted, its claim retry is forgotten", w.owner, st[w.owner], err)
	}
	h0 := l.leaseHolder(via, "failover")
	t0 := l.leaseTerm(via, "failover")
	offNode := l.nodeNow(via)
	if now, ok := corrosion.ParseUpdatedAt(offNode); ok && now.Sub(fenceAt) > 4*time.Minute {
		t.Skipf("inconclusive: %v since outage 1's fence, past the 4 minutes inside recentFenceWindow", now.Sub(fenceAt).Round(time.Second))
	}
	off := l.powerOff(w.owner)
	if _, _, ok := l.waitLogLine([]string{h0}, offNode, journalPair("retrying the recovery claims refused on an earlier tick", "host", w.owner), time.Time{}, nil, recoverBy); !ok {
		t.Errorf("the holder %s never retried outage 1's refused claims for %s after its power-off (failover/claims.go:832)", h0, w.owner)
	}
	recAt := waitEach(w.s, off, recoverBy, []string{w.key}, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != w.owner
	})
	if _, ok := recAt[w.key]; !ok {
		t.Errorf("%s not recovered within %v of %s losing power\n  %s", w.key, recoverBy, w.owner, w.s.last())
	}
	ps := l.waitProofs(via, "vm", w.test, w.since, 1, time.Minute)
	if len(ps) != 1 {
		t.Errorf("%d recovery proofs for %s, want 1: %+v", len(ps), w.test, ps)
	} else {
		if ps[0].Coordinator != h0 || ps[0].LeaseTerm != t0 {
			t.Errorf("the proof was minted by %s at term %d; the retry owed to outage 1 is %s's at term %d", ps[0].Coordinator, ps[0].LeaseTerm, h0, t0)
		}
		if p1 != "" && ps[0].ID != p1 {
			t.Errorf("outage 1's accepted value had proof %s; the recovery wrote %s (sameClaimIntent keeps the value)", p1, ps[0].ID)
		}
	}
	if p1 != "" {
		att, out := l.claimView(via, w.key, "claim-outage2.txt")
		dp := ""
		for _, a := range att {
			if a.Decided {
				dp = a.decidedProof()
			}
		}
		if dp != p1 {
			t.Errorf("the decided proof is %q; outage 1's accepted value had %s:\n%s", dp, p1, out)
		}
	}

	l.powerOnOwnerManual(via, w.owner, "")
	if _, err := l.restoreConfig(w.owner); err != nil {
		t.Errorf("restore %s's config: %v", w.owner, err)
	}
	if s := b.strategies[w.owner]; s != "" {
		l.setStrategy(via, w.owner, s)
	}
	l.waitNoOwnershipConditions(via, 6*time.Minute)
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, w.s, []string{w.key})
	w.s.Stop() // the exactly-once check runs in startCheckedSampler's cleanup
	assertOneDestination(t, w.s.snapshot(), []string{w.key})
}

// TestDrillW5_ClockSteps is scenario 5: stepped node clocks, inside the
// nodes only (time sync off first, never written to the RTC, |Δ| ≤ 60 s,
// restored from this machine's clock with time sync put back). Three
// subtests, in order, each on its own victim and test VM, on the adopted
// voter set:
//
//   - holder_back_20s: the lease holder steps back 20 s at its "relying on
//     the host's partition pause" line. One proof, at the newest lease term; no
//     replacement before (F−1)·P + W, nor before a successor's own wait
//     (coordinator.go:1013); restoring its clock logs the local stall
//     (health/stall.go:120).
//   - voter_forward_45s: a majority voter steps forward 45 s 3 s after the cut.
//     It logs the local stall and opens observer_stalled; the holder ignores
//     its future-dated rows (coordinator.go:821); recovery in the normal
//     window (+15 s with hlc_lww_v1), never before (F−1)·P + W.
//   - victim_back_60s_bridged: the victim steps back 60 s, then is cut from
//     every worker (SSH from everyone) and left reaching the witness. The
//     deadline refuses, bridged, with derived_voter_set=false, because its
//     pause report is missing or "predates this outage" (partition_pause.go:437,
//     456; design Q4); held 4 minutes; then cut from the witness too, it is
//     recovered within 90 s, exactly once.
func TestDrillW5_ClockSteps(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	w := l.requireWitnessTopology(l.hosts[0])
	mp := mailpitFromEnv()
	mail := l.mailpitReachable(l.hosts[1], mp)
	if mail {
		l.addMailpitRoute(l.hosts[1], mp, notify.KindHostRecoveryStalled)
	} else {
		l.mark("w5: Mailpit does not answer at %s; victim_back_60s_bridged does not check the notification", mp.api)
	}
	var used []string
	l.sub(t, "holder_back_20s", func() { used = append(used, l.w5HolderBack(used)) })
	l.sub(t, "voter_forward_45s", func() { used = append(used, l.w5VoterForward(w, used)) })
	l.sub(t, "victim_back_60s_bridged", func() { l.w5VictimBackBridged(w, mp, mail, used) })
}

// sub runs fn as subtest name with the harness bound to the subtest, so a
// Fatal or Skip inside ends that subtest only.
func (l *lab) sub(t *testing.T, name string, fn func()) bool {
	return t.Run(name, func(st *testing.T) {
		prev := l.t
		l.t = st
		l.logT.Store(st)
		defer func() { l.t = prev; l.logT.Store(prev) }()
		fn()
	})
}

// w5Begin requires the lab back at rest, registers the subtest's settle (heal,
// every host active, nothing paused) and picks a best-effort victim not in
// used and not the lease holder, and a CLI host that is neither.
func (l *lab) w5Begin(used []string) (v, q string) {
	l.t.Helper()
	states, err := l.hostStates(l.hosts[0])
	if err != nil {
		l.t.Skipf("cannot read host states: %v", err)
	}
	for _, h := range l.hosts {
		if states[h] != "HOST_ACTIVE" {
			l.t.Skipf("%s is %s: the lab is not back at rest from the previous subtest", h, states[h])
		}
	}
	l.requireClocksManageable(l.hosts...)
	l.t.Cleanup(func() {
		l.clearDrops(append(append([]string{}, l.hosts...), l.outsiders...)...)
		if via := l.liveHost(); via != "" {
			l.waitAllActive(via, 8*time.Minute)
		}
		l.waitNoPaused(5 * time.Minute)
	})
	holder := l.leaseHolder(l.hosts[0], "failover")
	for _, h := range l.hosts {
		if h != holder && !contains(used, h) && bestEffort(l.fenceStrategy(l.hosts[0], h)) {
			v = h
			break
		}
	}
	if v == "" {
		l.t.Skipf("no best-effort victim left outside the holder %s and %v", holder, used)
	}
	q = l.pick(func(h string) bool { return h != v && h != holder }, true)
	return v, q
}

// w5Settle heals, waits for the superseded copy on v to stop, and checks the
// workload executes exactly once.
func (l *lab) w5Settle(s *sampler, v string, keys []string) time.Time {
	l.t.Helper()
	healed := l.heal()
	if _, ok := waitEach(s, healed, settleBy, keys, func(r round, k string) bool {
		st := r.state(v, k)
		_, down := r.Down[v]
		return !down && st != "running" && st != "paused" && st != "frozen"
	})[keys[0]]; !ok {
		l.t.Errorf("%s: the superseded copy on %s was not stopped within %v of the heal\n  %s", keys[0], v, settleBy, s.last())
	}
	time.Sleep(tPause + 10*time.Second)
	assertExactlyOnceNow(l.t, s, keys)
	return healed
}

func (l *lab) w5HolderBack(used []string) string {
	t := l.t
	v, q := l.w5Begin(used)
	test := l.createVMsWhereRoom(q, "w5a", v)[v]
	if test == "" {
		t.Skipf("no room on %s for the test VM", v)
	}
	keys := []string{"vm/" + test}
	since := l.nodeNow(q)
	s := l.startCheckedSampler()
	waitAllAt(t, s, keys, v)
	lw := l.watchLease(l.allBut(v))
	start, _ := l.partition([]string{v}, l.except(v))
	h, _, ok := l.waitLogLine(l.allBut(v), since, journalPair("relying on the host's partition pause", "host", v), time.Time{}, nil, 2*time.Minute)
	if !ok {
		t.Fatalf("no holder relied on %s's partition pause within 2m (partition_pause.go:154)", v)
	}
	stepAt := time.Now()
	l.stepClock(h, -20*time.Second)
	hSince := nodeSinceMinus(since, 2*time.Minute)
	recAt := waitEach(s, start, recoverBy, keys, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != v
	})
	at, recovered := recAt[keys[0]]
	if !recovered {
		t.Errorf("%s not recovered within %v of isolating %s\n  %s", keys[0], recoverBy, v, s.last())
	}
	if recovered {
		if d := at.Sub(start); d < earliestReplacement(l.total) {
			t.Errorf("%s replacement at +%v, before (F−1)·P + W = %v", keys[0], d, earliestReplacement(l.total))
		}
		for _, c := range lw.history() {
			if c.At.Before(stepAt) || c.At.After(at) || c.Holder == h || c.Holder == "" {
				continue
			}
			// The lease moved before the recovery: the successor waits W afresh.
			if _, ln, ok := l.waitLogLine([]string{c.Holder}, since, journalPair("resuming recovery from a fence a previous leader recorded", "host", v), c.At.Add(-clockSlack), nil, 5*time.Second); ok {
				if min := ln.At.Add(pauseWait(l.total) - time.Second - clockSlack); at.Before(min) {
					t.Errorf("%s replacement at %s, before the successor %s's own pause wait from %s", keys[0], at.UTC().Format("15:04:05"), c.Holder, ln.At.UTC().Format("15:04:05"))
				}
			} else {
				l.mark("w5a: the lease moved to %s at %s; no resume line on it", c.Holder, c.At.UTC().Format("15:04:05"))
			}
			break
		}
	}
	// h's clock runs 20 s behind until restoreClock: a time h wrote (a proof's
	// created_at, a journal line) is that much behind this machine's.
	skew := func(coordinator string, at time.Time) time.Time {
		if coordinator == h && at.Add(20*time.Second).After(stepAt) {
			return at.Add(20 * time.Second)
		}
		return at
	}
	ps := l.waitProofs(q, "vm", test, since, 1, time.Minute)
	var minted leaseChange
	if len(ps) != 1 {
		t.Errorf("%d recovery proofs for %s, want 1: %+v", len(ps), test, ps)
	} else if created, ok := corrosion.ParseUpdatedAt(ps[0].Created); !ok {
		t.Errorf("proof %s has an unreadable created_at %q", ps[0].ID, ps[0].Created)
	} else {
		// Judged against the tenure it was minted in, not the newest term: the
		// skewed holder is expected to lose the lease after minting.
		var ok bool
		minted, ok = tenureAt(lw.history(), skew(ps[0].Coordinator, created), ps[0].Coordinator, ps[0].LeaseTerm)
		if !ok {
			t.Errorf("proof %s was minted by %s at term %d at %s, but the lease then was %+v (history %+v)", ps[0].ID, ps[0].Coordinator, ps[0].LeaseTerm, ps[0].Created, minted, lw.history())
		}
	}
	for _, ln := range l.journalLines(h, hSince, "lease lost, unshown or renewed as a new tenure mid-cycle, aborting") {
		l.mark("w5a: %s lost the lease mid-cycle: %s", h, ln.Text)
		lostAt := skew(h, ln.At)
		for _, p := range ps {
			created, ok := corrosion.ParseUpdatedAt(p.Created)
			if !ok || p.Coordinator != h || skew(h, created).Before(lostAt) {
				continue
			}
			// A proof h minted after losing the lease must rest on a tenure h
			// took afresh after the loss.
			if minted.Holder != h || minted.At.Before(lostAt.Add(-clockSlack)) {
				t.Errorf("%s minted %s at term %d after losing the lease at %s, under no tenure taken since", h, p.ID, p.LeaseTerm, lostAt.UTC().Format("15:04:05"))
			}
		}
	}
	restored := time.Now()
	l.restoreClock(h)
	if _, _, ok := l.waitLogLine([]string{h}, hSince, regexp.QuoteMeta(notRunningMsg), restored.Add(-clockSlack), nil, 30*time.Second); !ok {
		t.Errorf("%s did not log the local stall (health/stall.go:120) when its clock stepped forward 20 s again", h)
	}
	time.Sleep(30 * time.Second)
	l.w5Settle(s, v, keys)
	s.Stop() // the exactly-once check runs in startCheckedSampler's cleanup
	assertOneDestination(t, s.snapshot(), keys)
	return v
}

func (l *lab) w5VoterForward(w witnessTopology, used []string) string {
	t := l.t
	v, q := l.w5Begin(used)
	holder := l.leaseHolder(q, "failover")
	x := ""
	for _, h := range l.hosts {
		if h != v && h != q && h != holder {
			x = h
			break
		}
	}
	if x == "" {
		t.Skipf("no majority voter outside victim %s, CLI host %s and holder %s", v, q, holder)
	}
	test := l.createVMsWhereRoom(q, "w5b", v)[v]
	if test == "" {
		t.Skipf("no room on %s for the test VM", v)
	}
	keys := []string{"vm/" + test}
	since := l.nodeNow(q)
	s := l.startCheckedSampler()
	waitAllAt(t, s, keys, v)
	start, _ := l.partition([]string{v}, l.except(v))
	time.Sleep(time.Until(start.Add(3 * time.Second)))
	l.stepClock(x, 45*time.Second)
	if _, _, ok := l.waitLogLine([]string{x}, since, regexp.QuoteMeta(notRunningMsg), time.Time{}, nil, time.Minute); !ok {
		t.Errorf("%s did not log the local stall after stepping forward 45 s (health/stall.go:120)", x)
	}
	stalled := false
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline) && !stalled; time.Sleep(3 * time.Second) {
		c, ok, _ := l.condition(q, evalStall, health.CondObserverStalled, x)
		stalled = ok && c.FirstSeen >= since
	}
	if !stalled {
		t.Errorf("no %s for %s since %s", health.CondObserverStalled, x, since)
	}
	if _, _, ok := l.waitLogLine(l.allBut(v, x), since, journalPair("ignoring a future-dated health observation", "observer", x), time.Time{}, nil, 2*time.Minute); !ok {
		t.Errorf("no holder ignored %s's future-dated rows (coordinator.go:821)", x)
	}
	bound := recoverBy
	if w.hlc {
		bound += 15 * time.Second
	}
	recAt := waitEach(s, start, bound, keys, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != v
	})
	if at, ok := recAt[keys[0]]; !ok {
		t.Errorf("%s not recovered within %v (hlc_lww_v1 %v) with %s's clock 45 s ahead\n  %s", keys[0], bound, w.hlc, x, s.last())
	} else if d := at.Sub(start); d < earliestReplacement(l.total) {
		t.Errorf("%s replacement at +%v, before (F−1)·P + W = %v", keys[0], d, earliestReplacement(l.total))
	} else {
		l.mark("w5b: recovered at +%v", d.Round(time.Second))
	}
	if ps := l.waitProofs(q, "vm", test, since, 1, time.Minute); len(ps) != 1 {
		t.Errorf("%d recovery proofs for %s, want 1: %+v", len(ps), test, ps)
	}
	l.restoreClock(x)
	if w.hlc {
		// Rows stamped ahead stay ahead until the wall clock catches up.
		time.Sleep(45*time.Second + 30*time.Second)
	} else {
		time.Sleep(30 * time.Second)
	}
	l.w5Settle(s, v, keys)
	s.Stop() // the exactly-once check runs in startCheckedSampler's cleanup
	assertOneDestination(t, s.snapshot(), keys)
	return v
}

func (l *lab) w5VictimBackBridged(w witnessTopology, mp mailpit, mail bool, used []string) {
	t := l.t
	v, q := l.w5Begin(used)
	W := w.witness
	test := l.createVMsWhereRoom(q, "w5c", v)[v]
	if test == "" {
		t.Skipf("no room on %s for the test VM", v)
	}
	key := "vm/" + test
	keys := []string{key}
	since := l.nodeNow(q)
	s := l.startCheckedSampler()
	waitAllAt(t, s, keys, v)
	others := l.allBut(v)
	l.stepClock(v, -60*time.Second)
	tP1 := l.cutEdges(edgesFrom(v, l.except(v)...)...)
	l.sshCut(q, v, others)
	pausedAt := waitEach(s, tP1, 2*minorityPauseBy, keys, func(r round, k string) bool { return pausedState(r.state(v, k)) })
	if _, ok := pausedAt[key]; !ok {
		t.Fatalf("%s never paused on %s, which reaches only %s\n  %s", key, v, W, s.last())
	}
	c, _, ok := l.waitBridged(q, v, "the partition-pause deadline of "+v+" passed", 3*time.Minute)
	if !ok {
		t.Errorf("no %s for %s in its deadline form within 3m", condBridged, v)
	} else {
		if c.Bridged.DerivedVoterSet {
			t.Errorf("%s says derived_voter_set=true on the adopted generation", condBridged)
		}
		switch {
		case strings.Contains(c.Bridged.Detail, "predates this outage"):
			l.mark("w5c: refused because %s's partition_paused predates this outage (its clock is 60 s behind)", v)
		case strings.Contains(c.Bridged.Detail, "has not reported pausing anything"):
			l.mark("w5c: refused because %s's pause report had not reached the holder", v)
		default:
			t.Errorf("%s detail names neither a late nor a back-dated pause report: %s", condBridged, c.Bridged.Detail)
		}
		if !contains(c.Bridged.Observers, W) {
			t.Errorf("%s observers %v lack the witness %s", condBridged, c.Bridged.Observers, W)
		}
	}
	if _, _, ok := l.waitStallLine(others, since, v, "recovery refused at the partition-pause deadline", time.Time{}, 3*time.Minute); !ok {
		t.Errorf("no stall alert for %s naming the deadline refusal", v)
	}
	if mail {
		if _, ok := l.mailpitWait(q, mp, notify.KindHostRecoveryStalled+" "+v, tP1, 90*time.Second); !ok {
			t.Errorf("Mailpit never received %s %s", notify.KindHostRecoveryStalled, v)
		}
	}
	time.Sleep(time.Until(tP1.Add(4 * time.Minute)))
	if ps := l.proofsSince(q, "vm", test, since); len(ps) > 0 {
		t.Errorf("recovery proofs minted during the bridged hold of %s: %+v", v, ps)
	}
	assertPausedOn(t, s.snapshot(), key, v, pausedAt[key].Add(sampleSlop), time.Now(), "the bridged hold")
	tP2 := l.cutEdges([2]string{v, W})
	recAt := waitEach(s, tP2, 90*time.Second, keys, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != v
	})
	if _, ok := recAt[key]; !ok {
		t.Errorf("%s not recovered within 90 s of cutting %s from the witness\n  %s", key, v, s.last())
	}
	assertOnlyOn(t, s.snapshot(), key, v, tP1, tP2, "the bridged hold")
	if ps := l.waitProofs(q, "vm", test, since, 1, time.Minute); len(ps) != 1 {
		t.Errorf("%d recovery proofs for %s, want 1: %+v", len(ps), test, ps)
	}
	// Restored while v is still isolated: healed with its clock 60 s behind,
	// its LWW writes would lose to every peer's through the settle. The
	// forward step's local stall is harmless here.
	l.restoreClock(v)
	time.Sleep(30 * time.Second)
	l.w5Settle(s, v, keys)
	s.Stop() // the exactly-once check runs in startCheckedSampler's cleanup
	assertOneDestination(t, s.snapshot(), keys)
}

// ─── helpers ────────────────────────────────────────────────────────────────

// waitSelfPauseFence waits for host's newest fencing_log row since since to
// be a best-effort fence that relied on the partition pause
// (corrosion.FencePauseReliance in its detail), and returns its time.
func (l *lab) waitSelfPauseFence(via, host, since string) time.Time {
	l.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		rows, err := l.sql(via, "SELECT timestamp, method, hex(COALESCE(detail,'')) FROM fencing_log WHERE host_name='"+host+"' AND timestamp >= '"+since+"' ORDER BY timestamp DESC LIMIT 1")
		if err == nil && len(rows) > 0 && len(rows[0]) == 3 {
			at, _ := corrosion.ParseUpdatedAt(rows[0][0])
			detail := hexText(rows[0][2])
			if rows[0][1] != "best-effort-ssh" || !strings.HasPrefix(detail, corrosion.FencePauseReliance) {
				l.t.Errorf("%s's fence is %s %q, want a best-effort-ssh fence relying on its pause (partition_pause.go asSelfPause)", host, rows[0][1], detail)
			}
			l.mark("fence: %s %s at %s", host, rows[0][1], rows[0][0])
			return at
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("no fencing_log row for %s since %s", host, since)
		}
		time.Sleep(2 * time.Second)
	}
}

// waitProofs waits up to timeout for at least n proofs of name since since,
// and returns what is there then.
func (l *lab) waitProofs(via, kind, name, since string, n int, timeout time.Duration) []proof {
	deadline := time.Now().Add(timeout)
	for {
		ps := l.proofsSince(via, kind, name, since)
		if len(ps) >= n || time.Now().After(deadline) {
			return ps
		}
		time.Sleep(3 * time.Second)
	}
}

// tenureAt reports whether holder held the lease at term at instant at, by the
// sampled history: the newest change at or before at (plus clockSlack, for a
// change sampled up to a second late) must be that tenure, or, within
// clockSlack of a change, the one before it. It returns the matching change,
// or the newest one at or before at when none matches.
func tenureAt(history []leaseChange, at time.Time, holder string, term int) (leaseChange, bool) {
	var cands []leaseChange
	for _, c := range history {
		if !c.At.After(at.Add(clockSlack)) {
			cands = append(cands, c)
		}
	}
	if len(cands) == 0 {
		return leaseChange{}, false
	}
	last := cands[len(cands)-1]
	if last.Holder == holder && last.Term == term {
		return last, true
	}
	if len(cands) > 1 && last.At.After(at.Add(-clockSlack)) {
		if p := cands[len(cands)-2]; p.Holder == holder && p.Term == term {
			return p, true
		}
	}
	return last, false
}

// holdersBetween is every lease holder seen from from to to, including the
// one holding at from.
func holdersBetween(lw *leaseWatch, from, to time.Time) []string {
	var out []string
	for _, c := range lw.history() {
		if c.At.After(to) {
			break
		}
		if c.At.Before(from) {
			out = []string{c.Holder}
			continue
		}
		if !contains(out, c.Holder) {
			out = append(out, c.Holder)
		}
	}
	return out
}
