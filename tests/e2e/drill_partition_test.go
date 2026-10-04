package e2e

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Partition drills (docs/design/partition-pause.md §8, "Lab"): drill 1, the
// 2|3 split, and the fleet-wide blip. Both cut the cluster LAN with nftables on
// every node and judge the outcome from virsh and lxc-ls, sampled once a second
// on every node (lab_harness_test.go).

// Lab bounds that are not design constants. Each is generous on purpose: they
// catch "never happened", while the design's own timing is asserted separately
// against tPause, minorityPauseBy and earliestReplacement.
const (
	// recoverBy bounds a replacement starting after a fault. A lease holder on
	// the wrong side adds up to failoverLeaseTTL before anyone may decide.
	recoverBy = 6 * time.Minute
	// settleBy bounds Layer 3 stopping a superseded copy after the heal.
	settleBy = 5 * time.Minute
	// dualRunScanBy bounds the dual-run evaluator completing a scan after the
	// heal, so "no vm_dual_run" is not read off a detector that never looked.
	dualRunScanBy = 4 * time.Minute
)

var (
	// resumeBy bounds a fleet-wide blip's resume after the heal: the first
	// successful probe cycle, T_pause of unbroken Yes (§3.1), one resume recheck
	// (partitionResumeRecheck, 5 s) and two ticks, plus 30 s for the voters'
	// confirmation RPCs after gossip re-merges.
	resumeBy = probeCycle + tPause + 5*time.Second + 2*pauserTick + 30*time.Second
	// shortBlip is a blip strictly shorter than T_pause, with room for the rules
	// to go in and come out (G6: such a blip pauses nothing).
	shortBlip = tPause - 4*time.Second
	// longBlip comfortably outlasts minorityPauseBy, so every host pauses.
	longBlip = 2 * minorityPauseBy
	// healedQuiet separates two blips: the pauser's loss window is 2·T_pause
	// and a heal is T_pause of unbroken Yes (§3.1), so after this long the
	// second blip starts from a healed state.
	healedQuiet = 2*tPause + minorityDetect + 10*time.Second
)

// TestDrill1_SplitTwoThree is drill 1 of the kvm003 drills: {node-1, node-2} |
// {node-3, node-4, node-5}.
//
//   - the minority pauses its recoverable workloads no sooner than T_pause and
//     no later than minorityPauseBy after the link broke;
//   - the majority starts each replacement only after (F−1)·P + W, then
//     recovers every one of them;
//   - the replacement's root disk has the size litevirt recorded for it;
//   - after the heal, Layer 3 stops each superseded minority copy and keeps its
//     disk (G5);
//   - at no sample does any workload execute on two hosts, and no vm_dual_run
//     is raised.
func TestDrill1_SplitTwoThree(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	minority, majority := l.hosts[:2], l.hosts[2:]
	q := majority[0] // the CLI side that keeps a quorum
	test := l.createVMs(q, "d1", minority...)
	keys := l.recoverableOn(q, minority...)
	home := map[string]string{}
	disks := map[string]vmInfo{}
	for _, v := range l.vms(q) {
		k := "vm/" + v.Name
		home[k] = v.HostName
		disks[k] = v
	}
	for _, c := range l.containers(q) {
		home["ct/"+c.Name] = c.Host
	}
	for _, n := range test {
		if !contains(keys, "vm/"+n) {
			t.Fatalf("test VM %s is not recoverable per its own record; keys %v", n, keys)
		}
	}
	l.mark("drill1: minority %v majority %v, recoverable on the minority: %v", minority, majority, keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	if _, ok := s.waitFor(time.Now(), time.Minute, func(r round) bool {
		for _, k := range keys {
			if r.state(home[k], k) != "running" {
				return false
			}
		}
		return true
	}); !ok {
		t.Fatalf("not every minority workload runs on its home host before the split:\n  %s", s.last())
	}

	start, _ := l.partition(minority, majority)

	// ── 1. the minority pauses ──────────────────────────────────────────────
	pausedAt := waitEach(s, start, 2*minorityPauseBy, keys, func(r round, k string) bool {
		return r.state(home[k], k) == "paused" || r.state(home[k], k) == "frozen"
	})
	for _, k := range keys {
		at, ok := pausedAt[k]
		if !ok {
			t.Errorf("%s never paused on %s within %v of the split (virsh)\n  %s", k, home[k], 2*minorityPauseBy, s.last())
			continue
		}
		d := at.Sub(start)
		l.mark("drill1: %s paused on %s at +%v", k, home[k], d.Round(time.Millisecond))
		if d < tPause {
			t.Errorf("%s paused %v after the split, before T_pause=%v of loss could have accumulated", k, d, tPause)
		}
		if d > minorityPauseBy+sampleSlop {
			t.Errorf("%s paused %v after the split; the design bound is D_M+Δ+T_pause+Δ+E = %v (+%v sampling)", k, d, minorityPauseBy, sampleSlop)
		}
	}
	// No FailNow here: a minority that did not pause is exactly when the
	// exactly-once checks below have something to catch.

	// ── 2. the majority waits out the pause, then recovers ──────────────────
	onMajority := func(r round, k string) bool {
		for _, h := range r.executing(k) {
			if contains(majority, h) {
				return true
			}
		}
		return false
	}
	recoveredAt := waitEach(s, start, recoverBy, keys, onMajority)
	for _, k := range keys {
		at, ok := recoveredAt[k]
		if !ok {
			t.Errorf("%s was never recovered on the majority within %v (virsh)\n  %s", k, recoverBy, s.last())
			continue
		}
		d := at.Sub(start)
		l.mark("drill1: %s replacement executing at +%v on %v", k, d.Round(time.Millisecond), s.last().executing(k))
		if min := earliestReplacement(len(l.hosts)); d < min {
			t.Errorf("%s replacement executed %v after the split, before (F−1)·P + W = %v: the majority did not wait out the pause", k, d, min)
		}
		if p, ok := pausedAt[k]; ok && !at.After(p) {
			t.Errorf("%s replacement at %v is not after the minority's pause at %v", k, at, p)
		}
	}
	if len(recoveredAt) == 0 {
		t.FailNow()
	}

	// ── 3. the replacement disk has the recorded size ───────────────────────
	r := s.last()
	for _, k := range keys {
		v, ok := disks[k]
		if !ok {
			continue // containers carry no disk record
		}
		hs := r.executing(k)
		if len(hs) != 1 {
			continue // reported by the exactly-once checks
		}
		for _, d := range v.Disks {
			want, err := parseInt64(d.SizeBytes)
			if err != nil || want == 0 {
				t.Errorf("%s disk %s: no recorded size (%q)", k, d.Name, d.SizeBytes)
				continue
			}
			got, err := l.qemuVirtualSize(hs[0], d.Path)
			if err != nil {
				t.Errorf("%s disk %s on %s: %v", k, d.Name, hs[0], err)
				continue
			}
			if got != want {
				t.Errorf("%s disk %s on replacement host %s: qemu-img virtual size %d, litevirt recorded %d", k, d.Name, hs[0], got, want)
			}
		}
	}

	// ── 4. heal: Layer 3 stops the superseded copies ────────────────────────
	healed := l.heal()
	settledAt := waitEach(s, healed, settleBy, keys, func(r round, k string) bool {
		st := r.state(home[k], k)
		_, down := r.Down[home[k]]
		return !down && st != "running" && st != "paused" && st != "frozen"
	})
	for _, k := range keys {
		at, ok := settledAt[k]
		if !ok {
			t.Errorf("%s: the superseded copy on %s was not stopped within %v of the heal\n  %s", k, home[k], settleBy, s.last())
			continue
		}
		l.mark("drill1: %s settled on %s at heal+%v", k, home[k], at.Sub(healed).Round(time.Millisecond))
		if v, ok := disks[k]; ok {
			for _, d := range v.Disks {
				if !l.fileExists(home[k], d.Path) {
					t.Errorf("%s: settle on %s deleted disk %s (G5: no disk is deleted by either layer)", k, home[k], d.Path)
				}
			}
		}
	}
	// Give the heal a full T_pause of Yes and a resume recheck: a minority copy
	// resuming now would be a second executing copy.
	time.Sleep(tPause + 10*time.Second)

	// ── 5. exactly once, at every sample ────────────────────────────────────
	assertExactlyOnceNow(t, s, keys)
	s.Stop()
	assertNeverTwice(t, s.snapshot())
	assertNoDualRun(t, l, q, since, healed)

	t.Run("disk rows follow the replacement", func(t *testing.T) {
		assertDiskRowsFollow(t, l, q, s.last(), keys)
	})
}

// TestDrillBlip_FleetWide cuts every node off from every other node at once.
//
//   - a blip shorter than T_pause pauses nothing (G6);
//   - a long blip pauses every recoverable workload on every host, including a
//     container on an LXC host; nothing is fenced and nothing is replaced, and
//     every workload resumes in place after the heal (§3.5, F7);
//   - no host without LXC raises partition_pause_failed.
func TestDrillBlip_FleetWide(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	q := l.hosts[0]

	var lxcHost, plainHost string
	for _, h := range l.hosts {
		if b.lxcHosts[h] && lxcHost == "" {
			lxcHost = h
		}
		if !b.lxcHosts[h] && plainHost == "" {
			plainHost = h
		}
	}
	if lxcHost == "" || plainHost == "" {
		t.Fatalf("the blip needs a host with LXC and one without (litevirt.lxc labels: %v)", b.lxcHosts)
	}
	l.createVMs(q, "blip", plainHost)
	l.createContainer(q, "blip", lxcHost)
	keys := l.recoverableOn(q, l.hosts...)
	home := map[string]string{}
	for _, v := range l.vms(q) {
		home["vm/"+v.Name] = v.HostName
	}
	for _, c := range l.containers(q) {
		home["ct/"+c.Name] = c.Host
	}
	hasCT := false
	for _, k := range keys {
		hasCT = hasCT || strings.HasPrefix(k, "ct/")
	}
	if !hasCT {
		t.Fatalf("no recoverable container among %v", keys)
	}
	l.mark("blip: recoverable workloads %v", keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	if _, ok := s.waitFor(time.Now(), time.Minute, func(r round) bool {
		for _, k := range keys {
			if r.state(home[k], k) != "running" {
				return false
			}
		}
		return true
	}); !ok {
		t.Fatalf("not every recoverable workload runs at home before the blip:\n  %s", s.last())
	}
	var alone [][]string
	for _, h := range l.hosts {
		alone = append(alone, []string{h})
	}

	// ── short blip ──────────────────────────────────────────────────────────
	start, _ := l.partition(alone...)
	time.Sleep(time.Until(start.Add(shortBlip)))
	healed := l.heal()
	if healed.Sub(start) >= tPause {
		t.Fatalf("could not cut the short blip under T_pause: it lasted %v", healed.Sub(start))
	}
	time.Sleep(healedQuiet)
	for _, r := range s.snapshot() {
		if r.At.Before(start) {
			continue
		}
		for k, hs := range r.Copies {
			for h, st := range hs {
				if pausedState(st) {
					t.Errorf("short blip (%v < T_pause): %s paused on %s at +%v (G6)", healed.Sub(start).Round(time.Millisecond), k, h, r.At.Sub(start).Round(time.Millisecond))
				}
			}
		}
	}
	l.mark("blip: short blip of %v paused nothing", healed.Sub(start).Round(time.Millisecond))

	// ── long blip ───────────────────────────────────────────────────────────
	start, _ = l.partition(alone...)
	pausedAt := waitEach(s, start, 2*minorityPauseBy, keys, func(r round, k string) bool {
		return pausedState(r.state(home[k], k))
	})
	for _, k := range keys {
		at, ok := pausedAt[k]
		switch {
		case !ok:
			t.Errorf("long blip: %s never paused on %s (virsh/lxc-ls)\n  %s", k, home[k], s.last())
		case at.Sub(start) > minorityPauseBy+sampleSlop:
			t.Errorf("long blip: %s paused at +%v, bound %v", k, at.Sub(start), minorityPauseBy)
		default:
			l.mark("blip: %s paused on %s at +%v", k, home[k], at.Sub(start).Round(time.Millisecond))
		}
	}
	time.Sleep(time.Until(start.Add(longBlip)))
	healed = l.heal()
	resumedAt := waitEach(s, healed, resumeBy, keys, func(r round, k string) bool {
		return r.state(home[k], k) == "running"
	})
	for _, k := range keys {
		if at, ok := resumedAt[k]; !ok {
			t.Errorf("long blip: %s did not resume on %s within %v of the heal\n  %s", k, home[k], resumeBy, s.last())
		} else {
			l.mark("blip: %s resumed on %s at heal+%v", k, home[k], at.Sub(healed).Round(time.Millisecond))
		}
	}
	// Watch past the heal for a late fence or replacement.
	time.Sleep(time.Minute)
	s.Stop()
	rounds := s.snapshot()
	assertNeverTwice(t, rounds)
	for _, r := range rounds {
		for _, k := range keys {
			for _, h := range r.executing(k) {
				if h != home[k] {
					t.Errorf("blip: %s executed on %s, not its home %s, at %s: a replacement ran", k, h, home[k], r.At.UTC().Format("15:04:05.000"))
				}
			}
		}
	}

	// No fence, no replacement, every host still active.
	if rows := l.mustSQL(q, "SELECT host_name,method,result,timestamp FROM fencing_log WHERE timestamp >= '"+since+"'"); len(rows) > 0 {
		t.Errorf("blip: fences recorded during the blip: %v", rows)
	}
	for _, k := range keys {
		kind, name, _ := strings.Cut(k, "/")
		if kind == "ct" {
			kind = "container"
		}
		if ps := l.proofsSince(q, kind, name, since); len(ps) > 0 {
			t.Errorf("blip: %s has recovery proofs minted during the blip: %+v", k, ps)
		}
	}
	if states, err := l.hostStates(q); err != nil {
		t.Errorf("blip: %v", err)
	} else {
		for _, h := range l.hosts {
			if states[h] != "HOST_ACTIVE" {
				t.Errorf("blip: %s is %s after the blip; nothing should fence on a fleet-wide blip (F7)", h, states[h])
			}
		}
	}

	// partition_pause_failed must not appear on a host without LXC, and every
	// host that paused something raised partition_paused and resolved it.
	for _, row := range l.conditions(q, corrosion.CondPartitionPauseFailed, since) {
		host := strings.TrimPrefix(row[1], "host/")
		if !b.lxcHosts[host] {
			t.Errorf("blip: %s raised on %s, which runs no LXC: %v", corrosion.CondPartitionPauseFailed, host, row)
		} else {
			l.mark("blip: note %s on LXC host %s: %v", corrosion.CondPartitionPauseFailed, host, row)
		}
	}
	pausers := map[string]bool{}
	for _, k := range keys {
		pausers[home[k]] = true
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		open := map[string]bool{}
		seen := map[string]bool{}
		for _, row := range l.conditions(q, corrosion.CondPartitionPaused, since) {
			h := strings.TrimPrefix(row[1], "host/")
			seen[h] = true
			if row[4] == "" {
				open[h] = true
			}
		}
		var missing, unresolved []string
		for h := range pausers {
			if !seen[h] {
				missing = append(missing, h)
			} else if open[h] {
				unresolved = append(unresolved, h)
			}
		}
		if len(missing) == 0 && len(unresolved) == 0 {
			break
		}
		if time.Now().After(deadline) {
			sort.Strings(missing)
			sort.Strings(unresolved)
			t.Errorf("blip: %s never raised for %v, still open for %v (§3.6)", corrosion.CondPartitionPaused, missing, unresolved)
			break
		}
		time.Sleep(10 * time.Second)
	}
}

// TestDrill0_LabAtRest is the drills' preflight, and cheap: the lab is at its
// resting state, and the sampler sees each workload litevirt calls running
// executing exactly once, on the host litevirt names. A drill whose sampler
// disagreed with the cluster at rest could not be trusted under a fault.
func TestDrill0_LabAtRest(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	s := l.startSampler()
	time.Sleep(3 * samplePeriod)
	s.Stop()
	r := s.last()
	if len(r.Down) > 0 {
		t.Fatalf("sampler could not read %v", r.Down)
	}
	var keys []string
	for k, host := range b.running {
		keys = append(keys, k)
		if hs := r.executing(k); len(hs) != 1 || hs[0] != host {
			t.Errorf("%s: litevirt says running on %s, virsh/lxc-ls say executing on %v", k, host, hs)
		}
	}
	sort.Strings(keys)
	assertNeverTwice(t, s.snapshot())
	l.mark("rest: %d running workloads agree with virsh/lxc-ls: %v", len(keys), keys)
}

// ─── shared drill assertions ────────────────────────────────────────────────

// waitEach waits, up to timeout from now, until pred has held for every key in
// some round taken after `after`, and returns the first such round's time per key.
func waitEach(s *sampler, after time.Time, timeout time.Duration, keys []string, pred func(round, string) bool) map[string]time.Time {
	at := map[string]time.Time{}
	s.waitFor(after, timeout, func(r round) bool {
		for _, k := range keys {
			if _, ok := at[k]; !ok && pred(r, k) {
				at[k] = r.At
			}
		}
		return len(at) == len(keys)
	})
	return at
}

// assertNoDualRun requires that no vm_dual_run was raised since the drill
// began, and that the dual-run evaluator completed a scan after `after` — a
// clean answer from a detector that never looked is no answer.
func assertNoDualRun(t *testing.T, l *lab, via, since string, after time.Time) {
	t.Helper()
	afterNode := after.UTC().Add(-5 * time.Second) // node clocks agree within a second or two
	scanRe := regexp.MustCompile(`(?m)^\s*dual_run\s+complete\s+(\S+)`)
	deadline := time.Now().Add(dualRunScanBy)
	for {
		out, _ := l.lv(via, "health") // exits 1 while degraded; the text is what matters
		if m := scanRe.FindStringSubmatch(out); m != nil {
			if ts, err := time.Parse(time.RFC3339, m[1]); err == nil && ts.After(afterNode) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Errorf("the dual-run evaluator did not complete a scan within %v of %s; cannot vouch for 'no vm_dual_run':\n%s", dualRunScanBy, after.UTC().Format(time.RFC3339), out)
			break
		}
		time.Sleep(15 * time.Second)
	}
	if rows := l.conditions(via, "vm_dual_run", since); len(rows) > 0 {
		t.Errorf("vm_dual_run raised since %s: %v", since, rows)
	}
}

// assertDiskRowsFollow requires every VM's disk rows to name the host it now
// executes on (finding N7, fixed in 386206a3: failover used to leave them
// naming the old host).
func assertDiskRowsFollow(t *testing.T, l *lab, via string, r round, keys []string) {
	t.Helper()
	for _, k := range keys {
		kind, name, _ := strings.Cut(k, "/")
		if kind != "vm" {
			continue
		}
		hs := r.executing(k)
		if len(hs) != 1 {
			continue
		}
		v, err := l.inspectVM(via, name)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		for _, d := range v.Disks {
			if d.HostName != hs[0] {
				t.Errorf("%s disk %s row names %s; the VM executes on %s", k, d.Name, d.HostName, hs[0])
			}
		}
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscan(s, &n)
	return n, err
}
