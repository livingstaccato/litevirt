package e2e

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Recovery drills 2–5 (docs/design/recovery-claims.md §7.3): a frozen lease
// holder, a voter removed after a fence, a claim vetoed because the owner is
// still reachable, and the legacy path with claims off. Like drill 1 they judge
// where workloads execute from virsh and lxc-ls on every node.

var (
	// holderFreeze outlasts the failover lease, so the frozen holder wakes up
	// believing in a lease that has already expired: the stale holder.
	holderFreeze = failoverLeaseTTL + 20*time.Second
	// staleWatch is how long after the thaw drill 2 watches for the stale holder
	// to act: three lease terms.
	staleWatch = 3 * failoverLeaseTTL
	// claimWatch is how long drill 4 holds the owner-reachable split: enough for
	// many claim attempts, each a coordinator poll (5 s) apart.
	claimWatch = 150 * time.Second
	// hostDownBy bounds the majority marking a powered-off host not active:
	// F failures plus a fence and a coordinator poll, with lab slack.
	hostDownBy = 2 * time.Minute
	// capRefreshWait lets every peer's cached Ping of a just-restarted host
	// catch up with its new advertisement (4 × health.peerCapTTL).
	capRefreshWait = 4 * 30 * time.Second
	// returnWatch is how long a drill keeps sampling after powering a host back
	// on: a returning host is when a stale copy would restart.
	returnWatch = 90 * time.Second
)

// TestDrill2_FrozenLeaseHolderWhileAHostFails: the failover lease holder's
// daemon is SIGSTOPped while another host loses power. Exactly one recovery
// happens, and the stale holder, thawed after its lease expired, does not act
// on it.
//
// The holder's fence strategy is manual for the drill, as on kvm003: a frozen
// daemon looks dead to its peers, and the drill is about its lease, not about
// fencing it.
func TestDrill2_FrozenLeaseHolderWhileAHostFails(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	holder := l.leaseHolder(l.hosts[0], "failover")
	victim := l.pick(func(h string) bool { return h != holder }, true)
	q := l.pick(func(h string) bool { return h != holder && h != victim }, false)
	test := l.createVMs(q, "d2", victim)[victim]
	keys := l.relocatableOn(q, b, victim)
	holderKeys := l.recoverableOn(q, holder)
	l.mustLV(q, "host", "config", holder, "--fence-strategy", "manual")
	holderTerm := l.leaseTerm(q, "failover")
	l.mark("drill2: holder %s (failover term %d, fence manual), victim %s, recoverable on victim %v", holder, holderTerm, victim, keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, keys, victim)

	thaw := l.freezeDaemon(holder)
	t.Cleanup(func() { thaw() })
	off := l.powerOff(victim)
	time.Sleep(time.Until(off.Add(holderFreeze)))
	if err := thaw(); err != nil {
		t.Fatalf("thaw %s: %v", holder, err)
	}
	thawed := time.Now()
	thawedNode := l.nodeNow(holder)

	recovered := waitEach(s, off, recoverBy, keys, func(r round, k string) bool { return len(r.executing(k)) > 0 })
	for _, k := range keys {
		if _, ok := recovered[k]; !ok {
			t.Errorf("%s never recovered within %v of %s losing power\n  %s", k, recoverBy, victim, s.last())
		}
	}
	time.Sleep(time.Until(thawed.Add(staleWatch)))
	l.mark("drill2: watched the thawed holder for %v", staleWatch)

	// Exactly one recovery: one proof, one destination that never changes.
	p := l.proofsSince(q, "vm", test, since)
	if len(p) != 1 {
		t.Errorf("%s: %d recovery proofs since the failure, want exactly 1: %+v", test, len(p), p)
	}
	for _, pr := range p {
		if pr.Coordinator == holder && pr.LeaseTerm <= holderTerm {
			t.Errorf("%s: proof %s minted by the thawed holder %s under its stale term %d (held %d before the freeze)", test, pr.ID, holder, pr.LeaseTerm, holderTerm)
		}
	}
	lines := strings.Count(l.journalSince(holder, thawedNode, "rescheduling VM vm="+test+" "), "\n")
	wantLines := 0
	if len(p) == 1 && p[0].Coordinator == holder {
		wantLines = 1
	}
	if lines > wantLines {
		t.Errorf("the thawed holder %s logged %d reschedules of %s after the thaw, want %d", holder, lines, test, wantLines)
	}
	assertOneDestination(t, s.snapshot(), keys)

	// The holder was never fenced and nothing of its own moved.
	if st, err := l.hostStates(q); err == nil && st[holder] != "HOST_ACTIVE" {
		t.Errorf("holder %s is %s; a manual-strategy host must not be fenced without a confirmation", holder, st[holder])
	}
	last := s.last()
	for _, k := range holderKeys {
		if hs := last.executing(k); len(hs) != 1 || hs[0] != holder {
			t.Errorf("%s belonged to the frozen holder %s and now executes on %v", k, holder, hs)
		}
	}

	// Bring the victim back under the sampler: its return must not restart a copy.
	if err := l.powerOn(victim); err != nil {
		t.Errorf("power on %s: %v", victim, err)
	}
	l.waitAllActive(q, 6*time.Minute)
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, s, keys)
	s.Stop()
	assertNeverTwice(t, s.snapshot())

	t.Run("disk rows follow the replacement", func(t *testing.T) {
		skipUnlessFixed(t, "N7")
		assertDiskRowsFollow(t, l, q, s.last(), keys)
	})
}

// TestDrill3_VoterRemovedAfterAFence: one host is powered off and fenced, an
// operator removes it from the voter set, and then a second host fails. The
// second host's workloads are recovered by claims decided in the REDUCED
// generation, with no accept from the removed voter. The voter is added back.
func TestDrill3_VoterRemovedAfterAFence(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	n := len(l.hosts)
	first, second := l.hosts[n-1], l.hosts[n-2]
	q := l.hosts[0]
	test := l.createVMs(q, "d3", second)[second]
	keys := l.relocatableOn(q, b, second)
	gen0, _, err := l.voterSet(q)
	if err != nil {
		t.Fatal(err)
	}
	l.mark("drill3: fence %s, voter rm it, then fail %s (recoverable VMs %v)", first, second, keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, keys, second)

	l.powerOff(first)
	if !l.waitHostNot(q, first, "HOST_ACTIVE", hostDownBy) {
		t.Fatalf("%s still active %v after losing power", first, hostDownBy)
	}
	if out, err := l.lv(q, "cluster", "voter", "rm", first); err != nil {
		t.Fatalf("voter rm %s: %v\n%s", first, err, out)
	}
	gen1, members, err := l.voterSet(q)
	if err != nil {
		t.Fatal(err)
	}
	if gen1 <= gen0 || contains(members, first) || len(members) != n-1 {
		t.Fatalf("after voter rm %s: generation %d (was %d), members %v", first, gen1, gen0, members)
	}
	l.mark("drill3: generation %d = %v", gen1, members)

	off := l.powerOff(second)
	recovered := waitEach(s, off, recoverBy, keys, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != first && hs[0] != second
	})
	for _, k := range keys {
		if _, ok := recovered[k]; !ok {
			t.Errorf("%s not recovered on a survivor within %v\n  %s", k, recoverBy, s.last())
		}
	}

	// The claim behind the test VM's recovery was decided by the reduced set.
	ps := l.proofsSince(q, "vm", test, since)
	if len(ps) != 1 {
		t.Errorf("%s: %d recovery proofs, want 1: %+v", test, len(ps), ps)
	}
	for _, p := range ps {
		cert, err := corrosion.DecodeClaimCertificate(p.Cert)
		if err != nil {
			t.Errorf("%s proof %s: %v", test, p.ID, err)
			continue
		}
		if cert.ConfigGeneration != int64(gen1) {
			t.Errorf("%s: claim decided in generation %d, want the reduced generation %d", test, cert.ConfigGeneration, gen1)
		}
		var voters []string
		for _, a := range cert.Accepts {
			voters = append(voters, a.Voter)
			if !contains(members, a.Voter) {
				t.Errorf("%s: accept from %s, not a member of generation %d %v", test, a.Voter, gen1, members)
			}
		}
		if q := len(members)/2 + 1; len(cert.Accepts) < q {
			t.Errorf("%s: %d accepts %v, a majority of %v needs %d", test, len(cert.Accepts), voters, members, q)
		}
		l.mark("drill3: %s claim generation %d accepted by %v", test, cert.ConfigGeneration, voters)
	}

	// Restore under the sampler: both hosts back, the voter added back.
	if err := l.powerOn(first, second); err != nil {
		t.Errorf("power on: %v", err)
	}
	l.waitAllActive(q, 6*time.Minute)
	if out, err := l.lv(q, "cluster", "voter", "add", first); err != nil {
		t.Errorf("voter add %s: %v\n%s", first, err, out)
	}
	if gen, members, err := l.voterSet(q); err != nil || len(members) != n {
		t.Errorf("after voter add %s: generation %d, members %v, err %v", first, gen, members, err)
	}
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, s, keys)
	s.Stop()
	assertNeverTwice(t, s.snapshot())

	t.Run("disk rows follow the replacement", func(t *testing.T) {
		skipUnlessFixed(t, "N7")
		assertDiskRowsFollow(t, l, q, s.last(), keys)
	})
}

// TestDrill4_OwnerReachableVetoesTheClaim: the coordinator loses the owner
// while the other voters still reach it. The coordinator's fence quorum forms
// while the owner is cut off from three hosts; then the owner is cut off from
// the coordinator alone. Every voter that reaches the owner refuses the claim
// with recovery_claim_owner_reachable, no certificate forms, and the workload
// stays where it is.
//
// The owner runs with enforcement.partition_pause=false, as on kvm003: in the
// first phase it sees one peer and would otherwise pause, and the drill is
// about the claim veto, not the pause.
func TestDrill4_OwnerReachableVetoesTheClaim(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	coord := l.leaseHolder(l.hosts[0], "failover")
	owner := l.pick(func(h string) bool { return h != coord }, true)
	keep := l.pick(func(h string) bool { return h != coord && h != owner }, true)
	q := l.pick(func(h string) bool { return h != owner && h != keep }, false)
	var cut []string
	for _, h := range l.hosts {
		if h != owner && h != keep {
			cut = append(cut, h)
		}
	}
	test := l.createVMs(q, "d4", owner)[owner]
	key := "vm/" + test
	if err := l.setEnforcement(owner, "partition_pause", "false"); err != nil {
		t.Fatalf("partition_pause off on %s: %v", owner, err)
	}
	// Let the peers' cached Pings see the owner stop advertising the token. The
	// coordinator reads its LAST cached Ping (PeerAdvertisedLast, no RPC, no
	// age bound); the cache is refreshed by other callers at most every
	// peerCapTTL (30 s), so allow several.
	time.Sleep(capRefreshWait)
	// Finding P1: nothing refreshes that cache in steady state (only proof
	// replication does, through PeerSupports), so the coordinator keeps relying
	// on the pause the owner just turned off. The assertion below reports it.
	// E2E_DRILL4_REFRESH_PEERS=1 works around it, to exercise the veto itself:
	// a rolling restart empties every other host's cache, and an empty cache
	// is "not advertised".
	if os.Getenv("E2E_DRILL4_REFRESH_PEERS") == "1" {
		for _, h := range l.hosts {
			if h == owner {
				continue
			}
			time.Sleep(daemonRestartSpacing)
			if err := l.restartDaemon(h); err != nil {
				t.Fatalf("refresh peers: %v", err)
			}
		}
		time.Sleep(daemonRestartSpacing)
		coord = l.leaseHolder(q, "failover")
	}
	l.mark("drill4: coordinator %s, owner %s (partition_pause off), owner keeps only %s in phase 1", coord, owner, keep)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, []string{key}, owner)

	// Phase 1: the owner is cut off from all but one peer until a coordinator
	// reaches its fence quorum.
	if err := l.dropBetween(owner, cut); err != nil {
		t.Fatal(err)
	}
	l.mark("drill4: phase 1, %s drops %v", owner, cut)
	decider := l.waitJournal(cut, since, "quorum reached.*host="+owner+" ", 3*time.Minute)
	if decider == "" {
		t.Fatalf("no coordinator logged a fence quorum for %s within 3m", owner)
	}
	// Phase 2: only the deciding coordinator is cut off from the owner.
	if err := l.clearDrops(owner); err != nil {
		t.Fatal(err)
	}
	if err := l.dropBetween(owner, []string{decider}); err != nil {
		t.Fatal(err)
	}
	phase2 := l.mark("drill4: phase 2, %s (quorum for %s) is the only host cut off from it", decider, owner)
	time.Sleep(time.Until(phase2.Add(claimWatch)))
	if j := l.journalSince(decider, since, "relying on the host's partition pause.*host="+owner); j != "" {
		t.Errorf("coordinator %s relied on %s's partition pause although %s runs partition_pause=false: it decided on a capability advertisement cached before the flag went off, so it waited for a pause that would never happen instead of claiming:\n%s", decider, owner, owner, j)
	}

	// Every voter that reaches the owner refused; no certificate.
	via := l.pick(func(h string) bool { return h != owner && h != decider }, false)
	claim, err := l.lv(via, "cluster", "claim", key)
	if err != nil {
		t.Errorf("cluster claim %s: %v", key, err)
	}
	l.saveEvidence("claim-during.txt", claim)
	refusals := strings.Count(claim, health.ReasonClaimOwnerReachable)
	need := len(l.hosts) - (len(l.hosts)/2 + 1) + 1 // enough refusals that no majority can accept
	if refusals < need {
		t.Errorf("%s: %d voters refused with %s, want at least %d (all that reach the owner):\n%s", key, refusals, health.ReasonClaimOwnerReachable, need, claim)
	}
	if strings.Contains(claim, "decided") && !strings.Contains(claim, "no value accepted by a majority") {
		t.Errorf("%s: a claim value looks decided:\n%s", key, claim)
	}
	if j := l.journalSince(decider, since, "formed no certificate.*name="+test+" .*reason="+health.ReasonClaimOwnerReachable); j == "" {
		t.Errorf("coordinator %s never logged a claim for %s refused with %s", decider, test, health.ReasonClaimOwnerReachable)
	}
	if ps := l.proofsSince(via, "vm", test, since); len(ps) > 0 {
		t.Errorf("%s: recovery proofs minted although the owner was reachable: %+v", key, ps)
	}

	// Heal and watch: the workload never left the owner.
	if err := l.clearDrops(owner); err != nil {
		t.Fatal(err)
	}
	l.mark("drill4: healed")
	time.Sleep(returnWatch)
	s.Stop()
	rounds := s.snapshot()
	assertNeverTwice(t, rounds)
	for _, r := range rounds {
		if r.At.Before(phase2.Add(-claimWatch)) {
			continue
		}
		if hs := r.executing(key); len(hs) != 1 || hs[0] != owner {
			t.Errorf("%s executed on %v at %s; it must stay on its reachable owner %s", key, hs, r.At.UTC().Format("15:04:05.000"), owner)
			break
		}
	}
}

// TestDrill5_LegacyRecoveryWithClaimsOff: with enforcement.recovery_claim off
// on every host, a powered-off host's workloads are still recovered, once, by
// the legacy path (a proof with no claim certificate). The flag is restored.
func TestDrill5_LegacyRecoveryWithClaimsOff(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	victim := l.hosts[len(l.hosts)-1]
	q := l.hosts[0]
	test := l.createVMs(q, "d5", victim)[victim]
	keys := l.relocatableOn(q, b, victim)
	for i, h := range l.hosts {
		if err := l.setEnforcement(h, "recovery_claim", "false"); err != nil {
			t.Fatalf("recovery_claim off on %s: %v", h, err)
		}
		if i < len(l.hosts)-1 {
			time.Sleep(daemonRestartSpacing)
		}
	}
	time.Sleep(30 * time.Second)
	l.mark("drill5: recovery_claim off everywhere; victim %s (recoverable VMs %v)", victim, keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, keys, victim)
	off := l.powerOff(victim)
	recovered := waitEach(s, off, recoverBy, keys, func(r round, k string) bool { return len(r.executing(k)) == 1 })
	for _, k := range keys {
		if _, ok := recovered[k]; !ok {
			t.Errorf("%s not recovered within %v with claims off\n  %s", k, recoverBy, s.last())
		}
	}
	ps := l.proofsSince(q, "vm", test, since)
	if len(ps) != 1 {
		t.Errorf("%s: %d recovery proofs, want 1: %+v", test, len(ps), ps)
	}
	for _, p := range ps {
		if p.Cert != "" {
			t.Errorf("%s: proof %s carries a claim certificate with recovery_claim off; the legacy path mints none", test, p.ID)
		}
	}
	if err := l.powerOn(victim); err != nil {
		t.Errorf("power on %s: %v", victim, err)
	}
	l.waitAllActive(q, 6*time.Minute)
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, s, keys)
	s.Stop()
	assertNeverTwice(t, s.snapshot())

	t.Run("disk rows follow the replacement", func(t *testing.T) {
		skipUnlessFixed(t, "N7")
		assertDiskRowsFollow(t, l, q, s.last(), keys)
	})
}

// ─── helpers ────────────────────────────────────────────────────────────────

// pick returns the first host (or, with fromEnd, the last) that ok accepts.
func (l *lab) pick(ok func(string) bool, fromEnd bool) string {
	l.t.Helper()
	for i := range l.hosts {
		h := l.hosts[i]
		if fromEnd {
			h = l.hosts[len(l.hosts)-1-i]
		}
		if ok(h) {
			return h
		}
	}
	l.t.Fatalf("no host fits")
	return ""
}

// relocatableOn is recoverableOn minus containers that have nowhere to go:
// a container relocates only to another host running LXC, and on a lab with
// one LXC host a lost container stays down by design (it is restarted when its
// host returns).
func (l *lab) relocatableOn(via string, b baseline, lost ...string) []string {
	otherLXC := false
	for h := range b.lxcHosts {
		otherLXC = otherLXC || !contains(lost, h)
	}
	var ks []string
	for _, k := range l.recoverableOn(via, lost...) {
		if strings.HasPrefix(k, "vm/") || otherLXC {
			ks = append(ks, k)
		}
	}
	return ks
}

// leaseTerm is the newest term of a leader lease in via's replica.
func (l *lab) leaseTerm(via, key string) int {
	l.t.Helper()
	rows := l.mustSQL(via, "SELECT COALESCE(MAX(term),0) FROM leader_lease_terms WHERE key='"+key+"' AND deleted_at IS NULL")
	if len(rows) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(rows[0][0])
	return n
}

// waitHostNot waits until via reports host in some state other than state.
func (l *lab) waitHostNot(via, host, state string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := l.hostStates(via); err == nil && st[host] != "" && st[host] != state {
			l.mark("%s is %s", host, st[host])
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

// waitJournal returns the first of hosts whose litevirt journal matches
// pattern since a node-clock time, waiting up to timeout.
func (l *lab) waitJournal(hosts []string, since, pattern string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, h := range hosts {
			if strings.TrimSpace(l.journalSince(h, since, pattern)) != "" {
				l.mark("%s logged /%s/", h, pattern)
				return h
			}
		}
		time.Sleep(2 * time.Second)
	}
	return ""
}

// waitAllAt fails unless every key executes on host in a fresh sample.
func waitAllAt(t *testing.T, s *sampler, keys []string, host string) {
	t.Helper()
	if _, ok := s.waitFor(time.Now(), time.Minute, func(r round) bool {
		for _, k := range keys {
			if hs := r.executing(k); len(hs) != 1 || hs[0] != host {
				return false
			}
		}
		return true
	}); !ok {
		t.Fatalf("%v do not all execute on %s before the fault:\n  %s", keys, host, s.last())
	}
}

// assertOneDestination requires that once a workload executes somewhere new,
// it never moves again: one recovery, not two.
func assertOneDestination(t *testing.T, rounds []round, keys []string) {
	t.Helper()
	for _, k := range keys {
		var hosts []string
		for _, r := range rounds {
			hs := r.executing(k)
			if len(hs) == 1 && (len(hosts) == 0 || hosts[len(hosts)-1] != hs[0]) {
				hosts = append(hosts, hs[0])
			}
		}
		if len(hosts) > 2 {
			t.Errorf("%s executed on %s in turn; one recovery moves it once", k, strings.Join(hosts, " → "))
		}
	}
}
