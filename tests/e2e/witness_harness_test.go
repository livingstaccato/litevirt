package e2e

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/tests/e2e/latchparse"
)

// Harness for the witness and partition-pause drills (drill_witness_test.go,
// .superpowers/sdd/plan-residuals-2026-10-05/witness-drill-design.md §8).
// Every fault here goes into the drill nftables table, the node clocks or the
// cluster's own config, and registers its undo before it goes in.

const (
	// coordinatorPoll is failover/coordinator.go's poll interval.
	coordinatorPoll = 5 * time.Second
	// recoveryStallAfter and recoveryStallRepeat are failover/fence_wake.go's.
	recoveryStallAfter  = 60 * time.Second
	recoveryStallRepeat = 10 * time.Minute
	// clockSlack is how far apart an unskewed node's clock and this machine's
	// may be when a bound compares the two (lab NTP, plus a log line's
	// millisecond and a DB timestamp's second granularity).
	clockSlack = 3 * time.Second
	// stallLineMsg is the stall alert (failover/fence_wake.go:367).
	stallLineMsg = "failover: recovery of a fenced host has stalled"
	// notRunningMsg is the local stall line (health/stall.go:120).
	notRunningMsg = "health checker: this node was not running"
)

// ─── Topology preconditions ─────────────────────────────────────────────────

// witnessTopology is what the witness drills need from the lab and found there.
type witnessTopology struct {
	witness string   // the one witness outside E2E_LAB_NODES (lab 1's node-6)
	gen     int      // the adopted voter generation
	members []string // its members
	hlc     bool     // hlc_lww_v1 latched
	lt      leaseTermExpect
}

// requireWitnessTopology skips unless the lab is the one the design reasons
// about (witness-drill-design.md §0, §1): five worker hosts node-1..5 with none
// excluded, exactly one witness outside them that answers, an adopted voter
// generation whose members are exactly the five workers (so the witness does
// not vote), and partition_pause_v1, recovery_claim_v1 and lease_term_ledger_v1
// latched. lease_term_v1 is not required: requireLeaseTermMode reads whether
// the cluster enforces it, and the drills run in either mode.
func (l *lab) requireWitnessTopology(via string) witnessTopology {
	l.t.Helper()
	if len(l.excluded) > 0 {
		l.t.Skipf("witness drills need every worker: E2E_LAB_EXCLUDE leaves out %v", l.excluded)
	}
	if len(l.hosts) != 5 {
		l.t.Skipf("witness drills are designed for five workers node-1..5 (E2E_LAB_NODES=5), have %v", l.hosts)
	}
	outs := l.outsiderHosts()
	if len(outs) != 1 {
		l.t.Skipf("witness drills need exactly one witness outside E2E_LAB_NODES, found %v", outs)
	}
	w := witnessTopology{witness: outs[0]}
	if err := l.waitDaemon(w.witness, 30*time.Second); err != nil {
		l.t.Skipf("the witness %s does not answer: %v", w.witness, err)
	}
	gen, members, err := l.voterSet(via)
	if err != nil {
		l.t.Skipf("cannot read the voter set: %v", err)
	}
	w.gen, w.members = gen, members
	if strings.Join(members, ",") != strings.Join(l.hosts, ",") {
		l.t.Skipf("the design assumes an adopted voter generation of exactly %v (the witness not voting); generation %d has %v", l.hosts, gen, members)
	}
	up := l.mustLV(via, "cluster", "upgrade-status")
	l.saveEvidence("upgrade-status.txt", up)
	// lease_term_ledger_v1 (mandatory) is what mints lease terms, whatever
	// enforcement.lease_term says: W3, W4a, W4b and W5a compare terms.
	for _, tok := range []string{capabilities.PartitionPauseV1, capabilities.RecoveryClaimV1, capabilities.LeaseTermLedgerV1} {
		if !latchparse.TokenLatched(up, tok) {
			l.t.Skipf("%s is not latched on %s: the drill's expectations rest on it", tok, via)
		}
	}
	w.hlc = latchparse.TokenLatched(up, capabilities.HLCLwwV1)
	w.lt = l.requireLeaseTermMode(via)
	l.mark("witness: %s outside the voters; generation %d %v; hlc_lww_v1 latched=%v; lease_term %s", w.witness, gen, members, w.hlc, w.lt.Mode)
	return w
}

// bestEffort reports whether a fence strategy resolves to best-effort
// (fence.ResolveStrategy: "" is best-effort).
func bestEffort(s string) bool { return s == "" || s == "best-effort" }

// requireBestEffort skips unless every host is on the best-effort fence: the
// drills rely on a failed SSH power-off being recorded as a self-pause
// (failover/partition_pause.go asSelfPause), which only best-effort does.
func (l *lab) requireBestEffort(via string, hosts ...string) {
	l.t.Helper()
	for _, h := range hosts {
		if s := l.fenceStrategy(via, h); !bestEffort(s) {
			l.t.Skipf("%s is on the %q fence; the drill needs best-effort, whose failed power-off is a self-pause", h, s)
		}
	}
}

// setStrategy sets host's fence strategy. requireBaseline recorded every
// host's (witnesses outside E2E_LAB_NODES included) and restore puts them back.
func (l *lab) setStrategy(via, host, strategy string) {
	l.t.Helper()
	l.mustLV(via, "host", "config", host, "--fence-strategy", strategy)
	l.mark("fence: %s strategy %s", host, strategy)
}

// allBut is every cluster host (witnesses outside E2E_LAB_NODES included)
// except the named ones.
func (l *lab) allBut(skip ...string) []string {
	var out []string
	for _, h := range append(append([]string{}, l.hosts...), l.outsiderHosts()...) {
		if !contains(skip, h) {
			out = append(out, h)
		}
	}
	return out
}

// ─── Faults: edges and SSH ──────────────────────────────────────────────────

// drillChainsCmd creates the drill table and its two chains (idempotent).
func drillChainsCmd() string {
	return fmt.Sprintf(`nft add table inet %[1]s && nft add chain inet %[1]s in '{ type filter hook input priority -300; policy accept; }' && nft add chain inet %[1]s out '{ type filter hook output priority -300; policy accept; }'`, drillTable)
}

// cutPlan turns symmetric edges into, per host, the peers it drops: each edge
// is cut with a rule on both of its ends.
func cutPlan(edges [][2]string) map[string][]string {
	plan := map[string][]string{}
	for _, e := range edges {
		for i := 0; i < 2; i++ {
			a, b := e[i], e[1-i]
			if !contains(plan[a], b) {
				plan[a] = append(plan[a], b)
			}
		}
	}
	for h := range plan {
		sort.Strings(plan[h])
	}
	return plan
}

// edgesFrom is every edge between v and each of peers.
func edgesFrom(v string, peers ...string) [][2]string {
	var es [][2]string
	for _, p := range peers {
		es = append(es, [2]string{v, p})
	}
	return es
}

// cutEdges drops all cluster-LAN traffic across each edge, with rules on both
// ends, in the drill table (heal and clearDrops remove it). A witness outside
// E2E_LAB_NODES may be an end. It returns the instant before the first rule
// went in.
func (l *lab) cutEdges(edges ...[2]string) time.Time {
	l.t.Helper()
	l.outsiderHosts() // registers an outsider's address before it is cut
	start := l.mark("cut: %v", edges)
	plan := cutPlan(edges)
	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := map[string]error{}
	for h, peers := range plan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := l.dropBetween(h, peers)
			mu.Lock()
			errs[h] = err
			mu.Unlock()
		}()
	}
	wg.Wait()
	for h, err := range errs {
		if err != nil {
			l.t.Fatalf("cut rule on %s: %v", h, err)
		}
	}
	l.mark("cut: applied")
	return start
}

// sshPort is host's SSH port as the fence dials it (hosts.ssh_port, 22 when unset).
func (l *lab) sshPort(via, host string) int {
	l.t.Helper()
	rows := l.mustSQL(via, "SELECT COALESCE(NULLIF(ssh_port,0),22) FROM hosts WHERE name='"+host+"' AND deleted_at IS NULL")
	if len(rows) == 0 {
		l.t.Fatalf("no hosts row for %s on %s", host, via)
	}
	p, err := strconv.Atoi(rows[0][0])
	if err != nil || p <= 0 {
		return 22
	}
	return p
}

// sshCut makes host drop SSH from peers' cluster addresses, so every SSH
// power-off of it fails (a best-effort fence then comes back assumed, and is
// recorded as a self-pause). Health probes, gossip and replication are left
// alone. The rule is in the drill table. It then checks, from EVERY peer that
// is not already cut from host by a dropBetween rule (whose connect would time
// out with or without the SSH rule), that the port really is closed: a fence
// that reached the host would end the drill in a power-off it does not expect.
// A witness among peers is always one of them when it still reaches host.
func (l *lab) sshCut(via, host string, peers []string) {
	l.t.Helper()
	l.outsiderHosts()
	port := l.sshPort(via, host)
	var ips []string
	for _, p := range peers {
		ips = append(ips, l.ip[p])
	}
	cmd := drillChainsCmd() + fmt.Sprintf(` && nft add rule inet %s in ip saddr '{ %s }' tcp dport %d drop`, drillTable, strings.Join(ips, ", "), port)
	if _, err := l.ssh(host, 30*time.Second, cmd); err != nil {
		l.t.Fatalf("ssh cut on %s: %v", host, err)
	}
	l.mark("sshcut: %s drops tcp/%d from %v", host, port, peers)
	checked := 0
	for _, p := range peers {
		if l.isCut(host, p) {
			continue // fully cut: its CLOSED would prove nothing
		}
		out, err := l.ssh(p, 20*time.Second, fmt.Sprintf(`timeout 4 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null && echo OPEN || echo CLOSED`, l.ip[host], port))
		if err != nil {
			l.t.Fatalf("sshcut: cannot check %s:%d from %s, which still reaches it: %v", host, port, p, err)
		}
		if strings.Contains(out, "OPEN") {
			l.t.Fatalf("sshcut: %s still reaches %s:%d after the rule (is %s's address %s right?)", p, host, port, p, l.ip[p])
		}
		checked++
		l.mark("sshcut: %s cannot reach %s:%d", p, host, port)
	}
	if checked == 0 {
		l.t.Fatalf("sshcut: every peer of %s in %v is already cut from it; nothing shows the SSH rule works", host, peers)
	}
}

// startCheckedSampler is startSampler with the exactly-once check registered
// as a cleanup at once: a drill that ends early (a Fatal, a Skip, an
// inconclusive outcome) still has every sample it took checked, before the
// lab restore runs. A violation turns a skip into a failure.
func (l *lab) startCheckedSampler() *sampler {
	s := l.startSampler()
	t := l.t
	t.Cleanup(func() {
		s.Stop()
		assertNeverTwice(t, s.snapshot())
	})
	return s
}

// ─── Voter set ──────────────────────────────────────────────────────────────

// waitAdopted waits until every one of hosts has adopted generation gen.
func (l *lab) waitAdopted(gen int, hosts []string, deadline time.Time) error {
	for _, m := range hosts {
		ok := false
		for !ok && time.Now().Before(deadline) {
			rows, err := l.sql(m, "SELECT COALESCE(MAX(generation),0) FROM local_voter_adoption")
			ok = err == nil && len(rows) > 0 && rows[0][0] == strconv.Itoa(gen)
			if !ok {
				time.Sleep(3 * time.Second)
			}
		}
		if !ok {
			return fmt.Errorf("%s did not adopt voter generation %d", m, gen)
		}
	}
	return nil
}

var generationRe = regexp.MustCompile(`Generation (\d+) \(`)

// voterReset returns the cluster to the derived voter set (`lv cluster voter
// reset --yes`), waits until every worker has adopted the reset generation and
// requires `voter ls` to list no member. restore puts the baseline generation
// back with voterInit (and the drills do so themselves on success).
func (l *lab) voterReset(via string) int {
	l.t.Helper()
	out, err := l.lv(via, "cluster", "voter", "reset", "--yes")
	if err != nil {
		l.t.Fatalf("voter reset: %v\n%s", err, out)
	}
	m := generationRe.FindStringSubmatch(out)
	if m == nil {
		l.t.Fatalf("voter reset printed no generation:\n%s", out)
	}
	gen, _ := strconv.Atoi(m[1])
	if err := l.waitAdopted(gen, l.hosts, time.Now().Add(3*time.Minute)); err != nil {
		l.t.Fatalf("voter reset: %v", err)
	}
	g, members, err := l.voterSet(via)
	if err != nil || len(members) != 0 || g != gen {
		l.t.Fatalf("after voter reset: generation %d members %v (err %v), want generation %d with none", g, members, err, gen)
	}
	l.mark("voters: reset to the derived set at generation %d", gen)
	return gen
}

// voterInit starts a member generation of members (`lv cluster voter init
// --members ... --yes`) and waits until every member adopted it. It retries
// while a member is still adopting the previous generation.
func (l *lab) voterInit(via string, members []string) error {
	deadline := time.Now().Add(4 * time.Minute)
	var out string
	var err error
	for {
		out, err = l.lv(via, "cluster", "voter", "init", "--members", strings.Join(members, ","), "--yes")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("voter init %v: %v\n%s", members, err, out)
	}
	want := append([]string{}, members...)
	sort.Strings(want)
	// via may not have adopted the init yet, and then still prints the reset
	// generation with no members.
	var gen int
	var got []string
	for {
		gen, got, err = l.voterSet(via)
		if err == nil && strings.Join(got, ",") == strings.Join(want, ",") {
			break
		}
		if time.Now().After(deadline.Add(time.Minute)) {
			return fmt.Errorf("voter init: generation %d has %v (err %v), want %v", gen, got, err, want)
		}
		time.Sleep(3 * time.Second)
	}
	l.mark("voters: init generation %d %v", gen, got)
	return l.waitAdopted(gen, members, deadline.Add(2*time.Minute))
}

// ─── Conditions ─────────────────────────────────────────────────────────────

// bridgedEv is ha.recovery.bridged's evidence (failover/bridged_stall.go bridgedEvidence).
type bridgedEv struct {
	Detail          string   `json:"detail"`
	Workloads       []string `json:"workloads"`
	Observers       []string `json:"observers"`
	DerivedVoterSet bool     `json:"derived_voter_set"`
	Remedy          string   `json:"remedy"`
}

// condRow is one health_conditions row about a host.
type condRow struct {
	Lifecycle, FirstSeen, ResolvedAt, Evidence string
	Bridged                                    bridgedEv
}

// condition reads the evaluator/code condition about host in via's replica.
// The evidence travels hex-encoded, so no separator inside it can split it.
func (l *lab) condition(via, evaluator, code, host string) (condRow, bool, error) {
	rows, err := l.sql(via, fmt.Sprintf(
		"SELECT lifecycle, first_seen, COALESCE(resolved_at,''), hex(evidence) FROM health_conditions WHERE evaluator='%s' AND code='%s' AND subject_kind='host' AND subject_id IN ('%s','host/%s') AND deleted_at IS NULL",
		evaluator, code, host, host))
	if err != nil || len(rows) == 0 || len(rows[0]) < 4 {
		return condRow{}, false, err
	}
	r := condRow{Lifecycle: rows[0][0], FirstSeen: rows[0][1], ResolvedAt: rows[0][2]}
	if b, err := hex.DecodeString(rows[0][3]); err == nil {
		r.Evidence = string(b)
		_ = json.Unmarshal(b, &r.Bridged)
	}
	return r, true, nil
}

// condBridged is failover.CondRecoveryBridged, written by evaluator "failover"
// (failover/refence_condition.go RefenceEvaluator).
// evalStall writes health.CondObserverStalled (health/stall_condition.go:30).
const (
	condBridged  = "ha.recovery.bridged"
	evalFailover = "failover"
	evalStall    = "stall"
)

// waitBridged polls via every 2 s until host's ha.recovery.bridged is open
// with evidence whose detail starts with prefix.
func (l *lab) waitBridged(via, host, prefix string, timeout time.Duration) (condRow, time.Time, bool) {
	deadline := time.Now().Add(timeout)
	var last condRow
	for {
		c, ok, _ := l.condition(via, evalFailover, condBridged, host)
		if ok {
			last = c
			if c.Lifecycle != "resolved" && strings.HasPrefix(c.Bridged.Detail, prefix) {
				at := l.mark("bridged: %s %s open, observers %v, derived %v: %s", condBridged, host, c.Bridged.Observers, c.Bridged.DerivedVoterSet, c.Bridged.Detail)
				l.saveEvidence("bridged-"+host+"-"+at.UTC().Format("150405")+".json", c.Evidence)
				return c, at, true
			}
		}
		if time.Now().After(deadline) {
			l.t.Logf("bridged: last %s row for %s: %+v", condBridged, host, last)
			return last, time.Time{}, false
		}
		time.Sleep(2 * time.Second)
	}
}

// waitBridgedResolved polls via every 2 s until host's ha.recovery.bridged is resolved.
func (l *lab) waitBridgedResolved(via, host string, timeout time.Duration) (condRow, bool) {
	deadline := time.Now().Add(timeout)
	for {
		c, ok, _ := l.condition(via, evalFailover, condBridged, host)
		if ok && c.Lifecycle == "resolved" {
			l.mark("bridged: %s %s resolved at %s", condBridged, host, c.ResolvedAt)
			return c, true
		}
		if time.Now().After(deadline) {
			return c, false
		}
		time.Sleep(2 * time.Second)
	}
}

// ─── host_health rows ───────────────────────────────────────────────────────

type healthRow struct {
	Status   string
	Failures int
	Updated  time.Time
	Raw      string
}

// healthRowOf reads (observer, target) from via's host_health.
func (l *lab) healthRowOf(via, observer, target string) (healthRow, bool) {
	rows, err := l.sql(via, fmt.Sprintf("SELECT status, COALESCE(consecutive_failures,0), updated_at FROM host_health WHERE observer='%s' AND target='%s' AND deleted_at IS NULL", observer, target))
	if err != nil || len(rows) == 0 || len(rows[0]) < 3 {
		return healthRow{}, false
	}
	n, _ := strconv.Atoi(rows[0][1])
	upd, _ := corrosion.ParseUpdatedAt(rows[0][2])
	return healthRow{Status: rows[0][0], Failures: n, Updated: upd, Raw: strings.Join(rows[0], "|")}, true
}

// waitHealthRow samples via's (observer, target) row every second until pred
// holds, and returns this machine's time of the first sample that saw it.
func (l *lab) waitHealthRow(via, observer, target string, pred func(healthRow) bool, timeout time.Duration) (time.Time, healthRow, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if r, ok := l.healthRowOf(via, observer, target); ok && pred(r) {
			at := l.mark("health: %s's replica holds %s→%s %s", via, observer, target, r.Raw)
			return at, r, true
		}
		if time.Now().After(deadline) {
			return time.Time{}, healthRow{}, false
		}
		time.Sleep(time.Second)
	}
}

func failing(r healthRow) bool { return r.Failures >= 1 }

// arrivalWatch records when a query first returns a row in some replica, sampled
// every second in the background (sampleRowArrival).
type arrivalWatch struct {
	mu   sync.Mutex
	at   time.Time
	on   string
	stop chan struct{}
	done chan struct{}
}

// sampleRowArrival watches for the first row of query in the replica of
// whichever host via() names at each sample (the lease holder, which can change).
func (l *lab) sampleRowArrival(desc string, via func() string, query string) *arrivalWatch {
	w := &arrivalWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			h := via()
			if h != "" {
				if rows, err := l.sql(h, query); err == nil && len(rows) > 0 {
					w.mu.Lock()
					w.at, w.on = time.Now(), h
					w.mu.Unlock()
					l.mark("arrival: %s in %s's replica", desc, h)
					return
				}
			}
			select {
			case <-w.stop:
				return
			case <-tick.C:
			}
		}
	}()
	l.t.Cleanup(w.Stop)
	return w
}

func (w *arrivalWatch) Stop() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
}

func (w *arrivalWatch) result() (time.Time, string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.at, w.on, !w.at.IsZero()
}

// ─── Journal lines with their times ─────────────────────────────────────────

type logLine struct {
	At   time.Time // the record's own time= (the node's clock); zero if absent
	Text string
}

var logTimeRe = regexp.MustCompile(`(?:^|\s)time=(\S+)`)

// parseLogLines splits journal output into lines with the time= each slog
// text record carries.
func parseLogLines(out string) []logLine {
	var ls []logLine
	for _, s := range strings.Split(out, "\n") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		ll := logLine{Text: s}
		if m := logTimeRe.FindStringSubmatch(s); m != nil {
			if t, err := time.Parse(time.RFC3339Nano, strings.Trim(m[1], `"`)); err == nil {
				ll.At = t
			}
		}
		ls = append(ls, ll)
	}
	return ls
}

// journalLines is journalSince with each line's time.
func (l *lab) journalLines(host, since, pattern string) []logLine {
	return parseLogLines(l.journalSince(host, since, pattern))
}

// waitLogLine waits until one of hosts logs a line matching pattern (grep -E)
// that contains every one of must and is stamped at or after after (zero: any
// time), and returns the host and the line.
func (l *lab) waitLogLine(hosts []string, since, pattern string, after time.Time, must []string, timeout time.Duration) (string, logLine, bool) {
	deadline := time.Now().Add(timeout)
	for {
		for _, h := range hosts {
			for _, ln := range l.journalLines(h, since, pattern) {
				if !after.IsZero() && (ln.At.IsZero() || ln.At.Before(after)) {
					continue
				}
				ok := true
				for _, m := range must {
					ok = ok && strings.Contains(ln.Text, m)
				}
				if ok {
					l.mark("journal: %s: %s", h, ln.Text)
					return h, ln, true
				}
			}
		}
		if time.Now().After(deadline) {
			return "", logLine{}, false
		}
		time.Sleep(2 * time.Second)
	}
}

// stallPattern greps the stall alert for host.
func stallPattern(host string) string { return journalPair(stallLineMsg, "host", host) }

// waitStallLine waits for the stall alert for host, with reason containing
// reasonSubstr, on any of hosts (every node that may have held the lease).
func (l *lab) waitStallLine(hosts []string, since, host, reasonSubstr string, after time.Time, timeout time.Duration) (string, logLine, bool) {
	return l.waitLogLine(hosts, since, stallPattern(host), after, []string{reasonSubstr}, timeout)
}

// nodeSinceMinus is a node-clock timestamp d before since, for reading the
// journal of a node whose clock was stepped back.
func nodeSinceMinus(since string, d time.Duration) string {
	t, err := time.Parse(time.RFC3339, since)
	if err != nil {
		return since
	}
	return t.Add(-d).UTC().Format(time.RFC3339)
}

// ─── The failover lease over time ───────────────────────────────────────────

type leaseChange struct {
	At     time.Time
	Holder string
	Term   int
	Reader string // the replica that was read ("" for the merged history)
}

// leaseWatch samples the failover lease (holder and newest term) every second.
type leaseWatch struct {
	l       *lab
	mu      sync.Mutex
	readers []string
	avoided map[string]bool
	changes []leaseChange
	incoh   map[string]*incoherenceTracker
	// every incoherent sample, and the holder each term was first seen with
	incohSamples []leaseIncoherent
	termHolder   map[int]string
	fail         func(format string, args ...any)
	logf         func(format string, args ...any)
	summed       sync.Once
	selfClaim    selfClaimTracker
	unknownRun   map[string]int // consecutive failed reads per reader
	unknownTotal map[string]int // all failed reads per reader
	ticks        int            // ticks sampled
	all          []leaseChange  // every reader's tenures, tagged by reader
	lastBy       map[string]leaseChange
	maxTerm      map[string]int
	stop         chan struct{}
	done         chan struct{}
}

// watchLease samples leader_election and leader_lease_terms every second from
// the first of readers that is not avoided and answers (a frozen or stopped
// node's replica stops applying, so the drill avoids it while it is out).
func (l *lab) watchLease(readers []string) *leaseWatch {
	w := &leaseWatch{l: l, readers: readers, avoided: map[string]bool{}, incoh: map[string]*incoherenceTracker{}, termHolder: map[int]string{}, lastBy: map[string]leaseChange{}, maxTerm: map[string]int{}, fail: l.t.Errorf, logf: func(f string, a ...any) { l.mark(f, a...) }, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			w.sampleOnce()
			select {
			case <-w.stop:
				return
			case <-tick.C:
			}
		}
	}()
	l.t.Cleanup(w.Stop)
	return w
}

func (w *leaseWatch) sampleOnce() {
	w.mu.Lock()
	var rs []string
	for _, r := range w.readers {
		if !w.avoided[r] {
			rs = append(rs, r)
		}
	}
	w.mu.Unlock()
	var samples []readerSample
	for _, r := range rs { // every reader every tick: a later one can be the incoherent one
		rows, err := w.l.sql(r, "SELECT COALESCE((SELECT holder FROM leader_election WHERE key='failover'),''), (SELECT COALESCE(MAX(term),0) FROM leader_lease_terms WHERE key='failover' AND deleted_at IS NULL), COALESCE((SELECT holder FROM leader_lease_terms WHERE key='failover' AND deleted_at IS NULL ORDER BY term DESC LIMIT 1),''), COALESCE((SELECT group_concat(term || ':' || holder, ',') FROM leader_lease_terms WHERE key='failover' AND deleted_at IS NULL),''), COALESCE((SELECT expires_at FROM leader_election WHERE key='failover'),''), strftime('%Y-%m-%dT%H:%M:%SZ','now')")
		if err != nil || len(rows) == 0 || len(rows[0]) < 6 {
			samples = append(samples, readerSample{Reader: r, Failed: true})
			continue
		}
		term, _ := strconv.Atoi(rows[0][1])
		samples = append(samples, readerSample{Reader: r, S: leaseSample{Election: rows[0][0], Term: term, Ledger: rows[0][2], Terms: parseTermHolders(rows[0][3]), Expires: parseLeaseTime(rows[0][4]), Now: parseLeaseTime(rows[0][5])}})
	}
	w.sampleTick(time.Now(), samples)
}

// readerSample is one reader's answer in a tick; Failed is a sql read that
// gave nothing (the reader's state is unknown, not absent).
type readerSample struct {
	Reader string
	S      leaseSample
	Failed bool
}

// recorderOf picks the reader whose sample feeds the change history this
// tick: the usable (not lagging, not unexplained) sample with the highest
// ledger term, the first of those on a tie; "" when none is usable. A stale
// self-consistent replica therefore never stands in for the newest tenure.
func recorderOf(samples []readerSample) string {
	best, bestTerm := "", -1
	for _, rs := range samples {
		if rs.Failed {
			continue
		}
		if k := classifyLease(rs.S); k == leaseLag || k == leaseUnexplained || (k == leaseNeutral && rs.S.Election != "") {
			continue
		}
		if rs.S.Term > bestTerm {
			best, bestTerm = rs.Reader, rs.S.Term
		}
	}
	return best
}

// selfClaims reports whether the sample is a claim to count at once: the
// replica names its own node holder, is not lag-classified and the lease it
// names is unexpired by that replica's own clock. A lagging replica holding
// its own old election row is catching up, and an expired row is a tenure that
// ended: neither is a holder.
func selfClaims(r string, s leaseSample) bool {
	return s.Election == r && classifyLease(s) != leaseLag && !s.expired()
}

// sampleTick takes every reader's answer for one tick.
func (w *leaseWatch) sampleTick(now time.Time, samples []readerSample) {
	rec := recorderOf(samples)
	claims := map[string]string{}
	var unknown []string
	for _, rs := range samples {
		if rs.Failed {
			unknown = append(unknown, rs.Reader)
			continue
		}
		w.observe(rs.Reader, now, rs.S, rs.Reader == rec)
		if selfClaims(rs.Reader, rs.S) {
			claims[rs.Reader] = rs.S.Election // the node's own replica names the node itself
		}
	}
	w.observeTick(now, claims, unknown)
}

// selfClaimGrace is how long two nodes may each name themselves the holder in
// their own replicas (a handover seen from both ends) before it is a dual holder.
const (
	selfClaimGrace     = 5 * time.Second
	selfClaimGraceTick = 2
)

// selfClaimTracker follows consecutive ticks with two self-claimants.
type selfClaimTracker struct {
	held     bool            // a run is being held across an unreadable claimant
	last     map[string]bool // who claimed on the previous tick (or was carried)
	n        int
	since    time.Time
	reported bool
}

// observeTick takes the tick's self-claims (reader → itself) and fails when two
// different nodes have each been named holder by their OWN replica for 2
// consecutive ticks or selfClaimGrace. A stale replica of someone else's
// tenure is lag, not a claim, and never enters here.
func (w *leaseWatch) observeTick(now time.Time, claims map[string]string, unknown []string) {
	w.mu.Lock()
	c := &w.selfClaim
	persistent := w.noteUnknown(unknown)
	// A failed read of a node that claimed last tick is unknown: it neither
	// resets nor extends the run, so intermittent sql errors cannot evade it.
	carried := 0
	last := map[string]bool{}
	for r := range claims {
		last[r] = true
	}
	for _, u := range unknown {
		if c.last[u] {
			carried++
			last[u] = true
		}
	}
	if len(claims) < 2 {
		if len(claims)+carried >= 2 {
			// Bound the hold: a claimant unreadable for good is unverifiable.
			var gone []string
			for _, u := range unknown {
				if c.last[u] && w.unknownRun[u] > unknownPersistent+unknownHeldExtra {
					gone = append(gone, u)
				}
			}
			if len(gone) > 0 {
				k := w.unknownRun[gone[0]]
				*c = selfClaimTracker{}
				w.mu.Unlock()
				w.reportUnknown(persistent)
				w.fail("lease: dual claim unverifiable: %v claimed beside another holder, then unreadable %d ticks", gone, k)
				return
			}
			enter := !c.held
			c.held = true
			c.last = last
			w.mu.Unlock()
			w.reportUnknown(persistent)
			if enter {
				w.logf("lease: self-claim run held across an unreadable replica (%v)", unknown)
			}
			return
		}
		*c = selfClaimTracker{}
		w.mu.Unlock()
		w.reportUnknown(persistent)
		return
	}
	c.last = last
	c.held = false
	if c.n == 0 {
		c.since = now
	}
	c.n++
	fail := !c.reported && (c.n >= selfClaimGraceTick || now.Sub(c.since) >= selfClaimGrace)
	if fail {
		c.reported = true
	}
	n := c.n
	w.mu.Unlock()
	w.reportUnknown(persistent)
	names := make([]string, 0, len(claims))
	for r := range claims {
		names = append(names, r)
	}
	sort.Strings(names)
	w.logf("lease: SELF-CLAIMS by %v at the same tick (tick %d)", names, n)
	if fail {
		w.fail("lease: dual holder: %v each hold the lease in their own replica for %d consecutive ticks", names, n)
	}
}

// neverReadable lists readers whose sql failed on every sampled tick.
func (w *leaseWatch) neverReadable() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	if w.ticks < unknownPersistent+unknownHeldExtra {
		return nil
	}
	for r, n := range w.unknownTotal {
		if n == w.ticks {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// unknownPersistent is how many consecutive failed reads of one replica make
// it worth a log line.
const unknownPersistent = 3

// unknownHeldExtra is how many ticks past unknownPersistent a held run waits
// for its unreadable claimant before the drill fails.
const unknownHeldExtra = 3

// noteUnknown counts consecutive failed reads per reader (w.mu held) and
// returns the readers that just reached unknownPersistent.
func (w *leaseWatch) noteUnknown(unknown []string) []string {
	if w.unknownRun == nil {
		w.unknownRun = map[string]int{}
		w.unknownTotal = map[string]int{}
	}
	w.ticks++
	failed := map[string]bool{}
	var hit []string
	for _, u := range unknown {
		failed[u] = true
		w.unknownRun[u]++
		w.unknownTotal[u]++
		if w.unknownRun[u] == unknownPersistent {
			hit = append(hit, u)
		}
	}
	for r := range w.unknownRun {
		if !failed[r] {
			w.unknownRun[r] = 0
		}
	}
	return hit
}

func (w *leaseWatch) reportUnknown(hit []string) {
	for _, r := range hit {
		w.logf("lease: %s's replica could not be read for %d consecutive ticks; its self-claims are unknown", r, unknownPersistent)
	}
}

// leaseSample is one replica's view of the lease: its election row, the newest
// ledger term and that term's holder, and every term's holder.
type leaseSample struct {
	Election string
	Term     int
	Ledger   string
	Terms    map[int]string
	// Expires is the election row's expires_at and Now the reader's clock at
	// the read (the node's own sqlite). Zero means unknown, which counts as
	// unexpired: an unreadable expiry never excuses a claim.
	Expires time.Time
	Now     time.Time
}

// A drill that steps a watched reader's clock forward must account for this.
// leaseSkewMargin is how far past expires_at the reader's clock must be before
// the row counts as expired: clocks across nodes may differ by this much.
const leaseSkewMargin = clockSlack

// parseLeaseTime reads an RFC3339 lease timestamp; "" or garbage is the zero time.
func parseLeaseTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// expired reports whether the election row's lease had clearly ended by the
// reader's own clock, beyond the skew margin. Unknown is not expired.
func (s leaseSample) expired() bool {
	if s.Expires.IsZero() || s.Now.IsZero() {
		return false
	}
	return s.Now.After(s.Expires.Add(leaseSkewMargin))
}

// parseTermHolders reads "50:node-2,51:node-4".
func parseTermHolders(s string) map[int]string {
	m := map[int]string{}
	for _, kv := range strings.Split(s, ",") {
		t, h, ok := strings.Cut(kv, ":")
		if n, err := strconv.Atoi(t); ok && err == nil {
			m[n] = h
		}
	}
	return m
}

type leaseSampleKind int

const (
	leaseCoherent    leaseSampleKind = iota
	leaseNeutral                     // election empty, or an expired row, beside a held ledger term: between tenures
	leaseLag                         // election holds an OLDER term: the replica is behind
	leaseUnexplained                 // election holder holds no earlier term either
)

// classifyLease sorts a sample. A lagging replica holds its own old election
// row beside a newer ledger term; pairing the two would report a second
// holder at a term that had one.
func classifyLease(s leaseSample) leaseSampleKind {
	switch {
	case s.Ledger == "" || s.Election == s.Ledger:
		return leaseCoherent
	case s.Election == "":
		return leaseNeutral
	}
	for t, h := range s.Terms {
		if t < s.Term && h == s.Election {
			return leaseLag
		}
	}
	if s.expired() {
		return leaseNeutral // a tenure that ended, nobody holds it
	}
	return leaseUnexplained
}

// observe takes one sample from reader r and reports whether it was recorded
// as a lease change (only when record is set and the sample is usable).
// Nothing is dropped silently: every incoherent sample is kept for the Stop
// summary and logged; two holders for one term fail at once; an incoherence
// that persists on one reader fails after incoherenceBound.
func (w *leaseWatch) observe(r string, now time.Time, s leaseSample, record bool) bool {
	w.mu.Lock()
	// The ledger must have one holder per term, across readers and over time.
	var conflicts []string
	if w.maxTerm != nil && s.Term < w.maxTerm[r] {
		// The reader's ledger went backwards: a lease reset (or a replaced
		// replica) reuses term numbers, so earlier term holders no longer apply.
		w.termHolder = map[int]string{}
		defer w.logf("lease: %s's newest term fell from %d to %d; term holders forgotten", r, w.maxTerm[r], s.Term)
	}
	if w.maxTerm != nil {
		w.maxTerm[r] = s.Term
	}
	for t, h := range s.Terms {
		if prev, ok := w.termHolder[t]; ok && prev != h {
			conflicts = append(conflicts, fmt.Sprintf("term %d held by %q and by %q (read on %s)", t, prev, h, r))
		} else if !ok {
			w.termHolder[t] = h
		}
	}
	kind := classifyLease(s)
	tr := w.incoh[r]
	if tr == nil {
		tr = &incoherenceTracker{}
		w.incoh[r] = tr
	}
	var persistent bool
	switch kind {
	case leaseCoherent:
		tr.observe(now, true)
	case leaseNeutral:
		// neither resets nor extends a run
	case leaseLag:
		// A replica behind the ledger with an EXPIRED row is a restarted node's
		// leftover (leader_election is not carried by anti-entropy): recorded,
		// never failed. An unexpired or unknown one is a lease someone may still
		// be renewing beside a newer term, and counts toward the window.
		if !s.expired() {
			persistent = tr.observe(now, false)
		}
		w.incohSamples = append(w.incohSamples, leaseIncoherent{At: now, Reader: r, Sample: s, Kind: kind})
	default:
		persistent = tr.observe(now, false)
		w.incohSamples = append(w.incohSamples, leaseIncoherent{At: now, Reader: r, Sample: s, Kind: kind})
	}
	streak := tr.n
	w.mu.Unlock()
	for _, c := range conflicts {
		w.fail("lease: two holders for one term: %s", c)
	}
	if kind == leaseLag || kind == leaseUnexplained {
		w.logf("lease: INCOHERENT sample on %s: election holder %q, ledger term %d held by %q (%s, streak %d, expires %s, reader clock %s)", r, s.Election, s.Term, s.Ledger, [...]string{"", "", "lagging", "unexplained"}[kind], streak, s.Expires.Format(time.RFC3339), s.Now.Format(time.RFC3339))
	}
	if persistent {
		w.fail("lease: %s's replica has shown election holder %q beside ledger term %d held by %q for %d samples over %v: an unexpired election row that disagrees with the ledger (%s)", r, s.Election, s.Term, s.Ledger, streak, incoherenceBound, [...]string{"", "", "behind the ledger: a lease still being renewed beside a newer term", "no ledger term explains it"}[kind])
	}
	if kind == leaseLag || kind == leaseUnexplained || (kind == leaseNeutral && s.Election != "") {
		return false // not a tenure: an expired non-empty row names nobody who holds
	}
	c := leaseChange{At: now, Holder: s.Election, Term: s.Term, Reader: r}
	w.mu.Lock()
	if w.lastBy != nil {
		if p, ok := w.lastBy[r]; !ok || p.Holder != c.Holder || p.Term != c.Term {
			w.lastBy[r] = c
			w.all = append(w.all, c)
		}
	}
	if !record {
		w.mu.Unlock()
		return false
	}
	n := len(w.changes)
	if n == 0 || w.changes[n-1].Holder != c.Holder || w.changes[n-1].Term != c.Term {
		w.changes = append(w.changes, c)
		w.mu.Unlock()
		w.logf("lease: failover held by %s, term %d (read on %s)", c.Holder, c.Term, r)
		return true
	}
	w.mu.Unlock()
	return true
}

// leaseIncoherent is one kept incoherent sample.
type leaseIncoherent struct {
	At     time.Time
	Reader string
	Sample leaseSample
	Kind   leaseSampleKind
}

// summary is the end-of-drill account of every incoherent sample.
func (w *leaseWatch) summary() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var b strings.Builder
	if len(w.incohSamples) == 0 {
		b.WriteString("lease: no incoherent samples")
	} else {
		fmt.Fprintf(&b, "lease: %d incoherent sample(s):", len(w.incohSamples))
		for _, o := range w.incohSamples {
			fmt.Fprintf(&b, "\n  %s on %s: election %q, ledger term %d held by %q (kind %d, expires %s, reader clock %s)", o.At.Format("15:04:05"), o.Reader, o.Sample.Election, o.Sample.Term, o.Sample.Ledger, o.Kind, o.Sample.Expires.Format(time.RFC3339), o.Sample.Now.Format(time.RFC3339))
		}
	}
	var names []string
	for r, n := range w.unknownTotal {
		if n > 0 {
			names = append(names, r)
		}
	}
	sort.Strings(names)
	for _, r := range names {
		fmt.Fprintf(&b, "\nlease: %s unreadable on %d of %d tick(s) (its claims were unknown)", r, w.unknownTotal[r], w.ticks)
	}
	return b.String()
}

// incoherenceBound is the window in which one replica may show incoherenceMax
// election holders that disagree with its ledger before the drill fails.
const incoherenceBound = 10 * time.Second

// incoherenceTracker follows one reader's incoherent samples over a sliding
// window: a flapping election row cannot evade it by alternating.
type incoherenceTracker struct {
	times    []time.Time
	n        int // incoherent samples in the window
	reported bool
}

// incoherenceMax is how many incoherent samples one reader may show within
// incoherenceBound.
const incoherenceMax = 3

// observe records a sample and reports, once per episode, that incoherenceMax
// incoherent samples fell within incoherenceBound. Coherent samples do not
// clear the window; they only let it drain.
func (c *incoherenceTracker) observe(now time.Time, coherent bool) bool {
	keep := c.times[:0]
	for _, t := range c.times {
		if now.Sub(t) < incoherenceBound {
			keep = append(keep, t)
		}
	}
	c.times = keep
	if !coherent {
		c.times = append(c.times, now)
	}
	c.n = len(c.times)
	if c.n == 0 {
		c.reported = false
	}
	if c.reported || c.n < incoherenceMax {
		return false
	}
	c.reported = true
	return true
}

// allHistory is every reader's tenures, tagged by reader, in sampling order.
func (w *leaseWatch) allHistory() []leaseChange {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]leaseChange(nil), w.all...)
}

func (w *leaseWatch) Stop() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
	w.summed.Do(func() {
		w.logf("%s", w.summary())
		for _, r := range w.neverReadable() {
			w.fail("lease: W3 inconclusive: %s's replica was unreadable on every one of %d sampled ticks", r, w.ticks)
		}
	})
}

func (w *leaseWatch) avoid(h string, on bool) {
	w.mu.Lock()
	w.avoided[h] = on
	delete(w.incoh, h) // a replica returning from an outage starts a new run
	w.mu.Unlock()
}

func (w *leaseWatch) history() []leaseChange {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]leaseChange(nil), w.changes...)
}

// current is the newest sample's holder and term.
func (w *leaseWatch) current() leaseChange {
	h := w.history()
	if len(h) == 0 {
		return leaseChange{}
	}
	return h[len(h)-1]
}

// holders is every holder seen, in order of first appearance.
func (w *leaseWatch) holders() []string {
	var out []string
	for _, c := range w.history() {
		if c.Holder != "" && !contains(out, c.Holder) {
			out = append(out, c.Holder)
		}
	}
	return out
}

// waitHolderNot waits until the lease is held by someone other than old, and
// returns the new holder and when it was first seen.
func (w *leaseWatch) waitHolderNot(old string, after time.Time, timeout time.Duration) (leaseChange, bool) {
	deadline := time.Now().Add(timeout)
	for {
		for _, c := range w.history() {
			if c.At.After(after) && c.Holder != "" && c.Holder != old {
				return c, true
			}
		}
		if time.Now().After(deadline) {
			return leaseChange{}, false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// mainPID is host's litevirt MainPID ("" when unreadable).
func (l *lab) mainPID(host string) string {
	out, err := l.ssh(host, 20*time.Second, "systemctl show -p MainPID --value litevirt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// requireManual fails unless host is on the manual fence: a stopped or frozen
// holder looks dead to its peers, and only manual keeps them from fencing it.
func (l *lab) requireManual(via, host string) {
	l.t.Helper()
	if s := l.fenceStrategy(via, host); s != "manual" {
		l.t.Fatalf("%s is on the %q fence; the drill must set it manual before stopping or freezing it", host, s)
	}
}

// handoverByStop stops holder's daemon (a graceful stop records it upgrading,
// so it is not fenced) until the lease moves, then starts it again. A plain
// restart usually keeps the lease, so only a stop longer than the lease moves
// it. Returns the new holder.
func (l *lab) handoverByStop(via, holder string, lw *leaseWatch) (leaseChange, bool) {
	l.t.Helper()
	l.requireManual(via, holder)
	l.t.Cleanup(func() { l.ssh(holder, time.Minute, "systemctl start litevirt") })
	lw.avoid(holder, true)
	defer lw.avoid(holder, false)
	if _, err := l.ssh(holder, 2*time.Minute, "systemctl stop litevirt"); err != nil {
		l.t.Fatalf("stop litevirt on %s: %v", holder, err)
	}
	stopped := l.mark("handover: stopped litevirt on the holder %s", holder)
	next, ok := lw.waitHolderNot(holder, stopped, failoverLeaseTTL+15*time.Second)
	if _, err := l.ssh(holder, time.Minute, "systemctl start litevirt"); err != nil {
		l.t.Errorf("start litevirt on %s: %v", holder, err)
	}
	// Keep the holder avoided until it serves: its replica holds its own old
	// leader_election row for a moment after the restart.
	if err := l.waitServing(holder, 3*time.Minute); err != nil {
		l.t.Errorf("%v", err)
	}
	l.mark("handover: started litevirt on %s again (new holder %q, moved=%v)", holder, next.Holder, ok)
	return next, ok
}

// handoverByFreeze SIGSTOPs holder's daemon for holderFreeze (the lease TTL
// plus 20 s), which keeps its process and memory, then thaws it. Returns the
// holder that took the lease meanwhile.
func (l *lab) handoverByFreeze(via, holder string, lw *leaseWatch) (leaseChange, bool) {
	l.t.Helper()
	l.requireManual(via, holder)
	lw.avoid(holder, true)
	defer lw.avoid(holder, false)
	thaw := l.freezeDaemon(holder)
	l.t.Cleanup(func() { thaw() })
	frozen := time.Now()
	next, ok := lw.waitHolderNot(holder, frozen, holderFreeze)
	time.Sleep(time.Until(frozen.Add(holderFreeze)))
	if err := thaw(); err != nil {
		l.t.Errorf("thaw %s: %v", holder, err)
	}
	// Stay avoided until the thawed replica has caught up and serves.
	if err := l.waitServing(holder, 3*time.Minute); err != nil {
		l.t.Errorf("%v", err)
	}
	return next, ok
}

// ─── Node clocks ────────────────────────────────────────────────────────────

// clockStep is one node's stepped clock and what restores it.
type clockStep struct {
	host  string
	ntp   string // timedatectl NTP= before the drill
	total time.Duration
	done  bool
}

// stepClock steps host's wall clock by d (CLOCK_REALTIME only: Go's
// monotonic readings, the L2 guests' kvmclock and the lab host are not
// affected). Time sync is turned off first and the prior NTP= setting kept;
// the clock is never written to the RTC. |d| is capped at 60 s, well inside
// hlc.MaxSkewMS. The first step on a host registers its restore as a cleanup
// (it runs before the lab restore). It checks the step took.
func (l *lab) stepClock(host string, d time.Duration) {
	l.t.Helper()
	if d > 60*time.Second || d < -60*time.Second {
		l.t.Fatalf("stepClock %s by %v: the drills keep |Δ| ≤ 60 s", host, d)
	}
	if l.clocks == nil {
		l.clocks = map[string]*clockStep{}
	}
	cs := l.clocks[host]
	if cs == nil || cs.done {
		ntp := strings.TrimSpace(l.mustSSH(host, 20*time.Second, "timedatectl show -p NTP --value"))
		if ntp != "yes" && ntp != "no" {
			l.t.Fatalf("timedatectl on %s reports NTP=%q (requireClocksManageable should have skipped)", host, ntp)
		}
		cs = &clockStep{host: host, ntp: ntp}
		l.clocks[host] = cs
		l.t.Cleanup(func() { l.restoreClock(host) })
	}
	before := l.clockOffset(host)
	l.mustSSH(host, 30*time.Second, fmt.Sprintf(
		`timedatectl set-ntp false && now=$(date +%%s.%%N) && date -u -s "@$(awk -v n=$now -v d=%.3f 'BEGIN{printf "%%.3f", n+d}')" >/dev/null`,
		d.Seconds()))
	cs.total += d
	after := l.clockOffset(host)
	l.mark("clock: %s stepped by %v (offset %v → %v, NTP was %s)", host, d, before.Round(time.Millisecond), after.Round(time.Millisecond), cs.ntp)
	if got := after - before; got < d-2*time.Second || got > d+2*time.Second {
		l.t.Fatalf("clock: %s moved by %v, want %v (is a time daemon still stepping it?)", host, got, d)
	}
}

// requireClocksManageable skips unless every host's time sync can be read and
// turned off with timedatectl, and records each host's offset from this
// machine, which restoreClock puts back. Run it before any fault.
func (l *lab) requireClocksManageable(hosts ...string) {
	l.t.Helper()
	if l.clockBase == nil {
		l.clockBase = map[string]time.Duration{}
	}
	for _, h := range hosts {
		ntp, err := l.ssh(h, 20*time.Second, "timedatectl show -p NTP --value")
		if ntp = strings.TrimSpace(ntp); err != nil || (ntp != "yes" && ntp != "no") {
			l.t.Skipf("timedatectl on %s reports NTP=%q (%v): its clock cannot be stepped and restored safely", h, ntp, err)
		}
		if _, done := l.clockBase[h]; !done {
			l.clockBase[h] = l.clockOffset(h)
		}
	}
}

// restoreClock sets host's clock from this machine's plus the host's own
// offset before the drill (SSH latency, well under a second), puts its NTP
// setting back and checks it is within a second of where it was.
func (l *lab) restoreClock(host string) {
	cs := l.clocks[host]
	if cs == nil || cs.done {
		return
	}
	base := l.clockBase[host]
	var off time.Duration
	for i := 0; i < 3; i++ {
		now := time.Now().Add(base)
		_, err := l.ssh(host, 30*time.Second, fmt.Sprintf(`date -u -s "@%d.%03d" >/dev/null`, now.Unix(), now.Nanosecond()/1e6))
		if err != nil {
			l.t.Errorf("clock: restore %s: %v", host, err)
			continue
		}
		if off = l.clockOffset(host) - base; off < time.Second && off > -time.Second {
			break
		}
	}
	if _, err := l.ssh(host, 30*time.Second, "timedatectl set-ntp "+map[string]string{"yes": "true", "no": "false"}[cs.ntp]); err != nil {
		l.t.Errorf("clock: NTP back to %s on %s: %v", cs.ntp, host, err)
	}
	cs.done = true
	l.mark("clock: %s restored (offset %v, NTP %s)", host, off.Round(time.Millisecond), cs.ntp)
	if off >= time.Second || off <= -time.Second {
		l.t.Errorf("clock: %s is %v off its pre-drill offset after the restore", host, off)
	}
}

// clockOffset is host's clock minus this machine's, at the midpoint of the call.
func (l *lab) clockOffset(host string) time.Duration {
	t0 := time.Now()
	out, err := l.ssh(host, 20*time.Second, "date +%s.%N")
	t1 := time.Now()
	if err != nil {
		l.t.Errorf("clock: read %s: %v", host, err)
		return 0
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
	if err != nil {
		l.t.Errorf("clock: %s printed %q", host, out)
		return 0
	}
	node := time.Unix(0, int64(f*1e9))
	return node.Sub(t0.Add(t1.Sub(t0) / 2))
}

// ─── Notifications through Mailpit ──────────────────────────────────────────

// mailpit is the lab's mail sink: its HTTP API (E2E_MAILPIT) and SMTP
// listener (E2E_MAILPIT_SMTP), both reached from the nodes.
type mailpit struct{ api, smtpHost, smtpPort string }

// mailpitFromEnv reads E2E_MAILPIT (default lab 1's idm VM) and
// E2E_MAILPIT_SMTP (default the API host, port 1025).
func mailpitFromEnv() mailpit {
	api := strings.TrimRight(envOr("E2E_MAILPIT", "http://10.77.0.50:8025"), "/")
	host := "10.77.0.50"
	if u, err := url.Parse(api); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	smtp := envOr("E2E_MAILPIT_SMTP", host+":1025")
	h, p, ok := strings.Cut(smtp, ":")
	if !ok {
		p = "1025"
	}
	return mailpit{api: api, smtpHost: h, smtpPort: p}
}

// mailpitReachable reports whether via reaches Mailpit's API.
func (l *lab) mailpitReachable(via string, mp mailpit) bool {
	out, err := l.ssh(via, 20*time.Second, "curl -s -m 5 -o /dev/null -w '%{http_code}' "+shellQuote(mp.api+"/api/v1/info"))
	return err == nil && strings.TrimSpace(out) == "200"
}

var (
	targetIDRe = regexp.MustCompile(`created: (\S+)\s*$`)
	routeIDRe  = regexp.MustCompile(`\((\S+), ≥`)
)

// addMailpitRoute adds an email target at Mailpit and a route of pattern to
// it; restore removes both.
func (l *lab) addMailpitRoute(via string, mp mailpit, pattern string) {
	l.t.Helper()
	name := uniqueName("drill-mail")
	out := l.mustLV(via, "notify", "target", "add", "--name", name, "--type", "email",
		"--smtp-host", mp.smtpHost, "--smtp-port", mp.smtpPort, "--smtp-tls", "none",
		"--from", "drill@lab.invalid", "--to", "ops@lab.invalid")
	m := targetIDRe.FindStringSubmatch(strings.TrimSpace(out))
	if m == nil {
		l.t.Fatalf("no target id in %q", out)
	}
	target := m[1]
	l.onRestore(func() {
		if v := l.liveHost(); v != "" {
			l.lv(v, "notify", "target", "rm", target)
		}
	})
	out = l.mustLV(via, "notify", "route", "add", "--pattern", pattern, "--target", target, "--min-severity", "info")
	r := routeIDRe.FindStringSubmatch(out)
	if r == nil {
		l.t.Fatalf("no route id in %q", out)
	}
	route := r[1]
	l.onRestore(func() {
		if v := l.liveHost(); v != "" {
			l.lv(v, "notify", "route", "rm", route)
		}
	})
	l.mark("notify: route %s (%s) → Mailpit target %s", pattern, route, target)
}

// mailpitMatches returns the subjects of the messages in a Mailpit
// /api/v1/messages body that contain substr and were created at or after after.
func mailpitMatches(body []byte, substr string, after time.Time) ([]string, error) {
	var resp struct {
		Messages []struct {
			Subject string    `json:"Subject"`
			Created time.Time `json:"Created"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range resp.Messages {
		if strings.Contains(m.Subject, substr) && !m.Created.Before(after) {
			out = append(out, m.Subject)
		}
	}
	return out, nil
}

// mailpitWait waits until Mailpit holds a message whose subject contains
// substr, created at or after after (less clockSlack).
func (l *lab) mailpitWait(via string, mp mailpit, substr string, after time.Time, timeout time.Duration) (string, bool) {
	deadline := time.Now().Add(timeout)
	for {
		out, err := l.ssh(via, 20*time.Second, "curl -s -m 10 "+shellQuote(mp.api+"/api/v1/messages?limit=200"))
		if err == nil {
			if got, err := mailpitMatches([]byte(out), substr, after.Add(-clockSlack)); err == nil && len(got) > 0 {
				l.mark("mailpit: %q", got[0])
				return got[0], true
			}
		}
		if time.Now().After(deadline) {
			return "", false
		}
		time.Sleep(3 * time.Second)
	}
}

// ─── Operator actions that must be refused ──────────────────────────────────

// requireFenceConfirmRefused runs `lv host fence-confirm host` and fails
// unless it is refused with every one of substrs in the error. It is only
// issued once via's replica holds a healthy row from observer about host
// under 20 s old, so the refusal is the expected outcome; without one the
// check is skipped (an error), never risked. A confirmation that went through
// records a live host powered off, and ends the drill.
func (l *lab) requireFenceConfirmRefused(via, observer, host string, substrs ...string) {
	l.t.Helper()
	fresh := func(r healthRow) bool {
		if r.Failures != 0 || r.Updated.IsZero() {
			return false
		}
		now, ok := corrosion.ParseUpdatedAt(l.nodeNow(via))
		return ok && now.Sub(r.Updated) < 20*time.Second
	}
	if _, r, ok := l.waitHealthRow(via, observer, host, fresh, 30*time.Second); !ok {
		l.t.Errorf("fence-confirm %s not tried: %s's replica holds no healthy row from %s about it under 20 s old (%s)", host, via, observer, r.Raw)
		return
	}
	out, err := l.lv(via, "host", "fence-confirm", host)
	if err == nil {
		l.t.Fatalf("lv host fence-confirm %s was ACCEPTED while %s answers %s: %s", host, host, observer, out)
	}
	for _, s := range substrs {
		if !strings.Contains(err.Error(), s) {
			l.t.Errorf("lv host fence-confirm %s refused, but without %q: %v", host, s, err)
		}
	}
	l.mark("fence-confirm %s refused: %v", host, err)
}

// ─── Recovery claims ────────────────────────────────────────────────────────

type claimVoter struct {
	Voter, Promised, Accepted, Value, Proof, Dest, Source, Rest string
	Unreachable                                                 bool
}

type claimAttempt struct {
	N                         int
	Decided                   bool
	DecidedDest, DecidedValue string
	Voters                    []claimVoter
}

var (
	claimAttemptRe = regexp.MustCompile(`^Attempt (\d+) \(key .+?\): (?:DECIDED for (\S+) \(value (\S+)\)|no value accepted by a majority)`)
	// A ballot prints as "(round, coordinator, nonce)", with spaces, so the
	// two ballot columns are matched whole.
	claimVoterRe = regexp.MustCompile(`^(\S+)\s+(-|\([^)]*\))\s+(-|\([^)]*\))\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$`)
)

// parseClaimView parses `lv cluster claim <kind>/<name>`
// (cmd/litevirt/cluster_claim.go printClaimInspection).
func parseClaimView(out string) []claimAttempt {
	var as []claimAttempt
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, " \t")
		if m := claimAttemptRe.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			as = append(as, claimAttempt{N: n, Decided: m[2] != "", DecidedDest: m[2], DecidedValue: m[3]})
			continue
		}
		if len(as) == 0 || strings.HasPrefix(line, "VOTER") {
			continue
		}
		if m := claimVoterRe.FindStringSubmatch(line); m != nil {
			v := claimVoter{Voter: m[1], Promised: m[2], Accepted: m[3], Value: m[4], Proof: m[5], Dest: m[6], Source: m[7], Rest: m[8]}
			v.Unreachable = v.Promised == "-" && strings.Contains(v.Rest, "unreachable:")
			as[len(as)-1].Voters = append(as[len(as)-1].Voters, v)
		}
	}
	return as
}

// decidedProof is the proof id of a decided attempt's value: the PROOF of the
// voters whose accepted value is the decided one.
func (a claimAttempt) decidedProof() string {
	if !a.Decided {
		return ""
	}
	for _, v := range a.Voters {
		if v.Value == a.DecidedValue && v.Proof != "-" {
			return v.Proof
		}
	}
	return ""
}

// acceptedUndecided returns, for an attempt no majority accepted, the voters
// that accepted a value carrying a proof.
func (a claimAttempt) acceptedUndecided() []claimVoter {
	if a.Decided {
		return nil
	}
	var out []claimVoter
	for _, v := range a.Voters {
		if !v.Unreachable && v.Accepted != "-" && v.Proof != "-" {
			out = append(out, v)
		}
	}
	return out
}

// claimView runs and parses `lv cluster claim key` on via, and saves it.
func (l *lab) claimView(via, key, evidence string) ([]claimAttempt, string) {
	l.t.Helper()
	out, err := l.lv(via, "cluster", "claim", key)
	if err != nil {
		l.t.Errorf("cluster claim %s on %s: %v", key, via, err)
	}
	l.saveEvidence(evidence, out)
	return parseClaimView(out), out
}

// hexText decodes a column read as hex(...) ("" when it does not decode).
func hexText(h string) string {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return ""
	}
	return string(b)
}

// proofStatus is a runtime_action_proofs row's status in via's replica.
func (l *lab) proofStatus(via, id string) string {
	rows, err := l.sql(via, "SELECT status FROM runtime_action_proofs WHERE id='"+id+"'")
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0][0]
}

// waitProofStatus waits until proof id has status want in via's replica.
func (l *lab) waitProofStatus(via, id, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if l.proofStatus(via, id) == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(3 * time.Second)
	}
}

// newestFenceRow is the newest fencing_log row of host at or after since.
func (l *lab) newestFenceRow(via, host, since string) (time.Time, string, bool) {
	rows, err := l.sql(via, "SELECT timestamp, method, result FROM fencing_log WHERE host_name='"+host+"' AND timestamp >= '"+since+"' ORDER BY timestamp DESC LIMIT 1")
	if err != nil || len(rows) == 0 {
		return time.Time{}, "", false
	}
	at, ok := corrosion.ParseUpdatedAt(rows[0][0])
	return at, strings.Join(rows[0], "|"), ok
}

// ─── Exactly-once over a window ─────────────────────────────────────────────

// assertOnlyOn requires that in every sample from from to to key executes on
// no host but home (paused or absent there is fine).
func assertOnlyOn(t *testing.T, rounds []round, key, home string, from, to time.Time, what string) {
	t.Helper()
	n := 0
	defer func() {
		if n == 0 {
			t.Errorf("%s: no sample between %s and %s to check %s against", what, from.UTC().Format("15:04:05"), to.UTC().Format("15:04:05"), key)
		}
	}()
	for _, r := range rounds {
		if r.At.Before(from) || r.At.After(to) {
			continue
		}
		n++
		for _, h := range r.executing(key) {
			if h != home {
				t.Errorf("%s: %s executed on %s at %s, before any recovery was due\n  %s", what, key, h, r.At.UTC().Format("15:04:05.000"), r)
				return
			}
		}
	}
}

// assertPausedOn requires that in every sample from from to to key is paused
// on home and executes nowhere.
func assertPausedOn(t *testing.T, rounds []round, key, home string, from, to time.Time, what string) {
	t.Helper()
	n, down := 0, 0
	defer func() {
		switch {
		case n == 0:
			t.Errorf("%s: no sample between %s and %s to check %s against", what, from.UTC().Format("15:04:05"), to.UTC().Format("15:04:05"), key)
		case down*10 > n:
			t.Errorf("%s: %s could not be read in %d of %d samples; the hold on it is unproven", what, home, down, n)
		}
	}()
	for _, r := range rounds {
		if r.At.Before(from) || r.At.After(to) {
			continue
		}
		n++
		if _, d := r.Down[home]; d {
			down++
			continue
		}
		if hs := r.executing(key); len(hs) > 0 || !pausedState(r.state(home, key)) {
			t.Errorf("%s: %s is %q on %s and executes on %v at %s; want paused on %s only\n  %s", what, key, r.state(home, key), home, hs, r.At.UTC().Format("15:04:05.000"), home, r)
			return
		}
	}
}

// ─── Lease-term mode ────────────────────────────────────────────────────────

// leaseTermMode is whether the cluster enforces leader-lease terms
// (enforcement.lease_term, default off; capabilities.LeaseTermV1). The drills
// read it from the cluster, never from an operator setting, and run in either
// mode: the safety they assert (one copy at every moment, one proof) rests on
// partition_pause and recovery_claim, which stay on in both.
type leaseTermMode string

const (
	leaseTermOff   leaseTermMode = "off"
	leaseTermOn    leaseTermMode = "on"
	leaseTermMixed leaseTermMode = "mixed"
	// leaseTermPending: some host has the flag on and no latch yet. The
	// latch can form mid-drill (the HA monitor drives activation every
	// cycle), so the drill cannot vouch for either mode.
	leaseTermPending leaseTermMode = "pending"
)

// leaseTermPosture is one host's own report of lease_term_v1, read from its
// litevirt_enforcement_config_enabled and litevirt_enforcement_latched gauges
// (grpcapi ha_health.go, written every cycle for every supported token).
// PingResponse.not_enforcing cannot carry it: a host withholds lease_term_v1
// while its flag is off, and not_enforcing names only advertised tokens (and,
// of the withheld ones, recovery_claim_v1 and partition_pause_v1).
type leaseTermPosture struct {
	Host            string
	Config, Latched bool
	Err             string // why it could not be read; "" when it was
}

// enforcing is the executor's and the coordinator's own predicate: the flag
// AND the latch (grpcapi leaseTermEnforced, failover leaseTermEnforced).
func (p leaseTermPosture) enforcing() bool { return p.Config && p.Latched }

// leaseTermModeOf is pending when some host has the flag on and no latch yet,
// on when every host enforces lease terms, off when none does, and mixed
// otherwise. It fails when a host could not be read.
func leaseTermModeOf(ps []leaseTermPosture) (leaseTermMode, error) {
	if len(ps) == 0 {
		return "", fmt.Errorf("no host to read")
	}
	on, pending := 0, false
	for _, p := range ps {
		if p.Err != "" {
			return "", fmt.Errorf("%s: %s", p.Host, p.Err)
		}
		if p.enforcing() {
			on++
		}
		pending = pending || (p.Config && !p.Latched)
	}
	if pending {
		return leaseTermPending, nil
	}
	switch on {
	case 0:
		return leaseTermOff, nil
	case len(ps):
		return leaseTermOn, nil
	}
	return leaseTermMixed, nil
}

// parseEnforcementGauges reads feature's config and latch gauges from a
// /metrics scrape; ok is false unless both are there.
func parseEnforcementGauges(out, feature string) (config, latched, ok bool) {
	var haveCfg, haveLatch bool
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case `litevirt_enforcement_config_enabled{feature="` + feature + `"}`:
			config, haveCfg = f[1] == "1", true
		case `litevirt_enforcement_latched{feature="` + feature + `"}`:
			latched, haveLatch = f[1] == "1", true
		}
	}
	return config, latched, haveCfg && haveLatch
}

// leaseTermExpect is what the drills expect of the lease-term regime in one
// mode. Nothing in it turns off a safety assertion: sampling, never-twice,
// one proof and the pause bounds are asserted in every mode.
type leaseTermExpect struct {
	Mode leaseTermMode
	// Inert: no host refuses a proof, or a stamp, on its lease term (the
	// reconciler's gate and the coordinator's precheck both answer "nothing
	// to check" unless the flag AND the latch hold). A refusal is a failure.
	Inert bool
	// TenureStrict: a proof carries the term of the tenure its coordinator
	// held when it minted it (W5a). With lease_term off a superseded
	// coordinator's stamp is not refused, so the term is only logged; the
	// recovery claim keeps it to one proof either way.
	TenureStrict bool
}

func leaseTermExpectFor(m leaseTermMode) leaseTermExpect {
	switch m {
	case leaseTermOn:
		return leaseTermExpect{Mode: m, TenureStrict: true}
	case leaseTermOff:
		return leaseTermExpect{Mode: m, Inert: true}
	}
	return leaseTermExpect{Mode: m}
}

// leaseTermRefusalPattern (grep -E) matches every journal line with which a
// host refuses on a lease term only while it enforces them: the destination's
// reconciler gate and its claimant fence (health/reconciler.go), and the
// coordinator's stamp precheck and its abandonment
// (failover/coordinator.go leaseTermStampAllowed, noteLeaseTermRefusal).
// TestLeaseTermRefusalPattern pins it against the product's messages.
//
// One of them is not enforcement-only: the DR promote path logs "refusing to
// stamp an action proof" on a plain holder change (coordinator.go,
// !stillOurTenure). The witness drills have no DR VM, so it cannot fire
// here; a promote drill joining this harness would read it as a refusal.
const leaseTermRefusalPattern = "refused by the lease-term gate|already acted at this lease term|lease term is superseded|holds no usable lease term|refusing to stamp an action proof"

// leaseTermPostures reads every host's lease_term_v1 posture.
func (l *lab) leaseTermPostures(hosts []string) []leaseTermPosture {
	var out []leaseTermPosture
	for _, h := range hosts {
		p := leaseTermPosture{Host: h}
		m, err := l.ssh(h, 30*time.Second, "curl -s --max-time 10 http://127.0.0.1:7444/metrics | grep '^litevirt_enforcement_'")
		if err != nil {
			p.Err = err.Error()
		} else if cfg, latched, ok := parseEnforcementGauges(m, capabilities.LeaseTermV1); !ok {
			p.Err = "no litevirt_enforcement_config_enabled/latched gauge for " + capabilities.LeaseTermV1
		} else {
			p.Config, p.Latched = cfg, latched
		}
		out = append(out, p)
	}
	return out
}

// requireLeaseTermMode reads the cluster's lease-term mode, records it, and
// skips on a cluster that disagrees with itself or is still latching. It
// registers, to run inside restore once every host is back on (onRestore), a
// re-read that fails the drill if the mode changed under it, and with
// lease_term off a check that no host refused on a lease term from now on:
// by journal, from each host's own clock, and by the
// litevirt_runtime_action_refused_total counter.
func (l *lab) requireLeaseTermMode(via string) leaseTermExpect {
	l.t.Helper()
	hosts := l.allBut()
	ps := l.leaseTermPostures(hosts)
	m, err := leaseTermModeOf(ps)
	report := leaseTermReport(ps, m, err)
	l.saveEvidence("lease-term-mode.txt", report)
	if err != nil {
		l.t.Skipf("cannot read the lease_term posture of every host: %v", err)
	}
	switch m {
	case leaseTermMixed:
		l.t.Skipf("lease_term is enforced on some hosts and not on others (lease-term-mode.txt):\n%sthe drills expect one mode on every executor and every possible lease holder; set enforcement.lease_term alike everywhere", report)
	case leaseTermPending:
		l.t.Skipf("lease_term is pending: enforcement.lease_term is on where lease_term_v1 has not latched (lease-term-mode.txt):\n%sthe latch can form mid-drill; wait for lease_term_v1 on every host, or set the flag off everywhere", report)
	}
	e := leaseTermExpectFor(m)
	l.mark("lease_term mode: %s (flag AND latch, read from each host's own gauges)", m)
	t := l.t
	var since map[string]string
	var before map[string]refusalSnap
	if e.Inert {
		since, before = map[string]string{}, map[string]refusalSnap{}
		for _, h := range hosts {
			since[h] = l.nodeNow(h)
			before[h] = l.refusalSnap(h)
			if before[h].Err != "" {
				t.Skipf("cannot read %s's litevirt_runtime_action_refused_total: %s", h, before[h].Err)
			}
		}
	}
	l.onRestore(func() {
		ps2 := l.leaseTermPostures(hosts)
		m2, err2 := leaseTermModeOf(ps2)
		if err2 != nil || m2 != m {
			t.Errorf("lease_term mode changed during the drill: %s at the start, %s (%v) after it:\n%s", m, m2, err2, leaseTermReport(ps2, m2, err2))
		}
		if !e.Inert {
			return
		}
		var ev strings.Builder
		for _, h := range hosts {
			out, err := l.ssh(h, time.Minute, journalGrepCmd(since[h], leaseTermRefusalPattern))
			if msg := inertJournalVerdict(h, out, err); msg != "" {
				t.Error(msg)
			}
			after := l.refusalSnap(h)
			fail, note := refusalVerdict(before[h], after)
			if fail != "" {
				t.Errorf("lease_term off: %s: %s", h, fail)
			}
			fmt.Fprintf(&ev, "%s before=%+v after=%+v %s\n", h, before[h], after, note)
		}
		l.saveEvidence("lease-term-refusals.txt", ev.String())
	})
	return e
}

// leaseTermReport is the per-host posture table recorded as evidence.
func leaseTermReport(ps []leaseTermPosture, m leaseTermMode, err error) string {
	var b strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&b, "%s config=%v latched=%v enforcing=%v %s\n", p.Host, p.Config, p.Latched, p.enforcing(), p.Err)
	}
	fmt.Fprintf(&b, "mode=%s err=%v\n", m, err)
	return b.String()
}

// journalGrepCmd prints the litevirt journal lines since since (a node's own
// UTC time) matching pattern. Unlike journalSince it fails when the journal
// cannot be read, so an unread host is never a clean one.
func journalGrepCmd(since, pattern string) string {
	return fmt.Sprintf("out=$(journalctl -u litevirt --since %s --no-pager -o cat) || exit 3; printf '%%s\\n' \"$out\" | grep -E %s || true",
		shellQuote(strings.ReplaceAll(strings.TrimSuffix(since, "Z"), "T", " ")+" UTC"), shellQuote(pattern))
}

// inertJournalVerdict judges one host's lease-term refusal grep with lease_term
// off: a line, or a journal that could not be read, fails.
func inertJournalVerdict(host, out string, err error) string {
	if err != nil {
		return fmt.Sprintf("lease_term off: could not read %s's journal for lease-term refusals: %v", host, err)
	}
	if j := strings.TrimSpace(out); j != "" {
		return fmt.Sprintf("lease_term is off, yet %s refused on a lease term (the gate must be inert):\n%s", host, j)
	}
	return ""
}

// refusalSnap is one host's litevirt_runtime_action_refused_total, summed per
// reason over actions, with the daemon's PID to tell a restart.
type refusalSnap struct {
	PID      string
	ByReason map[string]float64
	Err      string
}

func (l *lab) refusalSnap(host string) refusalSnap {
	out, err := l.ssh(host, 30*time.Second, "m=$(curl -sf --max-time 10 http://127.0.0.1:7444/metrics) || exit 3; echo PID=$(systemctl show -p MainPID --value litevirt); printf '%s\\n' \"$m\" | grep '^litevirt_runtime_action_refused_total{' || true")
	if err != nil {
		return refusalSnap{Err: err.Error()}
	}
	return parseRefusalSnap(out)
}

// parseRefusalSnap reads refusalSnap's scrape: a PID= line, then the counter's
// series.
func parseRefusalSnap(out string) refusalSnap {
	s := refusalSnap{ByReason: map[string]float64{}}
	re := regexp.MustCompile(`^litevirt_runtime_action_refused_total\{.*reason="([^"]*)".*\}\s+(\S+)$`)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "PID="); ok {
			s.PID = v
		} else if m := re.FindStringSubmatch(line); m != nil {
			if v, err := strconv.ParseFloat(m[2], 64); err == nil {
				s.ByReason[m[1]] += v
			}
		}
	}
	if s.PID == "" || s.PID == "0" {
		s.Err = "no running litevirt (MainPID " + strconv.Quote(s.PID) + ")"
	}
	return s
}

// refusalVerdict compares a host's refusal counters across a lease_term-off
// drill. A rise in lease_term_unconfirmed fails: only the enforcement-gated
// judgment counts it. stale_lease_term is also counted on a plain holder
// change (skip_stopped.go rekeyStoppedVM), so its rise is only noted. A
// restarted daemon (another PID, or a counter that went down) cannot be
// compared; the journal check covers it.
func refusalVerdict(before, after refusalSnap) (fail, note string) {
	if after.Err != "" {
		return "could not read litevirt_runtime_action_refused_total after the drill: " + after.Err, ""
	}
	if before.Err != "" {
		return "", "no reading before the drill"
	}
	if before.PID != after.PID {
		return "", "daemon restarted (pid " + before.PID + " → " + after.PID + "); journal only"
	}
	for r, v := range before.ByReason {
		if after.ByReason[r] < v {
			return "", "counter " + r + " went down: reset; journal only"
		}
	}
	if d := after.ByReason[health.ReasonLeaseTermUnconfirmed] - before.ByReason[health.ReasonLeaseTermUnconfirmed]; d > 0 {
		return fmt.Sprintf("litevirt_runtime_action_refused_total{reason=%q} rose by %v although lease_term is not enforced", health.ReasonLeaseTermUnconfirmed, d), ""
	}
	if d := after.ByReason[health.ReasonStaleLeaseTerm] - before.ByReason[health.ReasonStaleLeaseTerm]; d > 0 {
		return "", fmt.Sprintf("%s +%v (also counted on a plain holder change; not a failure)", health.ReasonStaleLeaseTerm, d)
	}
	return "", ""
}

// w4aOutcome is W4a's judgment of the second outage: the outcome's name and,
// when it fails, why.
type w4aOutcome struct{ Name, Fail string }

// w4aVerdict judges W4a's second outage. dp is the decided proof (decided
// tells whether any attempt is), p1 outage 1's accepted value, and gateRefused
// whether the decided destination logged a lease-term refusal of p1.
func w4aVerdict(e leaseTermExpect, recovered, decided bool, dp, p1 string, gateRefused bool) w4aOutcome {
	switch {
	case recovered && dp == p1:
		return w4aOutcome{Name: "A"}
	case recovered && !decided:
		return w4aOutcome{Name: "B", Fail: "recovered, but no attempt reads decided"}
	case recovered:
		return w4aOutcome{Name: "B"}
	case decided && dp == p1 && gateRefused && e.Inert:
		return w4aOutcome{Name: "C", Fail: "the lease-term gate refused the adopted value's proof " + p1 + " although lease_term is not enforced"}
	case decided && dp == p1 && gateRefused:
		return w4aOutcome{Name: "C", Fail: "outcome C (design Q5): the adopted value's proof " + p1 + " is refused by the lease-term gate and the VM is stranded"}
	case decided && dp == p1 && e.Inert:
		return w4aOutcome{Name: "stranded", Fail: "the decided proof is outage 1's " + p1 + " and the VM is not running; lease_term is off, so the lease-term gate is inert and this is not design Q5"}
	case decided && dp == p1:
		return w4aOutcome{Name: "stranded", Fail: "the decided proof is outage 1's " + p1 + " and the VM is not running, with no lease-term refusal logged"}
	}
	return w4aOutcome{Name: "not recovered", Fail: "not recovered; decided proof " + strconv.Quote(dp)}
}

// freshTenureAt reports whether, by the sampled history, the tenure in force
// at at (as tenureAt reads it, clockSlack either side, but ignoring the term)
// is holder's and was taken no earlier than clockSlack before from.
func freshTenureAt(history []leaseChange, holder string, from, at time.Time) bool {
	var cands []leaseChange
	for _, c := range history {
		if !c.At.After(at.Add(clockSlack)) {
			cands = append(cands, c)
		}
	}
	ok := func(c leaseChange) bool { return c.Holder == holder && !c.At.Before(from.Add(-clockSlack)) }
	if len(cands) == 0 {
		return false
	}
	last := cands[len(cands)-1]
	if ok(last) {
		return true
	}
	return len(cands) > 1 && last.At.After(at.Add(-clockSlack)) && ok(cands[len(cands)-2])
}

// settleDeclinedEv is vm_settle_declined's evidence (health/settle_declined.go).
type settleDeclinedEv struct {
	ReasonClass string `json:"reason_class"`
	Reason      string `json:"reason"`
	RowHost     string `json:"row_host"`
	Remedy      string `json:"remedy"`
}

// vmSettleDeclined reads host's vm_settle_declined about vm in via's replica.
func (l *lab) vmSettleDeclined(via, vm, host string) (string, settleDeclinedEv, string, bool) {
	rows, err := l.sql(via, fmt.Sprintf(
		"SELECT lifecycle, hex(evidence) FROM health_conditions WHERE evaluator='%s' AND code='%s' AND subject_kind='vm' AND subject_id='%s@%s' AND deleted_at IS NULL",
		corrosion.PartitionPauseEvaluator, corrosion.CondVMSettleDeclined, vm, host))
	if err != nil || len(rows) == 0 || len(rows[0]) < 2 {
		return "", settleDeclinedEv{}, "", false
	}
	var ev settleDeclinedEv
	b, err := hex.DecodeString(rows[0][1])
	if err == nil {
		_ = json.Unmarshal(b, &ev)
	}
	return rows[0][0], ev, string(b), true
}

// uncertifiedDeclineVerdict is nil when ev declines vm's copy because its move
// to dest completed on a proof with no certificate, and its remedy checks the
// replacement by dest's runtime and stops the copy with virsh — never through
// `lv cluster claim`, which has no claim to show on a derived voter set.
func uncertifiedDeclineVerdict(ev settleDeclinedEv, vm, dest string) error {
	switch {
	case ev.ReasonClass != "proof_uncertified":
		return fmt.Errorf("reason class %q, want proof_uncertified (reason %q)", ev.ReasonClass, ev.Reason)
	case ev.RowHost != dest:
		return fmt.Errorf("row host %q, want the replacement's host %q", ev.RowHost, dest)
	case strings.Contains(ev.Remedy, "lv cluster claim"):
		return fmt.Errorf("the remedy points at a claim a derived voter set never decided: %s", ev.Remedy)
	case !strings.Contains(ev.Remedy, "virsh domstate "+vm):
		return fmt.Errorf("the remedy does not confirm the replacement by its runtime (virsh domstate %s): %s", vm, ev.Remedy)
	case !strings.Contains(ev.Remedy, "virsh destroy "+vm):
		return fmt.Errorf("the remedy does not name the stop (virsh destroy %s): %s", vm, ev.Remedy)
	}
	return nil
}
