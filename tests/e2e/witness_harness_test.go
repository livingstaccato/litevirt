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
}

// requireWitnessTopology skips unless the lab is the one the design reasons
// about (witness-drill-design.md §0, §1): five worker hosts node-1..5 with none
// excluded, exactly one witness outside them that answers, an adopted voter
// generation whose members are exactly the five workers (so the witness does
// not vote), and partition_pause_v1, recovery_claim_v1 and lease_term_v1
// latched.
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
	for _, tok := range []string{capabilities.PartitionPauseV1, capabilities.RecoveryClaimV1, capabilities.LeaseTermV1} {
		if !latchparse.TokenLatched(up, tok) {
			l.t.Skipf("%s is not latched on %s: the drill's expectations rest on it", tok, via)
		}
	}
	w.hlc = latchparse.TokenLatched(up, capabilities.HLCLwwV1)
	l.mark("witness: %s outside the voters; generation %d %v; hlc_lww_v1 latched=%v", w.witness, gen, members, w.hlc)
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
// alone. The rule is in the drill table. It then checks, from the first peer
// that answers, that the port really is closed: a fence that reached the host
// would end the drill in a power-off it does not expect.
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
	for _, p := range peers {
		out, err := l.ssh(p, 20*time.Second, fmt.Sprintf(`timeout 4 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null && echo OPEN || echo CLOSED`, l.ip[host], port))
		if err != nil {
			continue // that peer may itself be cut from this machine's view; try the next
		}
		if strings.Contains(out, "OPEN") {
			l.t.Fatalf("sshcut: %s still reaches %s:%d after the rule", p, host, port)
		}
		return
	}
	l.t.Fatalf("sshcut: no peer of %s answered to check the cut", host)
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
	gen, got, err := l.voterSet(via)
	if err != nil {
		return err
	}
	want := append([]string{}, members...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return fmt.Errorf("voter init: generation %d has %v, want %v", gen, got, want)
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
}

// leaseWatch samples the failover lease (holder and newest term) every second.
type leaseWatch struct {
	l       *lab
	mu      sync.Mutex
	readers []string
	avoided map[string]bool
	changes []leaseChange
	stop    chan struct{}
	done    chan struct{}
}

// watchLease samples leader_election and leader_lease_terms every second from
// the first of readers that is not avoided and answers (a frozen or stopped
// node's replica stops applying, so the drill avoids it while it is out).
func (l *lab) watchLease(readers []string) *leaseWatch {
	w := &leaseWatch{l: l, readers: readers, avoided: map[string]bool{}, stop: make(chan struct{}), done: make(chan struct{})}
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
	for _, r := range rs {
		rows, err := w.l.sql(r, "SELECT COALESCE((SELECT holder FROM leader_election WHERE key='failover'),''), (SELECT COALESCE(MAX(term),0) FROM leader_lease_terms WHERE key='failover' AND deleted_at IS NULL)")
		if err != nil || len(rows) == 0 || len(rows[0]) < 2 {
			continue
		}
		term, _ := strconv.Atoi(rows[0][1])
		c := leaseChange{At: time.Now(), Holder: rows[0][0], Term: term}
		w.mu.Lock()
		n := len(w.changes)
		if n == 0 || w.changes[n-1].Holder != c.Holder || w.changes[n-1].Term != c.Term {
			w.changes = append(w.changes, c)
			w.mu.Unlock()
			w.l.mark("lease: failover held by %s, term %d (read on %s)", c.Holder, c.Term, r)
			return
		}
		w.mu.Unlock()
		return
	}
}

func (w *leaseWatch) Stop() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
}

func (w *leaseWatch) avoid(h string, on bool) {
	w.mu.Lock()
	w.avoided[h] = on
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
	if err := l.waitDaemon(holder, 3*time.Minute); err != nil {
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
			l.t.Skipf("timedatectl on %s reports NTP=%q; cannot manage its time sync", host, ntp)
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

// restoreClock sets host's clock from this machine's (SSH latency, well under
// a second), puts its NTP setting back and checks it is within a second.
func (l *lab) restoreClock(host string) {
	cs := l.clocks[host]
	if cs == nil || cs.done {
		return
	}
	var off time.Duration
	for i := 0; i < 3; i++ {
		now := time.Now()
		_, err := l.ssh(host, 30*time.Second, fmt.Sprintf(`date -u -s "@%d.%03d" >/dev/null`, now.Unix(), now.Nanosecond()/1e6))
		if err != nil {
			l.t.Errorf("clock: restore %s: %v", host, err)
			continue
		}
		if off = l.clockOffset(host); off < time.Second && off > -time.Second {
			break
		}
	}
	if _, err := l.ssh(host, 30*time.Second, "timedatectl set-ntp "+map[string]string{"yes": "true", "no": "false"}[cs.ntp]); err != nil {
		l.t.Errorf("clock: NTP back to %s on %s: %v", cs.ntp, host, err)
	}
	cs.done = true
	l.mark("clock: %s restored (offset %v, NTP %s)", host, off.Round(time.Millisecond), cs.ntp)
	if off >= time.Second || off <= -time.Second {
		l.t.Errorf("clock: %s is %v off this machine's clock after the restore", host, off)
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
// unless it is refused with every one of substrs in the error. A
// confirmation that went through is reported loudly: it records a live host
// powered off.
func (l *lab) requireFenceConfirmRefused(via, host string, substrs ...string) {
	l.t.Helper()
	out, err := l.lv(via, "host", "fence-confirm", host)
	if err == nil {
		l.t.Errorf("lv host fence-confirm %s was ACCEPTED while %s answers an observer: %s", host, host, out)
		return
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
	for _, r := range rounds {
		if r.At.Before(from) || r.At.After(to) {
			continue
		}
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
	for _, r := range rounds {
		if r.At.Before(from) || r.At.After(to) {
			continue
		}
		if _, down := r.Down[home]; down {
			continue
		}
		if hs := r.executing(key); len(hs) > 0 || !pausedState(r.state(home, key)) {
			t.Errorf("%s: %s is %q on %s and executes on %v at %s; want paused on %s only\n  %s", what, key, r.state(home, key), home, hs, r.At.UTC().Format("15:04:05.000"), home, r)
			return
		}
	}
}
