package e2e

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
)

// Lab harness for the partition-safety drills (drill_*_test.go).
//
// The drills cut the network, freeze daemons and power hosts off, so they cannot
// run on a cluster node: they run on the machine that hosts the nested lab
// (kvm003-f3, ~/litevirt-lab) and reach every node over its own NAT'd SSH port,
// which the cluster-LAN nftables rules do not touch. Every claim a drill makes
// about where a workload executes is read from virsh and lxc-ls on the nodes,
// never only from litevirt's own view.
//
//	E2E_LAB_DIR        the lab checkout (lab.sh, cluster_key). Enables lab mode.
//	E2E_LAB_NODES      node count (default 5): nodes are node-1..node-N.
//	E2E_LAB_PREFIX     first three octets of the lab /24 (default 10.77.0); node N is <prefix>.(10+N).
//	E2E_LAB_PORT_BASE  node N's SSH is 127.0.0.1:(base+N) (default 2230).
//	E2E_LAB_EXCLUDE    comma-separated node numbers the harness leaves alone
//	                   (e.g. 3): never baselined, restored, powered on or picked.
//	E2E_LAB_SOCKET_DIR where the SSH control sockets live (default
//	                   <user cache dir>/litevirt-e2e-ssh, outside the lab checkout).
//	LV_BIN             in lab mode, the lv binary ON THE NODES
//	                   (e.g. /usr/local/bin/litevirt).
//	E2E_EVIDENCE_DIR   where each drill writes its samples and timeline.
//	LITEVIRT_E2E_DESTRUCTIVE=1  also run drill 6 (destroys and rebuilds hosts).

var (
	labDir       = os.Getenv("E2E_LAB_DIR")
	labMode      = labDir != ""
	evidenceRoot = os.Getenv("E2E_EVIDENCE_DIR")
)

// defaultLabPrefix is lab 1's /24: node N is <prefix>.(10+N).
const defaultLabPrefix = "10.77.0"

// parseLabPrefix validates E2E_LAB_PREFIX: the first three octets of the lab's
// IPv4 /24 ("10.78.0" for lab 2). Empty selects lab 1's.
func parseLabPrefix(v string) (string, error) {
	if v == "" {
		return defaultLabPrefix, nil
	}
	ip := net.ParseIP(v + ".0")
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("E2E_LAB_PREFIX=%q: need the first three octets of an IPv4 /24, like %q", v, defaultLabPrefix)
	}
	return v, nil
}

// labNodeIP is node n's address under prefix.
func labNodeIP(prefix string, n int) string { return fmt.Sprintf("%s.%d", prefix, 10+n) }

// labPrefix reads E2E_LAB_PREFIX, failing t on a malformed value.
func labPrefix(t *testing.T) string {
	t.Helper()
	p, err := parseLabPrefix(os.Getenv("E2E_LAB_PREFIX"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ─── Timing, tied to docs/design/partition-pause.md §4.1 ────────────────────
//
// The exported values come from internal/health itself, so a retuned T_pause or
// W moves the drills with it. The unexported probe constants are restated here
// with their source; checkDesignTimings fails the drill if the restatement and
// the exported values ever stop agreeing, rather than letting a stale bound pass.
const (
	probeInterval    = 2 * time.Second  // P, health.checkInterval
	probeCycle       = 3 * time.Second  // C = max(P, τ) for ≤16 probe targets
	suspectAfter     = 3                // k, health.suspectThreshold
	pauserTick       = time.Second      // Δ, health.partitionPauseTick
	failoverLeaseTTL = 45 * time.Second // failover.leaseDuration

	// samplePeriod is how often the sampler reads every node's runtime.
	samplePeriod = time.Second
	// sampleSlop is how late a sample can see an event: one period plus the
	// SSH round trip of a slow node.
	sampleSlop = 2 * samplePeriod
	// daemonRestartSpacing spaces rolling daemon restarts. HA fences hosts that
	// restart too close together (lab.sh deploy says ~13 s; the drills used 25).
	daemonRestartSpacing = 25 * time.Second
)

var (
	// tPause is T_pause: loss the minority accumulates before it pauses.
	tPause = health.PartitionPauseAfter
	// minorityDetect is D_M = (k+1)·C: until the minority stops counting a
	// majority voter healthy.
	minorityDetect = (suspectAfter + 1) * probeCycle
	// minorityPauseBy bounds the minority's pause from the moment the link
	// breaks: b + D_M + Δ + T_pause + Δ + E (§4.1, "So M pauses by", for a
	// host not in a resume pass when the link breaks, as in every drill: one
	// in a pass may see the loss up to R later).
	minorityPauseBy = minorityDetect + pauserTick + tPause + pauserTick + health.PartitionPauseExecBudget
	// decisionHeadStart is (F−1)·P: a fence decision rests on F consecutive
	// failures by each quorum observer, so t_d ≥ b + (F−1)·P.
	decisionHeadStart = time.Duration(health.FailuresToFence-1) * probeInterval
)

// pauseWait is W for a cluster of `hosts` hosts (each probes hosts−1 peers).
func pauseWait(hosts int) time.Duration { return health.PartitionPauseWaitFor(hosts - 1) }

// earliestReplacement is the earliest instant, after the link broke, at which
// the majority may start a replacement for a host it relies on pausing:
// t_d + W ≥ b + (F−1)·P + W.
func earliestReplacement(hosts int) time.Duration { return decisionHeadStart + pauseWait(hosts) }

// checkDesignTimings pins the restated constants to the exported ones and to the
// design document's own numbers for a 5-host cluster (§4.1, §4.4 table).
func checkDesignTimings(t *testing.T, hosts int) {
	t.Helper()
	if want := time.Duration(health.FailuresToFence) * probeInterval; tPause != want {
		t.Fatalf("T_pause = %v but F·P = %v: the drill's probeInterval no longer matches internal/health", tPause, want)
	}
	if tPause != 10*time.Second {
		t.Fatalf("T_pause = %v, design says 10 s: update the drills' expectations with the design", tPause)
	}
	if hosts <= 17 && pauseWait(hosts) != 26*time.Second {
		t.Fatalf("W(%d hosts) = %v, design table says 26 s", hosts, pauseWait(hosts))
	}
	// W = T_pause + max(0, D_M − (F−1)·P) + 2Δ + R + E + slack, slack = 2 s.
	recomputed := tPause + max(0, minorityDetect-decisionHeadStart) + 2*pauserTick + health.PartitionResumeStepBound +
		health.PartitionPauseExecBudget + 2*time.Second
	if hosts <= 17 && recomputed != pauseWait(hosts) {
		t.Fatalf("W recomputed from the restated constants = %v, internal/health says %v", recomputed, pauseWait(hosts))
	}
}

// ─── The lab ────────────────────────────────────────────────────────────────

type lab struct {
	t        *testing.T
	dir      string
	key      string
	portBase int
	prefix   string            // E2E_LAB_PREFIX
	hosts    []string          // node-1..node-N, less E2E_LAB_EXCLUDE
	total    int               // N, counting excluded nodes
	excluded map[string]bool   // nodes E2E_LAB_EXCLUDE leaves alone
	num      map[string]int    // node name → N
	ip       map[string]string // node name → cluster address
	lvPath   string
	cmDir    string
	evDir    string
	timeline *os.File
	tlMu     sync.Mutex
	// pending deletes test workloads. restore runs them once the faults are
	// undone (a delete issued into a live partition fails); newLab's own
	// cleanup runs whatever is left if restore never ran.
	pending []func()
	// outsiders are cluster hosts the harness does not otherwise drive (a
	// witness beyond E2E_LAB_NODES): found once, by outsiderHosts.
	outsiders      []string
	outsidersKnown bool
	// clocks are the node clocks a drill stepped (stepClock), by host, and
	// clockBase each node's offset from this machine before any step.
	clocks    map[string]*clockStep
	clockBase map[string]time.Duration
	// logT is the test mark logs to: l.t, read atomically, because the
	// background watchers mark while sub() rebinds l.t to a subtest.
	logT atomic.Pointer[testing.T]
	// cut records, per host, the peers dropBetween cut it from, until
	// clearDrops; sshCut checks only from peers it is not cut from.
	cutMu sync.Mutex
	cut   map[string]map[string]bool
}

// exceptExcluded drops the E2E_LAB_EXCLUDE nodes from hs.
func (l *lab) exceptExcluded(hs []string) []string {
	var out []string
	for _, h := range hs {
		if !l.excluded[h] {
			out = append(out, h)
		}
	}
	return out
}

// onRestore queues fn to run inside restore, after the faults are undone.
func (l *lab) onRestore(fn func()) { l.pending = append(l.pending, fn) }

func (l *lab) runPending() {
	for len(l.pending) > 0 {
		fn := l.pending[len(l.pending)-1]
		l.pending = l.pending[:len(l.pending)-1]
		fn()
	}
}

// newLab skips unless lab mode is on, and returns a harness bound to t.
func newLab(t *testing.T) *lab {
	t.Helper()
	if !labMode {
		t.Skip("partition drills need the nested lab: set E2E_LAB_DIR (see tests/e2e/README.md)")
	}
	n := 5
	if v := os.Getenv("E2E_LAB_NODES"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 3 {
			t.Fatalf("E2E_LAB_NODES=%q: need an integer ≥ 3", v)
		}
	}
	base := 2230
	if v := os.Getenv("E2E_LAB_PORT_BASE"); v != "" {
		var err error
		if base, err = strconv.Atoi(v); err != nil {
			t.Fatalf("E2E_LAB_PORT_BASE=%q: %v", v, err)
		}
	}
	excluded := map[string]bool{}
	for _, f := range strings.Split(os.Getenv("E2E_LAB_EXCLUDE"), ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		x, err := strconv.Atoi(f)
		if err != nil || x < 1 || x > n {
			t.Fatalf("E2E_LAB_EXCLUDE entry %q: need a node number in 1..%d", f, n)
		}
		excluded[fmt.Sprintf("node-%d", x)] = true
	}
	if n-len(excluded) < 1 {
		t.Fatalf("E2E_LAB_EXCLUDE leaves no node to drive")
	}
	sockRoot := os.Getenv("E2E_LAB_SOCKET_DIR")
	if sockRoot == "" {
		base, cerr := os.UserCacheDir()
		if cerr != nil {
			base = os.TempDir()
		}
		sockRoot = filepath.Join(base, "litevirt-e2e-ssh")
	}
	if err := os.MkdirAll(sockRoot, 0o700); err != nil {
		t.Fatalf("ssh control socket dir: %v", err)
	}
	cm, err := os.MkdirTemp(sockRoot, "e2ecm")
	if err != nil {
		t.Fatalf("ssh control dir: %v", err)
	}
	l := &lab{
		t: t, dir: labDir, key: filepath.Join(labDir, "cluster_key"), portBase: base,
		num: map[string]int{}, ip: map[string]string{}, lvPath: lvBin, cmDir: cm,
		total: n, excluded: excluded, cut: map[string]map[string]bool{},
	}
	l.logT.Store(t)
	l.prefix = labPrefix(t)
	for i := 1; i <= n; i++ {
		h := fmt.Sprintf("node-%d", i)
		l.num[h] = i
		l.ip[h] = labNodeIP(l.prefix, i)
		if !excluded[h] {
			l.hosts = append(l.hosts, h)
		}
	}
	t.Cleanup(func() {
		l.runPending()
		for _, h := range append(append([]string{}, l.hosts...), l.outsiders...) {
			l.closeMaster(h)
		}
		os.RemoveAll(cm)
		if l.timeline != nil {
			l.timeline.Close()
		}
	})
	if evidenceRoot != "" {
		l.evDir = filepath.Join(evidenceRoot, strings.ReplaceAll(t.Name(), "/", "_"))
		if err := os.MkdirAll(l.evDir, 0o755); err != nil {
			t.Fatalf("evidence dir: %v", err)
		}
		l.timeline, _ = os.Create(filepath.Join(l.evDir, "timeline.txt"))
	}
	// Learn each node's cluster address from the cluster itself rather than
	// trusting the lab's numbering.
	if out, err := l.lv(l.hosts[0], "host", "ls"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && l.num[f[0]] != 0 {
				l.ip[f[0]] = f[1]
			}
		}
	}
	checkDesignTimings(t, n)
	return l
}

// mark logs a timestamped event to the test log and the evidence timeline.
func (l *lab) mark(format string, args ...any) time.Time {
	now := time.Now()
	msg := fmt.Sprintf(format, args...)
	l.logT.Load().Logf("%s %s", now.UTC().Format("15:04:05.000"), msg)
	l.tlMu.Lock()
	if l.timeline != nil {
		fmt.Fprintf(l.timeline, "%s %s\n", now.UTC().Format(time.RFC3339Nano), msg)
	}
	l.tlMu.Unlock()
	return now
}

// saveEvidence writes a named file into this drill's evidence directory.
func (l *lab) saveEvidence(name, content string) {
	if l.evDir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(l.evDir, name), []byte(content), 0o644)
}

func (l *lab) sshArgs(host string) []string {
	return []string{
		"-i", l.key,
		"-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
		"-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=3",
		"-o", "ControlMaster=auto", "-o", "ControlPath=" + filepath.Join(l.cmDir, "%p"),
		"-o", "ControlPersist=120",
		"-p", strconv.Itoa(l.portBase + l.num[host]), "root@127.0.0.1",
	}
}

// closeMaster drops the multiplexed SSH connection to host, so the next call
// dials afresh (after a power-off or a rebuild).
func (l *lab) closeMaster(host string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := append(l.sshArgs(host)[:len(l.sshArgs(host))-1], "-O", "exit", "root@127.0.0.1")
	_ = exec.CommandContext(ctx, "ssh", args...).Run()
}

// ssh runs a shell command on host, bounded by timeout. It never fails the
// test: callers decide what an error means.
func (l *lab) ssh(host string, timeout time.Duration, cmd string) (string, error) {
	return l.sshInput(host, timeout, cmd, "")
}

// sshInput is ssh with stdin as the remote command's standard input: how a
// secret reaches a node without being on any command line
// (tests/e2e/labsecret). Its error quotes cmd, never stdin — and a caller
// handing a secret still redacts it.
func (l *lab) sshInput(host string, timeout time.Duration, cmd, stdin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "ssh", append(l.sshArgs(host), cmd)...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	c.WaitDelay = 2 * time.Second
	// stdout only: the CLI prints notes on stderr (`lv host inspect` follows its
	// JSON with one), and stderr belongs in the error, not in parsed output.
	var stderr strings.Builder
	c.Stderr = &stderr
	out, err := c.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("ssh %s: timed out after %v: %q", host, timeout, cmd)
	}
	if err != nil {
		return string(out), fmt.Errorf("ssh %s %q: %v: %s %s", host, cmd, err, strings.TrimSpace(string(out)), strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// mustSSH is ssh that fails the test on error.
func (l *lab) mustSSH(host string, timeout time.Duration, cmd string) string {
	l.t.Helper()
	out, err := l.ssh(host, timeout, cmd)
	if err != nil {
		l.t.Fatal(err)
	}
	return out
}

func shellQuote(s string) string {
	if s != "" && regexp.MustCompile(`^[A-Za-z0-9_./:=@,+-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// lv runs the CLI on host (mTLS as that host), bounded by two minutes.
func (l *lab) lv(host string, args ...string) (string, error) {
	return l.lvTimeout(host, 2*time.Minute, args...)
}

func (l *lab) mustLV(host string, args ...string) string {
	l.t.Helper()
	out, err := l.lv(host, args...)
	if err != nil {
		l.t.Fatalf("lv %s on %s: %v", strings.Join(args, " "), host, err)
	}
	return out
}

// sql runs a read-only query against host's state.db and returns rows of
// '|'-separated fields. The query travels base64-encoded, so no quoting.
func (l *lab) sql(host, query string) ([][]string, error) {
	b := base64.StdEncoding.EncodeToString([]byte(query))
	out, err := l.ssh(host, 30*time.Second,
		"echo "+b+" | base64 -d | sqlite3 -readonly -separator '|' /var/lib/litevirt/state.db")
	if err != nil {
		return nil, err
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line != "" {
			rows = append(rows, strings.Split(line, "|"))
		}
	}
	return rows, nil
}

func (l *lab) mustSQL(host, query string) [][]string {
	l.t.Helper()
	rows, err := l.sql(host, query)
	if err != nil {
		l.t.Fatalf("sql on %s: %v", host, err)
	}
	return rows
}

// nodeNow is host's own UTC clock, formatted like the DB's timestamps, so
// "since the drill began" comparisons never mix two machines' clocks.
func (l *lab) nodeNow(host string) string {
	l.t.Helper()
	return strings.TrimSpace(l.mustSSH(host, 20*time.Second, "date -u +%Y-%m-%dT%H:%M:%SZ"))
}

// labsh runs lab.sh on the lab host, bounded by timeout.
func (l *lab) labsh(timeout time.Duration, env []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "./lab.sh", args...)
	c.Dir = l.dir
	c.Env = append(append(os.Environ(), fmt.Sprintf("NODES=%d", l.total)), env...)
	c.WaitDelay = 5 * time.Second
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("lab.sh %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

func (l *lab) nums(hosts []string) []string {
	var ns []string
	for _, h := range hosts {
		ns = append(ns, strconv.Itoa(l.num[h]))
	}
	return ns
}

// ─── Faults ─────────────────────────────────────────────────────────────────

// drillTable is the nftables table the drills own. It is distinct from the
// manual drills' "drill" table, and restore deletes both.
const drillTable = "e2e_drill"

// dropBetween makes host drop every packet to and from peers' cluster addresses.
func (l *lab) dropBetween(host string, peers []string) error {
	var ips []string
	for _, p := range peers {
		ips = append(ips, l.ip[p])
	}
	set := strings.Join(ips, ", ")
	cmd := fmt.Sprintf(`nft add table inet %[1]s && nft add chain inet %[1]s in '{ type filter hook input priority -300; policy accept; }' && nft add chain inet %[1]s out '{ type filter hook output priority -300; policy accept; }' && nft add rule inet %[1]s in ip saddr '{ %[2]s }' drop && nft add rule inet %[1]s out ip daddr '{ %[2]s }' drop`, drillTable, set)
	_, err := l.ssh(host, 30*time.Second, cmd)
	if err == nil {
		l.cutMu.Lock()
		if l.cut[host] == nil {
			l.cut[host] = map[string]bool{}
		}
		for _, p := range peers {
			l.cut[host][p] = true
		}
		l.cutMu.Unlock()
	}
	return err
}

// isCut reports whether a dropBetween rule cuts host from peer, on either end.
func (l *lab) isCut(host, peer string) bool {
	l.cutMu.Lock()
	defer l.cutMu.Unlock()
	return l.cut[host][peer] || l.cut[peer][host]
}

// clearDrops removes the drill table (and a manual drill's table) on hosts.
func (l *lab) clearDrops(hosts ...string) error {
	var wg sync.WaitGroup
	errs := make([]error, len(hosts))
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = l.ssh(h, 30*time.Second, "nft delete table inet "+drillTable+" 2>/dev/null; nft delete table inet drill 2>/dev/null; ! nft list tables | grep -qE 'inet (e2e_drill|drill)$'")
		}()
	}
	wg.Wait()
	l.cutMu.Lock()
	for i, h := range hosts {
		if errs[i] == nil {
			delete(l.cut, h)
		}
	}
	l.cutMu.Unlock()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// witnessNames lists the cluster's witnesses (role = 'witness'), read from the
// replicated hosts table. A witness is a voter that runs no workload. A failed
// read fails the test: carrying on would partition without the witness and
// bring back the failure the witness handling exists to prevent, unannounced.
func (l *lab) witnessNames() []string {
	l.t.Helper()
	rows, err := l.sql(l.hosts[0], "SELECT name FROM hosts WHERE deleted_at IS NULL AND role = 'witness'")
	if err != nil {
		l.t.Fatalf("partition: cannot read the cluster's witnesses: %v", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r[0])
	}
	return out
}

// outsiderHosts returns the cluster's witnesses that are not in l.hosts, e.g.
// node-6 of a lab with E2E_LAB_NODES=5. A witness is a voter that runs no
// workload, so a partition that leaves it out reaches both sides and keeps the
// failover lease on the wrong one; it has to be cut like any other node. They are
// addressed by the lab's node-K numbering (SSH port base+K, address from `lv host
// ls`); a witness that does not follow that naming cannot be reached and is
// reported.
func (l *lab) outsiderHosts() []string {
	l.t.Helper()
	if l.outsidersKnown {
		return l.outsiders
	}
	l.outsidersKnown = true
	addr := map[string]string{}
	if out, err := l.lv(l.hosts[0], "host", "ls"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) >= 2 {
				addr[f[0]] = f[1]
			}
		}
	}
	for _, h := range l.witnessNames() {
		if contains(l.hosts, h) || l.excluded[h] {
			continue
		}
		k, ok := strings.CutPrefix(h, "node-")
		n, err := strconv.Atoi(k)
		if !ok || err != nil || n < 1 {
			l.t.Fatalf("witness %q is outside the lab's node-N naming: the harness cannot reach it to cut it from the split", h)
		}
		l.num[h] = n
		l.ip[h] = addr[h]
		if l.ip[h] == "" {
			l.ip[h] = labNodeIP(l.prefix, n)
		}
		l.outsiders = append(l.outsiders, h)
		l.mark("partition: witness %s is outside E2E_LAB_NODES=%d; it is cut with the split", h, l.total)
	}
	return l.outsiders
}

// joinMajority assigns every host in universe that no group names to the
// largest group, which is the majority side of a split: a host the drill did not
// name (a witness, say) must not sit between the sides and reach both. When no
// group is strictly the largest (every host alone, as in a fleet-wide blip) there
// is no majority to join and unnamed hosts stay out of it.
func joinMajority(groups [][]string, universe []string) (group map[string]int) {
	group = map[string]int{}
	for i, g := range groups {
		for _, h := range g {
			group[h] = i
		}
	}
	big, tie := -1, false
	for i, g := range groups {
		switch {
		case big < 0 || len(g) > len(groups[big]):
			big, tie = i, false
		case len(g) == len(groups[big]):
			tie = true
		}
	}
	if big < 0 || tie {
		return group
	}
	for _, h := range universe {
		if _, named := group[h]; !named {
			group[h] = big
		}
	}
	return group
}

// partition splits the cluster into groups: every host drops traffic to every
// host outside its own group. A host no group names (a witness, a node the drill
// left out) joins the majority group (joinMajority). It returns the instant
// before the first rule went in (no link can have broken earlier) and the
// instant the last one landed.
func (l *lab) partition(groups ...[]string) (start, applied time.Time) {
	l.t.Helper()
	universe := append(append([]string{}, l.hosts...), l.outsiderHosts()...)
	return l.partitionGroups(universe, joinMajority(groups, universe), groups)
}

// partitionNamedOnly is partition without the unnamed-host rule: a host no group
// names (a witness) is left untouched, so it still reaches every side. It is the
// non-transitive split of TestDrill1b_WitnessReachesBothSides.
func (l *lab) partitionNamedOnly(groups ...[]string) (start, applied time.Time) {
	l.t.Helper()
	group := map[string]int{}
	for i, g := range groups {
		for _, h := range g {
			group[h] = i
		}
	}
	return l.partitionGroups(l.hosts, group, groups)
}

func (l *lab) partitionGroups(universe []string, group map[string]int, groups [][]string) (start, applied time.Time) {
	l.t.Helper()
	start = l.mark("partition: applying %v (hosts %v)", groups, universe)
	var wg sync.WaitGroup
	errs := map[string]error{}
	var mu sync.Mutex
	for _, h := range universe {
		var others []string
		for _, p := range universe {
			if gi, ok := group[p]; ok && gi != group[h] {
				others = append(others, p)
			}
		}
		if _, in := group[h]; !in || len(others) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := l.dropBetween(h, others)
			mu.Lock()
			errs[h] = err
			mu.Unlock()
		}()
	}
	wg.Wait()
	for h, err := range errs {
		if err != nil {
			l.t.Fatalf("partition rule on %s: %v", h, err)
		}
	}
	applied = l.mark("partition: applied")
	return start, applied
}

// heal removes every drill rule on every host, witnesses outside l.hosts included.
func (l *lab) heal() time.Time {
	l.t.Helper()
	if err := l.clearDrops(append(append([]string{}, l.hosts...), l.outsiders...)...); err != nil {
		l.t.Fatalf("heal: %v", err)
	}
	return l.mark("partition: healed")
}

// powerOff kills the hosts' qemu processes (a hard power cut).
func (l *lab) powerOff(hosts ...string) time.Time {
	l.t.Helper()
	if _, err := l.labsh(time.Minute, nil, append([]string{"down"}, l.nums(hosts)...)...); err != nil {
		l.t.Fatalf("power off %v: %v", hosts, err)
	}
	for _, h := range hosts {
		l.closeMaster(h)
	}
	return l.mark("power: %v off", hosts)
}

// powerOn boots hosts (a no-op for one already running) and waits until each
// answers SSH with an active litevirt daemon.
func (l *lab) powerOn(hosts ...string) error {
	if _, err := l.labsh(2*time.Minute, nil, append([]string{"up"}, l.nums(hosts)...)...); err != nil {
		return err
	}
	l.mark("power: %v on", hosts)
	for _, h := range hosts {
		if err := l.waitDaemon(h, 6*time.Minute); err != nil {
			return err
		}
	}
	return nil
}

// isUp reports whether host's qemu process is running, by lab.sh's pid file.
func (l *lab) isUp(host string) bool {
	pidf := filepath.Join(l.dir, "nodes", host, "qemu.pid")
	b, err := os.ReadFile(pidf)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return false
	}
	return exec.Command("kill", "-0", strconv.Itoa(pid)).Run() == nil
}

// waitDaemon waits until host answers SSH and its litevirt unit is active and
// its CLI answers locally.
func (l *lab) waitDaemon(host string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		out, err := l.ssh(host, 20*time.Second, "systemctl is-active litevirt && "+shellQuote(l.lvPath)+" host ls >/dev/null && echo READY")
		if err == nil && strings.Contains(out, "READY") {
			return nil
		}
		last = err
		l.closeMaster(host)
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("%s: daemon not ready within %v: %v", host, timeout, last)
}

// restartOpt adjusts restartDaemon.
type restartOpt int

// anyState: the caller does not expect the host to come back HOST_ACTIVE
// (maintenance, fenced, still joining), so only the daemon answering is awaited.
const anyState restartOpt = 1

// restartDaemon restarts litevirt on host and waits until it is serving
// (HOST_ACTIVE in its own `host ls`), unless the anyState option says the
// caller expects another state.
func (l *lab) restartDaemon(host string, opts ...restartOpt) error {
	if _, err := l.ssh(host, time.Minute, "systemctl restart litevirt"); err != nil {
		return err
	}
	l.mark("daemon: restarted on %s", host)
	for _, o := range opts {
		if o == anyState {
			return l.waitDaemon(host, 3*time.Minute)
		}
	}
	return l.waitServing(host, 3*time.Minute)
}

// waitServing is waitDaemon plus: the host's own view lists it HOST_ACTIVE. A
// restarted daemon answers its CLI while still recording HOST_UPGRADING (the
// "upgrading, serving after ~28 s" boot state; HOST_DRAINING from a server
// on an earlier release), and a test that returns then
// makes the next test's baseline fail. A host its own `host ls` does not list
// at all (not yet a member) is not held to this. The whole wait, including each
// lv call, ends by timeout.
func (l *lab) waitServing(host string, timeout time.Duration) error {
	start := time.Now()
	end := start.Add(timeout)
	if err := l.waitDaemon(host, timeout); err != nil {
		return err
	}
	state, seen := "", "no host ls answered"
	for {
		left := time.Until(end)
		if left <= 0 {
			break
		}
		if left > 30*time.Second {
			left = 30 * time.Second
		}
		if out, err := l.lvTimeout(host, left, "host", "ls"); err == nil {
			state = parseHostStates(out)[host]
			seen = fmt.Sprintf("last seen state %q", state)
			if state == "" || state == "HOST_ACTIVE" {
				l.mark("daemon: %s serving (%q) %v after the restart", host, state, time.Since(start).Round(time.Second))
				return nil
			}
		} else {
			seen = "last host ls error: " + err.Error()
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("%s: daemon answers but is not HOST_ACTIVE %v after the restart (%s)", host, timeout, seen)
}

// freezeDaemon SIGSTOPs host's litevirt daemon and returns the thaw. The
// guests keep running: only the daemon stops.
func (l *lab) freezeDaemon(host string) (thaw func() error) {
	l.t.Helper()
	pid := strings.TrimSpace(l.mustSSH(host, 20*time.Second, "systemctl show -p MainPID --value litevirt"))
	if pid == "" || pid == "0" {
		l.t.Fatalf("no litevirt MainPID on %s", host)
	}
	l.mustSSH(host, 20*time.Second, "kill -STOP "+pid)
	l.mark("daemon: SIGSTOP %s pid %s", host, pid)
	var once sync.Once
	return func() error {
		var err error
		once.Do(func() {
			_, err = l.ssh(host, 20*time.Second, "kill -CONT "+pid)
			if err == nil {
				l.mark("daemon: SIGCONT %s pid %s", host, pid)
			}
		})
		return err
	}
}

// enforcementEditScript is the shell that sets enforcement.<key> in the YAML
// file at path. The key is written with the indentation the file's own
// enforcement block already uses (2, 4 or any width), never a hard-coded one: a
// 2-space line inside a 4-space block is a YAML parse error that stops the
// daemon. An absent block keeps the 2-space default for the line it cannot
// match against. The original is kept beside it as <path>.e2e-orig.
func enforcementEditScript(path, key, value string) string {
	return fmt.Sprintf(`set -e; f=%[1]s; [ -f $f.e2e-orig ] || cp -p $f $f.e2e-orig
ind=$(awk '/^enforcement:/{f=1;next} f && /^ +[^ #]/{match($0,/^ +/);print substr($0,1,RLENGTH);exit} f && /^[^ #]/{exit}' $f)
[ -n "$ind" ] || ind='  '
grep -qE '^enforcement:[[:space:]]*(#.*)?$' $f || { echo "enforcement: is missing or is not a plain block header (inline value or flow style)" >&2; exit 1; }
has=$(awk -v p="${ind}%[2]s:" '/^enforcement:/{f=1;next} f && /^[^ #]/{exit} f && index($0,p)==1{print 1;exit}' $f)
if [ -n "$has" ]; then
  awk -v p="${ind}%[2]s:" -v l="${ind}%[2]s: %[3]s" '/^enforcement:/{f=1;print;next} f && /^[^ #]/{f=0} f && index($0,p)==1{print l;next} {print}' $f > $f.e2e-new
  cat $f.e2e-new > $f; rm -f $f.e2e-new
else
  sed -i "/^enforcement:/a\\${ind}%[2]s: %[3]s" $f
fi
awk -v l="${ind}%[2]s: %[3]s" '/^enforcement:/{f=1;next} f && /^[^ #]/{f=0} f && $0==l{ok=1} END{exit !ok}' $f`, path, key, value)
}

// setEnforcement sets enforcement.<key> on host and restarts its daemon. The
// original config is kept beside it and put back by restoreConfig.
//
// The callers (drill_recovery, drill_witness) set it on hosts the baseline has
// just required HOST_ACTIVE, so it waits for HOST_ACTIVE; pass anyState for a
// host that may be in maintenance or fenced.
func (l *lab) setEnforcement(host, key, value string, opts ...restartOpt) error {
	if _, err := l.ssh(host, 30*time.Second, enforcementEditScript("/etc/litevirt/config.yaml", key, value)); err != nil {
		return err
	}
	l.mark("config: %s enforcement.%s=%s", host, key, value)
	return l.restartDaemon(host, opts...)
}

// restoreConfig puts host's original config back and restarts its daemon, if
// setEnforcement changed it. It reports whether a restart happened.
func (l *lab) restoreConfig(host string) (bool, error) {
	out, err := l.ssh(host, 30*time.Second, `f=/etc/litevirt/config.yaml; if [ -f $f.e2e-orig ]; then mv -f $f.e2e-orig $f && echo RESTORED; fi`)
	if err != nil || !strings.Contains(out, "RESTORED") {
		return false, err
	}
	l.mark("config: %s restored", host)
	// Restore runs after drills that may leave the host fenced or in maintenance.
	return true, l.restartDaemon(host, anyState)
}

// ─── Cluster state ──────────────────────────────────────────────────────────

type hostRow struct{ Name, State string }

// hostStates parses `lv host ls` on via.
func (l *lab) hostStates(via string) (map[string]string, error) {
	out, err := l.lv(via, "host", "ls")
	if err != nil {
		return nil, err
	}
	return parseHostStates(out), nil
}

// parseHostStates is host name → HOST_* state from `lv host ls` output.
func parseHostStates(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.HasPrefix(f[2], "HOST_") {
			m[f[0]] = f[2]
		}
	}
	return m
}

// voterSet parses `lv cluster voter ls` on via: generation and members.
func (l *lab) voterSet(via string) (int, []string, error) {
	out, err := l.lv(via, "cluster", "voter", "ls")
	if err != nil {
		return 0, nil, err
	}
	m := regexp.MustCompile(`Generation (\d+)`).FindStringSubmatch(out)
	if m == nil {
		return 0, nil, fmt.Errorf("no generation in voter ls:\n%s", out)
	}
	gen, _ := strconv.Atoi(m[1])
	var members []string
	inTable := false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "MEMBER" {
			inTable = true
			continue
		}
		if inTable && len(f) >= 2 {
			members = append(members, f[0])
		}
	}
	sort.Strings(members)
	return gen, members, nil
}

// leaseHolder is the failover lease holder in via's replica.
func (l *lab) leaseHolder(via, key string) string {
	l.t.Helper()
	// The holder can be a witness outside E2E_LAB_NODES (lab 1's node-6); the
	// harness addresses it only once outsiderHosts has registered it.
	l.outsiderHosts()
	rows := l.mustSQL(via, "SELECT holder FROM leader_election WHERE key='"+key+"'")
	if len(rows) == 0 {
		l.t.Fatalf("no %s lease row on %s", key, via)
	}
	return rows[0][0]
}

// labels returns host's labels from `lv host inspect`.
func (l *lab) labels(via, host string) map[string]string {
	l.t.Helper()
	var hi struct {
		Labels        map[string]string `json:"labels"`
		FenceStrategy string            `json:"fenceStrategy"`
	}
	if err := json.Unmarshal([]byte(l.mustLV(via, "host", "inspect", host)), &hi); err != nil {
		l.t.Fatalf("host inspect %s: %v", host, err)
	}
	return hi.Labels
}

func (l *lab) fenceStrategy(via, host string) string {
	l.t.Helper()
	var hi struct {
		FenceStrategy string `json:"fenceStrategy"`
	}
	if err := json.Unmarshal([]byte(l.mustLV(via, "host", "inspect", host)), &hi); err != nil {
		l.t.Fatalf("host inspect %s: %v", host, err)
	}
	return hi.FenceStrategy
}

// fenceableWhenOff is hosts minus those whose fence strategy cannot fence a
// powered-off machine: an `ssh` fence of a host that is off cannot connect and
// fails, and a `manual` one waits for an operator, so a power-off drill that
// expects its victim's workloads recovered must not pick either. It skips the
// test when none is left.
func (l *lab) fenceableWhenOff(via string, hosts []string) []string {
	l.t.Helper()
	var out []string
	for _, h := range hosts {
		switch l.fenceStrategy(via, h) {
		case "ssh", "manual":
			l.mark("victim choice: %s is on an ssh or manual fence, which cannot fence it powered off; not a candidate", h)
		default:
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		l.t.Skipf("no host among %v has a fence strategy that can fence a powered-off host (best-effort, ipmi, redfish)", hosts)
	}
	return out
}

// vmInfo is the slice of `lv inspect` the drills read.
type vmInfo struct {
	Name     string `json:"name"`
	HostName string `json:"hostName"`
	State    string `json:"state"`
	Spec     struct {
		OnHostFailure string `json:"onHostFailure"`
		SecureBoot    bool   `json:"secureBoot"`
		TPM           bool   `json:"tpm"`
	} `json:"spec"`
	Disks []struct {
		Name      string `json:"name"`
		HostName  string `json:"hostName"`
		Path      string `json:"path"`
		SizeBytes string `json:"sizeBytes"`
	} `json:"disks"`
}

// recoverable mirrors corrosion.VMRecoverableOnHostFailure for a VM without
// auto-promote replication (the lab has none). A stopped VM is not one:
// failover leaves it on its host, stopped, with its disks. This is stricter
// than the predicate, which recovers a VM that stopped without anyone asking
// (a guest shutdown) when every disk is on shared storage; the lab has no
// shared storage, so the two agree there.
func (v vmInfo) recoverable() bool {
	p := v.Spec.OnHostFailure
	return p != "" && p != "none" && !v.Spec.SecureBoot && !v.Spec.TPM && v.State != "VM_STOPPED"
}

func (l *lab) inspectVM(via, name string) (vmInfo, error) {
	var v vmInfo
	out, err := l.lv(via, "inspect", name)
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return v, fmt.Errorf("inspect %s: %v\n%s", name, err, out)
	}
	return v, nil
}

// vms lists every VM with its inspect record.
func (l *lab) vms(via string) map[string]vmInfo {
	l.t.Helper()
	m := map[string]vmInfo{}
	for _, line := range strings.Split(l.mustLV(via, "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "NAME" {
			continue
		}
		v, err := l.inspectVM(via, f[0])
		if err != nil {
			// A VM deleted between `ls` and `inspect` (a host removed for good
			// takes its stranded rows) is simply gone.
			if strings.Contains(err.Error(), "NotFound") {
				continue
			}
			l.t.Fatalf("%v", err)
		}
		m[v.Name] = v
	}
	return m
}

type ctInfo struct{ Host, Name, State, StateDetail, OnHostFailure, CreateSpec string }

// recoverable mirrors corrosion.ContainerRecoverableOnHostFailure's policy and
// stop rules: a container stopped by intent stays put; one failover itself
// marked relocate-skipped is stopped too, and the removed-host pass may still
// move it.
func (c ctInfo) recoverable() bool {
	stopped := c.State == "stopped" && c.StateDetail != "relocate-skipped"
	return c.OnHostFailure != "" && c.OnHostFailure != "none" && !stopped
}

// containers lists the live container rows in via's replica.
func (l *lab) containers(via string) map[string]ctInfo {
	l.t.Helper()
	m := map[string]ctInfo{}
	for _, r := range l.mustSQL(via, "SELECT host_name,name,state,COALESCE(state_detail,''),COALESCE(on_host_failure,''),COALESCE(create_spec,'') FROM containers WHERE deleted_at IS NULL AND is_template=0") {
		if len(r) >= 6 {
			m[r[1]] = ctInfo{Host: r[0], Name: r[1], State: r[2], StateDetail: r[3], OnHostFailure: r[4], CreateSpec: strings.Join(r[5:], "|")}
		}
	}
	return m
}

// recoverableOn returns the "vm/<name>" and "ct/<name>" keys of every
// recoverable workload whose row names one of hosts and that is running.
func (l *lab) recoverableOn(via string, hosts ...string) []string {
	l.t.Helper()
	on := map[string]bool{}
	for _, h := range hosts {
		on[h] = true
	}
	var keys []string
	for _, v := range l.vms(via) {
		if on[v.HostName] && v.recoverable() && v.State == "VM_RUNNING" {
			keys = append(keys, "vm/"+v.Name)
		}
	}
	for _, c := range l.containers(via) {
		if on[c.Host] && c.recoverable() && c.State == "running" {
			keys = append(keys, "ct/"+c.Name)
		}
	}
	sort.Strings(keys)
	return keys
}

// conditions returns condition rows of code first seen or updated at/after
// since (node clock, RFC3339 seconds), as code|subject|hosts|first_seen|resolved_at|lifecycle.
func (l *lab) conditions(via, code, since string) [][]string {
	l.t.Helper()
	return l.mustSQL(via, fmt.Sprintf(
		"SELECT code,subject_id,hosts,first_seen,COALESCE(resolved_at,''),lifecycle FROM health_conditions WHERE code='%s' AND deleted_at IS NULL AND (first_seen >= '%s' OR updated_at >= '%s') ORDER BY first_seen",
		code, since, since))
}

// proof is one runtime_action_proofs row.
type proof struct {
	ID, Action, Kind, Name, Dest, Coordinator, Status, Executor, Cert, Created, LeaseKey string
	LeaseTerm                                                                            int
}

// proofsSince lists proofs for workload name created at/after since.
func (l *lab) proofsSince(via, kind, name, since string) []proof {
	l.t.Helper()
	rows := l.mustSQL(via, fmt.Sprintf(
		"SELECT id,action,target_kind,target_name,dest_host,coordinator,status,executor_host,created_at,lease_key,lease_term,claim_certificate FROM runtime_action_proofs WHERE target_kind='%s' AND target_name='%s' AND created_at >= '%s' AND action IN ('reschedule','relocate','promote') ORDER BY created_at",
		kind, name, since))
	var ps []proof
	for _, r := range rows {
		if len(r) < 12 {
			continue
		}
		term, _ := strconv.Atoi(r[10])
		ps = append(ps, proof{ID: r[0], Action: r[1], Kind: r[2], Name: r[3], Dest: r[4], Coordinator: r[5],
			Status: r[6], Executor: r[7], Created: r[8], LeaseKey: r[9], LeaseTerm: term,
			Cert: strings.Join(r[11:], "|")})
	}
	return ps
}

// journalSince greps host's litevirt journal since a node-clock timestamp.
func (l *lab) journalSince(host, since, pattern string) string {
	out, _ := l.ssh(host, time.Minute, fmt.Sprintf(
		"journalctl -u litevirt --since %s --no-pager -o cat | grep -E %s || true",
		shellQuote(strings.ReplaceAll(strings.TrimSuffix(since, "Z"), "T", " ")+" UTC"), shellQuote(pattern)))
	return out
}

// qemuVirtualSize reads a disk image's virtual size on host with qemu-img
// (force-share, so a running guest's lock does not refuse the read).
func (l *lab) qemuVirtualSize(host, path string) (int64, error) {
	out, err := l.ssh(host, 30*time.Second, "qemu-img info -U --output=json "+shellQuote(path))
	if err != nil {
		return 0, err
	}
	var info struct {
		VirtualSize int64 `json:"virtual-size"`
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return 0, fmt.Errorf("qemu-img info %s on %s: %v", path, host, err)
	}
	return info.VirtualSize, nil
}

// fileExists reports whether path exists on host.
func (l *lab) fileExists(host, path string) bool {
	out, err := l.ssh(host, 20*time.Second, "test -e "+shellQuote(path)+" && echo YES || echo NO")
	return err == nil && strings.Contains(out, "YES")
}

// ─── Test workloads ─────────────────────────────────────────────────────────

// drillImage is the small image the drills boot, and drillMemory its memory:
// the lab's nodes keep ~1.4 GiB back for the host, so a 256 MiB guest (384 MiB
// with qemu overhead) does not fit beside a node's existing guests.
func drillImage() string  { return envOr("E2E_DRILL_IMAGE", "cirros") }
func drillMemory() string { return envOr("E2E_DRILL_MEMORY", "128M") }

// createVMs deploys one recoverable (restart-any) small VM pinned to each of
// hosts as one compose stack, waits until virsh shows each running, and deletes
// the stack in cleanup. It returns host → VM name.
func (l *lab) createVMs(via, prefix string, hosts ...string) map[string]string {
	l.t.Helper()
	return l.createStack(via, prefix, false, hosts...)
}

// createStack is createVMs; with roomOnly, a placement refused for want of
// room returns nil instead of failing the test.
func (l *lab) createStack(via, prefix string, roomOnly bool, hosts ...string) map[string]string {
	l.t.Helper()
	return l.createStackOf(via, prefix, roomOnly, drillImage(), drillMemory(), hosts...)
}

// putFile writes content to path on host and removes it in restore, once the
// faults are undone and the host answers again (a partitioned, frozen or
// powered-off node could not be reached sooner).
func (l *lab) putFile(host, path, content string) {
	l.t.Helper()
	l.mustSSH(host, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(content))+" | base64 -d > "+shellQuote(path))
	l.onRestore(func() { l.ssh(host, 30*time.Second, "rm -f "+shellQuote(path)) })
}

// firmwareLineFor is the compose line that boots the small drill image under
// BIOS: a 128 MiB cirros under the default UEFI firmware never boots ("can't
// allocate kernel"). Any other image keeps the default firmware.
func firmwareLineFor(image string) string {
	if image == drillImage() {
		return "    firmware: bios\n"
	}
	return ""
}

// createStackOf is createStack with an image and memory of its own.
func (l *lab) createStackOf(via, prefix string, roomOnly bool, image, memory string, hosts ...string) map[string]string {
	l.t.Helper()
	stack := uniqueName(prefix)
	names := map[string]string{}
	var b strings.Builder
	fmt.Fprintf(&b, "name: %s\nvms:\n", stack)
	for i, h := range hosts {
		n := fmt.Sprintf("%s-%d", stack, i+1)
		names[h] = n
		fmt.Fprintf(&b, "  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n%s    placement:\n      host: %s\n    migrate:\n      on-host-failure: restart-any\n", n, image, memory, firmwareLineFor(image), h)
	}
	file := "/tmp/" + stack + ".yaml"
	l.putFile(via, file, b.String())
	l.onRestore(func() { l.deleteVMs(stack, names) })
	if out, err := l.lv(via, "compose", "up", "-f", file, "-y"); err != nil {
		if errOut := err.Error() + out; roomOnly && strings.Contains(errOut, "no eligible host") {
			l.mark("workloads: no room for a test VM on %v: %s", hosts, strings.TrimSpace(errOut))
			return nil
		}
		l.t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	for h, n := range names {
		if !l.waitDomainState(h, n, "running", 4*time.Minute) {
			l.t.Fatalf("test VM %s never ran on %s (virsh)", n, h)
		}
	}
	l.mark("workloads: created %v", names)
	return names
}

// createVMsWhereRoom is createVMs with one stack per host, skipping a host the
// planner has no memory for: after earlier drills have moved workloads around,
// a fixed host can be full. It returns host → VM name for the hosts that took
// one.
func (l *lab) createVMsWhereRoom(via, prefix string, hosts ...string) map[string]string {
	l.t.Helper()
	all := map[string]string{}
	for _, h := range hosts {
		for hh, n := range l.createStack(via, prefix, true, h) {
			all[hh] = n
		}
	}
	return all
}

// deleteVMs removes a test stack and anything it left on any node: a domain a
// settle left defined, a disk file a failover left behind.
func (l *lab) deleteVMs(stack string, names map[string]string) {
	via := l.liveHost()
	if via == "" {
		l.t.Errorf("cleanup: no host answers; test VMs %v left behind", names)
		return
	}
	var list []string
	for _, n := range names {
		list = append(list, n)
	}
	// Delete through litevirt until NO replica holds a live row: a delete can be
	// refused while a just-restarted node's replica catches up, and a row left
	// behind makes that node's reconciler recreate the VM ("marked running but
	// not in libvirt"). Only then is anything left on a node's disk an orphan.
	//
	// Only a host whose replica can be read is asked. A machine that is up but
	// has no sqlite3 or no state.db (a rebuilt node before its add, or before
	// the drill installs sqlite3 on it) holds no replica the harness can read,
	// and counting it as unknown would spin here for the whole deadline.
	deadline := time.Now().Add(5 * time.Minute)
	unreadable := map[string]bool{}
	for {
		l.lv(via, "compose", "down", "--name", stack, "-y")
		left := map[string]bool{}
		for _, h := range l.upHosts() {
			if !l.replicaReadable(h) {
				if !unreadable[h] {
					unreadable[h] = true
					l.mark("cleanup: %s has no readable replica (no sqlite3 or no state.db); not asked for test VM rows", h)
				}
				continue
			}
			rows, err := l.sql(h, "SELECT name FROM vms WHERE deleted_at IS NULL AND name IN ('"+strings.Join(list, "','")+"')")
			if err != nil {
				left[h+":?"] = true
			}
			for _, r := range rows {
				left[r[0]] = true
			}
		}
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			l.t.Errorf("cleanup: test VMs still have live rows after 5m: %v", left)
			return
		}
		for n := range left {
			if !strings.Contains(n, ":") {
				l.lv(via, "rm", "--force", n)
			}
		}
		time.Sleep(10 * time.Second)
	}
	for _, h := range l.upHosts() {
		for _, n := range list {
			l.ssh(h, 30*time.Second, fmt.Sprintf(
				"virsh -c qemu:///system destroy %[1]s >/dev/null 2>&1; virsh -c qemu:///system undefine --nvram %[1]s >/dev/null 2>&1; rm -f /var/lib/litevirt/disks/%[1]s-*; true", shellQuote(n)))
		}
	}
	l.mark("cleanup: test VMs %v deleted", list)
}

// replicaReadable reports whether host answers SSH and has both sqlite3 and a
// state.db to read. An SSH failure is not "unreadable": the host may answer on
// the next try, so callers keep asking it.
func (l *lab) replicaReadable(host string) bool {
	out, err := l.ssh(host, 20*time.Second,
		"if command -v sqlite3 >/dev/null && test -s /var/lib/litevirt/state.db; then echo READABLE; else echo UNREADABLE; fi")
	if err != nil {
		return true
	}
	return !strings.Contains(out, "UNREADABLE")
}

// createContainer creates and starts a recoverable (image-recreate) container
// on host, waits until lxc-ls shows it running, and removes it in cleanup.
func (l *lab) createContainer(via, prefix, host string) string {
	l.t.Helper()
	name := uniqueName(prefix)
	l.onRestore(func() {
		v := l.liveHost()
		if v == "" {
			return
		}
		for _, h := range l.hosts {
			l.lv(v, "ct", "stop", name, "--host", h)
			l.lv(v, "ct", "rm", name, "--host", h, "--force")
		}
	})
	if out, err := l.lv(via, "ct", "create", name, "--host", host, "--on-host-failure", "image-recreate"); err != nil {
		l.t.Fatalf("ct create %s on %s: %v\n%s", name, host, err, out)
	}
	if out, err := l.lv(via, "ct", "start", name, "--host", host); err != nil {
		l.t.Fatalf("ct start %s: %v\n%s", name, err, out)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		out, _ := l.ssh(host, 20*time.Second, "lxc-ls -f -F NAME,STATE")
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == name && f[1] == "RUNNING" {
				l.mark("workloads: container %s running on %s", name, host)
				return name
			}
		}
		time.Sleep(3 * time.Second)
	}
	l.t.Fatalf("container %s never ran on %s (lxc-ls)", name, host)
	return ""
}

// waitDomainState polls virsh on host until domain is in state.
func (l *lab) waitDomainState(host, domain, state string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := l.ssh(host, 20*time.Second, "virsh -c qemu:///system domstate "+shellQuote(domain))
		if strings.TrimSpace(out) == state {
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

// liveHost returns a host whose daemon answers, preferring node-1.
func (l *lab) liveHost() string {
	for _, h := range l.hosts {
		if out, err := l.ssh(h, 15*time.Second, shellQuote(l.lvPath)+" host ls >/dev/null && echo OK"); err == nil && strings.Contains(out, "OK") {
			return h
		}
	}
	return ""
}

// ─── Baseline and restore ───────────────────────────────────────────────────

// baseline is the state every drill starts from and must leave behind.
type baseline struct {
	voters []string
	// allVoters is the adopted generation's members, E2E_LAB_EXCLUDE nodes
	// included: what restore re-initialises after a drill's voter reset.
	allVoters []string
	// strategies covers witnesses outside E2E_LAB_NODES too: a drill may set
	// theirs (TestDrillW3_LeaseChurnDuringAPausedManualHold).
	strategies map[string]string
	running    map[string]string // pre-existing running workload key → host
	cts        map[string]ctInfo
	lxcHosts   map[string]bool
}

// requireBaseline fails unless the lab is in its resting state: every host
// active, every host a voter, no drill rules, no paused guest. It records what
// was running, so restore can bring back anything a drill stopped.
func (l *lab) requireBaseline() baseline {
	l.t.Helper()
	via := l.hosts[0]
	states, err := l.hostStates(via)
	if err != nil {
		l.t.Fatalf("baseline: %v", err)
	}
	// Witnesses outside E2E_LAB_NODES too: the drills cut, stop and freeze
	// them, and a later drill run against an offline or still-cut witness
	// would read its own premises wrong.
	outsiders := l.outsiderHosts()
	for _, h := range append(append([]string{}, l.hosts...), outsiders...) {
		if states[h] != "HOST_ACTIVE" {
			l.t.Fatalf("baseline: %s is %q, want HOST_ACTIVE (lab not at rest: %v)", h, states[h], states)
		}
	}
	_, allVoters, err := l.voterSet(via)
	if err != nil {
		l.t.Fatalf("baseline: %v", err)
	}
	voters := l.exceptExcluded(allVoters)
	if strings.Join(voters, ",") != strings.Join(l.hosts, ",") {
		l.t.Fatalf("baseline: voters %v, want every host %v", voters, l.hosts)
	}
	if rows, err := l.openOwnershipConditions(via); err != nil || len(rows) > 0 {
		l.t.Fatalf("baseline: admission-gating conditions open (%v): %v", err, rows)
	}
	b := baseline{voters: voters, allVoters: allVoters, strategies: map[string]string{}, running: map[string]string{}, lxcHosts: map[string]bool{}}
	for _, h := range outsiders {
		b.strategies[h] = l.fenceStrategy(via, h)
		if out := l.mustSSH(h, 30*time.Second, "nft list tables"); strings.Contains(out, "inet "+drillTable) || regexp.MustCompile(`(?m)^table inet drill$`).MatchString(out) {
			l.t.Fatalf("baseline: drill nftables rules left on %s:\n%s", h, out)
		}
	}
	for _, h := range l.hosts {
		out := l.mustSSH(h, 30*time.Second, "nft list tables")
		if strings.Contains(out, "inet "+drillTable) || regexp.MustCompile(`(?m)^table inet drill$`).MatchString(out) {
			l.t.Fatalf("baseline: drill nftables rules left on %s:\n%s", h, out)
		}
		if paused := strings.TrimSpace(l.mustSSH(h, 30*time.Second, "virsh -c qemu:///system list --state-paused --name")); paused != "" {
			l.t.Fatalf("baseline: paused guests on %s: %s", h, paused)
		}
		b.strategies[h] = l.fenceStrategy(via, h)
		if l.labels(via, h)["litevirt.lxc"] == "true" {
			b.lxcHosts[h] = true
		}
	}
	for _, v := range l.vms(via) {
		if strings.HasPrefix(v.Name, "e2e-") {
			l.t.Fatalf("baseline: a test VM from an earlier run is left: %s on %s", v.Name, v.HostName)
		}
		if v.State == "VM_RUNNING" {
			b.running["vm/"+v.Name] = v.HostName
		}
	}
	b.cts = l.containers(via)
	for _, c := range b.cts {
		if c.State == "running" {
			b.running["ct/"+c.Name] = c.Host
		}
	}
	l.mark("baseline: %d hosts active, voters %v, %d running workloads", len(l.hosts), voters, len(b.running))
	return b
}

// restoreOnCleanup registers the lab restore. Register it right after
// requireBaseline: cleanups run last-in first-out, so a drill's own later
// cleanups (thawing a daemon, stopping the sampler) run before it, and the test
// workloads are deleted inside it once the faults are undone.
func (l *lab) restoreOnCleanup(b baseline) {
	l.t.Cleanup(func() { l.restore(b) })
}

// restore brings the lab back to b. Every step is bounded and keeps going on
// error, so one stuck step does not strand the rest; failures are test errors.
func (l *lab) restore(b baseline) {
	t := l.t
	l.mark("restore: begin")
	// 1. No drill rules anywhere (every host, including ones that were off).
	if err := l.clearDrops(append(l.upHosts(), l.outsiders...)...); err != nil {
		t.Errorf("restore: clearing nftables: %v", err)
	}
	// 2. Every host powered on with its daemon running (thaws are the drill's own
	//    cleanup; a SIGSTOPped daemon fails waitDaemon here and is reported).
	var down []string
	for _, h := range l.hosts {
		if !l.isUp(h) {
			down = append(down, h)
		}
	}
	if len(down) > 0 {
		if err := l.powerOn(down...); err != nil {
			t.Errorf("restore: power on %v: %v", down, err)
		}
	}
	for _, h := range l.outsiders {
		if !l.isUp(h) {
			down = append(down, h) // its strategy waits too (step 4)
			if err := l.powerOn(h); err != nil {
				t.Errorf("restore: power on %s: %v", h, err)
			}
		}
	}
	for _, h := range append(append([]string{}, l.hosts...), l.outsiders...) {
		if err := l.waitDaemon(h, 4*time.Minute); err != nil {
			t.Errorf("restore: %v", err)
		}
	}
	// 3. Original configs, one restart at a time, witnesses outside
	//    l.hosts included (a drill may set their enforcement too).
	for _, h := range append(append([]string{}, l.hosts...), l.outsiders...) {
		restarted, err := l.restoreConfig(h)
		if err != nil {
			t.Errorf("restore: config on %s: %v", h, err)
		}
		if restarted {
			time.Sleep(daemonRestartSpacing)
		}
	}
	via := l.liveHost()
	if via == "" {
		t.Errorf("restore: no host answers the CLI")
		return
	}
	// 4. Fence strategies. A host restore just powered on keeps whatever it
	//    has (a drill sets it manual first) until it has been active for two
	//    minutes: a best-effort host booted back must not race its own fence.
	setStrategies := func(booted bool) {
		for h, s := range b.strategies {
			if contains(down, h) != booted {
				continue
			}
			if s != "" && l.fenceStrategy(via, h) != s {
				if out, err := l.lv(via, "host", "config", h, "--fence-strategy", s); err != nil {
					t.Errorf("restore: fence strategy %s=%s: %v\n%s", h, s, err, out)
				}
			}
		}
	}
	setStrategies(false)
	// 5. Every host active, witnesses outside E2E_LAB_NODES included. A host
	//    the drill fenced and that booted again records itself active on its
	//    own; one that answered again without restarting needs `lv host
	//    undrain` (migration-failover.md, "What a fence records";
	//    partition-pause.md F6).
	l.waitActive(via, append(append([]string{}, l.hosts...), l.outsiders...), 6*time.Minute)
	if len(down) > 0 {
		time.Sleep(2 * time.Minute)
		setStrategies(true)
	}
	// 6. Every host a voter again, one member per generation. A drill that
	//    reset the cluster to the derived voter set (no members) gets the
	//    baseline generation back by init, which is the only way out of it.
	//    Every host's adoption is waited for first: a reset decided but not yet
	//    adopted on via would still read as the old members here.
	l.waitAdoptionAgrees(2 * time.Minute)
	if _, voters, err := l.voterSet(via); err == nil && len(voters) == 0 && len(b.allVoters) > 0 {
		if err := l.voterInit(via, b.allVoters); err != nil {
			t.Errorf("restore: %v", err)
		}
	} else if err == nil {
		have := map[string]bool{}
		for _, v := range voters {
			have[v] = true
		}
		for _, h := range b.voters {
			if !have[h] {
				if err := l.voterAdd(via, h); err != nil {
					t.Errorf("restore: %v", err)
				}
			}
		}
	}
	// 7. Test workloads go, then no guest may be left paused anywhere (a settle
	//    in progress gets time to finish).
	l.runPending()
	l.waitNoPaused(5 * time.Minute)
	// 8. The ownership conditions a fault leaves behind (runtime_owner_mismatch
	//    while a settle completes) refuse admission on the hosts they involve
	//    (grpcapi ownershipConditionCodes), which would fail the next drill's
	//    test VM create. They resolve after clean scans; wait for that.
	l.waitNoOwnershipConditions(via, 6*time.Minute)
	// 9. Pre-existing workloads that were running are running again somewhere.
	l.restartStopped(via, b)
	l.verifyRest(via, b)
	l.mark("restore: end")
}

// ownershipCodes are the condition codes that gate admission
// (internal/grpcapi/host_safety.go ownershipConditionCodes).
const ownershipCodes = "'vm_dual_run','ct_dual_run','runtime_owner_mismatch','owner_epoch_mismatch'"

// openOwnershipConditions lists unresolved admission-gating conditions.
func (l *lab) openOwnershipConditions(via string) ([][]string, error) {
	return l.sql(via, "SELECT code,subject_id,lifecycle,first_seen FROM health_conditions WHERE code IN ("+ownershipCodes+") AND deleted_at IS NULL AND lifecycle != 'resolved'")
}

func (l *lab) waitNoOwnershipConditions(via string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	var rows [][]string
	for time.Now().Before(deadline) {
		var err error
		rows, err = l.openOwnershipConditions(via)
		if err == nil && len(rows) == 0 {
			return
		}
		time.Sleep(10 * time.Second)
	}
	l.t.Errorf("restore: ownership conditions still open after %v: %v", timeout, rows)
}

// voterAdd adds host to the voter set and waits until every member of the new
// generation has adopted it. The next generation is decided by the members of
// this one, and a member still on the previous generation refuses to prepare
// it (recovery_claim_wrong_generation), so back-to-back adds fail without this.
func (l *lab) voterAdd(via, host string) error {
	deadline := time.Now().Add(3 * time.Minute)
	var out string
	var err error
	for {
		out, err = l.lv(via, "cluster", "voter", "add", host)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Second) // a member may still be adopting the last one
	}
	if err != nil {
		return fmt.Errorf("voter add %s: %v\n%s", host, err, out)
	}
	gen, members, err := l.voterSet(via)
	if err != nil {
		return err
	}
	l.mark("voter add %s: generation %d %v", host, gen, members)
	if err := l.waitAdopted(gen, members, deadline); err != nil {
		return fmt.Errorf("voter add %s: %v", host, err)
	}
	return nil
}

// waitAdoptionAgrees waits, up to timeout, until every up host reports the same
// newest adopted voter generation.
func (l *lab) waitAdoptionAgrees(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		gens := map[string]bool{}
		for _, h := range l.upHosts() {
			rows, err := l.sql(h, "SELECT COALESCE(MAX(generation),0) FROM local_voter_adoption")
			if err != nil || len(rows) == 0 {
				gens["?"] = true
				continue
			}
			gens[rows[0][0]] = true
		}
		if len(gens) <= 1 || time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Second)
	}
}

func (l *lab) upHosts() []string {
	var up []string
	for _, h := range l.hosts {
		if l.isUp(h) {
			up = append(up, h)
		}
	}
	return up
}

// waitAllActive undrains any host that is not active (once it answers) and
// waits until every host is HOST_ACTIVE.
func (l *lab) waitAllActive(via string, timeout time.Duration) {
	l.waitActive(via, l.hosts, timeout)
}

// waitActive is waitAllActive over a subset of hosts (drill 6 adds hosts back
// one at a time, while the others are still out of the cluster).
func (l *lab) waitActive(via string, hosts []string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	undrained := map[string]bool{}
	var states map[string]string
	for time.Now().Before(deadline) {
		var err error
		states, err = l.hostStates(via)
		if err == nil {
			all := true
			for _, h := range hosts {
				if states[h] == "HOST_ACTIVE" {
					continue
				}
				all = false
				if states[h] != "" && !undrained[h] {
					if out, err := l.lv(via, "host", "undrain", h); err == nil {
						undrained[h] = true
						l.mark("restore: undrain %s (was %s)", h, states[h])
					} else {
						l.t.Logf("undrain %s: %v %s", h, err, out)
					}
				}
			}
			if all {
				return
			}
		}
		time.Sleep(10 * time.Second)
	}
	l.t.Errorf("restore: hosts not all active after %v: %v", timeout, states)
}

func (l *lab) waitNoPaused(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		last = ""
		for _, h := range l.hosts {
			out, err := l.ssh(h, 20*time.Second, "virsh -c qemu:///system list --state-paused --name; command -v lxc-ls >/dev/null && lxc-ls -f -F NAME,STATE | awk '$2==\"FROZEN\"{print $1}'; true")
			if err == nil && strings.TrimSpace(out) != "" {
				last += h + ": " + strings.Join(strings.Fields(out), " ") + "; "
			}
		}
		if last == "" {
			return
		}
		time.Sleep(10 * time.Second)
	}
	l.t.Errorf("restore: guests still paused after %v: %s", timeout, last)
}

// restartStopped starts any pre-existing workload that was running at the
// baseline and is not running anywhere now (for example a policy-none VM on a
// host the drill powered off, or a container no survivor could relocate).
func (l *lab) restartStopped(via string, b baseline) {
	vms := l.vms(via)
	cts := l.containers(via)
	for key := range b.running {
		kind, name, _ := strings.Cut(key, "/")
		switch kind {
		case "vm":
			v, ok := vms[name]
			if !ok || v.State == "VM_RUNNING" {
				continue
			}
			if out, err := l.lv(via, "start", name); err != nil {
				l.t.Logf("restore: start %s: %v %s", name, err, out)
			} else {
				l.mark("restore: started %s (was %s)", key, v.State)
			}
		case "ct":
			c, ok := cts[name]
			if ok && c.State == "running" {
				continue
			}
			host := b.cts[name].Host
			if ok {
				host = c.Host
			}
			if out, err := l.lv(via, "ct", "start", name, "--host", host); err != nil {
				l.t.Logf("restore: ct start %s on %s: %v %s", name, host, err, out)
			} else {
				l.mark("restore: started %s on %s", key, host)
			}
		}
	}
}

// verifyRest is the postcondition every drill owes the next one.
func (l *lab) verifyRest(via string, b baseline) {
	states, err := l.hostStates(via)
	if err != nil {
		l.t.Errorf("rest: %v", err)
		return
	}
	for _, h := range append(append([]string{}, l.hosts...), l.outsiders...) {
		if states[h] != "HOST_ACTIVE" {
			l.t.Errorf("rest: %s left %s", h, states[h])
		}
	}
	if gen, voters, err := l.voterSet(via); err != nil || strings.Join(l.exceptExcluded(voters), ",") != strings.Join(b.voters, ",") {
		l.t.Errorf("rest: voters %v (generation %d, err %v), want %v", voters, gen, err, b.voters)
	}
	for _, h := range append(append([]string{}, l.hosts...), l.outsiders...) {
		out, err := l.ssh(h, 20*time.Second, "nft list tables")
		if err != nil || strings.Contains(out, "inet "+drillTable) || regexp.MustCompile(`(?m)^table inet drill$`).MatchString(out) {
			l.t.Errorf("rest: drill nftables state on %s: %v %s", h, err, out)
		}
		cfg, err := l.ssh(h, 20*time.Second, "test ! -e /etc/litevirt/config.yaml.e2e-orig && echo CLEAN")
		if err != nil || !strings.Contains(cfg, "CLEAN") {
			l.t.Errorf("rest: %s still has a drill config backup (flags not restored)", h)
		}
	}
	for h, s := range b.strategies {
		if got := l.fenceStrategy(via, h); s != "" && got != s {
			l.t.Errorf("rest: %s fence strategy %q, want %q", h, got, s)
		}
	}
}

// ─── The sampler: exactly-once, read from virsh and lxc-ls ──────────────────

// sampleCmd prints one line per guest on a node: "<kind> <name> <state>".
const sampleCmd = `v=$(virsh -c qemu:///system list --all 2>/dev/null) || { echo VIRSHERR; echo END; exit 0; }; echo "$v" | awk 'NR>2 && $2!="" {s=$3; for(i=4;i<=NF;i++) s=s"_"$i; print "vm "$2" "s}'; if command -v lxc-ls >/dev/null 2>&1; then lxc-ls -f -F NAME,STATE 2>/dev/null | awk 'NR>1 && $1!="" {print "ct "$1" "tolower($2)}'; fi; echo END`

// round is one sample of every node, taken concurrently.
type round struct {
	At     time.Time
	Copies map[string]map[string]string // workload key → host → state
	Down   map[string]string            // host → why it was not read
}

func (r round) state(host, key string) string { return r.Copies[key][host] }

// executingState is a guest whose vCPUs (or processes) run.
func executingState(s string) bool {
	switch s {
	case "running", "idle", "blocked", "in_shutdown":
		return true
	}
	return false
}

func pausedState(s string) bool { return s == "paused" || s == "frozen" }

// executing lists the hosts on which key executes in this round.
func (r round) executing(key string) []string {
	var hs []string
	for h, s := range r.Copies[key] {
		if executingState(s) {
			hs = append(hs, h)
		}
	}
	sort.Strings(hs)
	return hs
}

func (r round) String() string {
	var keys []string
	for k := range r.Copies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(r.At.UTC().Format("15:04:05.000"))
	for _, k := range keys {
		var hs []string
		for h, s := range r.Copies[k] {
			hs = append(hs, h+"="+s)
		}
		sort.Strings(hs)
		fmt.Fprintf(&b, " %s[%s]", k, strings.Join(hs, ","))
	}
	var down []string
	for h := range r.Down {
		down = append(down, h)
	}
	sort.Strings(down)
	if len(down) > 0 {
		fmt.Fprintf(&b, " down=%v", down)
	}
	return b.String()
}

type sampler struct {
	l      *lab
	mu     sync.Mutex
	rounds []round
	stop   chan struct{}
	done   chan struct{}
	out    *bufio.Writer
	file   *os.File
}

// startSampler reads every node's guests every samplePeriod until stopped
// (cleanup stops it at the latest).
func (l *lab) startSampler() *sampler {
	s := &sampler{l: l, stop: make(chan struct{}), done: make(chan struct{})}
	if l.evDir != "" {
		if f, err := os.Create(filepath.Join(l.evDir, "samples.log")); err == nil {
			s.file, s.out = f, bufio.NewWriter(f)
		}
	}
	go s.loop()
	l.t.Cleanup(s.Stop)
	return s
}

func (s *sampler) loop() {
	defer close(s.done)
	tick := time.NewTicker(samplePeriod)
	defer tick.Stop()
	for {
		s.sampleOnce()
		select {
		case <-s.stop:
			return
		case <-tick.C:
		}
	}
}

func (s *sampler) sampleOnce() {
	r := round{At: time.Now(), Copies: map[string]map[string]string{}, Down: map[string]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range s.l.hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !s.l.isUp(h) {
				mu.Lock()
				r.Down[h] = "powered off"
				mu.Unlock()
				return
			}
			out, err := s.l.ssh(h, 4*time.Second, sampleCmd)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || !strings.Contains(out, "END") {
				r.Down[h] = fmt.Sprint(err)
				return
			}
			if strings.Contains(out, "VIRSHERR") {
				// libvirt did not answer: a copy running there is invisible to
				// this sample, which must not read as "no guests".
				r.Down[h] = "virsh failed"
				return
			}
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) != 3 {
					continue
				}
				key := f[0] + "/" + f[1]
				if r.Copies[key] == nil {
					r.Copies[key] = map[string]string{}
				}
				r.Copies[key][h] = f[2]
			}
		}()
	}
	wg.Wait()
	s.mu.Lock()
	s.rounds = append(s.rounds, r)
	if s.out != nil {
		fmt.Fprintln(s.out, r.String())
		s.out.Flush()
	}
	s.mu.Unlock()
}

// Stop ends sampling; safe to call twice.
func (s *sampler) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
}

func (s *sampler) snapshot() []round {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]round(nil), s.rounds...)
}

// waitFor returns the first round taken after `after` for which pred holds,
// waiting up to timeout for one.
func (s *sampler) waitFor(after time.Time, timeout time.Duration, pred func(round) bool) (round, bool) {
	deadline := time.Now().Add(timeout)
	seen := 0
	for {
		rs := s.snapshot()
		for ; seen < len(rs); seen++ {
			if rs[seen].At.After(after) && pred(rs[seen]) {
				return rs[seen], true
			}
		}
		if time.Now().After(deadline) {
			return round{}, false
		}
		time.Sleep(samplePeriod / 2)
	}
}

// last returns the newest round.
func (s *sampler) last() round {
	rs := s.snapshot()
	if len(rs) == 0 {
		return round{}
	}
	return rs[len(rs)-1]
}

// assertNeverTwice is the drills' central property: in no sample does any
// workload execute on two hosts at once. It reports each workload once, at its
// first violating sample.
func assertNeverTwice(t *testing.T, rounds []round) {
	t.Helper()
	reported := map[string]bool{}
	for _, r := range rounds {
		for key := range r.Copies {
			if hs := r.executing(key); len(hs) > 1 && !reported[key] {
				reported[key] = true
				t.Errorf("%s executed on %v at once at %s (virsh/lxc-ls):\n  %s", key, hs, r.At.UTC().Format("15:04:05.000"), r)
			}
		}
	}
	if len(rounds) == 0 {
		t.Errorf("exactly-once: the sampler recorded no samples")
	}
}

// assertExactlyOnceNow requires every key to execute on exactly one host, with
// no paused copy left anywhere, in the newest sample.
func assertExactlyOnceNow(t *testing.T, s *sampler, keys []string) {
	t.Helper()
	r := s.last()
	for _, k := range keys {
		hs := r.executing(k)
		var paused []string
		for h, st := range r.Copies[k] {
			if pausedState(st) {
				paused = append(paused, h)
			}
		}
		if len(hs) != 1 || len(paused) != 0 {
			t.Errorf("%s: executing on %v, paused on %v; want exactly one executing copy and none paused\n  %s", k, hs, paused, r)
		}
	}
}
