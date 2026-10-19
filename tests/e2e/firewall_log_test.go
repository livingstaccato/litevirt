package e2e

// Firewall logging proven with real traffic (spec §3.7 C11, docs/firewall.md
// "Logging").
//
// A cirros VM on this host sits behind a security group that accepts tcp/22
// with log: true (so the test can log in, and a login is an "accept" record)
// and drops udp/5000 with log: true. The host's log budget is pinned with a
// host-scoped `lv firewall log-policy off --rate R --burst B` (the default
// verdict stays unlogged; logged rules log).
//
//   - Flood: this node sends UDP to the guest's 5000 as fast as it can for
//     30 s (host → guest is judged by the guest NIC's nic_in_ chain, on the
//     bridge output hook). `lv firewall log --workload` returns at least 25·R
//     and at most B + R·t + 1 records for it (t the flood's length, 30 s),
//     every one a drop; the guest receives none of the datagrams.
//   - Neither the kernel log nor the daemon's journal gains a line holding
//     "lv-log" across the flood (counted from a journal cursor taken before).
//   - The daemon's RSS grows by less than 32 MiB across the flood.
//   - The ruleset holds one named limit per NIC side at R/B, and every log
//     line sends to an NFLOG group (no kernel-log `log`).
//   - --follow prints a record that arrives after it started.
//   - A token scoped to a project is refused `lv firewall log`, while an
//     unscoped token of the same Admin user is answered.
//
// Runs ON a cluster node (local mode) as root: nft, journalctl and /proc are
// read here, and the guest is reached over its network's bridge, whose
// gateway address is this host's.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	fwLogRate  = 5
	fwLogBurst = 10
	fwLogFlood = 30 * time.Second
)

// fwLogRecord is one row of `lv firewall log`.
type fwLogRecord struct {
	Time, Host, Workload, Device, Side, Rule, Verdict, Proto, Src, Dst string
}

func parseFirewallLog(out string) []fwLogRecord {
	var recs []fwLogRecord
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 11 || f[0] == "TIME" {
			continue
		}
		recs = append(recs, fwLogRecord{f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9]})
	}
	return recs
}

// journalCursor is the cursor of the newest entry journalctl args selects.
func journalCursor(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("journalctl", append(args, "-n", "0", "--show-cursor", "--no-pager")...).CombinedOutput()
	if err != nil {
		t.Fatalf("journalctl %v: %v\n%s", args, err, out)
	}
	m := regexp.MustCompile(`-- cursor: (\S+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("journalctl %v printed no cursor:\n%s", args, out)
	}
	return m[1]
}

// journalLinesSince counts the lines holding needle after cursor.
func journalLinesSince(t *testing.T, cursor, needle string, args ...string) int {
	t.Helper()
	out, err := exec.Command("journalctl", append(args, "--after-cursor", cursor, "--no-pager", "-o", "cat")...).CombinedOutput()
	if err != nil {
		t.Fatalf("journalctl %v --after-cursor: %v\n%s", args, err, out)
	}
	return strings.Count(string(out), needle)
}

// daemonRSS is litevirtd's resident set, in KiB.
func daemonRSS(t *testing.T) (pid string, kib int) {
	t.Helper()
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", "litevirt").Output()
	pid = strings.TrimSpace(string(out))
	if err != nil || pid == "" || pid == "0" {
		t.Fatalf("litevirt's MainPID: %q %v", pid, err)
	}
	b, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^VmRSS:\s+(\d+) kB`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("no VmRSS in /proc/%s/status", pid)
	}
	kib, _ = strconv.Atoi(string(m[1]))
	return pid, kib
}

// floodUDP sends to addr as fast as it can for d and returns how many
// datagrams went and how long it took.
func floodUDP(t *testing.T, addr string, d time.Duration) (int, time.Duration) {
	t.Helper()
	c, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := []byte("lv-e2e-firewall-log-flood")
	n := 0
	start := time.Now()
	for time.Since(start) < d {
		for i := 0; i < 256; i++ {
			if _, err := c.Write(payload); err == nil {
				n++
			}
		}
	}
	return n, time.Since(start)
}

func TestFirewall_LogBudgetAndJournal(t *testing.T) {
	ensureTopology(t)
	host := localHost
	if host == "" {
		t.Skip("cannot tell which cluster host this node is")
	}
	for _, bin := range []string{"nft", "journalctl", "systemctl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed on this node", bin)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root (nft, the journal, the daemon's /proc)")
	}
	pid := os.Getpid() % 100000

	if !strings.Contains(lv(t, "firewall", "enforce", "status"), "per-NIC enforcement: enforce") {
		cleanup(t, func() { lvErr(t, "firewall", "enforce", "off") })
	}
	lv(t, "firewall", "enforce", "on")

	// Pin this host's budget; the default verdict is not logged.
	lv(t, "firewall", "log-policy", "off", "--scope", host, "--rate", strconv.Itoa(fwLogRate), "--burst", strconv.Itoa(fwLogBurst))
	cleanup(t, func() { lvErr(t, "firewall", "log-policy", "inherit", "--scope", host) })

	netName := uniqueName("fln")
	lv(t, "network", "create", netName, "--type", "isolated", "--subnet", "10.208.0.0/24", "--dhcp")
	cleanup(t, func() { lvErr(t, "network", "rm", netName, "--force") })

	stack := uniqueName("fls")
	vm := uniqueName("flvm")
	sg := fmt.Sprintf("fl%d", pid)
	compose := fmt.Sprintf(`name: %[1]s
security-groups:
  %[2]s:
    rules:
      - {direction: ingress, proto: tcp, port: "22", action: accept, log: true}
      - {direction: ingress, proto: udp, port: "5000", action: drop, log: true}
networks:
  %[3]s:
    external: true
vms:
  %[4]s:
    image: %[5]s
    cpu: 1
    memory: %[6]s
    firmware: bios
    network: [{name: %[3]s, security-groups: [%[2]s]}]
    placement: {host: %[7]s}
`, stack, sg, netName, vm, drillImage(), drillMemory(), host)
	file := writeComposeFile(t, stack, compose)
	lv(t, "compose", "up", "-f", file, "-y")
	cleanup(t, func() { lvErr(t, "compose", "down", "-f", file, "-y") })

	waitVM(t, vm, "RUNNING", 4*time.Minute)
	ip := vmIPOf(t, vm, 5*time.Minute)
	deadline := time.Now().Add(20 * time.Minute) // cirros may retry a metadata service for minutes
	for {
		if _, ok, err := guestDirect(ip, "true"); err == nil && ok {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("VM %s (%s) never accepted a login: %v", vm, ip, err)
		}
		time.Sleep(10 * time.Second)
	}
	// A listener in the guest counts what reaches 5000.
	// (Best effort: the kernel test proves the drop; this is the lab's view.)
	listening := false
	if out, _, err := guestDirect(ip, "setsid sh -c 'nc -u -l -p 5000 > /tmp/got 2>&1' </dev/null >/dev/null 2>&1 & sleep 1; netstat -lun | grep ':5000 '"); err == nil && strings.Contains(out, ":5000") {
		listening = true
	} else {
		t.Logf("no UDP listener on the guest's 5000 (%v); delivery is not checked here:\n%s", err, out)
	}

	records := func(t *testing.T) []fwLogRecord {
		t.Helper()
		return parseFirewallLog(lv(t, "firewall", "log", "--host", host, "--workload", vm, "--limit", "10000"))
	}
	dport := func(r fwLogRecord, port string) bool { return strings.HasSuffix(r.Dst, ":"+port) }

	t.Run("RulesetHasNamedLimitAndNFLOGOnly", func(t *testing.T) {
		out, err := exec.Command("nft", "list", "table", "bridge", "litevirt-nic").CombinedOutput()
		if err != nil {
			t.Fatalf("nft list: %v\n%s", err, out)
		}
		rs := string(out)
		want := fmt.Sprintf("rate %d/second burst %d packets", fwLogRate, fwLogBurst)
		if !regexp.MustCompile(`limit lv_lg_i_\S+ \{\s+` + regexp.QuoteMeta(want)).MatchString(rs) {
			t.Errorf("no per-NIC ingress limit at %q in bridge litevirt-nic:\n%s", want, rs)
		}
		logStmt := regexp.MustCompile(`\blog\b`)
		nflog := regexp.MustCompile(`\blog\b.* group \d+`)
		logged := 0
		for _, line := range strings.Split(rs, "\n") {
			if logStmt.MatchString(line) && !strings.Contains(line, "limit lv_lg_") {
				logged++
				if !nflog.MatchString(line) {
					t.Errorf("a log line without an NFLOG group (kernel log): %s", strings.TrimSpace(line))
				}
			}
		}
		t.Logf("%d log lines, each to an NFLOG group", logged)
		if !regexp.MustCompile(`udp dport 5000 limit name "lv_lg_i_[^"]+" log `).MatchString(rs) {
			t.Errorf("no logged udp/5000 line:\n%s", rs)
		}
	})

	t.Run("AcceptIsLogged", func(t *testing.T) {
		var got []fwLogRecord
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
			got = nil
			for _, r := range records(t) {
				if dport(r, "22") && r.Verdict == "accept" && r.Side == "in" {
					got = append(got, r)
				}
			}
			if len(got) > 0 {
				t.Logf("accept record: %+v", got[0])
				return
			}
		}
		t.Fatalf("no accept record for the logged tcp/22 rule after the logins")
	})

	kcur := journalCursor(t, "-k")
	ucur := journalCursor(t, "-u", "litevirt")
	pid0, rss0 := daemonRSS(t)
	time.Sleep(3 * time.Second) // let the budget refill to its burst

	sent, elapsed := floodUDP(t, net.JoinHostPort(ip, "5000"), fwLogFlood)
	t.Logf("flood: %d datagrams to %s:5000 in %v (%.0f/s)", sent, ip, elapsed.Round(time.Millisecond), float64(sent)/elapsed.Seconds())
	time.Sleep(3 * time.Second) // the listener and the store catch up

	t.Run("FloodRecordsWithinBudget", func(t *testing.T) {
		n := 0
		for _, r := range records(t) {
			if !dport(r, "5000") {
				continue
			}
			n++
			if r.Verdict != "drop" || r.Side != "in" || r.Host != host {
				t.Errorf("flood record %+v: want a drop on the in side on %s", r, host)
			}
		}
		floor := 25 * fwLogRate
		ceil := fwLogBurst + int(fwLogRate*elapsed.Seconds()+0.999) + 1
		t.Logf("%d records for udp/5000 (want %d..%d)", n, floor, ceil)
		if n < floor || n > ceil {
			t.Errorf("records = %d, want %d..%d", n, floor, ceil)
		}
		if out, _, err := guestDirect(ip, "wc -c < /tmp/got"); listening && err == nil && strings.TrimSpace(out) != "0" {
			t.Errorf("the guest received %s bytes on udp/5000, a drop rule", strings.TrimSpace(out))
		}
	})

	t.Run("NothingInTheJournal", func(t *testing.T) {
		if k := journalLinesSince(t, kcur, "lv-log", "-k"); k != 0 {
			t.Errorf("the kernel log gained %d lines holding lv-log", k)
		}
		if u := journalLinesSince(t, ucur, "lv-log", "-u", "litevirt"); u != 0 {
			t.Errorf("the daemon's journal gained %d lines holding lv-log", u)
		}
	})

	t.Run("RSSBound", func(t *testing.T) {
		pid1, rss1 := daemonRSS(t)
		if pid1 != pid0 {
			t.Fatalf("the daemon restarted during the flood (pid %s then %s)", pid0, pid1)
		}
		t.Logf("daemon RSS %d KiB then %d KiB (%+d KiB)", rss0, rss1, rss1-rss0)
		if rss1-rss0 >= 32<<10 {
			t.Errorf("daemon RSS grew by %d KiB, want under 32 MiB", rss1-rss0)
		}
	})

	t.Run("FollowPrintsNewRecords", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, lvBin, "firewall", "log", "--follow", "--host", host, "--workload", vm, "--limit", "1")
		cmd.Env = lvEnv()
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { cancel(); _ = cmd.Wait() }()
		lines := make(chan string, 64)
		go func() {
			sc := bufio.NewScanner(stdout)
			for sc.Scan() {
				lines <- sc.Text()
			}
			close(lines)
		}()
		time.Sleep(6 * time.Second) // the first answer is printed; the budget refills
		start := time.Now().UTC()
		c, err := net.Dial("udp4", net.JoinHostPort(ip, "5001"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("x")) // 5001 is not logged: never a record
		c.Close()
		c, err = net.Dial("udp4", net.JoinHostPort(ip, "5000"))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			_, _ = c.Write([]byte("follow"))
		}
		c.Close()
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatal("lv firewall log --follow exited")
				}
				rs := parseFirewallLog(l)
				if len(rs) == 1 && dport(rs[0], "5000") {
					if ts, err := time.Parse(time.RFC3339Nano, rs[0].Time); err != nil || !ts.Before(start.Add(-time.Second)) {
						t.Logf("--follow printed: %s", l)
						return
					}
				}
			case <-ctx.Done():
				t.Fatal("--follow printed no new record within 40 s")
			}
		}
	})

	t.Run("ProjectScopedTokenRefused", func(t *testing.T) {
		user := uniqueName("fluser") // e2e- prefix: the README's cleanup finds it
		pw := make([]byte, 16)
		_, _ = rand.Read(pw)
		lv(t, "user", "create", user, "--role", "viewer", "--password", hex.EncodeToString(pw))
		cleanup(t, func() { lvErr(t, "user", "delete", user) })
		out := lv(t, "role", "grant", "Admin", "user:"+user+"@local", "--path", "/", "--propagate")
		if m := regexp.MustCompile(`id=(\S+)`).FindStringSubmatch(out); m != nil {
			cleanup(t, func() { lvErr(t, "role", "revoke", m[1]) })
		}
		token := func(name string, scope ...string) string {
			args := []string{"user", "token-create", user, name}
			for _, s := range scope {
				args = append(args, "--scope-path", s)
			}
			m := regexp.MustCompile(`(?m)^Token:\s+(\S+)`).FindStringSubmatch(lv(t, args...))
			if m == nil {
				t.Fatal("token-create printed no token")
			}
			return m[1]
		}
		withToken := func(tok string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, lvBin, "firewall", "log", "--host", host, "--limit", "1")
			cmd.Env = append(lvEnv(), "LV_TOKEN="+tok)
			b, err := cmd.CombinedOutput()
			return string(b), err
		}
		if out, err := withToken(token("e2e-root")); err != nil {
			t.Fatalf("an Admin's unscoped token was refused (the control): %v\n%s", err, out)
		}
		out, err := withToken(token("e2e-proj", "/projects/e2e-fwlog"))
		if err == nil {
			t.Fatalf("a token scoped to /projects/e2e-fwlog read the firewall log:\n%s", out)
		}
		if !strings.Contains(strings.ToLower(out), "permission") && !strings.Contains(out, "firewall.log.view") {
			t.Errorf("refusal does not read as a permission error:\n%s", out)
		}
		t.Logf("scoped token refused: %s", strings.TrimSpace(out))
	})
}
