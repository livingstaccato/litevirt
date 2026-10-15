package firewall

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Firewall logging, the renderer (spec §3.4, plan C1).

// logPlan is a plan with one guest NIC whose security group logs a drop and
// an accept, and logging available on the host.
func logPlan(mode string) Plan {
	return Plan{
		DefaultDeny: true,
		NICMode:     mode,
		LogPolicy:   LogPolicy{Available: true, Group: 27},
		SecurityGroups: []SecurityGroup{{Name: "web", Rules: []Rule{
			{ID: "r-ssh", Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Drop, Log: true, Comment: "no ssh"},
			{ID: "r-web", Direction: Ingress, Proto: "tcp", PortRange: "80", Action: Accept, Log: true},
			{ID: "r-out", Direction: Egress, Proto: "udp", PortRange: "53", Action: Accept, Log: true},
			{ID: "r-quiet", Direction: Ingress, Proto: "tcp", PortRange: "443", Action: Accept},
		}}},
		NICs: []NICBinding{{NICDev: "tap0", VMName: "vm", SecurityGroups: []string{"web"}}},
	}
}

func mustRender(t *testing.T, p Plan) string {
	t.Helper()
	out, err := Render(p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out
}

// chainLines returns the rule lines of one chain (trimmed), in order.
func chainLines(t *testing.T, script, chain string) []string {
	t.Helper()
	head := "    chain " + chain + " {\n"
	i := strings.Index(script, head)
	if i < 0 {
		t.Fatalf("no chain %s in:\n%s", chain, script)
	}
	body := script[i+len(head):]
	body = body[:strings.Index(body, "\n    }\n")]
	var out []string
	for _, l := range strings.Split(body, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

var quotedRE = regexp.MustCompile(`"[^"]*"`)

// logStatements are the log statements of a ruleset outside quoted text: a
// prefix ("lv-log ...") or comment that says log is not one.
var (
	logWordRE  = regexp.MustCompile(`(^|[^\w-])log([^\w-]|$)`)
	logGroupRE = regexp.MustCompile(`^log group \d+ `)
)

// assertEveryLogHasGroup is the L-1 guard: every log statement the renderer
// writes sends to an NFLOG group, never to the kernel log.
func assertEveryLogHasGroup(t testing.TB, script string) {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		bare := quotedRE.ReplaceAllString(line, `""`)
		for _, m := range logWordRE.FindAllStringIndex(bare, -1) {
			if !logGroupRE.MatchString(strings.TrimLeft(bare[m[0]:], " \t")) {
				t.Errorf("log statement without a group (L-1: never the kernel log): %q", strings.TrimSpace(line))
			}
		}
	}
}

var (
	tableStartRE = regexp.MustCompile(`^table \S+ \S+ \{`)
	limitDeclRE  = regexp.MustCompile(`^\s+limit (\S+) \{`)
	limitRefRE   = regexp.MustCompile(`limit name "([^"]+)"`)
)

// assertLimitsDeclared is the declaration guard: every `limit name "X"` a
// table uses is declared in that same table, and no name is declared twice
// there. An undeclared reference or a duplicate declaration makes nft refuse
// the whole ruleset, and the host keeps its last one.
func assertLimitsDeclared(t testing.TB, script string) {
	t.Helper()
	declared := map[string]bool{}
	var refs []string
	table := ""
	flush := func() {
		for _, r := range refs {
			if !declared[r] {
				t.Errorf("table %s references limit %q it does not declare", table, r)
			}
		}
		declared, refs = map[string]bool{}, nil
	}
	for _, line := range strings.Split(script, "\n") {
		if tableStartRE.MatchString(line) {
			flush()
			table = line
			continue
		}
		if m := limitDeclRE.FindStringSubmatch(line); m != nil {
			if declared[m[1]] {
				t.Errorf("table %s declares limit %q twice", table, m[1])
			}
			declared[m[1]] = true
			continue
		}
		for _, m := range limitRefRE.FindAllStringSubmatch(line, -1) {
			refs = append(refs, m[1])
		}
	}
	flush()
}

// The log is its own line, ahead of the verdict line it logs: a limit that
// does not match stops its rule, so a verdict on the same line would be
// skipped once the budget is spent.
//
// Mutation: put `limit … log … drop` on one line — red.
func TestLogRender_LogLinePrecedesVerdictLine(t *testing.T) {
	lines := chainLines(t, mustRender(t, logPlan(NICModeEnforce)), "nic_in_tap0")
	want := []string{
		`oifname tap0 tcp dport 22 limit name "lv_lg_i_tap0" log group 27 snaplen 96 prefix "lv-log tap0 in r-ssh drop"`,
		`oifname tap0 tcp dport 22 drop comment "no ssh"`,
		`oifname tap0 tcp dport 80 limit name "lv_lg_i_tap0" log group 27 snaplen 96 prefix "lv-log tap0 in r-web accept"`,
		`oifname tap0 tcp dport 80 accept`,
		`oifname tap0 tcp dport 443 accept`,
		`drop`,
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("nic_in_tap0:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	out := chainLines(t, mustRender(t, logPlan(NICModeEnforce)), "nic_out_tap0")
	if len(out) < 2 || out[0] != `iifname tap0 udp dport 53 limit name "lv_lg_o_tap0" log group 27 snaplen 96 prefix "lv-log tap0 out r-out accept"` ||
		out[1] != `iifname tap0 udp dport 53 return` {
		t.Fatalf("nic_out_tap0:\n%s", strings.Join(out, "\n"))
	}
	// No line both logs and decides.
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		for _, l := range strings.Split(mustRender(t, logPlan(mode)), "\n") {
			if !strings.Contains(l, " log group ") {
				continue
			}
			if !regexp.MustCompile(`prefix "[^"]*"$`).MatchString(l) {
				t.Errorf("%s: a log line must end at its prefix (no verdict, counter or comment after it): %q", mode, l)
			}
		}
	}
}

// One named limit per guest NIC and side, shared by every log line of that
// side, plus lv_lg_routed for the tiers.
//
// Mutation: a limit per rule (two logged rules then double the budget) — red.
func TestLogRender_OneLimitPerNICSide(t *testing.T) {
	p := logPlan(NICModeEnforce)
	p.NICs = append(p.NICs, NICBinding{NICDev: "tap-b.1", VMName: "vm2", SecurityGroups: []string{"web"}})
	p.ClusterRules = []Rule{{ID: "c1", Direction: Ingress, Proto: "tcp", PortRange: "25", Action: Drop, Log: true}}
	inet, nic, err := RenderParts(p, true)
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^    limit (\S+) \{\n        rate (\d+)/second burst (\d+) packets\n    \}$`)
	got := map[string]int{}
	for _, m := range decl.FindAllStringSubmatch(nic, -1) {
		got[m[1]]++
		if m[2] != "5" || m[3] != "10" {
			t.Errorf("limit %s: rate %s burst %s, want the default 5/s burst 10", m[1], m[2], m[3])
		}
	}
	want := []string{"lv_lg_i_tap0", "lv_lg_o_tap0", "lv_lg_i_tap_b_1", "lv_lg_o_tap_b_1", "lv_lg_routed"}
	for _, w := range want {
		if got[w] != 1 {
			t.Errorf("bridge table declares limit %s %d times, want once", w, got[w])
		}
	}
	if len(got) != len(want) {
		t.Errorf("bridge table limits %v, want exactly %v", got, want)
	}
	if n := len(decl.FindAllString(inet, -1)); n != 1 || !strings.Contains(inet, "    limit lv_lg_routed {") {
		t.Errorf("inet table declares %d limits, want lv_lg_routed alone:\n%s", n, inet)
	}
	// Every log line of a NIC side names that side's limit.
	use := regexp.MustCompile(`limit name "([^"]+)" log group 27 snaplen 96 prefix "lv-log (\S+) (\S+) `)
	uses := 0
	for _, m := range use.FindAllStringSubmatch(inet+nic, -1) {
		uses++
		dev, side := m[2], m[3]
		want := "lv_lg_routed"
		if dev != "-" {
			want = "lv_lg_" + side[:1] + "_" + sanitiseChain(dev)
		}
		if m[1] != want {
			t.Errorf("log line of %s %s uses limit %s, want %s", dev, side, m[1], want)
		}
	}
	if uses == 0 {
		t.Fatal("no log line rendered")
	}
	// Two logged rules on one side share one limit.
	if n := strings.Count(strings.Join(chainLines(t, nic, "nic_in_tap0"), "\n"), `limit name "lv_lg_i_tap0"`); n != 3 {
		t.Errorf("nic_in_tap0 has %d lines on lv_lg_i_tap0, want 3 (cluster c1, r-ssh, r-web)", n)
	}
}

// The tiers log in the inet table and in routed_to_port, as dev `-` under
// lv_lg_routed.
func TestLogRender_TiersLogRouted(t *testing.T) {
	p := logPlan(NICModeEnforce)
	p.ClusterRules = []Rule{{ID: "c1", Direction: Ingress, Proto: "tcp", PortRange: "25", Action: Reject, Log: true}}
	p.HostRules = []Rule{{ID: "h1", Direction: Egress, Proto: "udp", PortRange: "123", Action: Accept, Log: true}}
	out := mustRender(t, p)
	for _, c := range []struct{ chain, log, verdict string }{
		{"cluster_default", `tcp dport 25 limit name "lv_lg_routed" log group 27 snaplen 96 prefix "lv-log - - c1 drop"`, `tcp dport 25 reject`},
		{"host_overrides", `udp dport 123 limit name "lv_lg_routed" log group 27 snaplen 96 prefix "lv-log - - h1 accept"`, `udp dport 123 accept`},
	} {
		l := chainLines(t, out, c.chain)
		if len(l) != 2 || l[0] != c.log || l[1] != c.verdict {
			t.Errorf("%s:\n%s\nwant:\n%s\n%s", c.chain, strings.Join(l, "\n"), c.log, c.verdict)
		}
	}
	r := chainLines(t, out, "routed_to_port")
	want := []string{
		`tcp dport 25 limit name "lv_lg_routed" log group 27 snaplen 96 prefix "lv-log - - c1 drop"`,
		`tcp dport 25 drop`,
		`udp dport 123 limit name "lv_lg_routed" log group 27 snaplen 96 prefix "lv-log - - h1 accept"`,
		`udp dport 123 accept`,
		`drop`,
	}
	if strings.Join(r, "\n") != strings.Join(want, "\n") {
		t.Errorf("routed_to_port:\n%s\nwant:\n%s", strings.Join(r, "\n"), strings.Join(want, "\n"))
	}
}

// The default verdict is logged only when the policy is on (L-7).
//
// Mutation: log the default verdict whatever the policy says — red.
func TestLogRender_DefaultVerdictOnlyWhenPolicyOn(t *testing.T) {
	off := mustRender(t, logPlan(NICModeEnforce))
	if strings.Contains(off, " default ") {
		t.Fatalf("default verdict logged with the policy off:\n%s", off)
	}
	p := logPlan(NICModeEnforce)
	p.LogPolicy.Default = true
	p.LogPolicy.Rate, p.LogPolicy.Burst = 7, 3
	on := mustRender(t, p)
	for _, side := range []struct{ chain, limit, word string }{{"nic_in_tap0", "lv_lg_i_tap0", "in"}, {"nic_out_tap0", "lv_lg_o_tap0", "out"}} {
		l := chainLines(t, on, side.chain)
		n := len(l)
		want := `limit name "` + side.limit + `" log group 27 snaplen 96 prefix "lv-log tap0 ` + side.word + ` default drop"`
		if n < 2 || l[n-2] != want || l[n-1] != "drop" {
			t.Errorf("%s ends:\n%s\nwant:\n%s\ndrop", side.chain, strings.Join(l[max(0, n-2):], "\n"), want)
		}
	}
	if !strings.Contains(on, "    limit lv_lg_i_tap0 {\n        rate 7/second burst 3 packets\n    }") {
		t.Errorf("the policy's budget is not the limit's:\n%s", on)
	}
	// Without default deny the default verdict is accept.
	p.DefaultDeny = false
	l := chainLines(t, mustRender(t, p), "nic_in_tap0")
	if last := l[len(l)-1]; last != `limit name "lv_lg_i_tap0" log group 27 snaplen 96 prefix "lv-log tap0 in default accept"` {
		t.Errorf("nic_in_tap0 without default deny ends %q", last)
	}
	// The policy alone, with no logged rule, still declares the budget.
	p = logPlan(NICModeEnforce)
	p.LogPolicy.Default = true
	for i := range p.SecurityGroups[0].Rules {
		p.SecurityGroups[0].Rules[i].Log = false
	}
	if out := mustRender(t, p); !strings.Contains(out, "    limit lv_lg_i_tap0 {") || strings.Contains(out, "lv_lg_routed") {
		t.Errorf("policy-only plan: want the NIC limits and no routed one:\n%s", out)
	}
}

// The prefix is at most 127 bytes (the kernel's NF_LOG_PREFIXLEN less its
// NUL), and a rule id outside [0-9a-z-]{1,32} prints as `rule`.
//
// Mutation: print the id as stored — red (the long and unsafe ids).
func TestLogRender_PrefixBounded(t *testing.T) {
	dev := "tap-0123456789a" // 15 bytes, the longest interface name
	long := strings.Repeat("z", 32)
	p := Plan{
		DefaultDeny: true,
		NICMode:     NICModeObserve,
		LogPolicy:   LogPolicy{Available: true, Group: 65535, Default: true},
		NICs: []NICBinding{{NICDev: dev, ExtraRules: []Rule{
			{ID: long, Direction: Ingress, Proto: "tcp", PortRange: "1", Action: Drop, Log: true},
			{ID: long + "z", Direction: Ingress, Proto: "tcp", PortRange: "2", Action: Drop, Log: true},
			{ID: `x" drop`, Direction: Ingress, Proto: "tcp", PortRange: "3", Action: Drop, Log: true},
			{ID: "UPPER", Direction: Ingress, Proto: "tcp", PortRange: "4", Action: Drop, Log: true},
			{ID: "", Direction: Ingress, Proto: "tcp", PortRange: "5", Action: Drop, Log: true},
		}}},
	}
	out := mustRender(t, p)
	prefixes := regexp.MustCompile(`prefix "([^"]*)"`).FindAllStringSubmatch(out, -1)
	if len(prefixes) != 7 { // five rules, and each side's default verdict
		t.Fatalf("want 7 prefixes, got %d:\n%s", len(prefixes), out)
	}
	ok := regexp.MustCompile(`^lv-log \S+ (in|out|-) ([0-9a-z-]{1,32}|default) (accept|drop|would-drop)$`)
	for _, m := range prefixes {
		if len(m[1]) > 127 {
			t.Errorf("prefix of %d bytes: %q", len(m[1]), m[1])
		}
		if !ok.MatchString(m[1]) {
			t.Errorf("prefix %q is not in the documented format", m[1])
		}
	}
	var ids []string
	for _, m := range prefixes {
		if f := strings.Fields(m[1]); f[3] != "default" {
			ids = append(ids, f[3])
		}
	}
	if want := []string{long, "rule", "rule", "rule", "rule"}; strings.Join(ids, " ") != strings.Join(want, " ") {
		t.Errorf("rule ids print as %q, want %q", ids, want)
	}
	// A rule whose id is `default` cannot pass for the default verdict.
	if got := logRuleID("default"); got != "rule" {
		t.Errorf("id default prints as %q", got)
	}
	// The longest possible prefix fits.
	if n := len(logPrefix(dev, "out", long, "would-drop")); n > 127 {
		t.Errorf("longest prefix is %d bytes", n)
	}
}

// Observe mode logs `would-drop` and still renders the would-drop counter.
//
// Mutation: drop the observe counter when a rule logs — red.
func TestLogRender_ObserveLogsWouldDropAndKeepsCounter(t *testing.T) {
	p := logPlan(NICModeObserve)
	p.LogPolicy.Default = true
	l := chainLines(t, mustRender(t, p), "nic_in_tap0")
	want := []string{
		`oifname tap0 tcp dport 22 limit name "lv_lg_i_tap0" log group 27 snaplen 96 prefix "lv-log tap0 in r-ssh would-drop"`,
		`oifname tap0 tcp dport 22 counter return comment "lv-wd tap0 in sg:web#0"`,
		`oifname tap0 tcp dport 80 limit name "lv_lg_i_tap0" log group 27 snaplen 96 prefix "lv-log tap0 in r-web accept"`,
		`oifname tap0 tcp dport 80 accept`,
		`oifname tap0 tcp dport 443 accept`,
		`limit name "lv_lg_i_tap0" log group 27 snaplen 96 prefix "lv-log tap0 in default would-drop"`,
		`counter comment "lv-wd tap0 in default"`,
	}
	if strings.Join(l, "\n") != strings.Join(want, "\n") {
		t.Fatalf("nic_in_tap0:\n%s\nwant:\n%s", strings.Join(l, "\n"), strings.Join(want, "\n"))
	}
	// The tally still reads the counters, and no log line as one.
	got := parseWouldDropsForTest(t, mustRender(t, p))
	if got["lv-wd tap0 in sg:web#0"] != 1 || got["lv-wd tap0 in default"] != 1 {
		t.Errorf("would-drop counters seen: %v", got)
	}
}

// parseWouldDropsForTest counts the lv-wd counters a script carries.
func parseWouldDropsForTest(t *testing.T, script string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, m := range regexp.MustCompile(`counter (?:return )?comment "(lv-wd [^"]*)"`).FindAllStringSubmatch(script, -1) {
		out[m[1]]++
	}
	return out
}

// With logging unavailable on the host (the zero value, or a kernel that
// refused the probe), a logged rule renders exactly as an unlogged one.
func TestLogRender_UnavailableRendersNoLog(t *testing.T) {
	for _, mode := range []string{NICModeEnforce, NICModeObserve, NICModeGuardsOnly} {
		p := logPlan(mode)
		p.ClusterRules = []Rule{{ID: "c1", Direction: Ingress, Proto: "tcp", PortRange: "25", Action: Drop, Log: true}}
		p.LogPolicy = LogPolicy{Default: true, Group: 27}
		plain := p
		plain.LogPolicy = LogPolicy{}
		plain.ClusterRules = []Rule{{ID: "c1", Direction: Ingress, Proto: "tcp", PortRange: "25", Action: Drop}}
		plain.SecurityGroups = []SecurityGroup{{Name: "web", Rules: nil}}
		for _, r := range p.SecurityGroups[0].Rules {
			r.Log = false
			plain.SecurityGroups[0].Rules = append(plain.SecurityGroups[0].Rules, r)
		}
		if got, want := mustRender(t, p), mustRender(t, plain); got != want {
			t.Errorf("%s: logging unavailable, yet the ruleset changed:\n%s", mode, got)
		}
	}
}

// A budget outside 1..max renders the default budget: the renderer never
// writes a limit nft refuses.
func TestLogRender_BudgetOutOfRangeIsDefault(t *testing.T) {
	for _, c := range []struct{ rate, burst, wantR, wantB int }{
		{0, 0, DefaultLogRate, DefaultLogBurst},
		{-1, -1, DefaultLogRate, DefaultLogBurst},
		{MaxLogRate + 1, MaxLogBurst + 1, DefaultLogRate, DefaultLogBurst},
		{MaxLogRate, MaxLogBurst, MaxLogRate, MaxLogBurst},
		{1, 1, 1, 1},
	} {
		p := logPlan(NICModeEnforce)
		p.LogPolicy.Rate, p.LogPolicy.Burst = c.rate, c.burst
		want := "    limit lv_lg_i_tap0 {\n        rate " + strconv.Itoa(c.wantR) + "/second burst " + strconv.Itoa(c.wantB) + " packets\n    }"
		if out := mustRender(t, p); !strings.Contains(out, want) {
			t.Errorf("rate %d burst %d: want %q in:\n%s", c.rate, c.burst, want, out)
		}
	}
}

// The guard catches a plain `log` (the kernel log), and passes NFLOG.
//
// Mutation: render `log prefix` without `group` — the golden and fuzz guards
// go red (this pins the guard itself).
func TestLogRender_GuardCatchesPlainLog(t *testing.T) {
	ft := &fakeT{}
	assertEveryLogHasGroup(ft, "        tcp dport 22 log prefix \"x\" drop\n")
	if !ft.failed {
		t.Error("guard passed a plain log")
	}
	ft = &fakeT{}
	assertEveryLogHasGroup(ft, "        tcp dport 22 limit name \"a\" log group 27 snaplen 96 prefix \"lv-log a in log drop\"\n        accept comment \"log\"\n")
	if ft.failed {
		t.Error("guard refused an NFLOG line")
	}
	assertEveryLogHasGroup(t, mustRender(t, logPlan(NICModeEnforce)))
}

// The declaration guard catches an undeclared and a doubly declared limit,
// and passes a declared one.
//
// Mutation: drop the `p.LogPolicy.Default ||` term in renderNICLogLimits —
// the fuzz seed (1,12,1), which logs only the default verdict, goes red
// through the guard.
func TestLogRender_GuardCatchesUndeclaredLimit(t *testing.T) {
	body := "    chain c {\n        limit name \"a\" log group 27 snaplen 96 prefix \"p\"\n    }\n"
	use := "table bridge x {\n" + body + "}\n"
	decl := "    limit a {\n        rate 1/second burst 1 packets\n    }\n"
	ft := &fakeT{}
	assertLimitsDeclared(ft, use)
	if !ft.failed {
		t.Error("guard passed an undeclared limit")
	}
	ft = &fakeT{}
	assertLimitsDeclared(ft, "table bridge x {\n"+decl+decl+"}\n")
	if !ft.failed {
		t.Error("guard passed a limit declared twice")
	}
	ft = &fakeT{}
	assertLimitsDeclared(ft, "table bridge x {\n"+decl+"}\n"+"table inet y {\n"+body+"}\n")
	if !ft.failed {
		t.Error("guard accepted a limit declared in another table")
	}
	ft = &fakeT{}
	assertLimitsDeclared(ft, "table bridge x {\n"+decl+body+"}\n")
	if ft.failed {
		t.Error("guard refused a declared limit")
	}
	assertLimitsDeclared(t, mustRender(t, logPlan(NICModeEnforce)))
}

type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper()               {}
func (f *fakeT) Errorf(string, ...any) { f.failed = true }

// Two devices whose names sanitise alike share one limit, declared once: a
// table declaring one name twice is not the renderer's to risk.
//
// Mutation: declare per device, unconditionally — red.
func TestLogRender_LimitDeclaredOncePerName(t *testing.T) {
	p := logPlan(NICModeEnforce)
	p.NICs = []NICBinding{
		{NICDev: "tap-a", SecurityGroups: []string{"web"}},
		{NICDev: "tap_a", SecurityGroups: []string{"web"}},
		{NICDev: "tap.a", SecurityGroups: []string{"web"}},
	}
	out := mustRender(t, p)
	for _, name := range []string{"lv_lg_i_tap_a", "lv_lg_o_tap_a"} {
		if n := strings.Count(out, "    limit "+name+" {"); n != 1 {
			t.Errorf("limit %s declared %d times, want once", name, n)
		}
	}
}
