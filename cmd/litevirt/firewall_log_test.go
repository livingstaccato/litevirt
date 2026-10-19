package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// logSpy is a macroSpy whose daemon answers GetFirewallLogPolicy with probeErr
// (nil: it answers) and records SetFirewallLogPolicy calls.
type logSpy struct {
	macroSpy
	probeErr error
	probes   int
	sets     []*pb.SetFirewallLogPolicyRequest
	policies []*pb.FirewallLogPolicy
}

func (l *logSpy) GetFirewallLogPolicy(context.Context, *pb.GetFirewallLogPolicyRequest, ...grpc.CallOption) (*pb.GetFirewallLogPolicyResponse, error) {
	l.probes++
	if l.probeErr != nil {
		return nil, l.probeErr
	}
	return &pb.GetFirewallLogPolicyResponse{Policies: l.policies}, nil
}

func (l *logSpy) SetFirewallLogPolicy(_ context.Context, in *pb.SetFirewallLogPolicyRequest, _ ...grpc.CallOption) (*pb.FirewallLogPolicy, error) {
	l.sets = append(l.sets, in)
	return &pb.FirewallLogPolicy{Scope: "cluster", DefaultPolicy: in.GetMode() == "on", Rate: 5, Burst: 10}, nil
}

// runMacroCLIWith runs an lv command line (from the root) against spy.
func runMacroCLIWith(t *testing.T, spy *logSpy, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SilenceUsage = true
	root.SilenceErrors = true
	var err error
	out := captureStdout(t, func() { err = root.ExecuteContext(context.Background()) })
	return out, err
}

// C3 (I-1): --log is refused before any write when the entry daemon answers
// GetFirewallLogPolicy with Unimplemented (it predates logging); with a daemon
// that answers, the rule is sent with log set and the plain action; on every
// rule-add command, macros included.
//
// Mutation: skip the probe — the rule is written through an old daemon,
// which drops the field, red.
func TestRuleAddLog_ProbesTheDaemon(t *testing.T) {
	for _, tc := range []struct {
		what string
		args []string
	}{
		{"sg", []string{"sg", "rule-add", "web", "--proto", "tcp", "--port", "22", "--action", "drop", "--log"}},
		{"sg macro", []string{"sg", "rule-add", "web", "--macro", "SSH", "--action", "drop", "--log"}},
		{"cluster", []string{"firewall", "cluster-rule", "add", "--proto", "tcp", "--port", "22", "--action", "drop", "--log"}},
		{"cluster macro", []string{"firewall", "cluster-rule", "add", "--macro", "DNS", "--action", "drop", "--log"}},
		{"host", []string{"firewall", "host-rule", "add", "--host", "h1", "--proto", "tcp", "--port", "22", "--action", "drop", "--log"}},
	} {
		old := &logSpy{probeErr: status.Error(codes.Unimplemented, "unknown method")}
		_, err := runMacroCLIWith(t, old, tc.args...)
		if err == nil || !strings.Contains(err.Error(), "older than this lv") {
			t.Errorf("%s against an old daemon: %v, want the upgrade refusal", tc.what, err)
		}
		if old.adds != 0 {
			t.Errorf("%s against an old daemon wrote %d rule(s)", tc.what, old.adds)
		}

		cur := &logSpy{}
		if _, err := runMacroCLIWith(t, cur, tc.args...); err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		var sent []struct {
			action string
			log    bool
		}
		for _, r := range cur.sgAdds {
			sent = append(sent, struct {
				action string
				log    bool
			}{r.GetAction(), r.GetLog()})
		}
		for _, r := range append(cur.clusterAdds, cur.hostAdds...) {
			sent = append(sent, struct {
				action string
				log    bool
			}{r.GetAction(), r.GetLog()})
		}
		if len(sent) == 0 || cur.probes != 1 {
			t.Errorf("%s: %d rule(s) sent after %d probe(s)", tc.what, len(sent), cur.probes)
		}
		for _, r := range sent {
			if r.action != "drop" || !r.log {
				t.Errorf("%s sent %+v, want drop with log", tc.what, r)
			}
		}
	}
	// Without --log no probe is made.
	cur := &logSpy{probeErr: status.Error(codes.Unimplemented, "unknown method")}
	if _, err := runMacroCLIWith(t, cur, "sg", "rule-add", "web", "--proto", "tcp", "--port", "22"); err != nil || cur.probes != 0 {
		t.Errorf("an unlogged rule: %v after %d probe(s), want written with none", err, cur.probes)
	}
}

// C3 (I-1): an --action with "+" is refused before any call; logging is asked
// with --log.
//
// Mutation: drop the refusal — the action is sent, red.
func TestRuleAdd_PlusActionRefused(t *testing.T) {
	for _, args := range [][]string{
		{"sg", "rule-add", "web", "--action", "drop+log"},
		{"firewall", "cluster-rule", "add", "--action", "drop+log"},
		{"firewall", "host-rule", "add", "--host", "h1", "--action", "accept+log"},
		{"sg", "rule-add", "web", "--macro", "SSH", "--action", "drop+log"},
	} {
		spy := &logSpy{}
		_, err := runMacroCLIWith(t, spy, args...)
		if err == nil || !strings.Contains(err.Error(), "--log") {
			t.Errorf("%v: %v, want a refusal naming --log", args, err)
		}
		if spy.adds != 0 || spy.probes != 0 {
			t.Errorf("%v: %d write(s), %d probe(s) after a refusal", args, spy.adds, spy.probes)
		}
	}
}

// C3: log-policy on/off/inherit send the scope, mode and budget; inherit
// needs --scope; status prints each scope.
//
// Mutation: send on as off — red; let inherit through without a scope — red.
func TestFirewallLogPolicyCLI(t *testing.T) {
	spy := &logSpy{}
	if _, err := runMacroCLIWith(t, spy, "firewall", "log-policy", "on", "--rate", "7", "--burst", "20"); err != nil {
		t.Fatal(err)
	}
	if _, err := runMacroCLIWith(t, spy, "firewall", "log-policy", "off", "--scope", "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := runMacroCLIWith(t, spy, "firewall", "log-policy", "inherit", "--scope", "h1"); err != nil {
		t.Fatal(err)
	}
	if len(spy.sets) != 3 {
		t.Fatalf("sets = %v", spy.sets)
	}
	if s := spy.sets[0]; s.GetMode() != "on" || s.GetScope() != "" || s.GetRate() != 7 || s.GetBurst() != 20 {
		t.Errorf("on = %+v", s)
	}
	if s := spy.sets[1]; s.GetMode() != "off" || s.GetScope() != "h1" || s.GetRate() != 0 {
		t.Errorf("off = %+v", s)
	}
	if s := spy.sets[2]; s.GetMode() != "inherit" || s.GetScope() != "h1" {
		t.Errorf("inherit = %+v", s)
	}
	if _, err := runMacroCLIWith(t, spy, "firewall", "log-policy", "inherit"); err == nil || len(spy.sets) != 3 {
		t.Errorf("inherit with no scope: %v, %d set(s)", err, len(spy.sets))
	}
	spy.policies = []*pb.FirewallLogPolicy{
		{Scope: "cluster", DefaultPolicy: true, Rate: 7, Burst: 20, SetBy: "alice"},
		{Scope: "h1", Rate: 5, Burst: 10, Inherited: true},
	}
	out, err := runMacroCLIWith(t, spy, "firewall", "log-policy", "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cluster", "on", "7", "20", "alice", "h1", "inherited"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
}

// logListSpy answers ListFirewallLog from a script of replies.
type logListSpy struct {
	logSpy
	replies []*pb.ListFirewallLogResponse
	got     []*pb.ListFirewallLogRequest
	onCall  func(n int)
}

func (l *logListSpy) ListFirewallLog(_ context.Context, in *pb.ListFirewallLogRequest, _ ...grpc.CallOption) (*pb.ListFirewallLogResponse, error) {
	l.got = append(l.got, in)
	n := len(l.got)
	if l.onCall != nil {
		defer l.onCall(n)
	}
	if n <= len(l.replies) {
		return l.replies[n-1], nil
	}
	return &pb.ListFirewallLogResponse{}, nil
}

func runLogListCLI(t *testing.T, ctx context.Context, spy *logListSpy, args ...string) (string, error) {
	out, _, err := runLogListCLI2(t, ctx, spy, args...)
	return out, err
}

func runLogListCLI2(t *testing.T, ctx context.Context, spy *logListSpy, args ...string) (string, string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	var stderr strings.Builder
	root.SetErr(&stderr)
	var err error
	out := captureStdout(t, func() { err = root.ExecuteContext(ctx) })
	return out, stderr.String(), err
}

// C5: lv firewall log prints the columns, asks with --host, --workload,
// --since (as a time) and --limit, and names a host that did not answer;
// --follow polls from each host's newest sequence.
//
// Mutations: --follow resends no cursor — the second request has no
// after_seq, red; drop the host errors — red.
func TestFirewallLogCLI(t *testing.T) {
	e := func(host string, seq uint64, wl string) *pb.FirewallLogEntry {
		return &pb.FirewallLogEntry{Host: host, Seq: seq, Time: "2026-10-18T12:00:01Z", Workload: wl, Device: "lvt0", Side: "in",
			RuleId: "r1", Verdict: "drop", Proto: "tcp", Src: "10.0.0.9", Sport: 40000, Dst: "10.0.0.1", Dport: 22, Length: 60}
	}
	spy := &logListSpy{replies: []*pb.ListFirewallLogResponse{
		{Entries: []*pb.FirewallLogEntry{e("a", 4, "web-1"), e("b", 9, "db-1")}, Errors: map[string]string{"c": "connection refused"}},
	}}
	before := time.Now()
	out, stderr, err := runLogListCLI2(t, context.Background(), spy, "firewall", "log", "--workload", "web-1", "--since", "15m", "--limit", "50", "--host", "a")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TIME", "HOST", "WORKLOAD", "DEVICE", "SIDE", "RULE", "VERDICT", "PROTO", "SRC", "DST", "LEN",
		"web-1", "10.0.0.9:40000", "10.0.0.1:22", "drop", "60"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(stderr, "c: connection refused") {
		t.Errorf("stderr does not name the host that failed:\n%s", stderr)
	}
	r := spy.got[0]
	since, perr := time.Parse(time.RFC3339, r.GetSince())
	if r.GetHost() != "a" || r.GetWorkload() != "web-1" || r.GetLimit() != 50 || perr != nil ||
		since.After(before.Add(-14*time.Minute)) || since.Before(before.Add(-16*time.Minute)) {
		t.Errorf("request = %+v, want host a, web-1, limit 50, since 15 minutes ago", r)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orig := logFollowInterval
	logFollowInterval = time.Millisecond
	t.Cleanup(func() { logFollowInterval = orig })
	spy = &logListSpy{replies: []*pb.ListFirewallLogResponse{
		{Entries: []*pb.FirewallLogEntry{e("a", 4, "web-1"), e("b", 9, "db-1")}},
		{Entries: []*pb.FirewallLogEntry{e("a", 5, "web-1")}},
	}, onCall: func(n int) {
		if n == 3 {
			cancel()
		}
	}}
	if _, err := runLogListCLI(t, ctx, spy, "firewall", "log", "--follow"); err != nil {
		t.Fatal(err)
	}
	if len(spy.got) < 3 {
		t.Fatalf("follow made %d request(s)", len(spy.got))
	}
	if c := spy.got[1].GetAfterSeq(); c["a"] != 4 || c["b"] != 9 {
		t.Errorf("second request cursor = %v, want a:4 b:9", c)
	}
	if c := spy.got[2].GetAfterSeq(); c["a"] != 5 || c["b"] != 9 {
		t.Errorf("third request cursor = %v, want a:5 b:9", c)
	}
}

// C7 (I-1): lv compose up with a rule holding `log: true` asks the daemon
// first and refuses one that predates logging before anything is sent; a
// gitops deploy of such a file likewise.
//
// Mutation: skip the compose probe — DeployStack is reached, red.
func TestComposeUpLog_ProbesTheDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := "name: s\nsecurity-groups:\n  web:\n    rules:\n      - { direction: ingress, proto: tcp, port: \"22\", action: drop, log: true }\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := &logSpy{probeErr: status.Error(codes.Unimplemented, "unknown method")}
	_, err := runMacroCLIWith(t, old, "compose", "up", "-f", path, "--yes")
	if err == nil || !strings.Contains(err.Error(), "older than this lv") || old.probes != 1 {
		t.Errorf("compose up against an old daemon: %v after %d probe(s), want the upgrade refusal", err, old.probes)
	}
	// gitops: a file lv parses is judged by its rules; one it does not, by
	// its decoded YAML keys; one that is not YAML is probed.
	for _, c := range []struct {
		name, body string
	}{
		{"parses, logs", body},
		{"does not parse, a LOG key", "name: s\nbogus: 1\nsecurity-groups:\n  web:\n    rules:\n      - { \"LOG\": true }\n"},
		{"does not parse, not YAML", "name: s\nsecurity-groups: [unclosed\n"},
	} {
		old = &logSpy{probeErr: status.Error(codes.Unimplemented, "unknown method")}
		err := gitopsDeploy(context.Background(), &tagAnswering{old}, path, c.body)
		if err == nil || !strings.Contains(err.Error(), "older than this lv") || old.probes != 1 {
			t.Errorf("gitops %s against an old daemon: %v after %d probe(s), want the upgrade refusal", c.name, err, old.probes)
		}
	}
	if hit, ok := gitopsYAMLMayHoldLog("name: s\nbogus: 1\n"); !ok || hit {
		t.Errorf("a file with no log key = %v, %v; want no probe", hit, ok)
	}
}

// tagAnswering is a logSpy whose daemon knows tag groups.
type tagAnswering struct{ *logSpy }

func (t *tagAnswering) ListFirewallTagGroups(context.Context, *pb.ListFirewallTagGroupsRequest, ...grpc.CallOption) (*pb.ListFirewallTagGroupsResponse, error) {
	return &pb.ListFirewallTagGroupsResponse{}, nil
}

// Round 1 m-8: status marks a row the daemon could not read (rate and burst
// 0, which no readable row has) as unreadable, with what it is read as.
//
// Mutation: print the row as an ordinary off row — red.
func TestFirewallLogPolicyCLI_UnreadableRow(t *testing.T) {
	spy := &logSpy{policies: []*pb.FirewallLogPolicy{
		{Scope: "cluster", DefaultPolicy: true, Rate: 7, Burst: 20},
		{Scope: "h1"},
	}}
	out, err := runMacroCLIWith(t, spy, "firewall", "log-policy", "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "unreadable") || !strings.Contains(out, "off at 5/10") {
		t.Errorf("status does not mark h1 unreadable:\n%s", out)
	}
}

// Round 1 m-4: a record's strings are printed with control characters
// escaped: a peer's answer cannot drive the terminal.
//
// Mutation: print raw — red.
func TestFirewallLogCLI_EscapesControlCharacters(t *testing.T) {
	spy := &logListSpy{replies: []*pb.ListFirewallLogResponse{{
		Entries: []*pb.FirewallLogEntry{{Host: "a\x1b[2J", Seq: 1, Time: "t", Workload: "w\r", Device: "d", Side: "in", RuleId: "r", Verdict: "drop"}},
		Errors:  map[string]string{"b\x1b]0;x\x07": "boom\x1b[1m"},
	}}}
	out, stderr, err := runLogListCLI2(t, context.Background(), spy, "firewall", "log")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out+stderr, "\x1b\r\x07") || !strings.Contains(out, `a\x1b[2J`) {
		t.Errorf("control characters reached the terminal:\n%q\n%q", out, stderr)
	}
}

// Round 2 m-2: a host inheriting an unreadable cluster row (0/0 inherited) is
// marked unreadable too, with what it is read as.
//
// Mutation: keep the !Inherited guard — the host prints "off 0 0", red.
func TestFirewallLogPolicyCLI_InheritedUnreadable(t *testing.T) {
	spy := &logSpy{policies: []*pb.FirewallLogPolicy{{Scope: "cluster"}, {Scope: "h1", Inherited: true}}}
	out, err := runMacroCLIWith(t, spy, "firewall", "log-policy", "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "unreadable (inherited; read as off at 5/10)") {
		t.Errorf("status does not mark the inheriting host:\n%s", out)
	}
}

// Round 2 m-4: format characters (bidi overrides and isolates, category Cf)
// are escaped as control characters are, so a peer's text cannot reorder
// what the terminal shows.
//
// Mutation: escape only unicode.IsControl — red.
func TestTermSafe_EscapesFormatCharacters(t *testing.T) {
	got := termSafe("a\u202eb\u2066c\u200bd")
	if strings.ContainsAny(got, "\u202e\u2066\u200b") || got != `a\u202eb\u2066c\u200bd` {
		t.Errorf("termSafe = %q", got)
	}
}
