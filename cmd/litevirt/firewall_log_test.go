package main

import (
	"context"
	"io"
	"strings"
	"testing"

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
