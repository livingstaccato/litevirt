package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// tagProbeSpy is macroSpy that also answers the tag-group probe (probeErr)
// and records DeployStack and the tag-group calls.
type tagProbeSpy struct {
	macroSpy
	probeErr error
	probes   int
	deploys  int
	groups   []*pb.FirewallTagGroup
	listReq  *pb.ListFirewallTagGroupsRequest
	setReq   *pb.SetFirewallTagGroupRequest
}

func (s *tagProbeSpy) SetFirewallTagGroup(_ context.Context, in *pb.SetFirewallTagGroupRequest, _ ...grpc.CallOption) (*pb.FirewallTagGroup, error) {
	s.setReq = in
	return in.GetGroup(), nil
}

func (s *tagProbeSpy) ListFirewallTagGroups(_ context.Context, in *pb.ListFirewallTagGroupsRequest, _ ...grpc.CallOption) (*pb.ListFirewallTagGroupsResponse, error) {
	s.probes++
	s.listReq = in
	if s.probeErr != nil {
		return nil, s.probeErr
	}
	return &pb.ListFirewallTagGroupsResponse{Groups: s.groups}, nil
}

func (s *tagProbeSpy) DeployStack(context.Context, *pb.DeployStackRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeployProgress], error) {
	s.deploys++
	return nil, errors.New("deploy reached")
}

func runTagProbeCLI(t *testing.T, spy *tagProbeSpy, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var err error
	out := captureStdout(t, func() { err = cmd.ExecuteContext(context.Background()) })
	return out, err
}

// Before it sends a tag:<group> cidr, lv asks the daemon whether it knows tag
// groups; an older daemon answers Unimplemented and nothing is written (spec
// §4.8, I-1). A cidr that is no tag reference asks nothing, so an older
// daemon still takes it; a daemon that answers gets the write.
//
// Mutation: skip the probe in any of the paths — that path writes: red;
// probe on every cidr — the plain case probes: red.
func TestTagCIDR_ProbeRefusesAnOlderDaemon(t *testing.T) {
	unimpl := status.Error(codes.Unimplemented, "unknown method ListFirewallTagGroups")
	paths := map[string]func(cidr string) (*cobra.Command, []string){
		"cluster-rule add": func(cidr string) (*cobra.Command, []string) {
			return newFirewallClusterRuleCmd(), []string{"add", "--proto", "tcp", "--port", "5432", "--cidr", cidr}
		},
		"cluster-rule add --macro": func(cidr string) (*cobra.Command, []string) {
			return newFirewallClusterRuleCmd(), []string{"add", "--macro", "ssh", "--cidr", cidr}
		},
		"host-rule add": func(cidr string) (*cobra.Command, []string) {
			return newFirewallHostRuleCmd(), []string{"add", "--host", "node-1", "--proto", "tcp", "--port", "5432", "--cidr", cidr}
		},
		"host-rule add --macro": func(cidr string) (*cobra.Command, []string) {
			return newFirewallHostRuleCmd(), []string{"add", "--host", "node-1", "--macro", "ssh", "--cidr", cidr}
		},
		"sg rule-add": func(cidr string) (*cobra.Command, []string) {
			return newSGRuleAddCmd(), []string{"web", "--proto", "tcp", "--port", "5432", "--cidr", cidr}
		},
		"sg rule-add --macro": func(cidr string) (*cobra.Command, []string) {
			return newSGRuleAddCmd(), []string{"web", "--macro", "ssh", "--cidr", cidr}
		},
	}
	for name, mk := range paths {
		t.Run(name, func(t *testing.T) {
			spy := &tagProbeSpy{probeErr: unimpl}
			cmd, args := mk("tag:web")
			_, err := runTagProbeCLI(t, spy, cmd, args...)
			if err == nil || !strings.Contains(err.Error(), "upgrade litevirtd") || spy.probes != 1 || spy.adds != 0 {
				t.Fatalf("tag:web against an older daemon: err=%v probes=%d writes=%d, want the upgrade refusal and no write", err, spy.probes, spy.adds)
			}

			spy = &tagProbeSpy{probeErr: unimpl}
			cmd, args = mk("10.0.0.0/8")
			if _, err := runTagProbeCLI(t, spy, cmd, args...); err != nil || spy.probes != 0 || spy.adds != 1 {
				t.Fatalf("a plain cidr against an older daemon: err=%v probes=%d writes=%d, want no probe and the write", err, spy.probes, spy.adds)
			}

			spy = &tagProbeSpy{}
			cmd, args = mk("tag:web")
			if _, err := runTagProbeCLI(t, spy, cmd, args...); err != nil || spy.probes != 1 || spy.adds != 1 {
				t.Fatalf("tag:web against a daemon that knows tag groups: err=%v probes=%d writes=%d", err, spy.probes, spy.adds)
			}
		})
	}
}

// `lv compose up` probes before it sends compose holding a tag: cidr, in a
// security-group rule or a cluster rule; nothing is deployed against an
// older daemon.
//
// Mutation: skip the probe — DeployStack is reached: red; read only the
// security groups — the cluster-rule case is red.
func TestComposeUp_TagCIDRProbesTheDaemon(t *testing.T) {
	write := func(t *testing.T, sgCIDR, clusterCIDR string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "litevirt-compose.yaml")
		body := `name: dd
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "443", cidr: "` + sgCIDR + `", action: accept}
firewall:
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "` + clusterCIDR + `", action: accept}
`
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	unimpl := status.Error(codes.Unimplemented, "unknown method")
	for _, c := range []struct{ name, sg, cluster string }{
		{"in a security-group rule", "tag:web", "10.0.0.0/8"},
		{"in a cluster rule", "10.0.0.0/8", "tag:web"},
	} {
		t.Run(c.name, func(t *testing.T) {
			spy := &tagProbeSpy{probeErr: unimpl}
			_, err := runTagProbeCLI(t, spy, newUpCmd(), "-f", write(t, c.sg, c.cluster), "-y")
			if err == nil || !strings.Contains(err.Error(), "upgrade litevirtd") || spy.deploys != 0 {
				t.Fatalf("compose with tag: against an older daemon: err=%v deploys=%d", err, spy.deploys)
			}
		})
	}
	spy := &tagProbeSpy{probeErr: unimpl}
	_, err := runTagProbeCLI(t, spy, newUpCmd(), "-f", write(t, "10.1.0.0/16", "10.0.0.0/8"), "-y")
	if spy.probes != 0 || spy.deploys != 1 || err == nil || !strings.Contains(err.Error(), "deploy reached") {
		t.Fatalf("compose with no tag: err=%v probes=%d deploys=%d, want no probe and the deploy", err, spy.probes, spy.deploys)
	}
}

// `tag-group ls --members` lists each member's addresses, or that it has no
// allocated address, and asks the daemon for members only then.
//
// Mutation: print the addresses only (the note is lost) — red; never ask for
// members — red.
func TestTagGroupLs_Members(t *testing.T) {
	spy := &tagProbeSpy{groups: []*pb.FirewallTagGroup{{
		Name: "web", Match: map[string]string{"role": "web"}, SecurityGroups: []string{"web-in"},
		Members: []*pb.FirewallTagMember{
			{Kind: "vm", Workload: "web-1", Addresses: []string{"10.0.0.5", "fd00::5"}},
			{Kind: "container", Workload: "web-2", Host: "node-2", AddressNote: "no allocated address"},
		},
	}}}
	out, err := runTagProbeCLI(t, spy, newFirewallTagGroupCmd(), "ls", "--members")
	if err != nil {
		t.Fatal(err)
	}
	if !spy.listReq.GetMembers() {
		t.Fatal("ls --members did not ask for members")
	}
	for _, want := range []string{"match role=web; binds web-in on every network", "web-1", "10.0.0.5,fd00::5", "node-2", "no allocated address"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls --members output lacks %q:\n%s", want, out)
		}
	}

	spy = &tagProbeSpy{probeErr: status.Error(codes.Unimplemented, "unknown method")}
	if _, err := runTagProbeCLI(t, spy, newFirewallTagGroupCmd(), "ls"); err == nil || !strings.Contains(err.Error(), "upgrade litevirtd") {
		t.Fatalf("ls against an older daemon: %v", err)
	}
}

// The probe lets a write through only on an answer that proves the daemon
// has the method; any error other than a refusal of the caller proves
// nothing, so it refuses (review m-1).
//
// Mutation: go ahead on any error but Unimplemented — the Unavailable case
// writes: red; refuse PermissionDenied — red.
func TestTagCIDR_ProbeFailsClosed(t *testing.T) {
	for _, c := range []struct {
		code  codes.Code
		write bool
	}{
		{codes.Unavailable, false}, {codes.DeadlineExceeded, false}, {codes.Internal, false},
		{codes.PermissionDenied, true}, {codes.Unauthenticated, true},
	} {
		spy := &tagProbeSpy{probeErr: status.Error(c.code, "x")}
		_, err := runTagProbeCLI(t, spy, newFirewallClusterRuleCmd(), "add", "--cidr", "tag:web")
		if (spy.adds == 1) != c.write || (err == nil) != c.write {
			t.Errorf("probe answered %v: err=%v writes=%d, want write=%v", c.code, err, spy.adds, c.write)
		}
		if !c.write && (err == nil || !strings.Contains(err.Error(), "could not confirm")) {
			t.Errorf("probe answered %v: %v, want the could-not-confirm refusal", c.code, err)
		}
	}
}

// --match k= and a key matched twice are refused: either would widen the
// selector the operator wrote (review m-2). A bare key means "has the key".
//
// Mutations: accept an empty value — red; let the last of two values win —
// red.
func TestTagGroupSet_MatchRefusesEmptyAndRepeated(t *testing.T) {
	for _, args := range [][]string{
		{"set", "web", "--match", "role="},
		{"set", "web", "--match", "role=web", "--match", "role=db"},
		{"set", "web", "--match", "role", "--match", "role=db"},
	} {
		spy := &tagProbeSpy{}
		if _, err := runTagProbeCLI(t, spy, newFirewallTagGroupCmd(), args...); err == nil || !strings.Contains(err.Error(), "--match") {
			t.Errorf("%v: %v, want a --match refusal", args, err)
		}
		if spy.setReq != nil {
			t.Errorf("%v: sent %v", args, spy.setReq)
		}
	}
	spy := &tagProbeSpy{}
	if _, err := runTagProbeCLI(t, spy, newFirewallTagGroupCmd(), "set", "web", "--match", "role=web", "--match", "env"); err != nil {
		t.Fatal(err)
	}
	if m := spy.setReq.GetGroup().GetMatch(); len(m) != 2 || m["role"] != "web" || m["env"] != "" {
		t.Fatalf("match sent = %v", m)
	}
}

// gitops sends no compose that holds, or may hold, a tag: cidr to a daemon
// that answers Unimplemented: judged by its rules when lv parses it, and
// probed whatever its text holds when lv does not, since an older daemon
// validates less than lv (review I-1) and an escaped YAML scalar
// ("\x74ag:web") spells tag: with no literal tag: in the file (D6 re-review
// n-1). A file that parses with no tag: deploys unprobed; an unparseable one
// deploys once the daemon proves it knows tag groups.
//
// Mutations: probe only on a parse — the unparseable cases deploy: red;
// never probe — red; probe an unparseable file only on a raw "tag:" scan —
// the escaped case deploys: red; probe every file — the plain parseable case
// probes: red.
func TestGitopsDeploy_ProbesForTag(t *testing.T) {
	unimpl := status.Error(codes.Unimplemented, "unknown method")
	parses := "name: dd\nsecurity-groups:\n  web:\n    rules:\n      - {direction: ingress, proto: tcp, port: \"443\", cidr: \"tag:web\", action: accept}\n"
	for _, c := range []struct {
		name, body string
		probeErr   error
		probe      bool
		deploy     bool
	}{
		{"parses, holds tag:", parses, unimpl, true, false},
		{"does not parse, holds TAG :", "name: dd\nbogus-field: 1\nsecurity-groups:\n  web:\n    rules:\n      - {cidr: \"TAG : web\", port: \"99999\"}\n", unimpl, true, false},
		{"does not parse, escaped tag:", "name: dd\nbogus-field: 1\nsecurity-groups:\n  web:\n    rules:\n      - {cidr: \"\\x74ag:web\"}\n", unimpl, true, false},
		{"does not parse, no tag", "name: dd\nbogus-field: 1\n", unimpl, true, false},
		{"does not parse, no tag, a daemon that knows tag groups", "name: dd\nbogus-field: 1\n", nil, true, true},
		{"parses, no tag", "name: dd\nsecurity-groups:\n  web:\n    rules:\n      - {direction: ingress, proto: tcp, port: \"443\", cidr: \"10.0.0.0/8\", action: accept}\n", unimpl, false, true},
	} {
		if _, perr := compose.ParseNamed("stack.yaml", []byte(c.body)); (perr == nil) != strings.HasPrefix(c.name, "parses") {
			t.Fatalf("%s: the fixture's parse = %v", c.name, perr)
		}
		if strings.Contains(c.name, "escaped") && strings.Contains(strings.ToLower(c.body), "tag:") {
			t.Fatalf("%s: the fixture holds a literal tag:", c.name)
		}
		spy := &tagProbeSpy{probeErr: c.probeErr}
		err := gitopsDeploy(context.Background(), spy, "stack.yaml", c.body)
		wantProbes := 0
		if c.probe {
			wantProbes = 1
		}
		if spy.probes != wantProbes {
			t.Errorf("%s: probes=%d, want %d", c.name, spy.probes, wantProbes)
		}
		if c.deploy {
			if spy.deploys != 1 {
				t.Errorf("%s: deploys=%d err=%v, want the deploy", c.name, spy.deploys, err)
			}
			continue
		}
		if spy.deploys != 0 || err == nil || !strings.Contains(err.Error(), "upgrade litevirtd") {
			t.Errorf("%s: deploys=%d err=%v, want the upgrade refusal and no deploy", c.name, spy.deploys, err)
		}
	}
}
