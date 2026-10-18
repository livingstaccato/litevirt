package main

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type synfloodSpy struct {
	pb.LiteVirtClient
	err      error
	sets     []*pb.SetFirewallSynfloodRequest
	get      *pb.GetFirewallSynfloodResponse
	health   *pb.ClusterHealth
	deadline bool
}

func (s *synfloodSpy) SetFirewallSynflood(_ context.Context, in *pb.SetFirewallSynfloodRequest, _ ...grpc.CallOption) (*pb.FirewallSynfloodPolicy, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.sets = append(s.sets, in)
	return &pb.FirewallSynfloodPolicy{Scope: in.GetScope(), Mode: in.GetMode(), Rate: in.GetRate(), Burst: in.GetBurst()}, nil
}

func (s *synfloodSpy) GetFirewallSynflood(ctx context.Context, _ *pb.GetFirewallSynfloodRequest, _ ...grpc.CallOption) (*pb.GetFirewallSynfloodResponse, error) {
	_, s.deadline = ctx.Deadline()
	if s.err != nil {
		return nil, s.err
	}
	return s.get, nil
}

func (s *synfloodSpy) GetClusterHealth(context.Context, *pb.GetClusterHealthRequest, ...grpc.CallOption) (*pb.ClusterHealth, error) {
	return s.health, nil
}

func runSynfloodCLI(t *testing.T, spy *synfloodSpy, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	var cmd *cobra.Command = newFirewallSynfloodCmd()
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var err error
	out := captureStdout(t, func() { err = cmd.ExecuteContext(context.Background()) })
	return out, err
}

// on/off/inherit send the scope, mode, rate and burst as given (on's
// defaults 200/1000); inherit without --scope is refused before anything is
// sent; an older daemon's Unimplemented says to upgrade.
//
// Mutations: drop the --scope check on inherit — a request is sent: red;
// send on's flags to off — red.
func TestSynfloodCLI_Writes(t *testing.T) {
	spy := &synfloodSpy{}
	for _, args := range [][]string{{"on"}, {"on", "--rate", "300", "--burst", "50", "--scope", "h1"}, {"off"}, {"inherit", "--scope", "h1"}} {
		if _, err := runSynfloodCLI(t, spy, args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	want := []*pb.SetFirewallSynfloodRequest{{Mode: "on", Rate: 200, Burst: 1000}, {Scope: "h1", Mode: "on", Rate: 300, Burst: 50},
		{Mode: "off"}, {Scope: "h1", Mode: "inherit"}}
	if len(spy.sets) != len(want) {
		t.Fatalf("sent %v, want %v", spy.sets, want)
	}
	for i, w := range want {
		g := spy.sets[i]
		if g.GetScope() != w.GetScope() || g.GetMode() != w.GetMode() || g.GetRate() != w.GetRate() || g.GetBurst() != w.GetBurst() {
			t.Errorf("request %d = %v, want %v", i, g, w)
		}
	}
	if _, err := runSynfloodCLI(t, spy, "inherit"); err == nil || len(spy.sets) != len(want) {
		t.Errorf("inherit without --scope: %v (sent %d), want refused before sending", err, len(spy.sets)-len(want))
	}
	old := &synfloodSpy{err: status.Error(codes.Unimplemented, "unknown method SetFirewallSynflood")}
	for _, args := range [][]string{{"on"}, {"status"}} {
		if _, err := runSynfloodCLI(t, old, args...); err == nil || !strings.Contains(err.Error(), "upgrade litevirtd") {
			t.Errorf("%v against an older daemon: %v, want the upgrade text", args, err)
		}
	}
}

// status prints the cluster's policy, then each host's with where it comes
// from and what is in force: a host whose kernel refused the probe shows
// unavailable.
//
// Mutations: ignore the condition — h2 shows on: red; print an unreadable
// count as 0 — red.
func TestSynfloodCLI_Status(t *testing.T) {
	spy := &synfloodSpy{
		get: &pb.GetFirewallSynfloodResponse{Policies: []*pb.FirewallSynfloodPolicy{
			{Scope: "cluster", Mode: "on", Rate: 200, Burst: 1000, SetBy: "olga", UpdatedAt: "t1"},
			{Scope: "host/h1", Mode: "off", SetBy: "olga", UpdatedAt: "t2"},
			{Scope: "host/h2", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, DropsV4: 17, DropsV6: 3},
			{Scope: "host/h3", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, Error: "unreachable"},
		}},
		health: &pb.ClusterHealth{Conditions: []*pb.HealthCondition{
			{Code: "firewall.synflood.unavailable", SubjectKind: "host", SubjectId: "h2", Lifecycle: "confirmed"},
			{Code: "firewall.synflood.unavailable", SubjectKind: "host", SubjectId: "h1", Lifecycle: "resolved"},
		}},
	}
	out, err := runSynfloodCLI(t, spy, "status")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 5 || lines[0] != "cluster: on, 200/second burst 1000 (set by olga at t1)" {
		t.Fatalf("status output:\n%s", out)
	}
	if f := strings.Fields(lines[2]); strings.Join(f, " ") != "h1 off off - - host 0 0 olga t2" {
		t.Errorf("h1 row = %q", lines[2])
	}
	if f := strings.Fields(lines[3]); strings.Join(f, " ") != "h2 on unavailable 200 1000 cluster 17 3 -" {
		t.Errorf("h2 row = %q", lines[3])
	}
	if f := strings.Fields(lines[4]); strings.Join(f, " ") != "h3 on on 200 1000 cluster - - - unreachable" {
		t.Errorf("h3 row = %q (a count that could not be read must not show as 0)", lines[4])
	}
}

// --rate 0 and --burst 0 are refused, not read as "the default" (Track B
// review m-5); nothing is sent. status runs under a deadline, so a cluster
// with silent hosts cannot hang the CLI (m-3).
//
// Mutations: drop the zero check — a request is sent: red; drop the status
// deadline — red.
func TestSynfloodCLI_ZeroRefusedAndStatusBounded(t *testing.T) {
	spy := &synfloodSpy{get: &pb.GetFirewallSynfloodResponse{Policies: []*pb.FirewallSynfloodPolicy{{Scope: "cluster", Mode: "off"}}}}
	for _, args := range [][]string{{"on", "--rate", "0"}, {"on", "--burst", "0"}} {
		if _, err := runSynfloodCLI(t, spy, args...); err == nil || !strings.Contains(err.Error(), "1-100000") {
			t.Errorf("%v: %v, want refused with the range", args, err)
		}
	}
	if len(spy.sets) != 0 {
		t.Errorf("a zero rate or burst was sent: %v", spy.sets)
	}
	if _, err := runSynfloodCLI(t, spy, "status"); err != nil || !spy.deadline {
		t.Errorf("status: %v, deadline %v; want a call under a deadline", err, spy.deadline)
	}
}
