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

// status prints the cluster's policy, then each host's: its policy, where
// that comes from, what the host itself has in force, and its drops. A host
// whose daemon predates in_force shows "predates"; a host that could not be
// asked shows "-" and why, never a 0 or an "on" (Track B review I-2).
//
// Mutations: show the policy as IN FORCE — h1 and h2 show on: red; show an
// empty in_force as on — h3: red; print an unreadable count as 0 — h4: red.
func TestSynfloodCLI_Status(t *testing.T) {
	spy := &synfloodSpy{
		get: &pb.GetFirewallSynfloodResponse{Policies: []*pb.FirewallSynfloodPolicy{
			{Scope: "cluster", Mode: "on", Rate: 200, Burst: 1000, SetBy: "olga", UpdatedAt: "t1"},
			{Scope: "host/h1", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, InForce: "observe", DropsV4: 0, DropsV6: 0},
			{Scope: "host/h2", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, InForce: "unavailable"},
			{Scope: "host/h3", Mode: "on", Rate: 200, Burst: 1000, Inherited: true},
			{Scope: "host/h4", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, Error: "unreachable"},
			{Scope: "host/h5", Mode: "off", SetBy: "olga", UpdatedAt: "t2", InForce: "off", DropsV4: 17, DropsV6: 3},
		}},
	}
	out, err := runSynfloodCLI(t, spy, "status")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 7 || lines[0] != "cluster: on, 200/second burst 1000 (set by olga at t1)" {
		t.Fatalf("status output:\n%s", out)
	}
	for i, want := range []string{
		"h1 on observe 200 1000 cluster 0 0 -",
		"h2 on unavailable 200 1000 cluster 0 0 -",
		"h3 on predates 200 1000 cluster 0 0 -",
		"h4 on - 200 1000 cluster - - - unreachable",
		"h5 off off - - host 17 3 olga t2",
	} {
		if got := strings.Join(strings.Fields(lines[i+2]), " "); got != want {
			t.Errorf("row %d = %q, want %q", i+1, got, want)
		}
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
