package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// captureGetClusterHealth runs `lv cluster health` against a client that
// records the request it received and returns a canned response, so the
// assertion is about the wire request (does --include-resolved actually
// reach GetClusterHealth?) rather than about the flag parsing alone.
type captureGetClusterHealth struct {
	pb.LiteVirtClient
	req  *pb.GetClusterHealthRequest
	resp *pb.ClusterHealth
}

func (c *captureGetClusterHealth) GetClusterHealth(_ context.Context, in *pb.GetClusterHealthRequest, _ ...grpc.CallOption) (*pb.ClusterHealth, error) {
	c.req = in
	if c.resp != nil {
		return c.resp, nil
	}
	return &pb.ClusterHealth{Overall: "HEALTHY"}, nil
}

func runClusterHealthCLI(t *testing.T, spy *captureGetClusterHealth, args ...string) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })

	cmd := newClusterHealthCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("lv cluster health %v: %v", args, err)
		}
	})
}

// TestClusterHealth_IncludeResolvedFlagReachesTheRequest is the whole point
// of the flag: a parsed-but-unwired flag looks identical from the CLI's
// output and silently always queries active-only conditions.
func TestClusterHealth_IncludeResolvedFlagReachesTheRequest(t *testing.T) {
	spy := &captureGetClusterHealth{}
	runClusterHealthCLI(t, spy, "--include-resolved")
	if spy.req == nil || !spy.req.GetIncludeResolved() {
		t.Fatalf("GetClusterHealth request IncludeResolved = %v, want true", spy.req.GetIncludeResolved())
	}
}

// TestClusterHealth_DefaultOmitsResolved pins that omitting the flag doesn't
// silently request resolved conditions too.
func TestClusterHealth_DefaultOmitsResolved(t *testing.T) {
	spy := &captureGetClusterHealth{}
	runClusterHealthCLI(t, spy)
	if spy.req == nil || spy.req.GetIncludeResolved() {
		t.Fatalf("GetClusterHealth request IncludeResolved = %v, want false", spy.req.GetIncludeResolved())
	}
}

// TestClusterHealth_PrintsAllThreeSections proves the command renders
// conditions, evaluators, and connectivity — not just the overall state.
func TestClusterHealth_PrintsAllThreeSections(t *testing.T) {
	spy := &captureGetClusterHealth{resp: &pb.ClusterHealth{
		Overall: "DEGRADED",
		Conditions: []*pb.HealthCondition{
			{Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectId: "vm1",
				Lifecycle: "confirmed", Severity: "critical"},
		},
		Evaluators: []*pb.HealthEvaluatorStatus{
			{Evaluator: "dual_run", Coverage: "complete", Reporter: "host-a"},
		},
		Connectivity: []*pb.ConnectivityEdge{
			{Observer: "host-a", Target: "host-b", Status: "healthy"},
		},
	}}
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })

	cmd := newClusterHealthCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("lv cluster health: %v", err)
		}
	})

	for _, want := range []string{"DEGRADED", "vm_dual_run", "vm/vm1", "confirmed", "critical", "dual_run", "complete", "host-a", "host-b"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}
