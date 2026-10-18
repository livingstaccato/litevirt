package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

type captureResolveCondition struct {
	pb.LiteVirtClient
	req *pb.ResolveHealthConditionRequest
	md  metadata.MD
}

func (c *captureResolveCondition) ResolveHealthCondition(ctx context.Context, in *pb.ResolveHealthConditionRequest, _ ...grpc.CallOption) (*pb.ResolveHealthConditionResponse, error) {
	c.req = in
	c.md, _ = metadata.FromOutgoingContext(ctx)
	return &pb.ResolveHealthConditionResponse{Condition: &pb.HealthCondition{
		Evaluator: "dual_run", Code: in.GetCode(), SubjectKind: in.GetSubjectKind(), SubjectId: in.GetSubjectId(),
		Lifecycle: "resolved",
	}}, nil
}

func runHealthResolve(t *testing.T, spy *captureResolveCondition, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newHealthCmd()
	cmd.SetArgs(append([]string{"resolve"}, args...))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	return out, err
}

// TestHealthResolve_SubjectAsPrinted: the subject is given the way `lv
// health` prints it (kind/id, an id may itself hold a slash or an @), and the
// flags reach the request.
func TestHealthResolve_SubjectAsPrinted(t *testing.T) {
	spy := &captureResolveCondition{}
	out, err := runHealthResolve(t, spy, "runtime_owner_mismatch", "vm/e2e-d1b-1442676-22-1",
		"--reason", "VM deleted", "--evaluator", "dual_run")
	if err != nil {
		t.Fatalf("lv health resolve: %v", err)
	}
	if spy.req == nil {
		t.Fatal("no request sent")
	}
	if spy.req.GetCode() != "runtime_owner_mismatch" || spy.req.GetSubjectKind() != "vm" ||
		spy.req.GetSubjectId() != "e2e-d1b-1442676-22-1" || spy.req.GetReason() != "VM deleted" ||
		spy.req.GetEvaluator() != "dual_run" {
		t.Fatalf("request = %+v", spy.req)
	}
	if !strings.Contains(out, "resolved") {
		t.Errorf("output %q does not say it resolved", out)
	}
}

func TestHealthResolve_RejectsASubjectWithoutKind(t *testing.T) {
	spy := &captureResolveCondition{}
	if _, err := runHealthResolve(t, spy, "runtime_owner_mismatch", "e2e-vm"); err == nil {
		t.Fatal("a subject with no kind/ prefix was accepted")
	}
	if spy.req != nil {
		t.Fatalf("a request was sent: %+v", spy.req)
	}
}

// The CLI's --accept metadata key and condition code are the server's.
func TestMoveAcceptKeyMatchesTheServer(t *testing.T) {
	if moveAcceptMDKey != grpcapi.MoveAcceptMDKey || moveUnresolvedCode != health.MoveUnresolvedCode {
		t.Fatalf("CLI %q/%q, server %q/%q", moveAcceptMDKey, moveUnresolvedCode, grpcapi.MoveAcceptMDKey, health.MoveUnresolvedCode)
	}
}

// m3-3, I3-1: --accept is refused for any code but vm.move_unresolved, before
// a request is sent, and is sent once per disk.
func TestHealthResolve_Accept(t *testing.T) {
	spy := &captureResolveCondition{}
	if _, err := runHealthResolve(t, spy, "vm_dual_run", "vm/web-1", "--reason", "x", "--accept", "/p"); err == nil ||
		!strings.Contains(err.Error(), "--accept applies only") {
		t.Fatalf("want --accept refused on a dual-run code, got %v", err)
	}
	if spy.req != nil {
		t.Fatalf("a request was sent: %+v", spy.req)
	}
	if _, err := runHealthResolve(t, spy, moveUnresolvedCode, "vm/web-1", "--reason", "x", "--accept", "/a/root", "--accept", "/b/data"); err != nil {
		t.Fatal(err)
	}
	if got := spy.md.Get(moveAcceptMDKey); len(got) != 2 || got[0] != "/a/root" || got[1] != "/b/data" {
		t.Fatalf("accept metadata = %q", got)
	}
}

// I3-1: `lv health` shows a vm.move_unresolved condition's moves before any
// resolve: both files, what is known of the pivot, and the error.
func TestPrintClusterHealth_ShowsMoveEvidence(t *testing.T) {
	out := captureStdout(t, func() {
		printClusterHealth(&pb.ClusterHealth{Overall: "DEGRADED", Conditions: []*pb.HealthCondition{{
			Code: moveUnresolvedCode, SubjectKind: "vm", SubjectId: "web-1", Hosts: []string{"node-a"},
			Evidence: `{"host":"node-a","moves":[{"disk":"root","src":"/hot/r","dst":"/warm/r","live":true,"error":"pivot failed"},` +
				`{"disk":"data","src":"/hot/d","dst":"/warm/d","catch_up":true}]}`,
		}}})
	})
	for _, want := range []string{"root on node-a: /hot/r -> /warm/r (live=true pivoted=false catch_up=false)",
		"either file may hold", "error: pivot failed", "catch_up=true", "holds every write: /warm/d"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
}
