package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type captureResolveCondition struct {
	pb.LiteVirtClient
	req *pb.ResolveHealthConditionRequest
}

func (c *captureResolveCondition) ResolveHealthCondition(_ context.Context, in *pb.ResolveHealthConditionRequest, _ ...grpc.CallOption) (*pb.ResolveHealthConditionResponse, error) {
	c.req = in
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
