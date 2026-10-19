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

// TestHealthResolve_StaleUEFIVarsNeedsTheFlagAndAReason: resolving
// nvram_flush_failed acknowledges that a vars store may be stale, so it needs
// --accept-stale-uefi-vars and a --reason; without either nothing is sent.
func TestHealthResolve_StaleUEFIVarsNeedsTheFlagAndAReason(t *testing.T) {
	for _, args := range [][]string{
		{"nvram_flush_failed", "host/node-1", "--reason", "disk replaced"},
		{"nvram_flush_failed", "host/node-1", "--accept-stale-uefi-vars"},
	} {
		spy := &captureResolveCondition{}
		if _, err := runHealthResolve(t, spy, args...); err == nil {
			t.Fatalf("%v was accepted", args)
		}
		if spy.req != nil {
			t.Fatalf("%v sent a request: %+v", args, spy.req)
		}
	}
	spy := &captureResolveCondition{}
	if _, err := runHealthResolve(t, spy, "nvram_flush_failed", "host/node-1", "--accept-stale-uefi-vars", "--reason", "disk replaced"); err != nil {
		t.Fatalf("with the flag and a reason: %v", err)
	}
	if spy.req == nil || spy.req.GetReason() != "disk replaced" {
		t.Fatalf("request = %+v", spy.req)
	}
}
