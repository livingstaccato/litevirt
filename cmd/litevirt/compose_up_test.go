package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// scriptedStream yields a fixed sequence of messages, then io.EOF.
type scriptedStream[T any] struct {
	fakeStream[T]
	msgs []*T
}

func (s *scriptedStream[T]) Recv() (*T, error) {
	if len(s.msgs) == 0 {
		return nil, io.EOF
	}
	m := s.msgs[0]
	s.msgs = s.msgs[1:]
	return m, nil
}

// deployClient answers the dry-run DeployStack with plan and the real one with
// progress — the two streams `lv compose up` reads, in that order.
type deployClient struct {
	pb.LiteVirtClient
	plan     []*pb.DeployProgress
	progress []*pb.DeployProgress
	teardown []*pb.DeleteProgress
	applied  bool // a non-dry-run DeployStack was issued
	deleted  bool // DeleteStack was issued
}

func (d *deployClient) DeployStack(_ context.Context, in *pb.DeployStackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeployProgress], error) {
	if in.DryRun {
		return &scriptedStream[pb.DeployProgress]{msgs: append([]*pb.DeployProgress(nil), d.plan...)}, nil
	}
	d.applied = true
	return &scriptedStream[pb.DeployProgress]{msgs: append([]*pb.DeployProgress(nil), d.progress...)}, nil
}

func (d *deployClient) ListVMs(_ context.Context, _ *pb.ListVMsRequest, _ ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	return &pb.ListVMsResponse{Vms: []*pb.VM{{Name: "ha1", State: pb.VMState_VM_RUNNING}}}, nil
}

func (d *deployClient) DeleteStack(_ context.Context, _ *pb.DeleteStackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeleteProgress], error) {
	d.deleted = true
	return &scriptedStream[pb.DeleteProgress]{msgs: append([]*pb.DeleteProgress(nil), d.teardown...)}, nil
}

const hbCompose = "name: hb\nvms:\n  ha1:\n    image: ubuntu\n    cpu: 1\n    memory: 512\n  ha2:\n    image: ubuntu\n    cpu: 1\n    memory: 512\n"

// runComposeCLI runs `lv compose <args>` against spy with stdin fed from
// stdinData and the terminal check pinned to tty. It returns stdout and the
// command's error.
func runComposeCLI(t *testing.T, spy *deployClient, tty bool, stdinData string, args ...string) (string, error) {
	t.Helper()
	return runComposeFileCLI(t, spy, hbCompose, tty, stdinData, args...)
}

// runComposeFileCLI is runComposeCLI with the compose file's contents given.
func runComposeFileCLI(t *testing.T, spy *deployClient, composeYAML string, tty bool, stdinData string, args ...string) (string, error) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "compose.yml")
	if err := os.WriteFile(file, []byte(composeYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	origClient := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	origTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return tty }
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(stdinData); err != nil {
		t.Fatal(err)
	}
	w.Close()
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		withClient = origClient
		stdinIsTerminal = origTTY
		os.Stdin = origStdin
		r.Close()
	})

	cmd := newComposeCmd()
	cmd.SetArgs(append(args, "-f", file))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var runErr error
	out := captureStdout(t, func() { runErr = cmd.Execute() })
	return out, runErr
}

func createPlan(names ...string) []*pb.DeployProgress {
	var out []*pb.DeployProgress
	for _, n := range names {
		out = append(out, &pb.DeployProgress{Phase: "create", VmName: n, Detail: "create " + n})
	}
	return out
}

// TestComposeUp_FailedCreateIsNotReportedAsDeployed reproduces the lab run: the
// daemon streamed an "error" phase for the only VM and returned OK, and the CLI
// printed `Stack "hb" deployed.` and exited 0. A failed action must become a
// non-nil error (non-zero exit) that names it, and the success line must not
// appear.
func TestComposeUp_FailedCreateIsNotReportedAsDeployed(t *testing.T) {
	spy := &deployClient{
		plan: createPlan("ha2"),
		progress: []*pb.DeployProgress{
			{Phase: "applying", VmName: "ha2", Detail: "create ha2"},
			{Phase: "error", VmName: "ha2", Error: `refusing admission to host "node-4"`},
		},
	}
	out, err := runComposeCLI(t, spy, false, "", "up", "-y")
	if err == nil {
		t.Fatalf("compose up with a failed create returned nil error (exit 0); stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), `stack "hb": 1 of 1 actions failed (ha2)`) {
		t.Errorf("error does not summarise the failure: %v", err)
	}
	if strings.Contains(out, "deployed.") {
		t.Errorf("a failed deploy was reported as deployed:\n%s", out)
	}
}

// TestComposeUp_PartialFailureIsVisibleAsPartial: one of two creates fails.
// The summary must count against the whole plan and name only the failure.
func TestComposeUp_PartialFailureIsVisibleAsPartial(t *testing.T) {
	spy := &deployClient{
		plan: createPlan("ha1", "ha2"),
		progress: []*pb.DeployProgress{
			{Phase: "applying", VmName: "ha1", Detail: "create ha1"},
			{Phase: "done", VmName: "ha1", ProgressPct: 100},
			{Phase: "applying", VmName: "ha2", Detail: "create ha2"},
			{Phase: "error", VmName: "ha2", Error: "no capacity"},
		},
	}
	out, err := runComposeCLI(t, spy, false, "", "up", "-y")
	if err == nil {
		t.Fatalf("partial failure returned nil error; stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), `stack "hb": 1 of 2 actions failed (ha2)`) {
		t.Errorf("error does not summarise the partial failure: %v", err)
	}
	if strings.Contains(out, "deployed.") {
		t.Errorf("a partially failed deploy was reported as deployed:\n%s", out)
	}
}

// TestComposeUp_AllSucceedStillSaysDeployed pins the unchanged success path.
func TestComposeUp_AllSucceedStillSaysDeployed(t *testing.T) {
	spy := &deployClient{
		plan: createPlan("ha1", "ha2"),
		progress: []*pb.DeployProgress{
			{Phase: "applying", VmName: "ha1", Detail: "create ha1"},
			{Phase: "done", VmName: "ha1", ProgressPct: 100},
			{Phase: "applying", VmName: "ha2", Detail: "create ha2"},
			{Phase: "done", VmName: "ha2", ProgressPct: 100},
		},
	}
	out, err := runComposeCLI(t, spy, false, "", "up", "-y")
	if err != nil {
		t.Fatalf("successful deploy returned error: %v", err)
	}
	if !strings.Contains(out, "\nStack \"hb\" deployed.\n") {
		t.Errorf("success line missing:\n%s", out)
	}
}

// TestComposeUp_NonTTYWithoutYesRefuses: over a non-tty ssh session the
// confirmation prompt used to block forever on an open, silent stdin. Without
// -y and without a terminal the command must refuse and say how to proceed —
// and must not apply, even if stdin happens to carry a "y".
func TestComposeUp_NonTTYWithoutYesRefuses(t *testing.T) {
	spy := &deployClient{plan: createPlan("ha1")}
	out, err := runComposeCLI(t, spy, false, "y\n", "up")
	if err == nil {
		t.Fatalf("non-tty compose up without -y returned nil; stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "-y") {
		t.Errorf("refusal does not point at -y: %v", err)
	}
	if spy.applied {
		t.Error("non-tty compose up without -y applied the plan")
	}
}

// TestComposeUp_TTYStillPrompts: on a terminal the prompt is still honoured —
// the refusal is about the missing terminal, not about a missing -y.
func TestComposeUp_TTYStillPrompts(t *testing.T) {
	spy := &deployClient{plan: createPlan("ha1")}
	out, err := runComposeCLI(t, spy, true, "y\n", "up")
	if err != nil {
		t.Fatalf("tty compose up answered y returned error: %v\n%s", err, out)
	}
	if !spy.applied {
		t.Errorf("tty compose up answered y did not apply:\n%s", out)
	}
}

// TestComposeDown_NonTTYWithoutYesRefuses: `compose down` has the same prompt
// and the same hang.
func TestComposeDown_NonTTYWithoutYesRefuses(t *testing.T) {
	spy := &deployClient{}
	out, err := runComposeCLI(t, spy, false, "y\n", "down")
	if err == nil {
		t.Fatalf("non-tty compose down without -y returned nil; stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "-y") {
		t.Errorf("refusal does not point at -y: %v", err)
	}
	if spy.deleted {
		t.Error("non-tty compose down without -y deleted the stack")
	}
}

// TestComposeDown_TTYStillPrompts mirrors the up case.
func TestComposeDown_TTYStillPrompts(t *testing.T) {
	spy := &deployClient{}
	out, err := runComposeCLI(t, spy, true, "y\n", "down")
	if err != nil {
		t.Fatalf("tty compose down answered y returned error: %v\n%s", err, out)
	}
	if !spy.deleted {
		t.Errorf("tty compose down answered y did not delete:\n%s", out)
	}
}

// TestComposeDown_FailedDeleteIsNotReportedAsTornDown: DeleteStack reports a
// per-VM failure as an "error" status and still ends the stream OK. The CLI
// printed the error and then `Stack "hb" torn down.` with exit 0, although the
// VM was still there and the stack was left "deleting".
func TestComposeDown_FailedDeleteIsNotReportedAsTornDown(t *testing.T) {
	spy := &deployClient{teardown: []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
		{VmName: "ha2", Status: "deleting"},
		{VmName: "ha2", Status: "error", Error: "an operation is in progress"},
	}}
	out, err := runComposeCLI(t, spy, false, "", "down", "-y")
	if err == nil {
		t.Fatalf("compose down with a failed delete returned nil error (exit 0); stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), `stack "hb": 1 of 2 deletions failed (ha2)`) {
		t.Errorf("error does not summarise the failure: %v", err)
	}
	if strings.Contains(out, "torn down.") {
		t.Errorf("a failed teardown was reported as torn down:\n%s", out)
	}
}

// TestComposeDown_AllSucceedStillSaysTornDown pins the unchanged success path.
func TestComposeDown_AllSucceedStillSaysTornDown(t *testing.T) {
	spy := &deployClient{teardown: []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
	}}
	out, err := runComposeCLI(t, spy, false, "", "down", "-y")
	if err != nil {
		t.Fatalf("successful teardown returned error: %v", err)
	}
	if !strings.Contains(out, "Stack \"hb\" torn down.\n") {
		t.Errorf("success line missing:\n%s", out)
	}
}

// TestComposeDown_FailedNetworkAndContainerListingAreCounted: DeleteStack
// reports a network it could not deprovision, or a container listing that
// failed, as an "error" status named for what was left. Those are failed
// deletions like any VM's, even when every VM went.
func TestComposeDown_FailedNetworkAndContainerListingAreCounted(t *testing.T) {
	spy := &deployClient{teardown: []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
		{VmName: "containers (list failed)", Status: "error", Error: "list the stack's containers: boom"},
		{VmName: "network hb_back", Status: "error", Error: "deprovision network: boom"},
	}}
	out, err := runComposeCLI(t, spy, false, "", "down", "-y")
	if err == nil {
		t.Fatalf("compose down with a failed network deprovision returned nil error; stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), `2 of 3 deletions failed (containers (list failed), network hb_back)`) {
		t.Errorf("error does not count the failures: %v", err)
	}
	if strings.Contains(out, "torn down.") {
		t.Errorf("an incomplete teardown was reported as torn down:\n%s", out)
	}
}

// TestComposeDown_UnnamedErrorIsStillCounted: an error status without a name
// must still fail the command and read sensibly, not "1 of 0 deletions".
func TestComposeDown_UnnamedErrorIsStillCounted(t *testing.T) {
	spy := &deployClient{teardown: []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleted"},
		{Status: "error", Error: "boom"},
	}}
	_, err := runComposeCLI(t, spy, false, "", "down", "-y")
	if err == nil {
		t.Fatal("compose down with an unnamed error returned nil error")
	}
	if !strings.Contains(err.Error(), `1 of 2 deletions failed (stack resource)`) {
		t.Errorf("error does not count the unnamed failure: %v", err)
	}
}

// The plan shows, under each VM it creates or updates, what its healthcheck
// will actually probe — resolved target, defaults filled in — so a target that
// means something other than the author thought is visible before applying.
func TestComposeUp_PlanShowsResolvedHealthcheck(t *testing.T) {
	spy := &deployClient{plan: []*pb.DeployProgress{
		{Phase: "create", VmName: "web-1", Detail: "create web-1"},
		{Phase: "update", VmName: "web-2", Detail: "update web-2"},
		{Phase: "create", VmName: "db", Detail: "create db"},
	}}
	src := "name: s\nvms:\n  web:\n    image: u\n    replicas: 2\n    healthcheck:\n      target: \"22\"\n  db:\n    image: u\n"
	out, err := runComposeFileCLI(t, spy, src, false, "", "up")
	if !errors.Is(err, errNoTTYConfirm) {
		t.Fatalf("compose up (no tty, no -y): err=%v, want the confirmation refusal after the plan", err)
	}
	hc := "      healthcheck: tcp (inferred) <vm address>:22 every 10s, timeout 5s, 3 retries, then restart\n"
	for _, want := range []string{
		"  + create web-1\n" + hc,
		"  ~ update web-2\n" + hc,
		"  + create db\n\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan does not contain %q:\n%s", want, out)
		}
	}
}

// An invalid compose file is refused before anything is sent to the daemon,
// with every problem positioned in the named file, and a non-zero exit.
func TestComposeUp_ValidationErrorsNameTheFile(t *testing.T) {
	spy := &deployClient{plan: createPlan("web")}
	src := "name: s\nvms:\n  web:\n    cpu: 1\n  db:\n    image: u\n    replicas: -1\n"
	_, err := runComposeFileCLI(t, spy, src, false, "", "up", "-y")
	if err == nil {
		t.Fatal("compose up accepted an invalid file")
	}
	for _, want := range []string{"compose.yml:3:3: vms.web: image or iso required", "compose.yml:7:15: vms.db.replicas: replicas must be >= 0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q:\n%v", want, err)
		}
	}
	if spy.applied {
		t.Error("an invalid compose file was deployed")
	}
}
