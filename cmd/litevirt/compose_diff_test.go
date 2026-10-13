package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// diffStackClient answers DiffStack with a fixed server plan, and records the
// request it was asked.
type diffStackClient struct {
	pb.LiteVirtClient
	resp *pb.DiffStackResponse
	err  error
	got  *pb.DiffStackRequest
}

func (d *diffStackClient) DiffStack(_ context.Context, in *pb.DiffStackRequest, _ ...grpc.CallOption) (*pb.DiffStackResponse, error) {
	d.got = in
	return d.resp, d.err
}

func runDiff(t *testing.T, c *diffStackClient, args ...string) (string, error) {
	t.Helper()
	yaml := "name: devs\nvms:\n  box-1:\n    image: LTS-24.04\n"
	file := filepath.Join(t.TempDir(), "litevirt.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	origConnect := cli.Connect
	t.Cleanup(func() { cli.Connect = origConnect })
	cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) { return c, func() {}, nil }
	var err error
	out := captureStdout(t, func() {
		cmd := newDiffCmd()
		cmd.SetArgs(append([]string{"-f", file}, args...))
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err = cmd.Execute()
	})
	if c.got != nil && !strings.Contains(c.got.ComposeYaml, "box-1") {
		t.Errorf("DiffStack was not sent the file: %q", c.got.ComposeYaml)
	}
	return out, err
}

// `lv compose diff` prints the server's plan, the one `lv compose up` applies:
// the client no longer computes its own from InspectVM, which disagreed with
// the server on the NIC security it compares (lab c713 N2, review I2).
func TestComposeDiff_PrintsTheServersPlan(t *testing.T) {
	c := &diffStackClient{resp: &pb.DiffStackResponse{Entries: []*pb.DiffEntry{
		{Operation: pb.DiffOp_DIFF_UNCHANGED, Detail: "⚠ box-1: nic 0 (lan) security groups not restored: re-run with --allow-weaken"},
		{Operation: pb.DiffOp_DIFF_UNCHANGED, Detail: "network lan (type=bridge)"},
		{VmName: "box-1", Operation: pb.DiffOp_DIFF_UPDATE, Detail: "update box-1: labels changed — applied in place, no restart"},
		{VmName: "box-2", Operation: pb.DiffOp_DIFF_UNCHANGED, Detail: "box-2: no changes"},
		{VmName: "box-1", Operation: pb.DiffOp_DIFF_CREATE, Detail: "dns box-1.example → pending (DHCP)"},
	}}}
	out, err := runDiff(t, c)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	for _, want := range []string{
		"warning: box-1: nic 0 (lan) security groups not restored: re-run with --allow-weaken",
		"Plan: 0 to create, 1 to update, 0 to delete, 1 unchanged",
		"  ~ update box-1: labels changed",
		"    box-2: no changes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if c.got.AllowWeaken {
		t.Error("diff asked for --allow-weaken without the flag")
	}
	if _, err := runDiff(t, c, "--allow-weaken"); err != nil || !c.got.AllowWeaken {
		t.Errorf("--allow-weaken not passed to the server plan (err %v)", err)
	}
}

// A plan the server refuses (a name collision) is the diff's error, worded as
// the server words it.
func TestComposeDiff_ServerRefusalIsTheError(t *testing.T) {
	c := &diffStackClient{err: status.Error(codes.FailedPrecondition,
		"pre-deploy validation failed:\n  - vm \"box-1\" already exists in stack \"app\" — rename it in this file or delete it there")}
	out, err := runDiff(t, c)
	if err == nil || !strings.Contains(err.Error(), `vm "box-1" already exists in stack "app"`) ||
		strings.Contains(err.Error(), "rpc error") {
		t.Fatalf("err = %v, want the server's refusal as written", err)
	}
	if strings.Contains(out, "Plan:") {
		t.Errorf("a refused plan was printed:\n%s", out)
	}
}
