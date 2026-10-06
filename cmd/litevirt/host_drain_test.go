package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// incompleteDrainStream yields one failed VM, then the server's
// "drain incomplete" refusal, as DrainHost ends when a VM stays behind.
type incompleteDrainStream struct {
	fakeStream[pb.DrainProgress]
	sent bool
}

func (s *incompleteDrainStream) Recv() (*pb.DrainProgress, error) {
	if !s.sent {
		s.sent = true
		return &pb.DrainProgress{VmName: "os2", TargetHost: "host-b", Strategy: pb.MigrateStrategy_MIGRATE_COLD,
			Status: "failed", Error: "not moved, left stopped on host-a with its disks: no space"}, nil
	}
	return nil, status.Error(codes.FailedPrecondition, `drain incomplete: 1 VM(s) remain on host "host-a"`)
}

type incompleteDrainClient struct{ pb.LiteVirtClient }

func (incompleteDrainClient) DrainHost(context.Context, *pb.DrainHostRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DrainProgress], error) {
	return &incompleteDrainStream{}, nil
}

// A drain that leaves a VM behind fails the command with the server's reason,
// and never claims the host drained.
func TestHostDrain_IncompleteDrainIsAnError(t *testing.T) {
	orig := cli.Connect
	cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) {
		return incompleteDrainClient{}, func() {}, nil
	}
	t.Cleanup(func() { cli.Connect = orig })

	origOut, origErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	root := newRootCmd()
	root.SetArgs([]string{"host", "drain", "host-a"})
	err := root.Execute()
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = origOut, origErr
	var outBuf, errBuf bytes.Buffer
	outBuf.ReadFrom(rOut)
	errBuf.ReadFrom(rErr)
	out, stderr := outBuf.String(), errBuf.String()

	if err == nil || !strings.Contains(err.Error(), "drain incomplete: 1 VM(s) remain") {
		t.Fatalf("lv host drain with a VM left behind = %v, want the drain-incomplete error", err)
	}
	if strings.Contains(out, "drained") {
		t.Errorf("lv host drain claimed success after an incomplete drain:\n%s", out)
	}
	if !strings.Contains(stderr, "os2") || !strings.Contains(stderr, "left stopped on host-a") {
		t.Errorf("the VM left behind is not reported: stderr=%q", stderr)
	}
}

// A drain line names a strategy only for a VM the drain moved or tried to
// move. The lab printed [MIGRATE_LIVE] for a stopped VM and a local-disk VM
// that a refusal left where they were: their frames carried no strategy, and
// the enum's zero value is MIGRATE_LIVE.
//
// Mutation: print the strategy whatever it is — the refused line carries
// [MIGRATE_NONE] and goes red.
func TestDrainProgressLine(t *testing.T) {
	for _, tc := range []struct {
		p    *pb.DrainProgress
		want string
	}{
		{&pb.DrainProgress{VmName: "a", TargetHost: "h2", Strategy: pb.MigrateStrategy_MIGRATE_NONE, Status: "skipped", Error: "drain refused: no_quorum"},
			"  a → h2 ERROR: drain refused: no_quorum"},
		{&pb.DrainProgress{VmName: "b", TargetHost: "h2", Strategy: pb.MigrateStrategy_MIGRATE_COLD, Status: "done"},
			"  b → h2 [MIGRATE_COLD] done"},
		{&pb.DrainProgress{VmName: "c", TargetHost: "h2", Strategy: pb.MigrateStrategy_MIGRATE_LIVE, Status: "done"},
			"  c → h2 [MIGRATE_LIVE] done"},
		{&pb.DrainProgress{VmName: "d", TargetHost: "h2", Strategy: pb.MigrateStrategy_MIGRATE_COLD, Status: "failed", Error: "not moved"},
			"  d → h2 [MIGRATE_COLD] ERROR: not moved"},
	} {
		if got := drainProgressLine(tc.p); got != tc.want {
			t.Errorf("drainProgressLine(%v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}
