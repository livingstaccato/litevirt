package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// pruneDaemon answers PruneImages as a daemon of the given kind: honours
// echoes --version, as this build does; an older build does not (and would
// prune every unused file of the image).
type pruneDaemon struct {
	pb.LiteVirtClient
	honours bool
	calls   []*pb.PruneImagesRequest
}

func (d *pruneDaemon) PruneImages(_ context.Context, in *pb.PruneImagesRequest, _ ...grpc.CallOption) (*pb.PruneImagesResponse, error) {
	d.calls = append(d.calls, in)
	resp := &pb.PruneImagesResponse{HostName: "node-1"}
	if d.honours {
		resp.Version = in.Version
	}
	return resp, nil
}

func runImagePrune(t *testing.T, d *pruneDaemon, args ...string) error {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, d)
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newImagePruneCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	var err error
	captureStdout(t, func() { err = cmd.Execute() })
	return err
}

// Review round 2, R-2: the operator's own node may run an older build
// (the commonest rolling-upgrade case). It ignores --version, and a
// removing call would prune every unused file of the image. The CLI asks a
// dry run first and never sends the removing call to such a daemon.
//
// Mutation "no CLI probe" — the removing call reaches the older daemon:
// red.
func TestImagePruneVersion_AnOlderDaemonIsNeverAskedToRemove(t *testing.T) {
	old := &pruneDaemon{}
	err := runImagePrune(t, old, "ubuntu", "--version", "ubuntu@0123456789abcdef.qcow2")
	if err == nil || !strings.Contains(err.Error(), "older build") {
		t.Fatalf("prune --version against an older daemon: %v; want a refusal naming the older build", err)
	}
	for _, c := range old.calls {
		if !c.DryRun {
			t.Fatalf("a removing call was sent to the older daemon: %+v", c)
		}
	}

	// A daemon that honours it gets the probe, then the removing call.
	cur := &pruneDaemon{honours: true}
	if err := runImagePrune(t, cur, "ubuntu", "--version", "ubuntu@0123456789abcdef.qcow2"); err != nil {
		t.Fatalf("prune --version: %v", err)
	}
	if len(cur.calls) != 2 || !cur.calls[0].DryRun || cur.calls[1].DryRun || cur.calls[1].Version == "" {
		t.Fatalf("calls %+v; want a dry-run probe, then the removing call with the version", cur.calls)
	}
}
