package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type pullClient struct {
	pb.LiteVirtClient
	got *pb.PullOCIImageRequest
}

func (p *pullClient) PullOCIImage(_ context.Context, in *pb.PullOCIImageRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	p.got = in
	return &emptypb.Empty{}, nil
}

// `lv ct pull` says what it did: it printed nothing on success.
func TestCTPull_SaysWhatItPulled(t *testing.T) {
	spy := &pullClient{}
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newCTCmd()
	cmd.SetArgs([]string{"pull", "ghcr.io/acme/web:1", "--dest", "web"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatal(err)
	}
	if spy.got == nil || !strings.Contains(out, "ghcr.io/acme/web:1") || !strings.Contains(out, "web") {
		t.Fatalf("lv ct pull printed %q, want the image and where it went", out)
	}
}

// `lv compose down` of a stack with no VMs does not call it a stack with
// "no running VMs": DeleteStack removes its containers too.
type noVMsClient struct{ *deployClient }

func (noVMsClient) ListVMs(context.Context, *pb.ListVMsRequest, ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	return &pb.ListVMsResponse{}, nil
}

func TestComposeDown_AStackWithoutVMsIsNotCalledEmpty(t *testing.T) {
	spy := &deployClient{}
	orig := withClient
	t.Cleanup(func() { withClient = orig })
	out, err := runComposeCLIWith(t, noVMsClient{spy}, "down", "-y")
	if err != nil {
		t.Fatalf("compose down: %v\n%s", err, out)
	}
	if strings.Contains(out, "has no running VMs") || !strings.Contains(out, "container") {
		t.Fatalf("compose down of a stack without VMs printed:\n%s", out)
	}
}

// runComposeCLIWith runs lv compose against client c, non-interactively.
func runComposeCLIWith(t *testing.T, c pb.LiteVirtClient, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error { return fn(ctx, c) }
	t.Cleanup(func() { withClient = orig })
	file := t.TempDir() + "/compose.yml"
	if err := os.WriteFile(file, []byte(hbCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := newComposeCmd()
	cmd.SetArgs(append(args, "-f", file))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	return out, err
}
