package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// keptDeleteSpy answers DeleteVM with the kept-image header a daemon sends.
type keptDeleteSpy struct {
	pb.LiteVirtClient
	kept []string
}

func (c *keptDeleteSpy) StopVM(context.Context, *pb.StopVMRequest, ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{}, nil
}

func (c *keptDeleteSpy) DeleteVM(_ context.Context, _ *pb.DeleteVMRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	for _, o := range opts {
		if h, ok := o.(grpc.HeaderCallOption); ok {
			md := metadata.MD{}
			for _, k := range c.kept {
				md.Append(grpcapi.KeptCephImageMD, k)
			}
			*h.HeaderAddr = md
		}
	}
	return &emptypb.Empty{}, nil
}

// Lab 2, Bug 2. `lv rm --force` of a VM whose ceph image a client still had
// open said only "VM … deleted", rc 0, and the image stayed in the pool with
// nothing naming it. The VM delete still succeeds (rc 0, as main), and the
// output names each image left in place, with its pool, name and reason.
func TestRm_NamesEachCephImageLeftInPlace(t *testing.T) {
	spy := &keptDeleteSpy{kept: []string{
		`{"image":"lv/web-data","disk":"data","reason":"ceph image lv/web-data is in use (another client still has it open; stop the VM using it first): {\"watchers\":[1]}"}`,
	}}
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newRmCmd()
	cmd.SetArgs([]string{"--force", "web"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatalf("rm: %v (the VM delete succeeded)", err)
	}
	for _, want := range []string{"VM web deleted", "lv/web-data", "disk data", "in use", "ceph_image_leftover"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q does not name %q", out, want)
		}
	}
	if strings.Contains(out, "rbd rm") {
		t.Fatalf("output advises a removal: %q", out)
	}
}
