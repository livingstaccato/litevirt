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

// forceSpy records the calls `lv rm --force` makes.
type forceSpy struct {
	pb.LiteVirtClient
	stops   int
	deletes []*pb.DeleteVMRequest
}

func (c *forceSpy) StopVM(context.Context, *pb.StopVMRequest, ...grpc.CallOption) (*pb.VM, error) {
	c.stops++
	return &pb.VM{}, nil
}

func (c *forceSpy) DeleteVM(_ context.Context, r *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.deletes = append(c.deletes, r)
	return &emptypb.Empty{}, nil
}

// F5: `lv rm --force` force-stopped the VM before DeleteVM could refuse the
// delete (operation barrier, linked clones, ...), leaving a powered-off VM. The
// stop is the daemon's, after its checks: the CLI sends no StopVM and asks the
// delete to force.
func TestRm_ForceLeavesTheStopToTheDelete(t *testing.T) {
	spy := &forceSpy{}
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
	captureStdout(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if spy.stops != 0 {
		t.Errorf("rm --force sent %d StopVM calls before the delete", spy.stops)
	}
	if len(spy.deletes) != 1 || !spy.deletes[0].GetForce() {
		t.Errorf("DeleteVM requests = %v, want one with force set", spy.deletes)
	}
}
