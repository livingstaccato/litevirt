package main

import (
	"context"
	"errors"
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

func (c *keptDeleteSpy) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{DeleteForce: true}, nil
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
	pingForce bool
	pingErr   error
	calls     []string
	deletes   []*pb.DeleteVMRequest
}

func (c *forceSpy) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	if c.pingErr != nil {
		return nil, c.pingErr
	}
	return &pb.PingResponse{DeleteForce: c.pingForce}, nil
}

func (c *forceSpy) StopVM(_ context.Context, r *pb.StopVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.calls = append(c.calls, "stop")
	if !r.GetForce() {
		return nil, errors.New("stop must be forced")
	}
	return &pb.VM{}, nil
}

func (c *forceSpy) DeleteVM(_ context.Context, r *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.calls = append(c.calls, "delete")
	c.deletes = append(c.deletes, r)
	return &emptypb.Empty{}, nil
}

func runRmForce(t *testing.T, spy *forceSpy) {
	t.Helper()
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
}

// F5: `lv rm --force` force-stopped the VM before DeleteVM could refuse the
// delete, leaving a powered-off VM. Against a daemon that honours delete force,
// the stop is the daemon's, after its checks: no StopVM, force set.
func TestRm_ForceLeavesTheStopToADaemonThatHonoursIt(t *testing.T) {
	spy := &forceSpy{pingForce: true}
	runRmForce(t, spy)
	if len(spy.calls) != 1 || spy.calls[0] != "delete" || !spy.deletes[0].GetForce() {
		t.Errorf("calls = %v, force = %v; want one delete with force set", spy.calls, spy.deletes[0].GetForce())
	}
}

// I3: a daemon that predates the field ignores it, so a stop-less delete would
// lose the stop hooks and the operator-stop record. The old flow stands: StopVM
// first, then a plain delete.
func TestRm_ForceStopsFirstAgainstADaemonThatIgnoresIt(t *testing.T) {
	for name, spy := range map[string]*forceSpy{
		"old daemon":        {pingForce: false},
		"ping unanswerable": {pingErr: errors.New("boom")},
	} {
		runRmForce(t, spy)
		if len(spy.calls) != 2 || spy.calls[0] != "stop" || spy.calls[1] != "delete" || spy.deletes[0].GetForce() {
			t.Errorf("%s: calls = %v force = %v; want [stop delete] without force", name, spy.calls, spy.deletes[0].GetForce())
		}
	}
}

// keptDiskSpy answers DeleteVM with the kept-disk header a daemon sends.
type keptDiskSpy struct {
	keptDeleteSpy
	disks []string
}

func (c *keptDiskSpy) DeleteVM(_ context.Context, _ *pb.DeleteVMRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	for _, o := range opts {
		if h, ok := o.(grpc.HeaderCallOption); ok {
			md := metadata.MD{}
			for _, k := range c.disks {
				md.Append(grpcapi.KeptDiskMD, k)
			}
			*h.HeaderAddr = md
		}
	}
	return &emptypb.Empty{}, nil
}

// F-5 (lab 2). A disk file a VM delete kept — whether another VM uses it
// could not be told — is never left unnamed: `lv rm` succeeds (as main) and
// prints it with its host, reason and the health condition naming it.
//
// Mutation: drop the KeptDiskMD loop — the path is not printed: red.
func TestRm_NamesEachDiskFileKept(t *testing.T) {
	spy := &keptDiskSpy{disks: []string{
		`{"path":"/var/lib/litevirt/disks/web-root.qcow2","disk":"root","host":"node-3","reason":"whether another VM uses it cannot be told (no answer)"}`,
	}}
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newRmCmd()
	cmd.SetArgs([]string{"web"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	for _, want := range []string{"VM web deleted", "/var/lib/litevirt/disks/web-root.qcow2", "disk root", "node-3", "cannot be told", "disk_leftover"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q does not name %q", out, want)
		}
	}
}
