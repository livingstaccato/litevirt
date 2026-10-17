package main

import (
	"context"
	"errors"
	"io"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type abortClient struct {
	pb.LiteVirtClient
	got      *pb.AbortVMOperationRequest
	unscoped bool // Ping lacks abort_scoped: a daemon that predates --operation
}

func (c *abortClient) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{AbortScoped: !c.unscoped}, nil
}

func (c *abortClient) AbortVMOperation(_ context.Context, req *pb.AbortVMOperationRequest, _ ...grpc.CallOption) (*pb.AbortVMOperationResponse, error) {
	c.got = req
	return &pb.AbortVMOperationResponse{Aborted: true, PreviousOperationId: req.OperationId}, nil
}

// `lv operation abort <vm> --operation <id> --force` sends the id, so the
// server can refuse when another operation is active; without it, none.
func TestOperationAbort_SendsTheOperation(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"vm1", "--force", "--operation", "op-1"}, "op-1"},
		{[]string{"vm1", "--force"}, ""},
	} {
		fake := &abortClient{}
		orig := withClient
		withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
			return fn(ctx, fake)
		}
		cmd := newOperationAbortCmd()
		cmd.SetArgs(tc.args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		var err error
		captureStdout(t, func() { err = cmd.Execute() })
		withClient = orig
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if fake.got == nil || fake.got.VmName != "vm1" || !fake.got.Force || fake.got.OperationId != tc.want {
			t.Errorf("%v sent %+v; want vm1, force, operation %q", tc.args, fake.got, tc.want)
		}
	}
}

// A daemon whose Ping lacks abort_scoped would drop operation_id and abort
// whatever is active, so --operation is refused before anything is sent.
// Without --operation the old daemon is still asked, as before.
func TestOperationAbort_RefusesAScopedAbortToAnOlderDaemon(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		refused bool
	}{
		{[]string{"vm1", "--force", "--operation", "op-1"}, true},
		{[]string{"vm1", "--force"}, false},
	} {
		fake := &abortClient{unscoped: true}
		orig := withClient
		withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
			return fn(ctx, fake)
		}
		cmd := newOperationAbortCmd()
		cmd.SetArgs(tc.args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		var err error
		captureStdout(t, func() { err = cmd.Execute() })
		withClient = orig
		if tc.refused {
			if !errors.Is(err, errAbortScopedUnsupported) {
				t.Errorf("%v: err = %v; want the older-daemon refusal", tc.args, err)
			}
			if fake.got != nil {
				t.Errorf("%v sent %+v to a daemon that ignores operation_id", tc.args, fake.got)
			}
			continue
		}
		if err != nil || fake.got == nil || fake.got.OperationId != "" {
			t.Errorf("%v: err %v, sent %+v; want the unscoped abort sent", tc.args, err, fake.got)
		}
	}
}
