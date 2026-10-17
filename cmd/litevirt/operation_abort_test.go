package main

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type abortClient struct {
	pb.LiteVirtClient
	got *pb.AbortVMOperationRequest
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
