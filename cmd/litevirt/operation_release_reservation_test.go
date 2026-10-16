package main

import (
	"context"
	"errors"
	"io"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type releaseReservationSpy struct {
	pb.LiteVirtClient
	reqs []*pb.ReleaseHostReservationRequest
}

func (c *releaseReservationSpy) ReleaseHostReservation(_ context.Context, req *pb.ReleaseHostReservationRequest,
	_ ...grpc.CallOption) (*pb.ReleaseHostReservationResponse, error) {
	c.reqs = append(c.reqs, req)
	return &pb.ReleaseHostReservationResponse{Released: true, Host: "node-1", Vcpu: 1, MemoryMib: 512}, nil
}

// L1: without --force the command refuses before it reaches the daemon; with
// it, the request carries force and the operation id.
func TestOperationReleaseReservation_RequiresForce(t *testing.T) {
	spy := &releaseReservationSpy{}
	dialed := 0
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		dialed++
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })

	cmd := newOperationReleaseReservationCmd()
	cmd.SetArgs([]string{"op-1"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); !errors.Is(err, errReleaseReservationNeedsForce) {
		t.Fatalf("without --force: %v, want the --force refusal", err)
	}
	if dialed != 0 || len(spy.reqs) != 0 {
		t.Fatalf("without --force the daemon was called (%d dials, %d requests)", dialed, len(spy.reqs))
	}

	cmd = newOperationReleaseReservationCmd()
	cmd.SetArgs([]string{"--force", "op-1"})
	cmd.SetOut(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("with --force: %v", err)
	}
	if len(spy.reqs) != 1 || spy.reqs[0].OperationId != "op-1" || !spy.reqs[0].Force {
		t.Fatalf("requests %+v, want one forced release of op-1", spy.reqs)
	}
}
