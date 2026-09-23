package grpcapi

import (
	"context"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type readyClient struct {
	pb.LiteVirtClient
	resp *pb.ReadyResponse
	err  error
}

func (c readyClient) Ready(context.Context, *pb.ReadyRequest, ...grpc.CallOption) (*pb.ReadyResponse, error) {
	return c.resp, c.err
}

func serverWithPeerReady(t *testing.T, c readyClient) *Server {
	t.Helper()
	s := testServer(t)
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return c, func() {}, nil
	}
	return s
}

// A peer's own "I cannot serve" answer reaches the health checker as
// not-ready — not as an error, which would land in the unreachable bucket.
func TestPeerReady_CarriesThePeersOwnVerdict(t *testing.T) {
	s := serverWithPeerReady(t, readyClient{
		resp: &pb.ReadyResponse{HostName: "host-b", Ready: false, NotReadyReason: "local read failed"},
	})

	ready, reason, err := s.PeerReady(context.Background(), "host-b")
	if err != nil {
		t.Fatalf("PeerReady returned an error: %v — the RPC completed, so this is not unreachable", err)
	}
	if ready {
		t.Error("ready = true for a peer that reported not ready")
	}
	if reason != "local read failed" {
		t.Errorf("reason = %q, want the peer's own reason", reason)
	}
}

// An RPC that does not complete is UNREACHABLE and must surface as an error,
// which is the verdict fencing quorum is allowed to count.
func TestPeerReady_TransportFailureIsAnError(t *testing.T) {
	s := serverWithPeerReady(t, readyClient{err: errors.New("connection refused")})

	if _, _, err := s.PeerReady(context.Background(), "host-b"); err == nil {
		t.Error("PeerReady returned no error for a peer that could not be reached")
	}
}

// A peer running a build that predates this RPC answers Unimplemented. The RPC
// ARRIVED, so the peer is reachable, and it said nothing about readiness — so
// it is neither unreachable nor unready. Reading it either way would mark every
// not-yet-upgraded node in a rolling upgrade as degraded and strip the cluster
// of its voting weight mid-rollout.
func TestPeerReady_OldPeerWithoutTheRPCIsNotDegraded(t *testing.T) {
	s := serverWithPeerReady(t, readyClient{
		err: status.Error(codes.Unimplemented, "unknown method Ready"),
	})

	ready, _, err := s.PeerReady(context.Background(), "host-b")
	if err != nil {
		t.Fatalf("PeerReady: %v — an Unimplemented answer is not a transport failure", err)
	}
	if !ready {
		t.Error("ready = false for a peer too old to have the RPC; it reported nothing, not a fault")
	}
}

// A ready peer reads as ready. Without this, "always report not ready" passes
// the first test.
func TestPeerReady_ReadyPeerReadsAsReady(t *testing.T) {
	s := serverWithPeerReady(t, readyClient{resp: &pb.ReadyResponse{HostName: "host-b", Ready: true}})

	ready, _, err := s.PeerReady(context.Background(), "host-b")
	if err != nil {
		t.Fatalf("PeerReady: %v", err)
	}
	if !ready {
		t.Error("ready = false for a peer that reported ready")
	}
}

// Asking about ourselves answers locally. A node cannot dial itself to find out
// whether its own database is wedged — the dial is the thing the wedge breaks.
func TestPeerReady_SelfIsAnsweredLocally(t *testing.T) {
	s := testServer(t)
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		t.Error("PeerReady dialled a peer to ask about this node")
		return nil, nil, errors.New("must not dial")
	}
	insertReadyHost(t, s, "test-host")

	ready, _, err := s.PeerReady(context.Background(), "test-host")
	if err != nil {
		t.Fatalf("PeerReady: %v", err)
	}
	if !ready {
		t.Error("ready = false for this node with a working database")
	}
}
