package grpcapi

import (
	"context"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestVRRPTransport_AllSetPreconditions(t *testing.T) {
	for _, tc := range []struct {
		name string
		code codes.Code
	}{{"viewer_set", codes.PermissionDenied}, {"scope_unlatched", codes.FailedPrecondition}, {"vrrp_unlatched", codes.FailedPrecondition}, {"missing_voter", codes.FailedPrecondition}, {"voter_read_error", codes.Unavailable}, {"invalid_transport", codes.InvalidArgument}, {"success", codes.OK}} {
		t.Run(tc.name, func(t *testing.T) {
			s := vrrpServer(t, true, false, false)
			g := fakeServerGate{healthy: []string{"peer-1", "peer-2"}, durablyLatchedTok: map[string]bool{capabilities.FailoverScopeV1: true}}
			if tc.name == "scope_unlatched" {
				g.durablyLatchedTok = nil
			}
			if tc.name == "missing_voter" {
				g.healthy = nil
			}
			s.SetGate(g)
			if _, err := s.GetVRRPTransport(viewerCtx(), nil); err != nil {
				t.Fatal("viewer read", err)
			}
			before, err := corrosion.GetVRRPTransport(context.Background(), s.db)
			if err != nil {
				t.Fatal(err)
			}
			ctx := adminCtx()
			if tc.name == "viewer_set" {
				ctx = viewerCtx()
			}
			transport := "multicast"
			if tc.name == "vrrp_unlatched" {
				transport = "unicast"
			}
			if tc.name == "invalid_transport" {
				transport = "broadcast"
			}
			if tc.name == "voter_read_error" {
				s.db.Close()
			}
			got, err := s.SetVRRPTransport(ctx, &pb.SetVRRPTransportRequest{Transport: transport})
			if status.Code(err) != tc.code {
				t.Fatalf("got %v %v want %v", got, err, tc.code)
			}
			if tc.name == "voter_read_error" {
				return
			}
			after, err := corrosion.GetVRRPTransport(context.Background(), s.db)
			if err != nil {
				t.Fatal(err)
			}
			if tc.code != codes.OK && after != before {
				t.Fatal("refusal mutated transport", before, after)
			}
			if tc.code == codes.OK && got.GetPolicy() != "multicast" {
				t.Fatal("successful policy missing", got)
			}
		})
	}
}
