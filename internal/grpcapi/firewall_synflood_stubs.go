package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// SYN-flood protection RPCs, not implemented on this build. Each answers
// Unimplemented, as an older daemon does.

func (s *Server) GetFirewallSynflood(context.Context, *pb.GetFirewallSynfloodRequest) (*pb.GetFirewallSynfloodResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetFirewallSynflood is not implemented on this build")
}

func (s *Server) SetFirewallSynflood(context.Context, *pb.SetFirewallSynfloodRequest) (*pb.FirewallSynfloodPolicy, error) {
	return nil, status.Error(codes.Unimplemented, "SetFirewallSynflood is not implemented on this build")
}
