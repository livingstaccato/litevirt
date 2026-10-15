package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Firewall logging RPCs, not implemented on this build. Each answers
// Unimplemented, as an older daemon does.

func (s *Server) GetFirewallLogPolicy(context.Context, *pb.GetFirewallLogPolicyRequest) (*pb.GetFirewallLogPolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetFirewallLogPolicy is not implemented on this build")
}

func (s *Server) SetFirewallLogPolicy(context.Context, *pb.SetFirewallLogPolicyRequest) (*pb.FirewallLogPolicy, error) {
	return nil, status.Error(codes.Unimplemented, "SetFirewallLogPolicy is not implemented on this build")
}

func (s *Server) ListFirewallLog(context.Context, *pb.ListFirewallLogRequest) (*pb.ListFirewallLogResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListFirewallLog is not implemented on this build")
}
