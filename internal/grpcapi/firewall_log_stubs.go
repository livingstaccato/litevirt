package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The firewall log reader, not implemented on this build. It answers
// Unimplemented, as an older daemon does.

func (s *Server) ListFirewallLog(context.Context, *pb.ListFirewallLogRequest) (*pb.ListFirewallLogResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListFirewallLog is not implemented on this build")
}
