package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Firewall tag-group RPCs, not implemented on this build.
// Each answers Unimplemented, as an older daemon does.

func (s *Server) ListFirewallTagGroups(context.Context, *pb.ListFirewallTagGroupsRequest) (*pb.ListFirewallTagGroupsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListFirewallTagGroups is not implemented on this build")
}

func (s *Server) SetFirewallTagGroup(context.Context, *pb.SetFirewallTagGroupRequest) (*pb.FirewallTagGroup, error) {
	return nil, status.Error(codes.Unimplemented, "SetFirewallTagGroup is not implemented on this build")
}

func (s *Server) DeleteFirewallTagGroup(context.Context, *pb.DeleteFirewallTagGroupRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "DeleteFirewallTagGroup is not implemented on this build")
}
