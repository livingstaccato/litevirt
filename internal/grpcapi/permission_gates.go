package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// permGate is one RequirePerm question, held in one place so the RPC that
// enforces it and a surface that only DISPLAYS it (the web UI deciding which
// controls to show) cannot ask different questions.
//
// The UI used to guess from the caller's coarse legacy role, so a user whose
// access came from an RBAC role binding — a custom role holding
// registry.cred.global, say — saw a read-only page for an action the RPC would
// have let them take. CheckPermissions answers with the gate itself.
type permGate struct {
	path, verb, fallbackRole string
}

// Gate names. A name is what CheckPermissions accepts; it is not a verb, and
// two gates may share one.
const (
	// GateRegistryCredGlobal guards global registry-credential CRUD and
	// `lv registry ls --all`.
	GateRegistryCredGlobal = "registry.cred.global"
)

var permGates = map[string]permGate{
	GateRegistryCredGlobal: {path: "/", verb: "registry.cred.global", fallbackRole: "operator"},
}

// requireGate is RequirePerm for a named gate. An unknown name is a
// programming error and refuses.
func (s *Server) requireGate(ctx context.Context, name string) error {
	g, ok := permGates[name]
	if !ok {
		return status.Errorf(codes.Internal, "unknown permission gate %q", name)
	}
	return s.RequirePerm(ctx, g.path, g.verb, g.fallbackRole)
}

// CheckPermissions reports, for the caller only, whether each named gate
// admits it. It is display only — hiding a control is never the boundary; the
// gated RPC runs requireGate itself. It reveals nothing a caller could not
// learn by attempting the RPC.
func (s *Server) CheckPermissions(ctx context.Context, req *pb.CheckPermissionsRequest) (*pb.CheckPermissionsResponse, error) {
	if callerUsername(ctx) == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated principal")
	}
	resp := &pb.CheckPermissionsResponse{Allowed: make(map[string]bool, len(req.Gates))}
	for _, name := range req.Gates {
		g, ok := permGates[name]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unknown permission gate %q", name)
		}
		err := s.RequirePerm(ctx, g.path, g.verb, g.fallbackRole)
		switch status.Code(err) {
		case codes.OK:
			resp.Allowed[name] = true
		case codes.PermissionDenied:
			resp.Allowed[name] = false
		default:
			return nil, err
		}
	}
	return resp, nil
}
