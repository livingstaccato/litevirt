package ui

import (
	"log/slog"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// callerAllowed asks the daemon whether each named permission gate admits the
// session user, and returns gate → allowed. The gate names are grpcapi's
// permGates: the daemon answers with the same RequirePerm question (path, verb,
// legacy fallback role) the gated RPC asks, through the RBAC engine. Pages use
// it to decide which controls to show instead of reading the caller's coarse
// legacy role, which misses every grant that comes from a role binding.
//
// Display only. A hidden control is never the security boundary — the RPC
// behind it runs the check itself. Fails closed: on any error every gate is
// reported false.
func (s *Server) callerAllowed(r *http.Request, gates ...string) map[string]bool {
	resp, err := s.grpc.CheckPermissions(s.uiBearerCtx(r), &pb.CheckPermissionsRequest{Gates: gates})
	if err != nil {
		slog.Debug("ui: permission check failed; hiding gated controls", "gates", gates, "error", err)
		return map[string]bool{}
	}
	return resp.Allowed
}
