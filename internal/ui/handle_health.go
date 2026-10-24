package ui

import (
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fence"
)

// sshOnlyFencing names the hosts (but one in maintenance) whose fence goes
// only over SSH, which never proves a power-off: the health page flags them
// and recommends ipmi or redfish, as `lv doctor fence` does.
func sshOnlyFencing(hosts []*pb.Host) []string {
	var out []string
	for _, h := range hosts {
		if h.GetState() != pb.HostState_HOST_MAINTENANCE && fence.SSHOnly(h.GetFenceStrategy()) {
			out = append(out, h.GetName())
		}
	}
	return out
}

// healthView derives the template inputs from the one health read: the
// connectivity matrix (observer→target status) and the host list it spans.
func healthView(h *pb.ClusterHealth) (hostNames []string, matrix map[string]map[string]string) {
	hostSet := map[string]bool{}
	for _, e := range h.GetConnectivity() {
		hostSet[e.Observer] = true
		hostSet[e.Target] = true
	}
	for name := range hostSet {
		hostNames = append(hostNames, name)
	}
	matrix = map[string]map[string]string{}
	for _, e := range h.GetConnectivity() {
		if matrix[e.Observer] == nil {
			matrix[e.Observer] = map[string]string{}
		}
		matrix[e.Observer][e.Target] = e.Status
	}
	return hostNames, matrix
}

func (s *Server) handleHealthTimeline(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	health, _ := s.grpc.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	audit, _ := s.grpc.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 50})

	hostNames, matrix := healthView(health)
	data := s.pageData("Health", "health")
	data["HostNames"] = hostNames
	data["Matrix"] = matrix
	data["Overall"] = health.GetOverall()
	data["Conditions"] = health.GetConditions()
	data["Evaluators"] = health.GetEvaluators()
	data["Events"] = audit.GetEntries()
	if hl, err := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{}); err == nil {
		data["SSHOnlyFencing"] = sshOnlyFencing(hl.GetHosts())
	}
	s.renderPage(w, "health_timeline.html", data)
}

func (s *Server) handleHealthTimelinePartial(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	health, _ := s.grpc.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})

	hostNames, matrix := healthView(health)
	s.renderPartial(w, "health_timeline.html", "health-matrix", map[string]any{
		"HostNames":   hostNames,
		"Matrix":      matrix,
		"Overall":     health.GetOverall(),
		"Conditions":  health.GetConditions(),
		"ClusterName": s.cluster,
	})
}
