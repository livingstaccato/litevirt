package ui

import (
	"encoding/json"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/notify"
)

// The page lists targets and routes through their RPCs with the session's
// bearer, never from the tables. A target's config IS its credential (a webhook
// or Slack URL is a bearer secret), and ListNotificationTargets redacts it below
// the operator floor; reading the table here once rendered every URL to a
// viewer. Every action, the test send included, goes through the daemon's
// notification RPCs too.

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Notifications", "notifications")
	ctx := s.uiBearerCtx(r)
	resp, err := s.grpc.ListNotificationTargets(ctx, &pb.ListNotificationTargetsRequest{})
	if err != nil {
		data["Error"] = grpcMsg(err)
		s.renderPage(w, "notifications.html", data)
		return
	}
	routes, err := s.grpc.ListNotificationRoutes(ctx, &pb.ListNotificationRoutesRequest{})
	if err != nil {
		data["Error"] = grpcMsg(err)
		s.renderPage(w, "notifications.html", data)
		return
	}
	data["Targets"] = resp.GetTargets()
	data["Routes"] = routes.GetRoutes()
	s.renderPage(w, "notifications.html", data)
}

func (s *Server) handleNotifyTargetModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "notify_target_modal.html", nil)
}

func (s *Server) handleCreateNotifyTarget(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	typ := strings.TrimSpace(r.FormValue("type"))
	url := strings.TrimSpace(r.FormValue("url"))
	if name == "" || url == "" {
		sendToast(w, "name and url are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cfg, _ := json.Marshal(map[string]string{"url": url})
	// Validate it builds a real target before storing.
	if _, err := notify.NewTarget(name, typ, string(cfg)); err != nil {
		sendToast(w, "invalid target: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Through the twin: it authorizes with the caller's forwarded bearer AND
	// writes the audit row. The ID is allocated there, not here.
	if _, err := s.grpc.CreateNotificationTarget(s.uiBearerCtx(r), &pb.CreateNotificationTargetRequest{
		Name: name, Type: typ, Config: string(cfg), Enabled: true,
	}); err != nil {
		rpcWriteFailed(w, "create", err)
		return
	}
	sendToast(w, "Target "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteNotifyTarget(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := s.grpc.DeleteNotificationTarget(s.uiBearerCtx(r),
		&pb.DeleteNotificationTargetRequest{Id: r.PathValue("id")}); err != nil {
		rpcWriteFailed(w, "delete", err)
		return
	}
	sendToast(w, "Target deleted", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleTestNotifyTarget(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Through the twin, like the CRUD above. Sending in-process let any session
	// with a role, a Viewer included, make the daemon load a target's stored
	// credentials and fire at its endpoint; the RPC requires operator.
	if _, err := s.grpc.TestNotificationTarget(s.uiBearerCtx(r),
		&pb.TestNotificationTargetRequest{Id: r.PathValue("id")}); err != nil {
		sendToast(w, "send failed: "+grpcMsg(err), "error")
		if status.Code(err) == codes.Unavailable {
			// The target refused or timed out: the page worked, the endpoint did not.
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(httpStatusFor(err))
		return
	}
	sendToast(w, "Test notification sent", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleNotifyRouteModal(w http.ResponseWriter, r *http.Request) {
	// Through the RPC like the page: the modal names targets only, and the
	// secret-bearing config should not reach a template for a viewer at all.
	var targets []*pb.NotificationTarget
	if resp, err := s.grpc.ListNotificationTargets(s.uiBearerCtx(r), &pb.ListNotificationTargetsRequest{}); err == nil {
		targets = resp.GetTargets()
	}
	s.renderFragment(w, "notify_route_modal.html", map[string]any{"Targets": targets})
}

func (s *Server) handleCreateNotifyRoute(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pattern := strings.TrimSpace(r.FormValue("event_pattern"))
	target := strings.TrimSpace(r.FormValue("target_id"))
	if pattern == "" || target == "" {
		sendToast(w, "pattern and target are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	minSev := r.FormValue("min_severity")
	if minSev == "" {
		minSev = "info"
	}
	// Through the gRPC twin, not the local DB handle: a notification route is
	// cluster state, and RequirePerm/RequireRole on the far side is the only
	// thing that sees the caller's token scopes and RBAC bindings.
	if _, err := s.grpc.CreateNotificationRoute(s.uiBearerCtx(r), &pb.CreateNotificationRouteRequest{
		EventPattern: pattern, TargetId: target, MinSeverity: minSev, Enabled: true,
	}); err != nil {
		rpcWriteFailed(w, "create", err)
		return
	}
	sendToast(w, "Route created", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteNotifyRoute(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := s.grpc.DeleteNotificationRoute(s.uiBearerCtx(r),
		&pb.DeleteNotificationRouteRequest{Id: r.PathValue("id")}); err != nil {
		sendToast(w, "delete failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	sendToast(w, "Route deleted", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}
