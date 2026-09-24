// REST coverage gap-fill, second pass.
//
// Adds the long-tail RPCs the original gateway didn't expose: stack
// mutation, container CRUD, session and realm read, scoped backup
// snapshot/restore + volume move/replicate (streaming via SSE),
// preflight-upgrade, and the anycast service-endpoint surface.

package restapi

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"gopkg.in/yaml.v3"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// registerCoverageRoutes wires the second-pass parity additions.
// Called from registerRoutes() alongside registerParityRoutes().
func (s *Server) registerCoverageRoutes() {
	// Stack mutation.
	s.mux.HandleFunc("/api/v1/stacks/deploy", s.wrap(s.handleStackDeploy))
	s.mux.HandleFunc("/api/v1/stacks/delete", s.wrap(s.handleStackDelete))
	s.mux.HandleFunc("/api/v1/stacks/export", s.wrap(s.handleStackExport))

	// Container CRUD + lifecycle.
	s.mux.HandleFunc("/api/v1/containers/create", s.wrap(s.handleContainerCreate))
	s.mux.HandleFunc("/api/v1/containers/start", s.wrap(s.handleContainerStart))
	s.mux.HandleFunc("/api/v1/containers/stop", s.wrap(s.handleContainerStop))
	s.mux.HandleFunc("/api/v1/containers/delete", s.wrap(s.handleContainerDelete))
	s.mux.HandleFunc("/api/v1/containers/exec", s.wrap(s.handleContainerExec))
	s.mux.HandleFunc("/api/v1/containers/pull", s.wrap(s.handleContainerPull))

	// Auth read paths (realms / sessions) — needed for SSO-aware UIs.
	s.mux.HandleFunc("/api/v1/realms", s.wrap(s.handleRealms))
	s.mux.HandleFunc("/api/v1/sessions", s.wrap(s.handleSessions))
	s.mux.HandleFunc("/api/v1/sessions/", s.wrap(s.handleSession))

	// Anycast service endpoints.
	s.mux.HandleFunc("/api/v1/services", s.wrap(s.handleServices))

	// Per-VM mutation surfaces that don't fit the legacy handleVM
	// path-suffix dispatch.
	s.mux.HandleFunc("/api/v1/vms/bind-sgs", s.wrap(s.handleVMBindSGs))
	s.mux.HandleFunc("/api/v1/vms/move-volume", s.wrap(s.handleVMMoveVolume))
	s.mux.HandleFunc("/api/v1/vms/replicate-volume", s.wrap(s.handleVMReplicateVolume))

	// Backup snapshot push / pull.
	s.mux.HandleFunc("/api/v1/backup/snapshot", s.wrap(s.handleBackupSnapshot))
	s.mux.HandleFunc("/api/v1/backup/restore", s.wrap(s.handleBackupRestore))

	// Host preflight (upgrade safety).
	s.mux.HandleFunc("/api/v1/hosts/preflight-upgrade", s.wrap(s.handlePreflightUpgrade))
}

// ── Stack ────────────────────────────────────────────────────────────────────

func (s *Server) handleStackDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.DeployStackRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ComposeYaml == "" {
		jsonError(w, http.StatusBadRequest, "compose_yaml required")
		return
	}
	stream, err := s.grpc.DeployStack(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	if wantsSSE(r) {
		streamSSE(w, r, func() (proto.Message, error) { return stream.Recv() })
		return
	}
	// The whole stream is read. Returning early closes it, and a closed
	// DeployStack stream cancels the deploy on the server: the old "first
	// frame" answer created at most one VM, abandoned the rest and said 200.
	// Per-action failures arrive as "error" frames on a stream that still ends
	// OK, so the result is judged the way `lv compose up` judges it.
	var named struct {
		Name string `yaml:"name"`
	}
	_ = yaml.Unmarshal([]byte(req.ComposeYaml), &named) // the name is only for the response
	res := stackDeployResult{Name: named.Name, Done: []string{}, Failures: []stackDeleteFailure{}}
	actions, failed := map[string]bool{}, map[string]bool{}
	for {
		p, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			code, msg := grpcHTTPStatus(http.StatusInternalServerError, rerr)
			if len(actions) == 0 && len(res.Done) == 0 {
				jsonError(w, code, msg)
				return
			}
			res.Error = fmt.Sprintf("stack %q: deploy failed: %s", res.Name, msg)
			w.WriteHeader(code)
			jsonWrite(w, res)
			return
		}
		if p.VmName != "" {
			actions[p.VmName] = true
		}
		switch p.Phase {
		case "error":
			item := p.VmName
			if item == "" {
				item = "stack resource"
			}
			if !failed[item] {
				failed[item] = true
				res.Failures = append(res.Failures, stackDeleteFailure{Name: item, Error: p.Error})
			}
		case "done":
			if p.VmName != "" {
				res.Done = append(res.Done, p.VmName)
			}
		}
	}
	if len(res.Failures) > 0 {
		names := make([]string, len(res.Failures))
		for i, f := range res.Failures {
			names[i] = f.Name
		}
		total := len(actions)
		if total < len(res.Failures) {
			total = len(res.Failures)
		}
		res.Error = fmt.Sprintf("stack %q: %d of %d actions failed (%s); the stack is left degraded and a re-deploy retries them",
			res.Name, len(res.Failures), total, strings.Join(names, ", "))
		w.WriteHeader(http.StatusInternalServerError)
	}
	jsonWrite(w, res)
}

// stackDeployResult is the non-SSE response of /api/v1/stacks/deploy.
type stackDeployResult struct {
	Name     string               `json:"name"`
	Done     []string             `json:"done"`
	Failures []stackDeleteFailure `json:"failures"`
	Error    string               `json:"error,omitempty"`
}

func (s *Server) handleStackDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "POST or DELETE")
		return
	}
	var req pb.DeleteStackRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stream, err := s.grpc.DeleteStack(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	if wantsSSE(r) {
		streamSSE(w, r, func() (proto.Message, error) { return stream.Recv() })
		return
	}

	// DeleteStack ends OK even when resources could not be removed — each is an
	// "error" status on the stream — so the whole stream is drained and judged
	// the way `lv compose down` judges it: 200 only when nothing failed.
	res := stackDeleteResult{Name: req.Name, Deleted: []string{}, Failures: []stackDeleteFailure{}}
	seen, failed := map[string]bool{}, map[string]bool{}
	for {
		p, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			code, msg := grpcHTTPStatus(http.StatusInternalServerError, rerr)
			if len(seen) == 0 {
				jsonError(w, code, msg)
				return
			}
			res.Error = fmt.Sprintf("stack %q: delete failed: %s", req.Name, msg)
			w.WriteHeader(code)
			jsonWrite(w, res)
			return
		}
		// Not only VMs: containers, a network that could not be deprovisioned
		// or a failed container listing arrive named for themselves, and an
		// unnamed error still counts.
		item := p.VmName
		if item == "" && p.Status == "error" {
			item = "stack resource"
		}
		if item != "" {
			seen[item] = true
		}
		switch p.Status {
		case "error":
			if !failed[item] {
				failed[item] = true
				res.Failures = append(res.Failures, stackDeleteFailure{Name: item, Error: p.Error})
			}
		case "deleted":
			res.Deleted = append(res.Deleted, p.VmName)
		}
	}
	if len(res.Failures) > 0 {
		names := make([]string, len(res.Failures))
		for i, f := range res.Failures {
			names[i] = f.Name
		}
		res.Error = fmt.Sprintf("stack %q: %d of %d deletions failed (%s); the stack is left in state \"deleting\" and the daemon retries the teardown",
			req.Name, len(res.Failures), len(seen), strings.Join(names, ", "))
		w.WriteHeader(http.StatusInternalServerError)
	}
	jsonWrite(w, res)
}

// stackDeleteResult is the non-SSE response of /api/v1/stacks/delete.
type stackDeleteResult struct {
	Name     string               `json:"name"`
	Deleted  []string             `json:"deleted"`
	Failures []stackDeleteFailure `json:"failures"`
	Error    string               `json:"error,omitempty"`
}

type stackDeleteFailure struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

func (s *Server) handleStackExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET or POST")
		return
	}
	var req pb.ExportStackRequest
	if r.Method == http.MethodPost {
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		req.Name = r.URL.Query().Get("name")
	}
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name required")
		return
	}
	resp, err := s.grpc.ExportStack(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

// ── Containers ───────────────────────────────────────────────────────────────

func (s *Server) handleContainerCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.CreateContainerRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := s.grpc.CreateContainer(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonProto(w, resp)
}

func (s *Server) handleContainerStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.StartContainerRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.grpc.StartContainer(s.grpcCtx(r), &req); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleContainerStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.StopContainerRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.grpc.StopContainer(s.grpcCtx(r), &req); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleContainerDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "POST or DELETE")
		return
	}
	var req pb.DeleteContainerRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.grpc.DeleteContainer(s.grpcCtx(r), &req); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleContainerExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.ExecContainerRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := s.grpc.ExecContainer(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleContainerPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.PullOCIImageRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.grpc.PullOCIImage(s.grpcCtx(r), &req); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Auth read paths ──────────────────────────────────────────────────────────

func (s *Server) handleRealms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.ListRealms(s.grpcCtx(r), &emptypb.Empty{})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.ListSessions(s.grpcCtx(r), &pb.ListSessionsRequest{
		Username: r.URL.Query().Get("user"),
	})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/")
	if id == "" {
		jsonError(w, http.StatusBadRequest, "session id required")
		return
	}
	if r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "DELETE only")
		return
	}
	if _, err := s.grpc.RevokeSession(s.grpcCtx(r), &pb.RevokeSessionRequest{Id: id}); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Service endpoints (anycast) ──────────────────────────────────────────────

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp, err := s.grpc.ListServiceEndpoints(s.grpcCtx(r), &pb.ListServiceEndpointsRequest{
			ServiceName: r.URL.Query().Get("name"),
		})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)
	case http.MethodPost:
		var req pb.UpsertServiceEndpointRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := s.grpc.UpsertServiceEndpoint(s.grpcCtx(r), &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonProto(w, resp)
	case http.MethodDelete:
		var req pb.DeleteServiceEndpointRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := s.grpc.DeleteServiceEndpoint(s.grpcCtx(r), &req); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "GET, POST or DELETE")
	}
}

// ── Per-VM ───────────────────────────────────────────────────────────────────

func (s *Server) handleVMBindSGs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.BindSecurityGroupsRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.grpc.BindSecurityGroups(s.grpcCtx(r), &req); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleVMMoveVolume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.MoveVolumeRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stream, err := s.grpc.MoveVolume(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	if wantsSSE(r) {
		streamSSE(w, r, func() (proto.Message, error) { return stream.Recv() })
		return
	}
	first, rerr := stream.Recv()
	if rerr != nil {
		grpcHTTPError(w, http.StatusInternalServerError, rerr)
		return
	}
	jsonProto(w, first)
}

func (s *Server) handleVMReplicateVolume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.ReplicateVolumeRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stream, err := s.grpc.ReplicateVolume(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	if wantsSSE(r) {
		streamSSE(w, r, func() (proto.Message, error) { return stream.Recv() })
		return
	}
	first, rerr := stream.Recv()
	if rerr != nil {
		grpcHTTPError(w, http.StatusInternalServerError, rerr)
		return
	}
	jsonProto(w, first)
}

// ── Backup snapshot push / pull ──────────────────────────────────────────────

func (s *Server) handleBackupSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.BackupSnapshotRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stream, err := s.grpc.BackupSnapshot(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	if wantsSSE(r) {
		streamSSE(w, r, func() (proto.Message, error) { return stream.Recv() })
		return
	}
	first, rerr := stream.Recv()
	if rerr != nil {
		grpcHTTPError(w, http.StatusInternalServerError, rerr)
		return
	}
	jsonProto(w, first)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.RestoreFromBackupRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stream, err := s.grpc.RestoreFromBackup(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	if wantsSSE(r) {
		streamSSE(w, r, func() (proto.Message, error) { return stream.Recv() })
		return
	}
	first, rerr := stream.Recv()
	if rerr != nil {
		grpcHTTPError(w, http.StatusInternalServerError, rerr)
		return
	}
	jsonProto(w, first)
}

// ── Preflight ────────────────────────────────────────────────────────────────

func (s *Server) handlePreflightUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.PreflightUpgradeRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := s.grpc.PreflightUpgrade(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}
