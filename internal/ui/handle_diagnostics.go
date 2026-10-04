package ui

import (
	"net/http"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	digest, err := s.grpc.GetStateDigest(s.uiBearerCtx(r), &emptypb.Empty{})
	data := s.pageData("Diagnostics", "diagnostics")
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Tables"] = digest.GetTables()
	}
	s.renderPage(w, "diagnostics.html", data)
}

func (s *Server) handleDiagnosticsPartial(w http.ResponseWriter, r *http.Request) {
	digest, err := s.grpc.GetStateDigest(s.uiBearerCtx(r), &emptypb.Empty{})
	data := map[string]any{"ClusterName": s.cluster}
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Tables"] = digest.GetTables()
	}
	s.renderPartial(w, "diagnostics.html", "diagnostics-table", data)
}

func (s *Server) handleForceSync(w http.ResponseWriter, r *http.Request) {
	// Kick an immediate anti-entropy pass on the connected host, as
	// `lv cluster converge` does. The state dump is peer-only — it carries
	// secret columns — so the UI never pulls it.
	_, err := s.grpc.TriggerAntiEntropy(s.uiBearerCtx(r), &pb.TriggerAntiEntropyRequest{})
	if err != nil {
		rpcWriteFailed(w, "Sync", err)
		return
	}
	sendToast(w, "State sync triggered", "success")
	w.WriteHeader(http.StatusOK)
}
