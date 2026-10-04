package ui

import (
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Resource mappings are read through ListResourceMappings and changed through
// the daemon's resource-mapping RPCs, all with the session's bearer, so the page
// is held to the same resourcemap.read and resourcemap.write checks at `/` as
// any other caller. A mapping names passthrough devices on every host, so a
// grant scoped to one project does not reach it.

// handleResourceMappings renders /resource-mappings: each mapping with its
// per-host devices, plus create / add-device / delete actions (#14).
func (s *Server) handleResourceMappings(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Resource Mappings", "resource-mappings")
	resp, err := s.grpc.ListResourceMappings(s.uiBearerCtx(r), &pb.ListResourceMappingsRequest{})
	if err != nil {
		s.renderPageRPCFailed(w, "resource_mappings.html", data, err)
		return
	}
	data["Mappings"] = resp.GetMappings()
	s.renderPage(w, "resource_mappings.html", data)
}

func (s *Server) handleMappingCreateModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "mapping_create_modal.html", nil)
}

func (s *Server) handleCreateMapping(w http.ResponseWriter, r *http.Request) {
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
	if name == "" {
		sendToast(w, "Name is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Through the twin, like delete: it checks resourcemap.write against the
	// caller's own credential, exactly as for the CLI, and audits.
	if _, err := s.grpc.CreateResourceMapping(s.uiBearerCtx(r), &pb.CreateResourceMappingRequest{
		Name: name, Description: strings.TrimSpace(r.FormValue("description")),
	}); err != nil {
		sendToast(w, "Create failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	sendToast(w, "Resource mapping "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteMapping(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Through the twin: it authorizes with the caller's forwarded bearer AND
	// writes the audit row. An in-process write leaves `lv audit verify`
	// reporting a clean, unbroken, signed chain in which nobody changed
	// anything -- which is worse than no audit log, because it reads as proof.
	if _, err := s.grpc.DeleteResourceMapping(s.uiBearerCtx(r),
		&pb.DeleteResourceMappingRequest{Name: r.PathValue("name")}); err != nil {
		rpcWriteFailed(w, "Delete", err)
		return
	}
	sendToast(w, "Resource mapping deleted", "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleMappingDeviceModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "mapping_device_modal.html", map[string]any{"Mapping": r.PathValue("name")})
}

func (s *Server) handleAddMappingDeviceUI(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mapping := r.PathValue("name")
	host := strings.TrimSpace(r.FormValue("host"))
	address := strings.TrimSpace(r.FormValue("address"))
	if host == "" || address == "" {
		sendToast(w, "Host and PCI address are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := s.grpc.AddMappingDevice(s.uiBearerCtx(r), &pb.AddMappingDeviceRequest{
		Mapping: mapping, Host: host, Address: address,
		Vendor: strings.TrimSpace(r.FormValue("vendor")), Device: strings.TrimSpace(r.FormValue("device")),
	}); err != nil {
		sendToast(w, "Add device failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	sendToast(w, "Device added to "+mapping, "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRemoveMappingDeviceUI(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	mapping := r.PathValue("name")
	host := r.URL.Query().Get("host")
	address := r.URL.Query().Get("address")
	if _, err := s.grpc.RemoveMappingDevice(s.uiBearerCtx(r), &pb.RemoveMappingDeviceRequest{
		Mapping: mapping, Host: host, Address: address,
	}); err != nil {
		sendToast(w, "Remove device failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	sendToast(w, "Device removed", "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}
