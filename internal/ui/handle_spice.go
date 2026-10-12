package ui

import (
	"fmt"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleSpiceModal fetches live SPICE connection info for a running VM and
// renders a modal with the URI plus a downloadable virt-viewer (.vv) file.
func (s *Server) handleSpiceModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	resp, err := s.grpc.GetSpiceInfo(s.uiBearerCtx(r), &pb.GetSpiceInfoRequest{VmName: name})
	if err != nil {
		s.renderFragment(w, "spice_modal.html", map[string]any{"Name": name, "Error": err.Error()})
		return
	}
	// The password itself stays out of the page; only the .vv file carries it.
	s.renderFragment(w, "spice_modal.html", map[string]any{
		"Name": name, "Host": resp.Host, "Port": resp.Port, "Uri": resp.Uri,
		"HasPassword": resp.Password != "",
	})
}

// handleSpiceVV returns a virt-viewer connection file (.vv) for the VM, which
// remote-viewer / virt-viewer opens directly — the same flow Proxmox uses for
// its SPICE console.
func (s *Server) handleSpiceVV(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	resp, err := s.grpc.GetSpiceInfo(s.uiBearerCtx(r), &pb.GetSpiceInfoRequest{VmName: name})
	if err != nil {
		http.Error(w, "SPICE unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/x-virt-viewer")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name+".vv"))
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "[virt-viewer]\ntype=spice\nhost=%s\nport=%d\ntitle=%s\ndelete-this-file=1\nfullscreen=0\n",
		resp.Host, resp.Port, name)
	// The console's password (docs/ui.md "Console passwords"), so
	// remote-viewer opens it without a prompt. delete-this-file=1 has the
	// viewer remove the file once it has read it.
	if resp.Password != "" {
		fmt.Fprintf(w, "password=%s\n", resp.Password)
	}
}
