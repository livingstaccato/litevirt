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
	// SPICE listens on the VM host's 127.0.0.1, so the URI offered is the
	// loopback one (on that host, or at the end of an SSH tunnel to it), never
	// resp.Uri at the host's address, which always refuses.
	s.renderFragment(w, "spice_modal.html", map[string]any{
		"Name": name, "Host": resp.Host, "Port": resp.Port, "Uri": spiceLoopbackURI(resp.Port),
		"HasPassword": resp.Password != "",
		"Warning":     resp.Warning,
	})
}

// spiceLoopbackURI is where a SPICE client reaches a console listening on
// port of its host's 127.0.0.1: on that host itself, or at the workstation
// end of `ssh -L <port>:127.0.0.1:<port>`.
func spiceLoopbackURI(port int32) string {
	return fmt.Sprintf("spice://127.0.0.1:%d", port)
}

// handleSpiceVV returns a virt-viewer connection file (.vv) for the VM, which
// remote-viewer / virt-viewer opens directly. The VM's SPICE listener is
// bound to its host's 127.0.0.1, so the file points at 127.0.0.1:<port>: it
// opens on that host itself, or through `ssh -L <port>:127.0.0.1:<port>` to
// it. The host's own address would always refuse. From anywhere else,
// `lv spice <vm> --launch` carries the console through litevirt instead.
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
	fmt.Fprintf(w, "[virt-viewer]\ntype=spice\nhost=127.0.0.1\nport=%d\ntitle=%s\ndelete-this-file=1\nfullscreen=0\n",
		resp.Port, name)
	// The console's password (docs/ui.md "Console passwords"), so
	// remote-viewer opens it without a prompt. delete-this-file=1 has the
	// viewer remove the file once it has read it.
	if resp.Password != "" {
		fmt.Fprintf(w, "password=%s\n", resp.Password)
	}
}
