package ui

import (
	"net/http"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestSpiceModalAndVV(t *testing.T) {
	mock := newDefaultMock()
	mock.spiceInfoResp = &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5901, Uri: "spice://10.0.0.5:5901"}
	s := newTestUIServer(t, mock)

	// SPICE listens on the VM host's 127.0.0.1, so the modal leads with the
	// path that works from anywhere (`lv spice --launch`, carried through
	// litevirt) and gives the tunnel for the .vv, never a URI at the host
	// address, which is always "connection refused" (N2 in
	// vnc-password-lab.md).
	//
	// Mutation "modal shows resp.Uri" — red.
	t.Run("modal shows how to reach the loopback listener + download link", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice-modal")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		mustContain(t, body, "lv spice vm1 --launch", "ssh -o ExitOnForwardFailure=yes -L 5901:127.0.0.1:5901", "10.0.0.5",
			"spice://127.0.0.1:5901", "/ui/vms/vm1/spice.vv")
		if strings.Contains(body, "spice://10.0.0.5:5901") {
			t.Errorf("the modal offers a URI at the host address, where SPICE does not listen:\n%s", body)
		}
	})

	// The .vv points at 127.0.0.1:<port>: the VM's host itself, or the
	// workstation end of the documented `ssh -L <port>:127.0.0.1:<port>`
	// tunnel. The lab proved this is the form that connects.
	//
	// Mutation ".vv host=resp.Host" — red.
	t.Run("vv file is a virt-viewer connection file", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice.vv")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		for _, want := range []string{"[virt-viewer]", "type=spice", "\nhost=127.0.0.1\n", "\nport=5901\n"} {
			if !strings.Contains(body, want) {
				t.Errorf(".vv missing %q:\n%s", want, body)
			}
		}
		if strings.Contains(body, "10.0.0.5") {
			t.Errorf(".vv points at the host address, where SPICE does not listen:\n%s", body)
		}
		if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "vm1.vv") {
			t.Errorf("Content-Disposition = %q, want attachment vm1.vv", cd)
		}
	})

	t.Run("no password, no password line", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice.vv")))
		if strings.Contains(w.Body.String(), "password=") {
			t.Errorf(".vv for a console with no password carries a password line:\n%s", w.Body.String())
		}
	})

	// A passworded console (docs/ui.md "Console passwords"): the .vv file
	// carries the password, so remote-viewer opens it without a prompt, and
	// the modal's HTML never does.
	//
	// Mutation "drop the password line" — red.
	t.Run("password rides in the vv file only", func(t *testing.T) {
		pm := newDefaultMock()
		pm.spiceInfoResp = &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5901, Uri: "spice://10.0.0.5:5901",
			Password: "Spice24CharPasswordAbcde"}
		ps := newTestUIServer(t, pm)
		w := serveRequest(ps, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice.vv")))
		assertStatus(t, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "\npassword=Spice24CharPasswordAbcde\n") {
			t.Errorf(".vv does not carry the console password:\n%s", w.Body.String())
		}
		m := serveRequest(ps, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice-modal")))
		if strings.Contains(m.Body.String(), "Spice24CharPasswordAbcde") {
			t.Error("the modal's HTML carries the console password")
		}
		mustContain(t, m.Body.String(), "requires a password")
	})

	// A host where SPICE cannot connect (FIPS) is named in the modal, which
	// still offers the .vv.
	//
	// Mutation "warning not rendered" — red.
	t.Run("modal shows the host's SPICE warning", func(t *testing.T) {
		wm := newDefaultMock()
		wm.spiceInfoResp = &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5901, Uri: "spice://10.0.0.5:5901",
			Warning: "the kernel is in FIPS mode: no SPICE client can connect"}
		ws := newTestUIServer(t, wm)
		w := serveRequest(ws, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice-modal")))
		mustContain(t, w.Body.String(), "may not be able to connect", "FIPS mode", "/ui/vms/vm1/spice.vv")
	})

	t.Run("modal surfaces unavailable error", func(t *testing.T) {
		em := newDefaultMock()
		em.spiceInfoErr = errSimulated
		es := newTestUIServer(t, em)
		w := serveRequest(es, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "SPICE console", "only while the VM is running")
	})
}

// TestSpiceCreateToggle: the create modal exposes the enable-SPICE checkbox,
// and the create handler honors it.
func TestSpiceCreateToggle(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/new-modal")))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), `name="enable_spice"`)

	mock := newDefaultMock()
	cs := newTestUIServer(t, mock)
	r := ctPost(t, "/ui/vms", "name=spicevm&image=ubuntu&cpu=2&memory=2048&enable_spice=true")
	cw := serveRequest(cs, withAuth(r))
	assertStatus(t, cw, http.StatusOK)
	if mock.lastCreateVMReq == nil || !mock.lastCreateVMReq.Spec.EnableSpice {
		t.Errorf("create did not set EnableSpice; req=%+v", mock.lastCreateVMReq)
	}
}
