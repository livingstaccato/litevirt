package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A refused write is answered with the daemon's status AND its words. These
// handlers used to answer a refusal with 200 and an error toast; under htmx 2's
// default responseHandling a 2xx swaps the (empty) body into the target, so a
// refused Delete replaced its own button with nothing and, on the VM page,
// pushed /vms into the history as if the VM were gone. A 4xx is not swapped,
// and htmx processes HX-Trigger before it looks at the status, so the toast
// still fires. That only holds if the refusal text is in the HX-Trigger header
// htmx dispatches as the showToast event base.html renders — which is what
// assertRefusalToast checks, not just the status code.

// renderedToast decodes the HX-Trigger header the way htmx does and returns the
// showToast detail base.html's listener renders (t.textContent = d.message).
func renderedToast(t *testing.T, w *httptest.ResponseRecorder) (message, typ string) {
	t.Helper()
	hdr := w.Header().Get("HX-Trigger")
	if hdr == "" {
		t.Fatalf("no HX-Trigger header: the browser gets no toast (status %d, body %q)", w.Code, w.Body.String())
	}
	var trig struct {
		ShowToast *struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"showToast"`
	}
	if err := json.Unmarshal([]byte(hdr), &trig); err != nil {
		t.Fatalf("HX-Trigger is not the JSON htmx parses: %v (%q)", err, hdr)
	}
	if trig.ShowToast == nil {
		t.Fatalf("HX-Trigger carries no showToast event: %q", hdr)
	}
	return trig.ShowToast.Message, trig.ShowToast.Type
}

func assertRefusalToast(t *testing.T, what string, w *httptest.ResponseRecorder, wantStatus int, daemonMsg string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Errorf("%s: status = %d, want %d", what, w.Code, wantStatus)
	}
	msg, typ := renderedToast(t, w)
	if typ != "error" {
		t.Errorf("%s: toast type = %q, want error (message %q)", what, typ, msg)
	}
	if daemonMsg == "" || !strings.Contains(msg, daemonMsg) {
		t.Errorf("%s: toast %q does not carry the daemon's refusal %q", what, msg, daemonMsg)
	}
}

// daemonRefusal asks the daemon, as the same session, for the refusal the
// handler should relay, so the test names the daemon's words rather than a
// string it guessed.
func daemonRefusal(t *testing.T, s *Server, r *http.Request, call func(ctx context.Context) error) string {
	t.Helper()
	err := call(s.uiBearerCtx(r))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the daemon did not refuse the viewer: %v", err)
	}
	return status.Convert(err).Message()
}

func TestUIViewerRefusedWrites_403WithDaemonMessage(t *testing.T) {
	s, _ := newUIOverRealDaemon(t, "vic", "viewer")

	cases := []struct {
		what string
		req  func() *http.Request
		call func(ctx context.Context) error
	}{
		{
			what: "delete VM",
			req:  func() *http.Request { return uiSessionReq(t, "DELETE", "/ui/vms/web1", nil) },
			call: func(ctx context.Context) error {
				_, err := s.grpc.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web1"})
				return err
			},
		},
		{
			what: "set VM labels",
			req: func() *http.Request {
				return uiSessionReq(t, "POST", "/ui/vms/web1/tags", url.Values{"tags": {"env=prod"}})
			},
			call: func(ctx context.Context) error {
				_, err := s.grpc.SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "web1", Labels: map[string]string{"env": "prod"}})
				return err
			},
		},
		{
			what: "delete load balancer",
			req:  func() *http.Request { return uiSessionReq(t, "POST", "/lb/front/delete", url.Values{}) },
			call: func(ctx context.Context) error {
				_, err := s.grpc.DeleteLoadBalancer(ctx, &pb.DeleteLBRequest{Name: "front"})
				return err
			},
		},
		{
			what: "drain load balancer backend",
			req: func() *http.Request {
				return uiSessionReq(t, "POST", "/lb/front/drain", url.Values{"backend": {"web1"}})
			},
			call: func(ctx context.Context) error {
				_, err := s.grpc.DrainBackend(ctx, &pb.DrainBackendRequest{LbName: "front", Backend: "web1"})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			r := tc.req()
			want := daemonRefusal(t, s, r, tc.call)
			w := serveRequest(s, tc.req())
			assertRefusalToast(t, tc.what, w, http.StatusForbidden, want)
			if loc := w.Header().Get("HX-Redirect"); loc != "" {
				t.Errorf("%s: a refused write redirects to %q as if it had succeeded", tc.what, loc)
			}
		})
	}
}

// ── Storage upload ───────────────────────────────────────────────────────────

// refusedUploadStream models how grpc-go reports a refused client stream: the
// server's status is delivered by CloseAndRecv, and a Send after the server
// has ended the stream returns io.EOF — never the status itself.
type refusedUploadStream struct {
	fakeUploadStream
	refuseOnSend bool
	err          error
}

func (f *refusedUploadStream) Send(r *pb.UploadStoragePoolContentRequest) error {
	if f.refuseOnSend {
		return io.EOF
	}
	return f.fakeUploadStream.Send(r)
}

func (f *refusedUploadStream) CloseAndRecv() (*pb.UploadStoragePoolContentResponse, error) {
	return nil, f.err
}

type refusingUploadMock struct {
	*mockGRPC
	stream *refusedUploadStream
}

func (m *refusingUploadMock) UploadStoragePoolContent(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	return m.stream, nil
}

func uploadReq(t *testing.T) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("host", "host1")
	_ = mw.WriteField("pool", "local")
	_ = mw.WriteField("field", "iso")
	fw, _ := mw.CreateFormFile("file", "alpine.iso")
	_, _ = fw.Write([]byte("ISO-CONTENTS-HERE"))
	_ = mw.Close()
	r, _ := http.NewRequest("POST", "/ui/storage/upload", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return withAuth(r)
}

func TestUIUploadStorageContent_RefusalReachesTheUser(t *testing.T) {
	const refusal = "operator role required on /hosts/host1/pools/local"
	for _, onSend := range []bool{false, true} {
		name := "refused at close"
		if onSend {
			name = "refused while sending"
		}
		t.Run(name, func(t *testing.T) {
			mock := &refusingUploadMock{mockGRPC: newDefaultMock(), stream: &refusedUploadStream{
				refuseOnSend: onSend, err: status.Error(codes.PermissionDenied, refusal),
			}}
			s, err := NewServer(mock, "test-cluster")
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			w := serveRequest(s, uploadReq(t))
			assertRefusalToast(t, "upload", w, http.StatusForbidden, refusal)
		})
	}
}

// A body that is not a readable multipart upload is the browser's fault, not a
// server's and not a success: 400, with the reason in the toast.
func TestUIUploadStorageContent_MalformedBodyIs400WithReason(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())

	notMultipart, _ := http.NewRequest("POST", "/ui/storage/upload", strings.NewReader("host=h"))
	notMultipart.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveRequest(s, withAuth(notMultipart))
	assertRefusalToast(t, "non-multipart upload", w, http.StatusBadRequest, "multipart")

	truncated, _ := http.NewRequest("POST", "/ui/storage/upload",
		strings.NewReader("--XB\r\nContent-Disposition: form-data; name=\"host\"\r\n\r\nh1"))
	truncated.Header.Set("Content-Type", "multipart/form-data; boundary=XB")
	w = serveRequest(s, withAuth(truncated))
	assertRefusalToast(t, "truncated multipart upload", w, http.StatusBadRequest, "Upload failed")
}

// The toast assertRefusalToast reads from HX-Trigger only becomes visible text
// through base.html's showToast listener; pin that link, and that the
// non-2xx fallback stands aside when the server already sent a toast (so a
// refusal is not toasted twice, once as raw body text).
func TestBaseTemplate_RendersShowToastMessage(t *testing.T) {
	b, err := os.ReadFile("templates/base.html")
	if err != nil {
		t.Fatalf("read base.html: %v", err)
	}
	src := string(b)
	for _, want := range []string{
		`document.body.addEventListener('showToast', function(e) {`,
		`t.textContent = d.message`,
		`if (!hdr || hdr.indexOf('showToast') === -1) {`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("base.html no longer contains %q: a refusal's HX-Trigger toast may not reach the user", want)
		}
	}
}
