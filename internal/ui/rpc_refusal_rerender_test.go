package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// VM start/stop/restart, snapshot restore and container start/stop/delete
// re-render their region (the VM page, the containers table) whether the
// action worked or not. A refusal used to arrive as 200: an error toast plus
// the re-rendered region. It now carries the daemon's status, and still the
// toast and the region: the response names swapOnErrorHeader, and base.html's
// htmx:beforeSwap listener swaps a non-2xx body that carries it, which htmx 2
// otherwise would not. What the user sees is unchanged.

func TestUIViewerRefusedRerenderingActions_403WithToastAndRegion(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "vic", "viewer")
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: "web1", HostName: "host1", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	const vmRegion, ctRegion = `<div id="vm-page">`, "All Containers ("
	cases := []struct {
		what, method, path, region string
		call                       func(ctx context.Context) error
	}{
		{"start VM", "POST", "/ui/vms/web1/start", vmRegion, func(ctx context.Context) error {
			_, err := s.grpc.StartVM(ctx, &pb.StartVMRequest{Name: "web1"})
			return err
		}},
		{"stop VM", "POST", "/ui/vms/web1/stop", vmRegion, func(ctx context.Context) error {
			_, err := s.grpc.StopVM(ctx, &pb.StopVMRequest{Name: "web1"})
			return err
		}},
		{"restart VM", "POST", "/ui/vms/web1/restart", vmRegion, func(ctx context.Context) error {
			_, err := s.grpc.RestartVM(ctx, &pb.RestartVMRequest{Name: "web1"})
			return err
		}},
		{"restore snapshot", "POST", "/ui/vms/web1/snapshot/s1/restore", vmRegion, func(ctx context.Context) error {
			_, err := s.grpc.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: "web1", SnapshotName: "s1"})
			return err
		}},
		{"start container", "POST", "/ui/containers/host1/ct1/start", ctRegion, func(ctx context.Context) error {
			_, err := s.grpc.StartContainer(ctx, &pb.StartContainerRequest{HostName: "host1", Name: "ct1"})
			return err
		}},
		{"stop container", "POST", "/ui/containers/host1/ct1/stop", ctRegion, func(ctx context.Context) error {
			_, err := s.grpc.StopContainer(ctx, &pb.StopContainerRequest{HostName: "host1", Name: "ct1", TimeoutSec: 30})
			return err
		}},
		{"delete container", "DELETE", "/ui/containers/host1/ct1", ctRegion, func(ctx context.Context) error {
			_, err := s.grpc.DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: "host1", Name: "ct1"})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			want := daemonRefusal(t, s, uiSessionReq(t, tc.method, tc.path, nil), tc.call)
			w := serveRequest(s, uiSessionReq(t, tc.method, tc.path, nil))
			assertRefusalToast(t, tc.what, w, http.StatusForbidden, want)
			if got := w.Header().Get(swapOnErrorHeader); got != "true" {
				t.Errorf("%s: %s = %q, want true: htmx would not swap the re-rendered region", tc.what, swapOnErrorHeader, got)
			}
			if !strings.Contains(w.Body.String(), tc.region) {
				t.Errorf("%s: the refusal no longer re-renders its region (%q); body %q", tc.what, tc.region, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("%s: Content-Type = %q, want text/html for the swapped region", tc.what, ct)
			}
			if loc := w.Header().Get("HX-Redirect"); loc != "" {
				t.Errorf("%s: a refused action redirects to %q as if it had succeeded", tc.what, loc)
			}
		})
	}
}

// When the region cannot be rendered (here: the re-render's own read fails),
// the answer is what rpcWriteFailed gives: the toast and the RPC's status, and
// no swap of the render's error page into the region.
func TestRPCWriteFailedRerender_ARegionThatCannotRenderIsNotSwapped(t *testing.T) {
	w := httptest.NewRecorder()
	rpcWriteFailedRerender(w, "Start", status.Error(codes.PermissionDenied, "caller lacks vm.update"), func(w http.ResponseWriter) {
		http.Error(w, "VM not found", http.StatusNotFound)
	})
	assertRefusalToast(t, "start", w, http.StatusForbidden, "caller lacks vm.update")
	if got := w.Header().Get(swapOnErrorHeader); got != "" {
		t.Errorf("%s = %q on a response with no region to swap", swapOnErrorHeader, got)
	}
	if strings.Contains(w.Body.String(), "VM not found") {
		t.Errorf("the failed re-render's error page reached the body: %q", w.Body.String())
	}
}

// base.html's listener is what makes htmx swap a non-2xx body that names the
// header; without it the region would silently stop re-rendering on a refusal.
func TestBaseTemplate_SwapsAnErrorBodyThatAsksForIt(t *testing.T) {
	b, err := os.ReadFile("templates/base.html")
	if err != nil {
		t.Fatalf("read base.html: %v", err)
	}
	src := string(b)
	for _, want := range []string{
		`document.body.addEventListener('htmx:beforeSwap', function(e) {`,
		`getResponseHeader('` + swapOnErrorHeader + `') === 'true'`,
		`e.detail.shouldSwap = true;`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("base.html no longer contains %q: a refused action's re-rendered region would not be swapped", want)
		}
	}
}
