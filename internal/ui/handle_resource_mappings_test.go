package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestHandleResourceMappings_RendersWithDevices(t *testing.T) {
	// The page lists mappings through ListResourceMappings, so the rows have to
	// reach it through the real daemon.
	s, db := newUIOverRealDaemon(t, "ada", "admin")
	ctx := context.Background()
	if err := corrosion.CreateResourceMapping(ctx, db, "gpu-a100", "A100 pool"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, db, "gpu-a100", "kvm-01", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}
	w := serveRequest(s, uiSessionReq(t, http.MethodGet, "/resource-mappings", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "gpu-a100", "A100 pool", "kvm-01", "0000:41:00.0")
}

func TestHandleResourceMappings_Modals(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	for _, path := range []string{
		"/ui/resource-mappings/create-modal",
		"/ui/resource-mappings/gpu-a100/device-modal",
	} {
		r := withAuth(httptest.NewRequest(http.MethodGet, path, nil))
		w := serveRequest(s, r)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, w.Code)
		}
	}
}
