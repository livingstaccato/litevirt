package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The live-restore form's "without devices" box reaches the daemon as
// without_devices, and only with auto-start (the daemon refuses it alone).
//
// Mutation: drop WithoutDevices from handleRestoreLive's request: red.
func TestUIRestoreLive_WithoutDevicesReachesTheRequest(t *testing.T) {
	for _, tc := range []struct {
		form string
		want bool
	}{
		{"auto_start=on&without_devices=on", true},
		{"without_devices=on", false},
		{"auto_start=on", false},
	} {
		t.Run(tc.form, func(t *testing.T) {
			mock := newDefaultMock()
			// The op's progress goroutine writes its state while the handler
			// renders it (an unsynchronised backupOpState, as for every backup
			// op); held until the response is written, so this test does not
			// race on it.
			gate := make(chan struct{})
			mock.restoreLiveGate = gate
			defer func() {
				select {
				case <-gate:
				default:
					close(gate)
				}
			}()
			s := newTestUIServer(t, mock)
			r := httptest.NewRequest(http.MethodPost, "/ui/backups/restore-live",
				strings.NewReader("repo_path=r&vm_name=vm1&disk_name=root&timestamp=t&"+tc.form))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if w := serveRequest(s, withAuth(r)); w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			close(gate)
			var req *pb.RestoreLiveRequest
			for deadline := time.Now().Add(5 * time.Second); req == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				mock.mu.Lock()
				req = mock.lastRestoreLiveReq
				mock.mu.Unlock()
			}
			if req == nil {
				t.Fatal("RestoreLive was never called")
			}
			if req.WithoutDevices != tc.want {
				t.Fatalf("without_devices = %v, want %v", req.WithoutDevices, tc.want)
			}
		})
	}
}

// The modal offers the box.
func TestUIRestoreLiveModal_OffersWithoutDevices(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(httptest.NewRequest(http.MethodGet, "/ui/backups/restore-live-modal?repo=r&vm=vm1&ts=t", nil)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="without_devices"`) {
		t.Fatalf("status %d; the modal has no without_devices box:\n%s", w.Code, w.Body.String())
	}
}
