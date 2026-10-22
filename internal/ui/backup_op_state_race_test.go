package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// An op's goroutine writes its progress while the poll handler, and
// backupInFlight (the repo GC guard), read it. Run under -race.
//
// Mutation: write a field of the state outside its lock: red.
func TestBackupOpState_PollingWhileTheOpWritesDoesNotRace(t *testing.T) {
	for _, tc := range []struct{ name, method, path, body string }{
		{"backup", http.MethodPost, "/ui/vms/vm1/backup-snapshot", "repo=r"},
		{"restore", http.MethodPost, "/ui/backups/restore-from", "repo_path=r&vm_name=vm1&disk_name=root&timestamp=t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestUIServer(t, newDefaultMock())
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if w := serveRequest(s, withAuth(r)); w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			poll := "/ui/vms/vm1/backup-progress"
			if tc.name == "restore" {
				poll = "/ui/backups/op-progress?id=" + url.QueryEscape(restoreOpID("vm1", "root", "t"))
			}
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				w := serveRequest(s, withAuth(httptest.NewRequest(http.MethodGet, poll, nil)))
				s.backupInFlight("r")
				if !strings.Contains(w.Body.String(), "hx-get") {
					return // Done: the panel stops polling itself
				}
			}
			t.Fatal("op never finished")
		})
	}
}
