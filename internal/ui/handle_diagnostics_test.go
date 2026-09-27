package ui

import (
	"net/http"
	"testing"
)

// The diagnostics page's Force Sync button kicks an anti-entropy pass. It must
// not pull the state dump: that RPC is peer-only (it carries hosts.ipmi_pass,
// users.password_hash and tokens.token_hash), so a UI bearer is refused it, and
// the dump it used to fetch was discarded anyway — it never synced anything.
func TestHandler_ForceSyncTriggersAntiEntropy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/diagnostics/sync"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if mock.stateDumpCalls != 0 {
		t.Errorf("Force Sync made %d GetStateDump calls; the dump is peer-only", mock.stateDumpCalls)
	}
	if mock.lastTriggerAntiEntropy == nil {
		t.Fatal("Force Sync did not call TriggerAntiEntropy")
	}
}
