package grpcapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
)

// NotifyRecoveryStalled delivers a host.recovery.stalled notification at
// error severity, for the host, naming the coordinator and the reason, to a
// route subscribed to it.
//
// Mutation: send it at warn severity — the error-only route drops it.
func TestNotifyRecoveryStalled_KindSeverityAndDetail(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	got := make(chan notify.Notification, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n notify.Notification
		if err := json.NewDecoder(r.Body).Decode(&n); err == nil {
			got <- n
		}
	}))
	defer srv.Close()
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	if err := corrosion.InsertNotificationTarget(ctx, s.db, corrosion.NotificationTarget{
		ID: "t1", Name: "hook", Type: "webhook", Config: string(cfg), Enabled: true,
	}); err != nil {
		t.Fatalf("InsertNotificationTarget: %v", err)
	}
	if err := corrosion.InsertNotificationRoute(ctx, s.db, corrosion.NotificationRoute{
		ID: "r1", EventPattern: "host.recovery.*", TargetID: "t1", MinSeverity: "error", Enabled: true,
	}); err != nil {
		t.Fatalf("InsertNotificationRoute: %v", err)
	}

	s.NotifyRecoveryStalled("node-2", "node-4", "fence failed (ssh: no identity)", 3, time.Now().Add(-2*time.Minute))

	select {
	case n := <-got:
		if n.Kind != "host.recovery.stalled" {
			t.Errorf("kind = %q, want host.recovery.stalled", n.Kind)
		}
		if n.Severity != notify.SevError || n.Subject != "node-2" {
			t.Errorf("severity %q subject %q, want error for node-2", n.Severity, n.Subject)
		}
		for _, want := range []string{"coordinator=node-4", "pending=3", "fence failed (ssh: no identity)"} {
			if !strings.Contains(n.Detail, want) {
				t.Errorf("detail %q lacks %q", n.Detail, want)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no host.recovery.stalled notification delivered")
	}
}
