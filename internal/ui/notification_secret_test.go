package ui

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A notification target's config IS its credential: a webhook or Slack URL is a
// bearer secret. ListNotificationTargets redacts it below operator
// (internal/grpcapi/notification_secret_test.go), but the notifications page
// read the targets straight from the local DB and rendered {{.Config}} to any
// session with a role, a viewer included. The page now reads through the RPC,
// so the redaction rule lives in one place. Addresses colonelpanik/litevirt#200.

const uiNotifySecret = "https://hooks.slack.com/services/T000/B000/uiSeCrEtToKeN"

func renderNotificationsAs(t *testing.T, user, role string) string {
	t.Helper()
	s, db, _ := newUIOverRealDaemonSvc(t, user, role)
	if err := corrosion.InsertNotificationTarget(context.Background(), db, corrosion.NotificationTarget{
		ID: "t1", Name: "ops-slack", Type: "slack", Config: `{"url":"` + uiNotifySecret + `"}`, Enabled: true,
	}); err != nil {
		t.Fatalf("InsertNotificationTarget: %v", err)
	}
	w := serveRequest(s, uiSessionReq(t, "GET", "/notifications", nil))
	assertStatus(t, w, http.StatusOK)
	page := w.Body.String()
	// Knowing THAT a target exists stays viewer-visible.
	mustContain(t, page, "ops-slack", "/ui/notifications/targets/t1")
	return page
}

func TestNotificationsPage_ViewerDoesNotSeeTargetSecret(t *testing.T) {
	page := renderNotificationsAs(t, "val", "viewer")
	if strings.Contains(page, "uiSeCrEtToKeN") {
		t.Fatalf("viewer's notifications page renders the target's webhook secret")
	}
	if !strings.Contains(page, "redacted: requires operator") {
		t.Fatalf("viewer's page should show the redaction placeholder in place of the config")
	}
}

func TestNotificationsPage_OperatorSeesTargetConfig(t *testing.T) {
	for _, role := range []string{"operator", "admin"} {
		t.Run(role, func(t *testing.T) {
			page := renderNotificationsAs(t, "o-"+role, role)
			if !strings.Contains(page, uiNotifySecret) {
				t.Fatalf("%s's notifications page should show the target config", role)
			}
		})
	}
}
