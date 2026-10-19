package ui

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// Round 1 m-8: the firewall page marks a logged rule "log" beside its plain
// verdict, and never shows the stored suffix.
//
// Mutation: drop the marker from the template — red.
func TestUIFirewall_MarksLoggedRules(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "ada", "admin")
	ctx := context.Background()
	if err := db.Execute(ctx, `INSERT INTO cluster_firewall_rules
		(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('rl', 'ingress', 'tcp', '22', '', 'drop+log', 100, '', '', 't', '1')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `INSERT INTO host_firewall_rules
		(id, host_name, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('hl', 'kvm-03', 'ingress', 'tcp', '23', '', 'accept+log', 100, '', '', 't', '1')`); err != nil {
		t.Fatal(err)
	}
	w := serveRequest(s, uiSessionReq(t, "GET", "/firewall", nil))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if strings.Contains(body, "+log") {
		t.Error("the page shows the stored +log suffix")
	}
	if n := strings.Count(body, `title="logs each packet it matches">log</span>`); n != 2 {
		t.Errorf("log markers = %d, want 2 (cluster and host rule)", n)
	}
}
