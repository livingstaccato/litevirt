package ui

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

const fwAuditSessionToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// newUIOverRealDaemon wires the UI to a real grpcapi server through a real gRPC
// connection and the daemon's own auth interceptor — the production shape. The
// mock the other UI tests use cannot show who an audit row names, because the
// name is decided by the interceptor from the session's bearer token.
func newUIOverRealDaemon(t *testing.T, user, role string) (*Server, *corrosion.Client) {
	t.Helper()
	s, db, _ := newUIOverRealDaemonSvc(t, user, role)
	return s, db
}

// newUIOverRealDaemonSvc is newUIOverRealDaemon that also returns the daemon,
// for a test that has to wire an RBAC engine into it.
func newUIOverRealDaemonSvc(t *testing.T, user, role string) (*Server, *corrosion.Client, *grpcapi.Server) {
	t.Helper()
	ctx := context.Background()
	db := newCorrosionForUITest(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(fwAuditSessionToken), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if err := corrosion.InsertUser(ctx, db, user, role, string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := corrosion.InsertToken(ctx, db, corrosion.TokenRecord{
		ID: "ui-session", Username: user, Name: "ui session", TokenHash: string(hash),
	}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	service := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "test-host", DataDir: t.TempDir(), DB: db})
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(grpc.UnaryInterceptor(service.UnaryAuthInterceptor))
	pb.RegisterLiteVirtServer(gs, service)
	go func() { _ = gs.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
		_ = listener.Close()
	})

	s, err := NewServer(pb.NewLiteVirtClient(conn), "test-cluster")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.SetCorrosionDB(db)
	return s, db, service
}

func uiSessionReq(t *testing.T, method, path string, form url.Values) *http.Request {
	t.Helper()
	r := authReq(t, method, path, form)
	r.Header.Del("Cookie")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fwAuditSessionToken})
	return r
}

type uiAuditRow struct {
	found                        bool
	user, target, detail, result string
}

func lastUIAuditRow(t *testing.T, db *corrosion.Client, action string) uiAuditRow {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT username, target, detail, result FROM audit_log
		 WHERE action = ? ORDER BY seq DESC, timestamp DESC LIMIT 1`, action)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if len(rows) == 0 {
		return uiAuditRow{}
	}
	r := rows[0]
	return uiAuditRow{found: true, user: r.String("username"), target: r.String("target"),
		detail: r.String("detail"), result: r.String("result")}
}

func wantUIAudit(t *testing.T, db *corrosion.Client, action, user, target, detail string) {
	t.Helper()
	got := lastUIAuditRow(t, db, action)
	if !got.found {
		t.Fatalf("%s: the web UI changed firewall policy and left no audit row", action)
	}
	if got.user != user || got.target != target || got.detail != detail || got.result != "ok" {
		t.Errorf("%s audit row = user=%q target=%q detail=%q result=%q\n"+
			"                 want user=%q target=%q detail=%q result=\"ok\"",
			action, got.user, got.target, got.detail, got.result, user, target, detail)
	}
}

// Issue colonelpanik/litevirt#182, the audit half, on the web UI path: the
// cluster default policy and the cluster rule set changed from a browser
// session must be recorded against THAT session's user, with the policy before
// and after — not against the daemon, and not as a bare "changed".
func TestUIFirewallMutation_AuditsTheSessionUserBeforeAndAfter(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "carol", "operator")

	w := serveRequest(s, uiSessionReq(t, "POST", "/ui/firewall/default-deny", url.Values{"deny": {"on"}}))
	assertStatus(t, w, http.StatusOK)
	wantUIAudit(t, db, "firewall.default-deny", "carol", "cluster", "before=unset after=deny")

	w = serveRequest(s, uiSessionReq(t, "POST", "/ui/firewall/default-deny", url.Values{"deny": {"off"}}))
	assertStatus(t, w, http.StatusOK)
	wantUIAudit(t, db, "firewall.default-deny", "carol", "cluster", "before=deny after=accept")

	w = serveRequest(s, uiSessionReq(t, "POST", "/ui/firewall/cluster-rules", url.Values{
		"direction": {"ingress"}, "proto": {"tcp"}, "port_range": {"443"}, "action": {"accept"},
	}))
	assertStatus(t, w, http.StatusOK)
	rules, err := corrosion.ListClusterFirewallRules(context.Background(), db)
	if err != nil || len(rules) != 1 {
		t.Fatalf("cluster rules = %v (err %v), want the one just added", rules, err)
	}
	rule := "{ingress tcp port=443 cidr=any accept priority=100}"
	wantUIAudit(t, db, "firewall.cluster-rule.add", "carol", rules[0].ID, "before=none after="+rule)

	w = serveRequest(s, uiSessionReq(t, "DELETE", "/ui/firewall/cluster-rules/"+rules[0].ID, nil))
	assertStatus(t, w, http.StatusOK)
	wantUIAudit(t, db, "firewall.cluster-rule.rm", "carol", rules[0].ID, "before="+rule+" after=none")
}

// The security-group pages go through the same RPCs as `lv sg`, which audit.
// Removing a group or a rule has to record what was removed: both are
// tombstoned, and the audit row is then the only record of what traffic they
// governed.
func TestUISecurityGroupMutation_AuditsBeforeAndAfter(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "carol", "admin")
	ctx := context.Background()

	w := serveRequest(s, uiSessionReq(t, "POST", "/ui/security-groups", url.Values{"name": {"isolate"}}))
	assertStatus(t, w, http.StatusOK)
	wantUIAudit(t, db, "sg.add", "carol", "isolate", "before=none after={name=isolate rules=[]}")
	sgs, err := corrosion.ListSecurityGroups(ctx, db, "")
	if err != nil || len(sgs) != 1 {
		t.Fatalf("security groups = %v (err %v)", sgs, err)
	}
	sgID := sgs[0].ID

	w = serveRequest(s, uiSessionReq(t, "POST", "/ui/security-groups/"+sgID+"/rules", url.Values{
		"direction": {"ingress"}, "port_range": {"22"}, "cidr": {"10.0.0.0/8"},
	}))
	assertStatus(t, w, http.StatusOK)
	rule := "{sg=" + sgID + " ingress all port=22 cidr=10.0.0.0/8 accept priority=100}"
	wantUIAudit(t, db, "sg.rule.add", "carol", sgID, "before=none after="+rule)

	rules, err := corrosion.ListSGRules(ctx, db, sgID)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules = %v (err %v)", rules, err)
	}
	w = serveRequest(s, uiSessionReq(t, "DELETE", "/ui/security-groups/rules/"+rules[0].ID, nil))
	assertStatus(t, w, http.StatusOK)
	wantUIAudit(t, db, "sg.rule.rm", "carol", rules[0].ID, "before="+rule+" after=none")

	// A second rule, so the group's removal has something of its own to record.
	w = serveRequest(s, uiSessionReq(t, "POST", "/ui/security-groups/"+sgID+"/rules", url.Values{
		"direction": {"egress"}, "proto": {"udp"}, "port_range": {"53"}, "action": {"drop"}, "priority": {"5"},
	}))
	assertStatus(t, w, http.StatusOK)
	w = serveRequest(s, uiSessionReq(t, "DELETE", "/ui/security-groups/"+sgID, nil))
	assertStatus(t, w, http.StatusOK)
	wantUIAudit(t, db, "sg.rm", "carol", sgID,
		"before={name=isolate rules=[{sg="+sgID+" egress udp port=53 cidr=any drop priority=5}]} after=none")
}
