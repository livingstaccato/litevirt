package ui

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The security-group page and the Add-NIC modal used to read the security
// group tables in-process, because no RPC listed them. Any logged-in session
// therefore saw every group and rule in the cluster, a scoped API token and a
// project-only grant included. They now read through ListSecurityGroups with
// the session's bearer, which checks sg.read at the cluster root as the writes
// check sg.write there.

const (
	sgSecretName = "sg-secret-name"
	sgSecretCIDR = "203.0.113.77/32"
)

func seedSecretSG(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-1", Name: sgSecretName}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{
		ID: "rule-1", SGID: "sg-1", Direction: "ingress", Proto: "tcp", PortRange: "8443", CIDR: sgSecretCIDR,
	}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}
}

func assertNoSGLeak(t *testing.T, what, body string) {
	t.Helper()
	for _, secret := range []string{sgSecretName, sgSecretCIDR} {
		if strings.Contains(body, secret) {
			t.Errorf("%s showed %q, which ListSecurityGroups refuses this session", what, secret)
		}
	}
}

func TestUISecurityGroups_AScopedTokenSessionCannotReadThem(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "ada", "admin")
	seedSecretSG(t, db)
	scopeUISession(t, db, `["/projects/teamA"]`)

	w := serveRequest(s, uiSessionReq(t, "GET", "/security-groups", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("a scoped token reading security groups: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	assertNoSGLeak(t, "/security-groups", w.Body.String())
}

func TestUISecurityGroups_AProjectScopedGrantCannotReadThem(t *testing.T) {
	s, db, _ := newUIBoundAt(t, "pat", "/projects/teamA", "Admin")
	seedSecretSG(t, db)

	w := serveRequest(s, uiSessionReq(t, "GET", "/security-groups", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("a project-scoped grant reading security groups: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	assertNoSGLeak(t, "/security-groups", w.Body.String())
}

func TestUISecurityGroups_AClusterViewerStillReadsThem(t *testing.T) {
	s, db := newUIBoundTo(t, "vera", "Viewer")
	seedSecretSG(t, db)

	w := serveRequest(s, uiSessionReq(t, "GET", "/security-groups", nil))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), sgSecretName, "sg-1", sgSecretCIDR, ":8443", "tcp", "ingress",
		`hx-delete="/ui/security-groups/sg-1"`, `hx-delete="/ui/security-groups/rules/rule-1"`)
}

func TestUIAddNICModal_ListsSecurityGroupsOnlyToASessionThatMayReadThem(t *testing.T) {
	t.Run("scoped token", func(t *testing.T) {
		s, db := newUIOverRealDaemon(t, "ada", "admin")
		seedSecretSG(t, db)
		scopeUISession(t, db, `["/projects/teamA"]`)
		w := serveRequest(s, uiSessionReq(t, "GET", "/ui/vms/vm-x/add-nic-modal", nil))
		assertNoSGLeak(t, "the Add-NIC modal", w.Body.String())
	})
	t.Run("cluster viewer", func(t *testing.T) {
		s, db := newUIBoundTo(t, "vera", "Viewer")
		seedSecretSG(t, db)
		w := serveRequest(s, uiSessionReq(t, "GET", "/ui/vms/vm-x/add-nic-modal", nil))
		mustContain(t, w.Body.String(), `<option value="`+sgSecretName+`">`)
	})
}

// whoamiDown is the daemon during an outage that hits Whoami and nothing else:
// sessionValid cannot tell whether the session is still good, and fails OPEN
// for a read. Every other RPC still reaches the real daemon.
type whoamiDown struct{ pb.LiteVirtClient }

func (whoamiDown) Whoami(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.WhoamiResponse, error) {
	return nil, status.Error(codes.Unavailable, "whoami: connection refused")
}

// sessionValid lets a READ through when Whoami fails with anything but
// Unauthenticated. That is safe only while every read handler gets its data
// from an RPC called with the session's bearer: the daemon then refuses a dead
// session on the read itself. This test is that claim, made against every GET
// page and fragment the UI serves: with Whoami down and the session revoked or
// expired, no handler may render the cluster state seeded below.
func TestUIReads_DuringAWhoamiOutageADeadSessionGetsNoData(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	routeRe := regexp.MustCompile(`mux\.HandleFunc\("GET (/[^"]*)", s\.requireAuthFunc\(`)
	var routes []string
	for _, m := range routeRe.FindAllStringSubmatch(string(src), -1) {
		routes = append(routes, regexp.MustCompile(`\{[a-z]+\}`).ReplaceAllString(m[1], "x"))
	}
	if len(routes) < 100 {
		t.Fatalf("found %d authenticated GET routes in server.go, want the full set (>= 100); has the registration shape changed?", len(routes))
	}

	kill := map[string]string{
		"revoked": `UPDATE tokens SET deleted_at = '2000-01-01T00:00:00Z' WHERE id = 'ui-session'`,
		"expired": `UPDATE tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE id = 'ui-session'`,
	}
	for how, stmt := range kill {
		t.Run(how, func(t *testing.T) {
			s, db := newUIOverRealDaemon(t, "ada", "admin")
			seedSecretSG(t, db)
			seedSecretFirewall(t, db)
			seedOtherTenantsBindings(t, db)
			seedSecretMapping(t, db)
			if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
				Name: "x", HostName: "host-secret", Spec: "{}", State: "running",
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}

			// Control: while the session is alive, the daemon hands this
			// session the data, so a page that shows none of it below was
			// refused, not empty.
			if w := serveRequest(s, uiSessionReq(t, "GET", "/security-groups", nil)); !strings.Contains(w.Body.String(), sgSecretName) {
				t.Fatalf("control: a live admin session did not see the seeded security group (status %d)", w.Code)
			}

			if err := db.Execute(context.Background(), stmt); err != nil {
				t.Fatalf("kill the session token: %v", err)
			}
			if _, err := s.grpc.Whoami(withBearerToken(context.Background(), fwAuditSessionToken), &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("precondition: the daemon still accepts the %s session (Whoami err = %v)", how, err)
			}
			s.grpc = whoamiDown{s.grpc}

			secrets := []string{sgSecretName, sgSecretCIDR, "fw-secret-comment", "blocklist-secret",
				"198.51.100.0/24", "user:bob@local", "secretco", "gpu-secret", "kvm-07", "host-secret"}
			// A secret that a template prints anyway (a placeholder, an
			// example) would fail for a page that read nothing.
			tmpls, _ := os.ReadDir("templates")
			for _, e := range tmpls {
				b, _ := os.ReadFile("templates/" + e.Name())
				for _, secret := range secrets {
					if strings.Contains(string(b), secret) {
						t.Fatalf("templates/%s contains %q itself; pick a seed value no template prints", e.Name(), secret)
					}
				}
			}
			for _, route := range routes {
				done := make(chan string, 1)
				go func() {
					w := serveRequest(s, uiSessionReq(t, "GET", route, nil))
					done <- w.Body.String()
				}()
				select {
				case body := <-done:
					for _, secret := range secrets {
						if strings.Contains(body, secret) {
							t.Errorf("GET %s with a %s session during a Whoami outage rendered %q", route, how, secret)
						}
					}
				case <-time.After(10 * time.Second):
					t.Errorf("GET %s with a %s session during a Whoami outage did not answer in 10s", route, how)
				}
			}
		})
	}
}
