package grpcapi

import (
	"context"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// resetAdminFixture is a signing server named test-host with a live admin and
// its own host row, so a loopback call presenting test-host's certificate
// authenticates as local-root through the real interceptor logic.
func resetAdminFixture(t *testing.T) *Server {
	t.Helper()
	s, _, _ := retireFixture(t, "test-host")
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "test-host", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "other-host", Address: "10.0.0.2", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertUser(ctx, s.db, "admin", "admin", "old-hash"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	return s
}

// authedCtx runs the real authenticate() over a synthetic transport.
func authedCtx(t *testing.T, s *Server, cn string, addr net.Addr, bearer string) (context.Context, error) {
	t.Helper()
	return s.authenticate(mtlsPeerCtx(cn, addr, bearer))
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), auth.BcryptCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func resetAdminRows(t *testing.T, s *Server) []corrosion.Row {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash, key_id, signature
		 FROM audit_log WHERE action = 'user.reset-admin'`)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	return rows
}

// TestResetAdminPassword_LocalRootResetsAndAuditsOnce is the daemon-up path end
// to end at the handler: the hash lands, exactly one signed row names root on
// this host and the admin account, the chain verifies clean, and neither the
// password nor its hash is anywhere in the row.
func TestResetAdminPassword_LocalRootResetsAndAuditsOnce(t *testing.T) {
	s := resetAdminFixture(t)
	ctx, err := authedCtx(t, s, "test-host", tcpAddr("127.0.0.1"), "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	const password = "0123456789abcdef-the-new-secret"
	hash := mustHash(t, password)

	if _, err := s.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{PasswordHash: hash, OsUser: "tim"}); err != nil {
		t.Fatalf("ResetAdminPassword: %v", err)
	}

	u, err := corrosion.GetUser(context.Background(), s.db, "admin")
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v %v", u, err)
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		t.Fatal("the admin's stored hash does not accept the new password")
	}

	rows := resetAdminRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("%d user.reset-admin rows, want exactly 1", len(rows))
	}
	r := rows[0]
	if r.String("username") != "root@test-host" || r.String("host_name") != "test-host" ||
		r.String("target") != "admin" || r.String("result") != "ok" {
		t.Errorf("row = user %q host %q target %q result %q; want root@test-host, test-host, admin, ok",
			r.String("username"), r.String("host_name"), r.String("target"), r.String("result"))
	}
	if !strings.Contains(r.String("detail"), "via=local-root") || !strings.Contains(r.String("detail"), "os_user=tim") {
		t.Errorf("detail = %q, want the channel and the reported OS user", r.String("detail"))
	}
	if r.String("signature") == "" {
		t.Error("the reset row is unsigned")
	}
	for _, col := range []string{"id", "timestamp", "username", "host_name", "action", "target", "detail", "result"} {
		v := r.String(col)
		if strings.Contains(v, password) || strings.Contains(v, hash) || strings.Contains(v, "$2a$") {
			t.Errorf("audit column %s carries secret material: %q", col, v)
		}
	}

	res, err := corrosion.VerifyAuditChain(context.Background(), s.db)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.Tampered() || res.Unsigned != 0 {
		t.Fatalf("`lv audit verify` is not clean after a reset: %+v", res)
	}
}

// TestResetAdminPassword_OnlyLocalRoot: every other caller is refused and
// nothing changes. Each of these is admin to the rest of the API, which is the
// point: holding a session or a peer certificate is not root on this host.
func TestResetAdminPassword_OnlyLocalRoot(t *testing.T) {
	s := resetAdminFixture(t)
	sess, _, _, err := s.mintSession(context.Background(), "admin", "local", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("mintSession: %v", err)
	}
	cases := []struct {
		name   string
		cn     string
		addr   net.Addr
		bearer string
	}{
		{"peer over the network", "test-host", tcpAddr("10.0.0.7"), ""},
		{"another host's certificate over loopback", "other-host", tcpAddr("127.0.0.1"), ""},
		{"client certificate over loopback", "lv-cli", tcpAddr("127.0.0.1"), ""},
		{"admin session over loopback", "test-host", tcpAddr("127.0.0.1"), sess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := authedCtx(t, s, tc.cn, tc.addr, tc.bearer)
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			_, err = s.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{PasswordHash: mustHash(t, "x")})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want PermissionDenied", err)
			}
		})
	}
	u, _ := corrosion.GetUser(context.Background(), s.db, "admin")
	if u == nil || u.PasswordHash != "old-hash" {
		t.Fatalf("a refused caller changed the admin password")
	}
	if n := len(resetAdminRows(t, s)); n != 0 {
		t.Errorf("%d reset rows written for refused callers, want 0 (the interceptor-level refusal is not a reset attempt)", n)
	}
}

// TestResetAdminPassword_RefusesWhatIsNotAStrongBcryptHash: the daemon stores
// what it is sent, so a plaintext or a weak hash must not become the admin
// credential.
func TestResetAdminPassword_RefusesWhatIsNotAStrongBcryptHash(t *testing.T) {
	s := resetAdminFixture(t)
	ctx, err := authedCtx(t, s, "test-host", tcpAddr("127.0.0.1"), "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	// The package's TestMain drops the cost to MinCost for speed; raise the floor
	// one step so a MinCost hash is genuinely below it.
	prev := auth.BcryptCost
	auth.BcryptCost = bcrypt.MinCost + 1
	t.Cleanup(func() { auth.BcryptCost = prev })
	weak, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	for _, h := range []string{"hunter2", string(weak)} {
		_, err := s.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{PasswordHash: h})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("hash %.10q: err = %v, want InvalidArgument", h, err)
		}
	}
	if u, _ := corrosion.GetUser(context.Background(), s.db, "admin"); u == nil || u.PasswordHash != "old-hash" {
		t.Fatal("a rejected hash was stored")
	}
}

// TestResetAdminPassword_NoAdminIsRefusedAndAudited: the daemon path keeps the
// CLI's rule (reset, never create), and the refused attempt is itself on record.
func TestResetAdminPassword_NoAdminIsRefusedAndAudited(t *testing.T) {
	s := resetAdminFixture(t)
	if err := corrosion.DeleteUser(context.Background(), s.db, "admin"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	ctx, err := authedCtx(t, s, "test-host", tcpAddr("127.0.0.1"), "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	_, err = s.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{PasswordHash: mustHash(t, "x")})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if u, _ := corrosion.GetUser(context.Background(), s.db, "admin"); u != nil {
		t.Fatal("reset-admin resurrected a deleted admin")
	}
	rows := resetAdminRows(t, s)
	if len(rows) != 1 || !strings.HasPrefix(rows[0].String("result"), "denied") {
		t.Fatalf("want one denied reset row, got %d", len(rows))
	}
}
