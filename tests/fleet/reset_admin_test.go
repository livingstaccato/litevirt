// Fleet scenario: `lv user reset-admin` with the daemon running.
//
// internal/grpcapi covers the handler with a synthetic transport. What only the
// fleet reaches is the real one: the CLI's own local-root dial (cli.ConnectLocalRoot)
// over real TLS into the real auth interceptor, and the audit row travelling to
// peers that verify it with nothing but the cluster CA and what replicated.

package fleet

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_ResetAdminIsAuditedAndVerifiesEverywhere: a reset through the local
// root channel lands on every node with exactly one signed user.reset-admin row
// that every node verifies clean, and the password works cluster-wide.
func TestFleet_ResetAdminIsAuditedAndVerifiesEverywhere(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, cc := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	for _, n := range []*Node{a, b, cc} {
		signNode(t, n)
	}
	if err := corrosion.InsertUser(ctx, a.DB, "admin", "admin", "old-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	// Exactly what `lv user reset-admin` dials on node-0.
	client, closeConn, err := cli.ConnectLocalRoot(a.PKIDir, a.Port)
	if err != nil {
		t.Fatalf("ConnectLocalRoot: %v", err)
	}
	defer closeConn()
	const password = "fleet-reset-password-0123456789"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{
		PasswordHash: string(hash), OsUser: "tim",
	}); err != nil {
		t.Fatalf("ResetAdminPassword over the local root channel: %v", err)
	}

	dump := pullDump(t, c, a)
	b.DB.MergeStateBytesLWW(dump)
	cc.DB.MergeStateBytesLWW(dump)

	for _, n := range []*Node{a, b, cc} {
		rows, err := n.DB.Query(ctx, `SELECT username, host_name, detail, result, signature
			FROM audit_log WHERE action = 'user.reset-admin'`)
		if err != nil {
			t.Fatalf("query on %s: %v", n.Name, err)
		}
		if len(rows) != 1 {
			t.Fatalf("%s holds %d user.reset-admin rows, want exactly 1", n.Name, len(rows))
		}
		r := rows[0]
		if r.String("username") != "root@node-0" || r.String("host_name") != "node-0" ||
			r.String("result") != "ok" || r.String("signature") == "" {
			t.Errorf("%s: row = %q on %q result %q signed=%v", n.Name, r.String("username"),
				r.String("host_name"), r.String("result"), r.String("signature") != "")
		}
		if d := r.String("detail"); strings.Contains(d, password) || strings.Contains(d, string(hash)) {
			t.Errorf("%s: the audit detail carries secret material: %q", n.Name, d)
		}
		res := verifyOn(t, n)
		if res.Tampered() || res.Unsigned != 0 || res.Unverifiable != 0 {
			t.Fatalf("`lv audit verify` on %s is not clean after the reset: %+v", n.Name, res)
		}
		u, err := corrosion.GetUser(ctx, n.DB, "admin")
		if err != nil || u == nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
			t.Errorf("%s: the new admin password does not verify there (%v)", n.Name, err)
		}
	}
}

// TestFleet_ResetAdminRefusesAnyoneButLocalRoot: over the real stack, a peer's
// certificate — even arriving on loopback, as every fleet peer does — and an
// admin session are refused, and nothing is reset.
func TestFleet_ResetAdminRefusesAnyoneButLocalRoot(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a, b := c.Node("node-0"), c.Node("node-1")
	if err := corrosion.InsertUser(ctx, a.DB, "admin", "admin", "old-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), auth.BcryptCost)
	req := &pb.ResetAdminPasswordRequest{PasswordHash: string(hash)}

	if _, err := c.PeerClient(b, a).ResetAdminPassword(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("node-1's certificate: err = %v, want PermissionDenied", err)
	}

	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{Username: "ops", Password: "ops-pass", Role: "admin"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	login, err := c.SelfClient(a).Login(ctx, &pb.LoginRequest{Username: "ops", Password: "ops-pass"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := c.bearerClient(a, login.Token).ResetAdminPassword(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("admin session: err = %v, want PermissionDenied", err)
	}

	if u, _ := corrosion.GetUser(ctx, a.DB, "admin"); u == nil || u.PasswordHash != "old-hash" {
		t.Fatal("a refused caller reset the admin password")
	}
}
