package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func auditRowsOf(t *testing.T, s *Server, action string) []map[string]string {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT username, target, detail, result FROM audit_log WHERE action = ? ORDER BY timestamp, rowid`, action)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, r := range rows {
		out = append(out, map[string]string{"username": r.String("username"), "target": r.String("target"), "detail": r.String("detail"), "result": r.String("result")})
	}
	return out
}

// (re-review rr1 N5) A pool create refused on the node it entered — not
// forwarded — is audited as the operator.
//
// Mutation: register the create audit for a forwarded create only — red.
func TestPoolTrust_ALocalCreateRefusalIsAudited(t *testing.T) {
	s := trustServer(t)
	_, err := s.CreateStoragePool(trustOperatorCtx("oscar"), &pb.CreateStoragePoolRequest{Name: "p", Driver: "dir", Target: filepath.Join(t.TempDir(), "p")})
	if err == nil {
		t.Fatal("an operator named a host path in a create")
	}
	rows := auditRowsOf(t, s, "storage.pool.create")
	if len(rows) != 1 || rows[0]["username"] != "oscar" || !strings.HasPrefix(rows[0]["result"], "error: PermissionDenied") {
		t.Fatalf("create audit = %v, want oscar's refusal", rows)
	}
}

// (re-review rr1 N6) The trust audit is written only once the name is a
// valid pool name, and the strings the request carries are quoted (a control
// character escaped) and capped.
//
// Mutations: register the audit before the name is validated — the invalid
// name is audited, red; write the raw strings — the escape and the cap are
// missing, red.
func TestPoolTrust_TheAuditRecordsValidatedQuotedValues(t *testing.T) {
	s := trustServer(t)
	if _, err := s.TrustStoragePool(adminCtx(), &pb.TrustStoragePoolRequest{Name: "bad/\x1b[2Jname", Driver: "dir", Target: "/srv/x"}); err == nil {
		t.Fatal("an invalid pool name was accepted")
	}
	if rows := auditRowsOf(t, s, "storage.pool.trust"); len(rows) != 0 {
		t.Fatalf("an invalid name was audited: %v", rows)
	}
	long := "/srv/" + strings.Repeat("a", 5000) + "\x1b[8m"
	forgeRow(t, s, "x", filepath.Join(t.TempDir(), "x"))
	if _, err := s.TrustStoragePool(adminCtx(), &pb.TrustStoragePoolRequest{Name: "x", Driver: "dir", Source: "s\x1b[8m", Target: long}); err == nil {
		t.Fatal("a mismatching confirmation was accepted")
	}
	rows := auditRowsOf(t, s, "storage.pool.trust")
	if len(rows) != 1 {
		t.Fatalf("trust audit = %v, want one refusal", rows)
	}
	d := rows[0]["detail"]
	if strings.Contains(d, "\x1b") || !strings.Contains(d, `\x1b`) || len(d) > 4*auditFieldMax {
		t.Fatalf("audit detail not quoted and capped (%d bytes): %q", len(d), d)
	}
}
