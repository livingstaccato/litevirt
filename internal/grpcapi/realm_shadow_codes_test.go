package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// stubRealm authenticates every login as one external subject.
type stubRealm struct{ subject string }

func (r stubRealm) Name() string { return "ldap:corp" }
func (r stubRealm) Authenticate(context.Context, auth.Credentials) (*auth.Principal, error) {
	return &auth.Principal{Subject: r.subject, Realm: "ldap:corp"}, nil
}
func (r stubRealm) SyncGroups(context.Context) error { return nil }

func ldapLogin(s *Server, subject string) error {
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	reg.Register(stubRealm{subject: subject})
	s.SetRealmRegistry(reg)
	_, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "ldap:corp", Username: subject, Password: "x"})
	return err
}

// TestLogin_ExternalUserWithoutEvidence (re-review 2, N2): an external login
// under a users row with no local password and no evidence is refused with a
// code that says what to do — Unavailable ("retry") while this node cannot
// decide yet, FailedPrecondition naming `lv user mark-external` once it is up
// to date — never Internal. An administrator's mark then lets it in.
func TestLogin_ExternalUserWithoutEvidence(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	// A legacy external user, written directly: no host vouches for it.
	if err := s.db.Execute(ctx, `INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"legacy", "viewer", "", "2025-01-01T00:00:00Z", s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, s.db, "local", "operator", "$2a$10$local-hash"); err != nil {
		t.Fatal(err)
	}
	s.db.SetCredentialsSplitGate(func() bool { return true })
	s.db.SetCredentialsClearGate(func() bool { return true })

	// Not credentials-live yet: transient.
	if err := ldapLogin(s, "legacy"); status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "retry") {
		t.Errorf("before the first pass: %v, want Unavailable with retry", err)
	}
	if _, err := s.db.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	// Live, and still no evidence: durable, naming the admin action.
	err := ldapLogin(s, "legacy")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv user mark-external legacy") {
		t.Fatalf("after the first pass: %v, want FailedPrecondition naming `lv user mark-external legacy`", err)
	}

	if _, err := s.MarkUserExternal(adminCtx(), &pb.MarkUserExternalRequest{Username: "local"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("marking an account with a password external: %v, want FailedPrecondition", err)
	}
	if _, err := s.MarkUserExternal(ctx, &pb.MarkUserExternalRequest{Username: "legacy"}); status.Code(err) == codes.OK {
		t.Error("a caller without the admin role marked a user external")
	}
	if _, err := s.MarkUserExternal(adminCtx(), &pb.MarkUserExternalRequest{Username: "legacy"}); err != nil {
		t.Fatalf("MarkUserExternal: %v", err)
	}
	if err := ldapLogin(s, "legacy"); err != nil {
		t.Errorf("after the admin's mark the external login is still refused: %v", err)
	}
	if err := ldapLogin(s, "local"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an external login under a local account: %v, want PermissionDenied", err)
	}
}
