package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func loginID(t *testing.T, s *Server, ctx context.Context, user string) string {
	t.Helper()
	resp, err := s.Login(ctx, &pb.LoginRequest{Username: user, Password: "hunter2"})
	if err != nil {
		t.Fatalf("Login(%s): %v", user, err)
	}
	return strings.TrimPrefix(resp.Token, SessionTokenPrefix)
}

func revokedAt(t *testing.T, s *Server, id string) string {
	t.Helper()
	sess, err := corrosion.GetSession(context.Background(), s.db, id)
	if err != nil || sess == nil {
		t.Fatalf("GetSession(%s): %v %v", id, sess, err)
	}
	return sess.RevokedAt
}

// insertSessionWithID plants a session whose id is chosen by the test, so two
// can share a prefix.
func insertSessionWithID(t *testing.T, s *Server, id, user string) {
	t.Helper()
	now := time.Now().UTC()
	if err := corrosion.InsertSession(context.Background(), s.db, corrosion.SessionRecord{
		ID: id, Username: user, Realm: "local", IP: "192.0.2.1",
		CreatedAt: now.Format(time.RFC3339), LastUsedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("InsertSession: %v", err)
	}
}

// O10: `lv session ls` shows a 12-character prefix of the id, which is also
// the session's bearer secret and so is never shown in full. An admin must be
// able to revoke another user's session with what ls shows.
func TestRevokeSession_AdminRevokesAnotherUsersSessionByListedPrefix(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "bob", "viewer", "hunter2")
	id := loginID(t, s, context.Background(), "bob")

	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: id[:12]}); err != nil {
		t.Fatalf("RevokeSession(prefix): %v", err)
	}
	if revokedAt(t, s, id) == "" {
		t.Fatal("bob's session is still live after the admin revoked it by its listed prefix")
	}
}

// The owner may revoke their own session by prefix, as they may by full id.
func TestRevokeSession_OwnerRevokesOwnByPrefix(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	id := loginID(t, s, context.Background(), "alice")
	if _, err := s.RevokeSession(userCtx("alice", "viewer"), &pb.RevokeSessionRequest{Id: id[:12]}); err != nil {
		t.Fatalf("RevokeSession(own prefix): %v", err)
	}
	if revokedAt(t, s, id) == "" {
		t.Fatal("alice's own session is still live")
	}
}

// A non-admin's prefix resolves only among their own sessions: another user's
// session is NotFound — not PermissionDenied, which would confirm it exists —
// and is left live.
func TestRevokeSession_NonAdminPrefixNeverReachesOthers(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	seedUser(t, s, "bob", "viewer", "hunter2")
	bob := loginID(t, s, context.Background(), "bob")

	_, err := s.RevokeSession(userCtx("alice", "viewer"), &pb.RevokeSessionRequest{Id: bob[:12]})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("non-admin revoking another user's session by prefix: got %v, want NotFound", err)
	}
	if revokedAt(t, s, bob) != "" {
		t.Fatal("a non-admin revoked another user's session")
	}
}

// A non-admin's ambiguity is computed over their own sessions only: another
// user's session sharing the prefix neither blocks the revoke nor is touched,
// and its existence is not revealed.
func TestRevokeSession_NonAdminAmbiguityIgnoresOthers(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	seedUser(t, s, "bob", "viewer", "hunter2")
	aliceID := "abcdef12" + strings.Repeat("1", 56)
	bobID := "abcdef12" + strings.Repeat("2", 56)
	insertSessionWithID(t, s, aliceID, "alice")
	insertSessionWithID(t, s, bobID, "bob")

	if _, err := s.RevokeSession(userCtx("alice", "viewer"), &pb.RevokeSessionRequest{Id: "abcdef12"}); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if revokedAt(t, s, aliceID) == "" {
		t.Fatal("alice's session is still live")
	}
	if revokedAt(t, s, bobID) != "" {
		t.Fatal("bob's session was revoked by alice's prefix")
	}
}

// An ambiguous prefix is refused, names the matches by their short form, and
// revokes nothing.
func TestRevokeSession_AmbiguousPrefixRefused(t *testing.T) {
	s := testServer(t)
	a := "abcdef12" + strings.Repeat("1", 56)
	b := "abcdef12" + strings.Repeat("2", 56)
	insertSessionWithID(t, s, a, "alice")
	insertSessionWithID(t, s, b, "bob")

	_, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: "abcdef12"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ambiguous prefix: got %v, want InvalidArgument", err)
	}
	msg := status.Convert(err).Message()
	for _, want := range []string{"abcdef121111", "abcdef122222", "alice", "bob"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not name %q", msg, want)
		}
	}
	if strings.Contains(msg, a) || strings.Contains(msg, b) {
		t.Errorf("refusal %q discloses a full session id (the bearer secret)", msg)
	}
	if revokedAt(t, s, a) != "" || revokedAt(t, s, b) != "" {
		t.Fatal("an ambiguous prefix revoked a session")
	}
}

// A prefix too short to name a session with confidence is refused outright.
func TestRevokeSession_ShortPrefixRefused(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "bob", "viewer", "hunter2")
	id := loginID(t, s, context.Background(), "bob")
	_, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: id[:4]})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("4-char prefix: got %v, want InvalidArgument", err)
	}
	if revokedAt(t, s, id) != "" {
		t.Fatal("a 4-character prefix revoked a session")
	}
}

// A revoked session is not a prefix candidate.
func TestRevokeSession_PrefixSkipsRevoked(t *testing.T) {
	s := testServer(t)
	a := "abcdef12" + strings.Repeat("1", 56)
	b := "abcdef12" + strings.Repeat("2", 56)
	insertSessionWithID(t, s, a, "alice")
	insertSessionWithID(t, s, b, "bob")
	if err := corrosion.RevokeSession(context.Background(), s.db, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: "abcdef12"}); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if revokedAt(t, s, b) == "" {
		t.Fatal("the one live match was not revoked")
	}
}

func sessionAudit(t *testing.T, s *Server, action string) []corrosion.Row {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT target, detail, result FROM audit_log WHERE action = ?`, action)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	return rows
}

// C1 (round 1): ListSessions never returns a session id, which is the bearer
// secret. It returns the 12-character handle RevokeSession takes, and marks the
// caller's own session itself so no client compares tokens.
func TestListSessions_ReturnsHandlesNeverTheBearer(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	a := loginID(t, s, context.Background(), "alice")
	b := loginID(t, s, context.Background(), "alice")

	ctx := context.WithValue(userCtx("alice", "viewer"), ctxKeySessionID, a)
	resp, err := s.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(resp.Sessions) != 2 {
		t.Fatalf("%d sessions, want 2", len(resp.Sessions))
	}
	current := 0
	for _, ss := range resp.Sessions {
		if ss.Id == a || ss.Id == b || len(ss.Id) != 12 {
			t.Fatalf("listed id %q: want a 12-character handle, never the session id", ss.Id)
		}
		if ss.Id != a[:12] && ss.Id != b[:12] {
			t.Fatalf("listed id %q is not a handle of either session", ss.Id)
		}
		if ss.Current {
			current++
			if ss.Id != a[:12] {
				t.Errorf("current is %q, want the caller's own %q", ss.Id, a[:12])
			}
		}
	}
	if current != 1 {
		t.Errorf("%d sessions marked current, want 1", current)
	}

	// An admin listing alice's sessions sees handles too, and none is current.
	resp, err = s.ListSessions(adminCtx(), &pb.ListSessionsRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ListSessions(admin): %v", err)
	}
	for _, ss := range resp.Sessions {
		if len(ss.Id) != 12 || ss.Current {
			t.Errorf("admin listing: %+v, want a handle and not current", ss)
		}
	}
	// The listed handle revokes the session.
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: resp.Sessions[0].Id}); err != nil {
		t.Fatalf("RevokeSession(listed handle): %v", err)
	}
}

// M1/M2 (round 1): the audit row and the log name the handle, never the
// secret; a refused revoke is audited as denied.
func TestRevokeSession_AuditsTheHandleAndDenials(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	seedUser(t, s, "bob", "viewer", "hunter2")
	bob := loginID(t, s, context.Background(), "bob")

	if _, err := s.RevokeSession(userCtx("alice", "viewer"), &pb.RevokeSessionRequest{Id: bob[:12]}); status.Code(err) != codes.NotFound {
		t.Fatalf("alice revoking bob's prefix: %v", err)
	}
	if _, err := s.RevokeSession(userCtx("alice", "viewer"), &pb.RevokeSessionRequest{Id: bob}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("alice revoking bob's full id: %v", err)
	}
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: bob[:12]}); err != nil {
		t.Fatalf("admin revoke: %v", err)
	}
	var ok, denied int
	for _, r := range sessionAudit(t, s, "session.revoke") {
		d := r.String("detail")
		if strings.Contains(d, bob) || strings.Contains(r.String("target"), bob) {
			t.Errorf("audit row %q / %q carries the full session id", r.String("target"), d)
		}
		if !strings.Contains(d, bob[:12]) {
			t.Errorf("audit detail %q does not name the handle %s", d, bob[:12])
		}
		switch r.String("result") {
		case "ok":
			ok++
		case "denied":
			denied++
		}
	}
	if ok != 1 || denied != 2 {
		t.Errorf("session.revoke rows: %d ok, %d denied; want 1 and 2", ok, denied)
	}
}

// M7 (round 1): an ambiguous long prefix discloses at most 16 characters of
// any match.
func TestRevokeSession_AmbiguousLongPrefixDisclosesLittle(t *testing.T) {
	s := testServer(t)
	common := strings.Repeat("ab", 20) // 40 characters
	a := common + strings.Repeat("1", 24)
	b := common + strings.Repeat("2", 24)
	insertSessionWithID(t, s, a, "alice")
	insertSessionWithID(t, s, b, "bob")
	_, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: common})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ambiguous long prefix: %v", err)
	}
	// The caller typed the 40 common characters; the refusal adds none.
	if msg := status.Convert(err).Message(); strings.Contains(msg, a[:len(common)+1]) || strings.Contains(msg, b[:len(common)+1]) ||
		!strings.Contains(msg, a[:16]+"…") {
		t.Errorf("refusal %q: want each match shown as its first 16 characters, nothing past the typed prefix", msg)
	}
}
