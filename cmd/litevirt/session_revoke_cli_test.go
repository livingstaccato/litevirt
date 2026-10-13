package main

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// O10: `lv session ls` shows the id's first 12 characters followed by "…".
// Pasting that cell revokes the session: the ellipsis is not part of the id.
func TestSessionRevoke_AcceptsTheListedShortForm(t *testing.T) {
	m := newMockClient()
	if _, _, err := runCmd(t, m, "session", "revoke", "abcdef123456…"); err != nil {
		t.Fatalf("session revoke: %v", err)
	}
	if m.revokedSession != "abcdef123456" {
		t.Fatalf("RevokeSession id %q, want abcdef123456", m.revokedSession)
	}
}

// C1 (round 1): the daemon marks the caller's own session; ls shows it.
func TestSessionLs_MarksTheCurrentSession(t *testing.T) {
	m := newMockClient()
	m.sessions = []*pb.Session{
		{Id: "aaaaaaaaaaaa", Username: "alice", Current: true},
		{Id: "bbbbbbbbbbbb", Username: "alice"},
	}
	stdout, _, err := runCmd(t, m, "session", "ls")
	if err != nil {
		t.Fatalf("session ls: %v", err)
	}
	var cur, other string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.Contains(l, "aaaaaaaaaaaa") {
			cur = l
		}
		if strings.Contains(l, "bbbbbbbbbbbb") {
			other = l
		}
	}
	if !strings.Contains(cur, "*") || strings.Contains(other, "*") {
		t.Fatalf("ls output:\n%s\nwant only the current session marked *", stdout)
	}
}

// M6 (round 1), F1 (round 3): a short-id NotFound carries the older-daemon
// hint only when the daemon is older (it lists full session ids); against a
// current daemon (it lists handles) it is a plain not-found.
func TestSessionRevoke_OlderDaemonHintOnlyAgainstAnOlderDaemon(t *testing.T) {
	notFound := status.Error(codes.NotFound, "session not found")

	older := newMockClient()
	older.revokeSessionErr = notFound
	older.sessions = []*pb.Session{{Id: strings.Repeat("a", 64), Username: "alice"}}
	_, _, err := runCmd(t, older, "session", "revoke", "abcdef123456")
	if err == nil || !strings.Contains(err.Error(), "older") || !strings.Contains(err.Error(), "full") {
		t.Fatalf("older daemon: err %v, want the older-daemon hint", err)
	}

	current := newMockClient()
	current.revokeSessionErr = notFound
	current.sessions = []*pb.Session{{Id: "aaaaaaaaaaaa", Username: "alice", Current: true}}
	_, _, err = runCmd(t, current, "session", "revoke", "abcdef123456")
	if err == nil || strings.Contains(err.Error(), "older") || !strings.Contains(err.Error(), "session not found") {
		t.Fatalf("current daemon: err %v, want a plain not-found", err)
	}

	none := newMockClient()
	none.revokeSessionErr = notFound
	_, _, err = runCmd(t, none, "session", "revoke", "abcdef123456")
	if err == nil || strings.Contains(err.Error(), "older") {
		t.Fatalf("no sessions listed: err %v, want a plain not-found", err)
	}
}
