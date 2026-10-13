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

// M6 (round 1): a short id NotFound from a daemon too old to resolve prefixes
// says so instead of only "session not found".
func TestSessionRevoke_ShortIdNotFoundHintsAtAnOlderDaemon(t *testing.T) {
	m := newMockClient()
	m.revokeSessionErr = status.Error(codes.NotFound, "session not found")
	_, _, err := runCmd(t, m, "session", "revoke", "abcdef123456")
	if err == nil || !strings.Contains(err.Error(), "older") || !strings.Contains(err.Error(), "full session id") {
		t.Fatalf("err %v: want a hint about an older daemon needing the full session id", err)
	}
}
