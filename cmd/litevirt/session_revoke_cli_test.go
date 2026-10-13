package main

import (
	"testing"
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
