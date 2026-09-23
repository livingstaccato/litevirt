package corrosion

import (
	"context"
	"testing"
)

// TestCredentialsUnhydrated_SetByTheDiscard is the reseed's auth fail-open.
//
// DiscardReplicatedStateForReseed DELETEs the secret-bearing tables --
// user_2fa, user_2fa_sets, recovery_codes, recovery_code_sets,
// registry_credentials -- and the code comment names the hazard outright: "a
// window in which this node has no 2FA factors at all, and the API reads 'no
// factors' as 'no 2FA' -- a discard that fails OPEN." It then relied on the
// caller to close that window.
//
// The caller cannot. fetchPeerSensitiveDump can succeed and
// MergeSensitiveStateBytesLWW still fail -- a transient DB error, a truncated
// stream, SQLITE_BUSY, a crash -- and the RPC error it returns does not stop
// the daemon serving. Every enrolled operator then logs in against that node
// with a password alone, and the state persists until someone repeats the
// reseed.
//
// So the emptiness is made SELF-REFUSING: the discard marks the node
// unhydrated, and only a verified sensitive merge clears it.
func TestCredentialsUnhydrated_SetByTheDiscard(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()

	if c.CredentialsUnhydrated() {
		t.Fatal("a fresh node must not start out unhydrated")
	}
	if _, err := c.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if !c.CredentialsUnhydrated() {
		t.Fatal("the discard emptied user_2fa and friends without marking the node " +
			"unhydrated; an empty user_2fa reads as 'this user has no second factor'")
	}
	c.ClearCredentialsUnhydrated()
	if c.CredentialsUnhydrated() {
		t.Fatal("a verified sensitive merge must clear the mark")
	}
}

// TestCredentialsUnhydrated_SurvivesARestart covers the case the in-memory flag
// alone cannot: the process dies between the discard and the merge, and comes
// back up with a populated `users` table and an empty `user_2fa`.
func TestCredentialsUnhydrated_SurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	c := newTestDB(t)
	c.SetDataDirForTest(dir)
	if _, err := c.DiscardReplicatedStateForReseed(context.Background()); err != nil {
		t.Fatalf("discard: %v", err)
	}

	// A "restart": a second client over the same data directory, with no
	// in-memory carry.
	fresh := newTestDB(t)
	fresh.SetDataDirForTest(dir)
	if !fresh.CredentialsUnhydrated() {
		t.Fatal("a node that crashed between the discard and the sensitive merge came back " +
			"reading as hydrated; every enrolled operator would log in with a password alone")
	}
}
