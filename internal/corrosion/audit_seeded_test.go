package corrosion

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func localClient(t *testing.T, dir string) *Client {
	t.Helper()
	c, err := NewLocalClient(dir, "node-0")
	if err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAuditSeeded_AnExistingMemberIsSeededAtItsFirstStart is the rolling
// upgrade: a member that already holds its own audit history, and is not
// holding its rows, is seeded the first time this build runs on it — no
// genesis, no peer — so a cluster upgraded node by node keeps admitting hosts.
// The decision survives a restart.
//
// Mutation: never grandfather (seeded only by genesis or a peer) — false.
func TestAuditSeeded_AnExistingMemberIsSeededAtItsFirstStart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	ins(t, c, "old-1", "node-0", "")
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); err != nil || !seeded {
		t.Fatalf("DecideAuditSeeded on a member with its own history = %v, %v; want seeded", seeded, err)
	}
	c.Close()
	c = localClient(t, dir)
	defer c.Close()
	if !c.AuditSeeded(ctx) {
		t.Fatal("the seeded decision did not survive a restart")
	}
}

// TestAuditSeeded_AFreshReplicaIsDecidedOnceAndNotGrandfatheredLater: a fresh
// replica — a rebuilt host — is not seeded, and writing rows of its own
// afterwards does not grandfather it on a restart: the decision is taken once
// per state.db.
//
// Mutation: re-decide on every start — the restart grandfathers it.
func TestAuditSeeded_AFreshReplicaIsDecidedOnceAndNotGrandfatheredLater(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); err != nil || seeded {
		t.Fatalf("DecideAuditSeeded on a fresh replica = %v, %v; want not seeded", seeded, err)
	}
	ins(t, c, "new-1", "node-0", "")
	c.Close()
	c = localClient(t, dir)
	defer c.Close()
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); err != nil || seeded {
		t.Fatalf("after a restart with rows of its own = %v, %v; want still not seeded", seeded, err)
	}
}

// TestAuditSeeded_AHeldReplicaIsNotGrandfathered: a replica holding its own
// audit rows is waiting for its history, whatever rows it has.
func TestAuditSeeded_AHeldReplicaIsNotGrandfathered(t *testing.T) {
	ctx := context.Background()
	c := localClient(t, t.TempDir())
	defer c.Close()
	ins(t, c, "old-1", "node-0", "")
	c.ResetAuditChainForTests()
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0", Target: 5})
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); err != nil || seeded {
		t.Fatalf("DecideAuditSeeded while held = %v, %v; want not seeded", seeded, err)
	}
}

// TestAuditSeeded_AMarkerForAnotherStateDBDoesNotCount: the marker is bound to
// the state.db it was written for. A replaced or reseeded state.db beside an old
// marker is undecided, and a fresh one is not seeded.
//
// Mutation: drop the incarnation comparison — the copied marker counts.
func TestAuditSeeded_AMarkerForAnotherStateDBDoesNotCount(t *testing.T) {
	ctx := context.Background()
	a, b := t.TempDir(), t.TempDir()
	ca := localClient(t, a)
	if err := ca.MarkAuditSeeded(ctx, "genesis"); err != nil {
		t.Fatal(err)
	}
	ca.Close()
	data, err := os.ReadFile(filepath.Join(a, AuditSeededFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, AuditSeededFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cb := localClient(t, b)
	defer cb.Close()
	if cb.AuditSeeded(ctx) {
		t.Fatal("a marker written for another state.db made this one seeded")
	}
}

// TestAuditSeeded_AnUnusableMarkerFailsClosed is M-N: a marker that exists and
// cannot be used is a decision — not seeded — not an absence. Read as
// undecided, the upgrade rule would grandfather a rebuilt host that has rows of
// its own by now.
//
// Mutation: treat an unparseable marker as undecided — the replica is
// grandfathered.
func TestAuditSeeded_AnUnusableMarkerFailsClosed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	defer c.Close()
	ins(t, c, "own-1", "node-0", "")
	if err := os.WriteFile(filepath.Join(dir, AuditSeededFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if seeded, _ := DecideAuditSeeded(ctx, c, "node-0"); seeded || c.AuditSeeded(ctx) {
		t.Fatal("an unusable marker re-opened the upgrade rule and seeded a replica holding rows of its own")
	}
	if c.AuditSeededProblem(ctx) == "" {
		t.Fatal("no problem reported for an unusable marker")
	}
}

// TestAuditSeeded_ADecisionThatCannotBeWrittenFailsClosed is M-N's other half:
// a decision that is not durable could be taken differently on the next start,
// so this process proceeds as not seeded and says why.
//
// Mutation: adopt the decision before writing it — seeded in memory.
func TestAuditSeeded_ADecisionThatCannotBeWrittenFailsClosed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	defer c.Close()
	ins(t, c, "own-1", "node-0", "")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); seeded || err == nil {
		t.Fatalf("DecideAuditSeeded with an unwritable marker = %v, %v; want not seeded and the error", seeded, err)
	}
	if c.AuditSeeded(ctx) || c.AuditSeededProblem(ctx) == "" {
		t.Fatal("an unrecorded decision was adopted, or no problem was reported")
	}
}

// TestAuditSeeded_AnOperatorAssertionSeedsOnce is M-O's way out of a cluster
// with no seeded replica: root creates the assertion file, the next start
// records the replica seeded and removes the file.
//
// Mutation: ignore the assertion — not seeded.
func TestAuditSeeded_AnOperatorAssertionSeedsOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	if seeded, _ := DecideAuditSeeded(ctx, c, "node-0"); seeded {
		t.Fatal("fixture: a fresh replica decided seeded")
	}
	c.Close()
	if err := os.WriteFile(filepath.Join(dir, AuditSeededAssertFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c = localClient(t, dir)
	defer c.Close()
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); !seeded || err != nil {
		t.Fatalf("with the operator's assertion = %v, %v; want seeded", seeded, err)
	}
	if _, err := os.Stat(filepath.Join(dir, AuditSeededAssertFileName)); !os.IsNotExist(err) {
		t.Fatalf("the assertion was not consumed: %v", err)
	}
}

// TestGapReason_NeverNamesSeqZero is M-P: a lowest-missing lookup that failed
// (0) falls back to the general wording rather than "seq 0 is missing".
func TestGapReason_NeverNamesSeqZero(t *testing.T) {
	if r := gapReason(5, 0); strings.Contains(r, "seq 0") {
		t.Fatalf("gapReason(5, 0) = %q", r)
	}
	if r := gapReason(5, 2); !strings.Contains(r, "seq 2 is missing") {
		t.Fatalf("gapReason(5, 2) = %q", r)
	}
}
