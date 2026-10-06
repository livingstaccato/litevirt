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

func writeAssertion(t *testing.T, c *Client, dir, content string) {
	t.Helper()
	if content == "<incarnation>" {
		inc, err := c.VoterIncarnation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		content = inc + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, AuditSeededAssertFileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertionRows(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT id FROM audit_log WHERE action = 'audit.seeded_asserted'`)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// TestAuditSeeded_AnOperatorAssertionSeedsOnce is the way out of a cluster with
// no seeded replica: root writes this state.db's incarnation into the assertion
// file, the next start records the replica seeded and removes the file.
//
// Mutation: ignore the assertion — not seeded.
func TestAuditSeeded_AnOperatorAssertionSeedsOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	defer c.Close()
	writeAssertion(t, c, dir, "<incarnation>")
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); !seeded || err != nil {
		t.Fatalf("with the operator's assertion = %v, %v; want seeded", seeded, err)
	}
	if _, err := os.Stat(filepath.Join(dir, AuditSeededAssertFileName)); !os.IsNotExist(err) {
		t.Fatalf("the assertion was not consumed: %v", err)
	}
}

// TestAuditSeeded_AnAssertionNotNamingThisStateDBIsIgnored is I-E: anyone who
// can place a file in data_dir without being root on the node (a storage pool
// aimed at it) does not know this state.db's incarnation, which is never
// replicated. A file without it is ignored — and so is one left behind for an
// earlier state.db.
//
// Mutation: drop the content check — the blind write seeds the replica.
func TestAuditSeeded_AnAssertionNotNamingThisStateDBIsIgnored(t *testing.T) {
	ctx := context.Background()
	for _, content := range []string{"", "x", "0123456789abcdef0123456789abcdef"} {
		dir := t.TempDir()
		c := localClient(t, dir)
		writeAssertion(t, c, dir, content)
		if seeded, _ := DecideAuditSeeded(ctx, c, "node-0"); seeded || c.AuditSeeded(ctx) {
			t.Errorf("an assertion containing %q seeded the replica", content)
		}
		c.Close()
	}
}

// TestAuditSeeded_AnAssertionIsAuditedOnceSigned is I-D: the cluster's audit log
// records that this node vouches on an operator's word — one signed row,
// written once the keyring is wired, never twice: not on a second call, not
// across a restart, and not when the marker's "audited" flag was lost after the
// row landed.
//
// Mutation: drop the InsertAuditLog in RecordAuditSeededAssertion — no row.
func TestAuditSeeded_AnAssertionIsAuditedOnceSigned(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	writeAssertion(t, c, dir, "<incarnation>")
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); !seeded || err != nil {
		t.Fatalf("assertion not applied: %v %v", seeded, err)
	}
	pkiDir := SignAuditRowsForTest(t, c, "node-0")
	for i := 0; i < 2; i++ {
		if err := RecordAuditSeededAssertion(ctx, c, "node-0"); err != nil {
			t.Fatal(err)
		}
	}
	if n := assertionRows(t, c); n != 1 {
		t.Fatalf("%d audit.seeded_asserted rows, want exactly one", n)
	}
	AssertAuditRowsSignedForTest(t, c, 1)
	c.Close()

	// The marker loses its "audited" flag (a crash between the row and the
	// flag): the row's id is the assertion's, so it is not written again.
	path := filepath.Join(dir, AuditSeededFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"assertion_audited":true`, `"assertion_audited":false`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	c = localClient(t, dir)
	defer c.Close()
	kr, err := LoadAuditKeyring(pkiDir, "node-0")
	if err != nil {
		t.Fatal(err)
	}
	c.SetAuditKeyring(kr)
	if _, err := DecideAuditSeeded(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	if err := RecordAuditSeededAssertion(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	if n := assertionRows(t, c); n != 1 {
		t.Fatalf("after a restart with the flag lost: %d audit.seeded_asserted rows, want one", n)
	}
}

// TestAuditSeeded_AnAssertionThatOutlivesItsRemovalIsNotReapplied is M-Q (b):
// if the file could not be removed it is still there on the next start, and
// must not be applied — and audited — again.
//
// Mutation: drop the "applied already" guard — a second assertion row.
func TestAuditSeeded_AnAssertionThatOutlivesItsRemovalIsNotReapplied(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	writeAssertion(t, c, dir, "<incarnation>")
	if _, err := DecideAuditSeeded(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	pkiDir := SignAuditRowsForTest(t, c, "node-0")
	if err := RecordAuditSeededAssertion(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	writeAssertion(t, c, dir, "<incarnation>") // the removal "failed"
	c.Close()
	c = localClient(t, dir)
	defer c.Close()
	kr, err := LoadAuditKeyring(pkiDir, "node-0")
	if err != nil {
		t.Fatal(err)
	}
	c.SetAuditKeyring(kr)
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); !seeded || err != nil {
		t.Fatalf("DecideAuditSeeded = %v %v", seeded, err)
	}
	if err := RecordAuditSeededAssertion(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	if n := assertionRows(t, c); n != 1 {
		t.Fatalf("%d audit.seeded_asserted rows: the leftover assertion was applied again", n)
	}
}

// unwritableMarkerClient is a client whose seeded marker cannot be written:
// its data dir is read-only. (The database lives elsewhere, so its own writes
// still work, as on a node whose data dir is full while the database is not.)
func unwritableMarkerClient(t *testing.T) (*Client, string) {
	t.Helper()
	c := newAuditTestClient(t)
	dir := t.TempDir()
	c.SetDataDirForTest(dir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	return c, dir
}

// TestAuditSeeded_AnUnwrittenDecisionHoldsOwnRows is M-N's remainder: a "not
// seeded" decision that could not be written must not let this host write rows
// of its own, or the next start finds rows and no decision and the upgrade rule
// grandfathers it. Its rows are held until the decision is written.
//
// Mutations: drop the unpersisted check in auditTargetReached, or the rehold in
// DecideAuditSeeded — the row lands, and the restart grandfathers the replica.
func TestAuditSeeded_AnUnwrittenDecisionHoldsOwnRows(t *testing.T) {
	ctx := context.Background()
	c, dir := unwritableMarkerClient(t)
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0"})
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); seeded || err == nil {
		t.Fatalf("DecideAuditSeeded with an unwritable marker = %v, %v", seeded, err)
	}
	ins(t, c, "own-1", "node-0", "")
	if _, ok := auditSeqOf(t, c, "own-1"); ok {
		t.Fatal("a row of this host's landed while its seeded decision was unwritten")
	}
	// The restart, with the data dir writable again.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	c.ResetAuditSeededForTests()
	c.ResetAuditChainForTests()
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); seeded || err != nil {
		t.Fatalf("the restart decided %v, %v; want not seeded", seeded, err)
	}
}

// TestAuditSeeded_AWrittenRetryLandsTheHeldRows: once the decision can be
// written, the held rows land.
func TestAuditSeeded_AWrittenRetryLandsTheHeldRows(t *testing.T) {
	ctx := context.Background()
	c, dir := unwritableMarkerClient(t)
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0"})
	_, _ = DecideAuditSeeded(ctx, c, "node-0")
	ins(t, c, "own-1", "node-0", "")
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.RetryAuditSeededDecision(ctx); err != nil {
		t.Fatal(err)
	}
	if held, err := c.LandHeldAudit(ctx, "node-0"); held || err != nil {
		t.Fatalf("still held after the decision was written: %v %v", held, err)
	}
	if _, ok := auditSeqOf(t, c, "own-1"); !ok {
		t.Fatal("the held row did not land")
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
