package corrosion

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
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

// markerOf reads the seeded marker under dir.
func markerOf(t *testing.T, dir string) auditSeededMarker {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, AuditSeededFileName))
	if err != nil {
		t.Fatal(err)
	}
	var m auditSeededMarker
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// assertNonceOf is what root reads out of the marker to assert.
func assertNonceOf(t *testing.T, dir string) string {
	t.Helper()
	n := markerOf(t, dir).AssertNonce
	if n == "" {
		t.Fatal("the seeded marker carries no assert_nonce")
	}
	return n
}

// writeAssertion puts content into the assertion file. "<nonce>" is the
// marker's assert nonce, as root would copy it; "<incarnation>" is this
// state.db's voter incarnation.
func writeAssertion(t *testing.T, c *Client, dir, content string) {
	t.Helper()
	switch content {
	case "<incarnation>":
		inc, err := c.VoterIncarnation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		content = inc + "\n"
	case "<nonce>":
		content = assertNonceOf(t, dir) + "\n"
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

// undecidedReplica is a node with no seeded replica to learn from: its first
// start decides "not seeded" and writes the marker, and with it the nonce
// root asserts with. It returns the restarted client.
func undecidedReplica(t *testing.T, dir string) *Client {
	t.Helper()
	ctx := context.Background()
	c := localClient(t, dir)
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); seeded || err != nil {
		t.Fatalf("first start = %v, %v; want not seeded", seeded, err)
	}
	c.Close()
	return localClient(t, dir)
}

// restart closes c and opens the same data dir again, as a daemon restart does.
func restart(t *testing.T, c *Client, dir string) *Client {
	t.Helper()
	c.Close()
	return localClient(t, dir)
}

// TestAuditSeeded_AnOperatorAssertionSeedsOnce is the way out of a cluster with
// no seeded replica: root copies the marker's assert nonce into the assertion
// file, the next start records the replica seeded and removes the file.
//
// Mutation: ignore the assertion — not seeded.
func TestAuditSeeded_AnOperatorAssertionSeedsOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := undecidedReplica(t, dir)
	writeAssertion(t, c, dir, "<nonce>")
	c = restart(t, c, dir)
	defer c.Close()
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); !seeded || err != nil {
		t.Fatalf("with the operator's assertion = %v, %v; want seeded", seeded, err)
	}
	if _, err := os.Stat(filepath.Join(dir, AuditSeededAssertFileName)); !os.IsNotExist(err) {
		t.Fatalf("the assertion was not consumed: %v", err)
	}
}

// TestAuditSeeded_AnAssertionOfTheIncarnationIsIgnored is I-E': the voter
// incarnation is NOT a secret — GetRecoveryClaim returns it to an operator,
// voter_configs replicates it, GetVoterConfig and InspectRecoveryClaim show it
// to a viewer — so an operator who can put a file in data_dir (a storage pool
// aimed at it) could write it. Only the node-local nonce asserts.
//
// Mutation: accept the incarnation as well as the nonce — seeded.
func TestAuditSeeded_AnAssertionOfTheIncarnationIsIgnored(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := undecidedReplica(t, dir)
	writeAssertion(t, c, dir, "<incarnation>")
	c = restart(t, c, dir)
	defer c.Close()
	if seeded, _ := DecideAuditSeeded(ctx, c, "node-0"); seeded || c.AuditSeeded(ctx) {
		t.Fatal("an assertion naming the voter incarnation, which RPCs return, seeded the replica")
	}
	if n := assertionRows(t, c); n != 0 {
		t.Fatalf("%d audit.seeded_asserted rows for an ignored assertion", n)
	}
}

// TestAuditSeeded_AnAssertionNotNamingTheNonceIsIgnored is I-E: anyone who
// can place a file in data_dir without being root on the node does not know the
// nonce, which only the 0600 marker holds. A file without it is ignored.
//
// Mutation: drop the content check — the blind write seeds the replica.
func TestAuditSeeded_AnAssertionNotNamingTheNonceIsIgnored(t *testing.T) {
	ctx := context.Background()
	for _, content := range []string{"", "x", "0123456789abcdef0123456789abcdef"} {
		dir := t.TempDir()
		c := undecidedReplica(t, dir)
		writeAssertion(t, c, dir, content)
		c = restart(t, c, dir)
		if seeded, _ := DecideAuditSeeded(ctx, c, "node-0"); seeded || c.AuditSeeded(ctx) {
			t.Errorf("an assertion containing %q seeded the replica", content)
		}
		c.Close()
	}
}

// TestAuditSeeded_AnotherStateDBsNonceIsIgnored: the nonce is bound to the
// marker, and the marker to its state.db. A state.db replaced beside the old
// marker mints a new nonce, so an assertion carrying the old one — a file left
// behind, or a copy of the old marker — does not apply.
//
// Mutation: adopt the marker's nonce whatever its incarnation — seeded.
func TestAuditSeeded_AnotherStateDBsNonceIsIgnored(t *testing.T) {
	ctx := context.Background()
	a, b := t.TempDir(), t.TempDir()
	ca := undecidedReplica(t, a)
	ca.Close()
	old := assertNonceOf(t, a)
	data, err := os.ReadFile(filepath.Join(a, AuditSeededFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, AuditSeededFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, AuditSeededAssertFileName), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cb := localClient(t, b)
	defer cb.Close()
	if seeded, _ := DecideAuditSeeded(ctx, cb, "node-0"); seeded || cb.AuditSeeded(ctx) {
		t.Fatal("another state.db's nonce seeded this replica")
	}
	if n := assertNonceOf(t, b); n == old {
		t.Fatal("the replaced state.db kept the old marker's nonce")
	}
}

// TestAuditSeeded_TheAssertNonceIsPrivateAndRandom: the nonce is ≥128 bits of
// hex, lives in a 0600 marker — a loose marker is tightened when the nonce is
// added — and is different on every replica.
//
// Mutations: write the marker 0644 — red; a fixed nonce — the two replicas share it.
func TestAuditSeeded_TheAssertNonceIsPrivateAndRandom(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	undecidedReplica(t, a).Close()
	undecidedReplica(t, b).Close()
	na, nb := assertNonceOf(t, a), assertNonceOf(t, b)
	if raw, err := hex.DecodeString(na); err != nil || len(raw) < 16 {
		t.Fatalf("assert nonce %d chars, hex error %v; want at least 128 bits of hex", len(na), err)
	}
	if na == nb {
		t.Fatal("two replicas minted the same assert nonce")
	}
	fi, err := os.Stat(filepath.Join(a, AuditSeededFileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("seeded marker mode %04o, want 0600", fi.Mode().Perm())
	}
}

// TestAuditSeeded_AMarkerWithoutANonceGetsOneAtTheNextStart: a marker written
// by the build before this one has no nonce. The next start adds one, keeps the
// decision, and leaves the marker 0600 even if it was loose.
//
// Mutation: no backfill — no assert_nonce.
func TestAuditSeeded_AMarkerWithoutANonceGetsOneAtTheNextStart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := localClient(t, dir)
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	old := `{"incarnation":"` + inc + `","seeded":true,"reason":"genesis","at":"2026-10-01T00:00:00Z"}`
	path := filepath.Join(dir, AuditSeededFileName)
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	c = localClient(t, dir)
	defer c.Close()
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); !seeded || err != nil {
		t.Fatalf("DecideAuditSeeded = %v, %v; want the recorded decision (seeded)", seeded, err)
	}
	m := markerOf(t, dir)
	if m.AssertNonce == "" || !m.Seeded || m.Reason != "genesis" {
		t.Fatalf("after the next start the marker is %+v; want the old decision plus a nonce", m)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode %04o after the nonce was added, want 0600", fi.Mode().Perm())
	}
}

// TestAuditSeeded_TheAssertNonceIsNeverLoggedOrAudited: no log line, at any
// level, and no audit row carries the nonce — neither the one asserted with nor
// the one minted after it — through an ignored assertion, an applied one, its
// audit row and a leftover.
//
// Mutation: log the expected nonce in the "IGNORED" line — red.
func TestAuditSeeded_TheAssertNonceIsNeverLoggedOrAudited(t *testing.T) {
	ctx := context.Background()
	buf := &syncBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := t.TempDir()
	c := undecidedReplica(t, dir)
	used := assertNonceOf(t, dir)
	writeAssertion(t, c, dir, "wrong")
	c = restart(t, c, dir)
	_, _ = DecideAuditSeeded(ctx, c, "node-0")
	writeAssertion(t, c, dir, "<nonce>")
	c = restart(t, c, dir)
	if seeded, err := DecideAuditSeeded(ctx, c, "node-0"); !seeded || err != nil {
		t.Fatalf("assertion not applied: %v %v", seeded, err)
	}
	SignAuditRowsForTest(t, c, "node-0")
	if err := RecordAuditSeededAssertion(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	minted := assertNonceOf(t, dir)
	writeAssertion(t, c, dir, used) // a leftover
	c = restart(t, c, dir)
	defer c.Close()
	_, _ = DecideAuditSeeded(ctx, c, "node-0")

	buf.mu.Lock()
	logged := buf.b.String()
	buf.mu.Unlock()
	if !strings.Contains(logged, "IGNORED") || !strings.Contains(logged, "asserted seeded") {
		t.Fatalf("the flow did not log what it should have (the capture is broken):\n%s", logged)
	}
	rows, err := c.Query(ctx, `SELECT id || ' ' || username || ' ' || target || ' ' || detail AS r FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{used, minted} {
		if strings.Contains(logged, n) {
			t.Errorf("the assert nonce %s is in the log:\n%s", n, logged)
		}
		for _, r := range rows {
			if strings.Contains(fmt.Sprint(r.Values...), n) {
				t.Errorf("the assert nonce is in an audit row: %v", r.Values)
			}
		}
	}
	if used == minted {
		t.Error("the nonce was not replaced once it had been used")
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
	c := undecidedReplica(t, dir)
	writeAssertion(t, c, dir, "<nonce>")
	c = restart(t, c, dir)
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
// must not be applied — and audited — again. The leftover here names the
// marker's CURRENT nonce, so only the "applied already" guard stops it.
//
// Mutation: drop the "applied already" guard — a second assertion row.
func TestAuditSeeded_AnAssertionThatOutlivesItsRemovalIsNotReapplied(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := undecidedReplica(t, dir)
	writeAssertion(t, c, dir, "<nonce>")
	c = restart(t, c, dir)
	if _, err := DecideAuditSeeded(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	pkiDir := SignAuditRowsForTest(t, c, "node-0")
	if err := RecordAuditSeededAssertion(ctx, c, "node-0"); err != nil {
		t.Fatal(err)
	}
	writeAssertion(t, c, dir, "<nonce>") // the removal "failed"
	c = restart(t, c, dir)
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
