package corrosion

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestRegistryCredentialID_Frozen pins the deterministic id derivation (a change here is a
// contract break — it would strand every existing credential from its canonical row).
func TestRegistryCredentialID_Frozen(t *testing.T) {
	cases := map[string][3]string{
		"3ccd6170-44ce-80c6-9963-991ad2891923": {"user", "alice", "ghcr.io"},
		"82f03ff9-767b-82f1-9552-d92e643b6c57": {"global", "", "docker.io"},
	}
	for want, in := range cases {
		if got := RegistryCredentialID(in[0], in[1], in[2]); got != want {
			t.Errorf("RegistryCredentialID%v = %q, want %q (frozen)", in, got, want)
		}
	}
	// Deterministic: same inputs → same id.
	if RegistryCredentialID("user", "bob", "reg:5000") != RegistryCredentialID("user", "bob", "reg:5000") {
		t.Error("id must be deterministic")
	}
	// v8 (custom) UUID shape: version nibble 8, RFC-4122 variant.
	id := RegistryCredentialID("user", "alice", "ghcr.io")
	if id[14] != '8' {
		t.Errorf("expected a version-8 UUID, got %q", id)
	}
	if v := id[19]; v != '8' && v != '9' && v != 'a' && v != 'b' {
		t.Errorf("expected RFC-4122 variant, got %q", id)
	}
}

// TestRegistryCredentialID_LengthPrefixed: field boundaries are unambiguous — ("ab","c") and
// ("a","bc") must NOT collide (a naive concatenation would).
func TestRegistryCredentialID_LengthPrefixed(t *testing.T) {
	if RegistryCredentialID("user", "ab", "c") == RegistryCredentialID("user", "a", "bc") {
		t.Error("length-prefixing must keep distinct triples distinct")
	}
}

// TestRegistryCredentialID_NoLowercasing: the id hashes the STORED registry verbatim. Since
// NormalizeRegistry preserves case (it only folds the Docker Hub aliases), the id must NOT
// re-case — else a credential stored as "GHCR.io" would split from its own pulls.
func TestRegistryCredentialID_NoLowercasing(t *testing.T) {
	if RegistryCredentialID("user", "alice", "GHCR.io") == RegistryCredentialID("user", "alice", "ghcr.io") {
		t.Error("id must not lowercase the registry (normalization is frozen upstream)")
	}
}

func liveRegistryRows(t *testing.T, c *Client, scope, owner, registry string) []Row {
	t.Helper()
	rows, err := c.Query(context.Background(),
		"SELECT id, username, secret FROM registry_credentials WHERE scope=? AND owner=? AND registry=? AND deleted_at IS NULL",
		scope, owner, registry)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return rows
}

// canonicalUpsertStmt builds the canonical upsert of the retired design (registryCanonicalUpsertSQL).
func canonicalUpsertStmt(id, scope, owner, registry, username, secret, createdAt, updatedAt string) Statement {
	return Statement{
		SQL:    registryCanonicalUpsertSQL,
		Params: []interface{}{id, scope, owner, registry, username, secret, createdAt, updatedAt},
	}
}

// applyRegistryWAL drives one replicated statement through the WAL apply path, returning the apply
// error (nil on success). Infra failures fail the test.
func applyRegistryWAL(t *testing.T, c *Client, s Statement) error {
	t.Helper()
	r := NewReplicator(c, "", RelayConfig{})
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	aerr := r.applyStatementLWW(context.Background(), tx, s, s.Params[len(s.Params)-1].(string))
	if aerr != nil {
		tx.Rollback()
		return aerr
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return nil
}

// seedRegistryRow writes one credential row with an exact id and updated_at, as a node that
// already holds it would. The id is whatever the caller says: a random legacy id, or the
// deterministic one a canonical write would have produced.
func seedRegistryRow(t *testing.T, c *Client, id, secret, updatedAt string) {
	t.Helper()
	if err := c.Execute(context.Background(),
		`INSERT INTO registry_credentials (id, scope, owner, registry, username, secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "user", "alice", "ghcr.io", "alice", secret, "2020-01-01T00:00:00Z", updatedAt); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// TestRegistryCanonicalUpsert_AlwaysRejected: the canonical upsert of the retired design is
// registered as plain DispReject — no capability can make it acceptable — and a receiver refuses it
// on apply, applying nothing. Before the retirement a durable canonical_registry_v1 latch turned it
// into an applied upsert; nothing on this build has that switch any more.
func TestRegistryCanonicalUpsert_AlwaysRejected(t *testing.T) {
	le, err := LedgerEntryFor(registryCanonicalUpsertSQL)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	entry, ok := LedgerLookup(le.Fingerprint)
	if !ok {
		t.Fatal("the canonical upsert must stay registered, so the shape is known and refused")
	}
	if entry.Disposition != DispReject || entry.RequiresCapability != "" || entry.DispositionAfter != "" {
		t.Fatalf("ledger entry = %+v, want plain DispReject with no capability gate", entry)
	}

	c := mustTestClient(t)
	id := RegistryCredentialID("user", "alice", "ghcr.io")
	s := canonicalUpsertStmt(id, "user", "alice", "ghcr.io", "alice", "s", "2020-01-01T00:00:00Z", "1000000000000-0000-a")
	if err := applyRegistryWAL(t, c, s); err == nil {
		t.Fatal("the canonical upsert must be rejected")
	}
	if rows, _ := c.Query(context.Background(), "SELECT id FROM registry_credentials"); len(rows) != 0 {
		t.Fatalf("a rejected canonical upsert applied %d row(s)", len(rows))
	}
}

// TestRegistryCanonicalRows_StayValidForTheLegacyPaths covers a cluster that latched the retired
// token and applied a canonical row before upgrading. The row is an ordinary registry_credentials
// row whose id happens to be RegistryCredentialID(triple): the pull-time resolver and the list
// return it, the legacy writer replaces it (tombstoning it by triple, as it would any live row),
// revoke removes it, and a replicated legacy login converges over it. Nothing needs migrating.
func TestRegistryCanonicalRows_StayValidForTheLegacyPaths(t *testing.T) {
	ctx := context.Background()
	detID := RegistryCredentialID("user", "alice", "ghcr.io")

	c := mustTestClient(t)
	seedRegistryRow(t, c, detID, "canonical", "1000000000000-0000-a")

	got, err := ResolveRegistryCredential(ctx, c, "alice", "ghcr.io")
	if err != nil || got == nil || got.ID != detID || got.Secret != "canonical" {
		t.Fatalf("resolve = %+v, %v; want the canonical row", got, err)
	}
	if list, err := ListRegistryCredentials(ctx, c, "alice", false); err != nil || len(list) != 1 || list[0].ID != detID {
		t.Fatalf("list = %+v, %v; want the canonical row", list, err)
	}

	// The legacy writer rotates it: the canonical row is tombstoned, a random-id row is live.
	if err := UpsertRegistryCredential(ctx, c, RegistryCredential{ID: "rand-1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "rotated"}); err != nil {
		t.Fatalf("legacy rotate over a canonical row: %v", err)
	}
	if live := liveRegistryRows(t, c, "user", "alice", "ghcr.io"); len(live) != 1 || live[0].String("id") != "rand-1" || live[0].String("secret") != "rotated" {
		t.Fatalf("after rotate, live = %v; want only rand-1", live)
	}
	if found, err := DeleteRegistryCredential(ctx, c, "user", "alice", "ghcr.io"); err != nil || !found {
		t.Fatalf("revoke = %v, %v", found, err)
	}
	if live := liveRegistryRows(t, c, "user", "alice", "ghcr.io"); len(live) != 0 {
		t.Fatalf("after revoke, live = %v", live)
	}

	// A peer's newer legacy login arrives over a node still holding the canonical row live.
	p := mustTestClient(t)
	seedRegistryRow(t, p, detID, "canonical", "1000000000000-0000-a")
	const newer = "2000000000000-0000-peer"
	for _, s := range []Statement{
		{SQL: registryTombstoneByTripleSQL, Params: []interface{}{"2020-06-01T00:00:00Z", newer, "user", "alice", "ghcr.io"}},
		{SQL: registryLegacyInsertSQL, Params: []interface{}{"rand-peer", "user", "alice", "ghcr.io", "alice", "peer", "2020-06-01T00:00:00Z", newer}},
	} {
		if err := applyRegistryWAL(t, p, s); err != nil {
			t.Fatalf("replicated legacy login over a canonical row must apply: %v", err)
		}
	}
	if live := liveRegistryRows(t, p, "user", "alice", "ghcr.io"); len(live) != 1 || live[0].String("id") != "rand-peer" {
		t.Fatalf("live = %v; want the peer's login", live)
	}
}

// TestRegistryLegacyConcurrentLogin_StallsUntilSensitiveAE reproduces the collision the planned
// canonical model exists to remove (docs/design/canonical-registry-credentials.md). Nodes A and B
// each log in to the same (scope, owner, registry) before either's entry reaches the other, so
// each mints its own random id. B's login is newer.
//
//   - B's entry at A applies: its by-triple tombstone wins LWW over A's older row, and B's row
//     becomes the one live credential. The NEWER login wins.
//   - A's entry at B does not: its tombstone loses LWW to B's newer row, so B's row stays live and
//     A's INSERT collides with it on the partial UNIQUE index. The whole entry rolls back and the
//     watermark does not advance, so A's stream into B is held at that entry.
//   - The sensitive anti-entropy lane then carries A's row for rand-a — tombstoned by B's login —
//     to B. Now B holds rand-a at a NEWER updated_at than A's entry, so the retried entry's
//     INSERT is an LWW no-op, the entry applies, and the stream resumes.
//
// So the stall lasts one sensitive-AE cycle between the pair, not until the entry ages out of
// the log. The final mutation-verified step is that last one: without the AE merge, the retry
// back-pressures again.
func TestRegistryLegacyConcurrentLogin_StallsUntilSensitiveAE(t *testing.T) {
	ctx := context.Background()
	const older, newer = "1000000000000-0000-a", "2000000000000-0000-b"
	login := func(id, secret, hlc string) []*pb.MutationEntry {
		origin := map[string]string{older: "node-a", newer: "node-b"}[hlc]
		return replayEntry(t, origin, hlc,
			Statement{SQL: registryTombstoneByTripleSQL, Params: []interface{}{"2020-06-01T00:00:00Z", hlc, "user", "alice", "ghcr.io"}},
			Statement{SQL: registryLegacyInsertSQL, Params: []interface{}{id, "user", "alice", "ghcr.io", "alice", secret, "2020-01-01T00:00:00Z", hlc}})
	}
	loginA, loginB := login("rand-a", "from-a", older), login("rand-b", "from-b", newer)

	// Each node has applied its own login.
	a, b := mustTestClient(t), mustTestClient(t)
	seedRegistryRow(t, a, "rand-a", "from-a", older)
	seedRegistryRow(t, b, "rand-b", "from-b", newer)
	ra, rb := NewReplicator(a, "", RelayConfig{}), NewReplicator(b, "", RelayConfig{})

	// B's newer login reaches A and converges it.
	if _, err := ra.ApplyRemoteMutations(ctx, loginB); err != nil {
		t.Fatalf("the newer login must apply at the older node: %v", err)
	}
	if live := liveRegistryRows(t, a, "user", "alice", "ghcr.io"); len(live) != 1 || live[0].String("id") != "rand-b" {
		t.Fatalf("A live = %v; want B's newer login", live)
	}

	// A's older login reaches B and is held.
	if _, err := rb.ApplyRemoteMutations(ctx, loginA); err == nil {
		t.Fatal("the older login's entry must back-pressure at the newer node")
	}
	assertNotSeen(t, b, "node-a")
	if live := liveRegistryRows(t, b, "user", "alice", "ghcr.io"); len(live) != 1 || live[0].String("id") != "rand-b" {
		t.Fatalf("B live = %v; want its own newer login untouched", live)
	}

	// One sensitive anti-entropy cycle: B merges A's peer-only dump.
	if err := b.MergeSensitiveStateBytesLWW(a.DumpSensitiveStateBytes()); err != nil {
		t.Fatalf("sensitive merge: %v", err)
	}
	if _, err := rb.ApplyRemoteMutations(ctx, loginA); err != nil {
		t.Fatalf("the held entry must apply once sensitive AE has carried rand-a's tombstone: %v", err)
	}
	if live := liveRegistryRows(t, b, "user", "alice", "ghcr.io"); len(live) != 1 || live[0].String("id") != "rand-b" {
		t.Fatalf("B live = %v; the newer login must still be the one live credential", live)
	}
}

// TestRegistryReadiness_WriterThenContract: the two latch-free readiness reads. A legacy live row
// makes neither ready. Once only the canonical row is live the writer is ready but the contract is
// not — the legacy tombstone left behind would violate a non-partial UNIQUE(scope,owner,registry).
// Once that tombstone is reclaimed, both are ready.
func TestRegistryReadiness_WriterThenContract(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	if err := UpsertRegistryCredential(ctx, c, RegistryCredential{ID: "rand-1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "s1"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if wr, _ := RegistryWriterReady(ctx, c); wr {
		t.Fatal("writer-ready with a legacy live row")
	}

	if _, err := DeleteRegistryCredential(ctx, c, "user", "alice", "ghcr.io"); err != nil {
		t.Fatalf("tombstone legacy: %v", err)
	}
	seedRegistryRow(t, c, RegistryCredentialID("user", "alice", "ghcr.io"), "s1", "9000000000000-0000-a")
	if wr, _ := RegistryWriterReady(ctx, c); !wr {
		t.Fatal("writer-ready must be true once only the canonical row is live")
	}
	if cr, _ := RegistryContractReady(ctx, c); cr {
		t.Fatal("contract-ready must be false while a legacy tombstone remains")
	}

	if err := c.Execute(ctx, "DELETE FROM registry_credentials WHERE id = 'rand-1'"); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if cr, _ := RegistryContractReady(ctx, c); !cr {
		t.Fatal("contract-ready must be true once no non-canonical physical row remains")
	}
}

// TestRegistryLegacyInsert_AlwaysApplies: the legacy mint-new-id INSERT auto-derives to a plain
// insert and is accepted on apply. Rejecting it is a step of the planned activation, not of
// anything shipped.
func TestRegistryLegacyInsert_AlwaysApplies(t *testing.T) {
	c := mustTestClient(t)
	s := Statement{SQL: registryLegacyInsertSQL,
		Params: []interface{}{"rand-1", "user", "alice", "ghcr.io", "alice", "s1", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"}}
	if err := applyRegistryWAL(t, c, s); err != nil {
		t.Fatalf("legacy INSERT must apply: %v", err)
	}
	if rows, _ := c.Query(context.Background(), "SELECT id FROM registry_credentials WHERE id='rand-1'"); len(rows) != 1 {
		t.Fatal("legacy row must exist")
	}
}
