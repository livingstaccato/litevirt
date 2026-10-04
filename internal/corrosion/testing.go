package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"

	_ "modernc.org/sqlite"

	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/pki"
)

var testDBCounter atomic.Int64

// TestingT is the part of testing.TB that NewTestClientT needs. It is an
// interface so this non-test file does not import "testing".
type TestingT interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// NewTestClientT is NewTestClient for a test: it fails t on error and closes
// the client when t finishes.
//
// Prefer it. A shared-cache in-memory database lives exactly as long as a
// handle to it is open, and modernc's sqlite allocates outside the Go heap, so
// an unclosed test client holds ~2 MB that neither the GC nor a heap profile
// ever sees. Leaked once per test, that grew the internal/grpcapi test binary
// to 4.4 GB of RSS.
func NewTestClientT(t TestingT) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("corrosion.NewTestClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TempDirT is TestingT plus a temp dir, for helpers that write files.
type TempDirT interface {
	TestingT
	TempDir() string
}

// SignAuditRowsForTest puts c in the state a daemon with audit signing on leaves
// its client in: a fresh cluster CA and a host certificate for hostName, the
// host's keyring wired onto c (so InsertAuditLog signs), and the key adopted
// (so the host is under a signing contract). Returns the PKI dir.
//
// For a test that has to prove some audit writer's rows come out SIGNED. The
// signing itself happens in InsertAuditLog, so what such a test really pins is
// that the writer goes through InsertAuditLog on the client it was given —
// see TestAuditWriters_EveryCallSiteIsCovered.
func SignAuditRowsForTest(t TempDirT, c *Client, hostName string) string {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := pki.GenerateHostCert(caCert, caKey,
		filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"),
		hostName, net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}
	kr, err := LoadAuditKeyring(dir, hostName)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	c.SetAuditKeyring(kr)
	if _, err := AdoptAuditKey(context.Background(), c, kr, hostName); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	return dir
}

// AssertAuditRowsSignedForTest fails t unless c's audit log holds at least
// minRows rows, every one signed, and verify counts them all as signed with no
// finding and no host listed as not signing.
func AssertAuditRowsSignedForTest(t TestingT, c *Client, minRows int) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx, `SELECT id, action, signature FROM audit_log`)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if len(rows) < minRows {
		t.Fatalf("audit_log holds %d rows, want at least %d", len(rows), minRows)
	}
	for _, r := range rows {
		if r.String("signature") == "" {
			t.Fatalf("audit row %s (%s) is unsigned on a client that signs", r.String("id"), r.String("action"))
		}
	}
	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.RowsChecked != len(rows) || res.Unsigned != 0 || res.Unverifiable != 0 ||
		res.Tampered() || res.Unverified() || len(res.NotSigning) != 0 {
		t.Fatalf("verify does not count every row as signed: %+v", res)
	}
}

// NewTestClient creates an in-memory SQLite client with no gossip.
// Intended for use in tests across packages. The caller must Close it — see
// NewTestClientT, which does.
func NewTestClient() (*Client, error) {
	// Each test client gets a unique in-memory DB
	id := testDBCounter.Add(1)
	// busy_timeout matches the production DSN (client.go): shared-cache
	// in-memory DBs serve every fleet node from one pool, and under full-suite
	// load a concurrent read can otherwise hit SQLITE_BUSY instantly — which
	// the fail-closed admission paths correctly refuse on, turning raw lock
	// contention into spurious test-only refusals.
	dsn := fmt.Sprintf("file:testdb%d?mode=memory&cache=shared&_pragma=busy_timeout(5000)", id)

	db, gens, keeper, err := openTestDB(dsn)
	if err != nil {
		return nil, err
	}

	c := &Client{
		db:               db,
		memKeeper:        keeper,
		dsn:              dsn,
		tableGens:        gens,
		hostName:         "test-node",
		clock:            hlc.NewClock("test-node"),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
	}
	c.SetLeaseTermLedgerGate(testLeaseTermLedgerOpen)
	return c, nil
}

// openTestDB opens a shared-cache in-memory database for a test client, plus
// a keeper: a second handle to the same database that holds one connection
// open for as long as the client is (Close releases it).
//
// A shared-cache in-memory database exists only while some connection to it
// is open, and the client's pool closes a connection nobody has used for
// maxConnIdleTime. A test that sits idle that long — waiting out a daemon
// loop's first delay, say — would otherwise lose every connection and the
// database with them, and its next statement would open a fresh, empty one
// ("no such table"). The keeper is a separate handle rather than a connection
// pinned out of the client's own pool, so that pool's sizing and its Stats
// stay what production sees. It sets neither an idle time nor a lifetime, so
// database/sql never closes the connection Ping leaves in it.
func openTestDB(dsn string) (*sql.DB, *tableGenerations, *sql.DB, error) {
	db, gens, err := openHookedDB(dsn)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*sql.DB, *tableGenerations, *sql.DB, error) {
		db.Close()
		releaseGenerations(dsn)
		return nil, nil, nil, err
	}
	if err := db.Ping(); err != nil {
		return fail(err)
	}
	keeper, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fail(err)
	}
	keeper.SetMaxIdleConns(1)
	if err := keeper.Ping(); err != nil {
		keeper.Close()
		return fail(err)
	}
	return db, gens, keeper, nil
}

// testLeaseTermLedgerOpen is what the test constructors wire into
// Client.leaseTermLedger. The real gate is DurablyLatched(lease_term_ledger_v1),
// which answers "is any peer still on a build that cannot resolve the mint's
// statement shape" — a question a single-version test cluster cannot pose. A
// test that wants the CLOSED side calls SetLeaseTermLedgerGate itself.
func testLeaseTermLedgerOpen() bool { return true }

// NewSharedTestClient opens a shared in-memory SQLite database identified by
// dsnSuffix. Multiple calls with the same dsnSuffix return clients pointing
// at the same DB — a reasonable proxy for "all hosts converged via CRDT
// replication" in cross-package tests, without needing the full replicator.
//
// Use distinct suffixes when you want to simulate a network partition.
//
// Test-only. The returned client is not started (no replicator, no gossip).
func NewSharedTestClient(dsnSuffix, hostName string) (*Client, error) {
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma=busy_timeout(5000)", dsnSuffix)
	db, gens, keeper, err := openTestDB(dsn)
	if err != nil {
		return nil, err
	}
	c := &Client{
		db:               db,
		memKeeper:        keeper,
		dsn:              dsn,
		tableGens:        gens,
		hostName:         hostName,
		clock:            hlc.NewClock(hostName),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
	}
	c.SetLeaseTermLedgerGate(testLeaseTermLedgerOpen)
	return c, nil
}

// ExecOutOfProcessForTest runs one statement on this client's database
// through a handle of its own that carries no pre-update hook — the write
// another process makes, which this client's digest cache cannot see.
func (c *Client) ExecOutOfProcessForTest(q string, args ...interface{}) error {
	db, err := sql.Open("sqlite", c.dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = db.Exec(q, args...)
	return err
}

// SetDataDirForTest points a test client at a data directory, so the node-local
// markers that survive a restart (the credentials-unhydrated mark) can be
// exercised without standing up a daemon.
func (c *Client) SetDataDirForTest(dir string) { c.dataDir = dir }

// ReplaceVoterIncarnationForTest re-mints this database's voter incarnation:
// the state a re-imaged host or a reseeded state.db comes back with, which a
// voter must abstain from voting under (docs/design/recovery-claims.md §3.11).
func (c *Client) ReplaceVoterIncarnationForTest(ctx context.Context) (string, error) {
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := tx.Exec(ctx, `DELETE FROM local_voter_incarnation WHERE id = 1`)
		return err
	}); err != nil {
		return "", err
	}
	if err := c.mintVoterIncarnation(ctx); err != nil {
		return "", err
	}
	return c.VoterIncarnation(ctx)
}
