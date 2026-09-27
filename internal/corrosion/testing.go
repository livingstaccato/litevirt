package corrosion

import (
	"database/sql"
	"fmt"
	"sync/atomic"

	_ "modernc.org/sqlite"

	"github.com/litevirt/litevirt/internal/hlc"
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

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	return &Client{
		db:               db,
		hostName:         "test-node",
		clock:            hlc.NewClock("test-node"),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
		leaseTermLedger:  testLeaseTermLedgerOpen,
	}, nil
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
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Client{
		db:               db,
		hostName:         hostName,
		clock:            hlc.NewClock(hostName),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
		leaseTermLedger:  testLeaseTermLedgerOpen,
	}, nil
}

// SetDataDirForTest points a test client at a data directory, so the node-local
// markers that survive a restart (the credentials-unhydrated mark) can be
// exercised without standing up a daemon.
func (c *Client) SetDataDirForTest(dir string) { c.dataDir = dir }
