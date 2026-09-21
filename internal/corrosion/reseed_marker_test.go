package corrosion

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/hlc"
)

// openFileClient opens a file-backed client on the same path twice over, which
// is the only way to test what this marker exists for: an in-memory DB cannot
// be reopened after the process that held it died.
func openFileClient(t *testing.T, dir string) *Client {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(dir, "state.db")))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping sqlite: %v", err)
	}
	return &Client{
		db:               db,
		hostName:         "test-node",
		clock:            hlc.NewClock("test-node"),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
		leaseTermLedger:  testLeaseTermLedgerOpen,
	}
}

// The marker's entire job is to outlive the process that set it. A reseed that
// dies between the operator merge and the sensitive merge leaves users and their
// password hashes restored while user_2fa is still empty, and nothing in the
// running process survives to say so.
func TestReseedMarker_SurvivesTheProcessThatSetIt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	first := openFileClient(t, dir)
	if err := InitSchema(ctx, first); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := first.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}
	// The daemon dies here, mid-reseed.
	first.db.Close()

	second := openFileClient(t, dir)
	defer second.db.Close()
	if err := InitSchema(ctx, second); err != nil {
		t.Fatalf("InitSchema on reopen: %v", err)
	}

	incomplete, source, err := second.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if !incomplete {
		t.Fatal("ReseedIncomplete = false after a restart mid-reseed; " +
			"the marker did not survive, so nothing stops this node serving logins " +
			"with an empty user_2fa")
	}
	if source != "kvm001" {
		t.Errorf("source = %q, want %q — an operator needs to know which peer to repeat the reseed from", source, "kvm001")
	}
}

// Only a completed reseed clears it. This is the pair to the test above: the
// marker has to be releasable, or the first reseed would wedge the node
// permanently.
func TestReseedMarker_FinishClears(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := openFileClient(t, dir)
	defer c.db.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	if err := c.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}
	if err := c.FinishReseed(ctx); err != nil {
		t.Fatalf("FinishReseed: %v", err)
	}

	incomplete, _, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if incomplete {
		t.Error("ReseedIncomplete = true after FinishReseed; a completed reseed must release the node")
	}
}

// A fresh node has never reseeded and must serve normally.
func TestReseedMarker_AbsentOnAFreshNode(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	incomplete, _, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if incomplete {
		t.Error("ReseedIncomplete = true on a node that has never reseeded")
	}
}

// A second BeginReseed must not collide with the first. A repeat reseed is the
// documented recovery path, so it has to be callable while the marker is set.
func TestReseedMarker_ARepeatReseedReplacesTheMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := openFileClient(t, dir)
	defer c.db.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	if err := c.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("first BeginReseed: %v", err)
	}
	if err := c.BeginReseed(ctx, "kvm002"); err != nil {
		t.Fatalf("second BeginReseed (the repeat-reseed recovery path): %v", err)
	}

	incomplete, source, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if !incomplete {
		t.Fatal("ReseedIncomplete = false while a repeat reseed is in flight")
	}
	if source != "kvm002" {
		t.Errorf("source = %q, want %q — the marker must name the reseed actually running", source, "kvm002")
	}
}

// The marker must not replicate. It describes one node's interrupted operation;
// a peer that adopted it would refuse logins for a reseed it never ran.
func TestReseedMarker_IsNotReplicated(t *testing.T) {
	for _, name := range tableNames {
		if name == "reseed_in_progress" {
			t.Fatal("reseed_in_progress is in sync.go tableNames; it would replicate to peers " +
				"and lock them out over a reseed they never ran")
		}
	}
	for _, name := range sensitiveTableNames {
		if name == "reseed_in_progress" {
			t.Fatal("reseed_in_progress is in sensitiveTableNames; it would replicate to peers")
		}
	}
}

// The discard loop walks the replicated table names, so a marker absent from
// them is structurally safe from it. This pins that reasoning: the marker set
// before the discard must still be there after it.
func TestReseedMarker_SurvivesTheDiscardItGuards(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := c.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}

	if _, err := c.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("DiscardReplicatedStateForReseed: %v", err)
	}

	incomplete, _, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if !incomplete {
		t.Fatal("the discard deleted the marker that guards it — the window is now unguarded " +
			"for exactly the operation the marker exists for")
	}
}
