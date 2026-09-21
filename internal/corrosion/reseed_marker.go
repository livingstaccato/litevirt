package corrosion

import (
	"context"
	"fmt"
)

// reseedInProgressDDL records that a reseed has deleted this node's state and
// has not yet finished restoring it.
//
// A reseed is three steps that cannot be one transaction: discard the
// replicated tables, merge the operator dump, merge the SENSITIVE dump. The
// middle step restores users and their password hashes; the last one restores
// user_2fa. A process that dies between them leaves a node that can
// authenticate every enrolled account with a password alone, because
// LocalRealm.Authenticate sets Requires2FA from len(factors) > 0 and an empty
// user_2fa is indistinguishable there from nobody having enrolled.
//
// DiscardReplicatedStateForReseed's own comment already names this hazard and
// states the mitigation as a contract on the caller ("MUST repopulate them in
// the same operation"). A crash does not honour contracts, so this marker
// enforces it: set before the discard, cleared only once the sensitive merge
// has committed, and consulted by the pre-session login paths, which refuse
// while it is set.
//
// Created by the framework rather than listed in schemaDDL, following
// appliedMigrationsDDL and acknowledgedTiesDDL and for the same reasons: it
// costs no schema version and it is LOCAL-ONLY. Every write goes through
// execLocal (no mutation_log row) and the table is absent from sync.go's
// tableNames, so peers never replicate it — which is also why the discard loop
// cannot delete it, since that loop walks exactly those replicated names.
// Replicating it would be actively wrong: it describes one node's interrupted
// operation, not a fact about the cluster.
//
// One row, pinned by CHECK (id = 1): "is this node mid-reseed" is a single
// fact, and a table that could hold two of them could disagree with itself.
const reseedInProgressDDL = `CREATE TABLE IF NOT EXISTS reseed_in_progress (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	started_at TEXT NOT NULL,
	source     TEXT NOT NULL
)`

// BeginReseed marks this node as mid-reseed. It must be called and must have
// COMMITTED before the discard, because the window it guards opens with the
// first DELETE.
//
// INSERT OR REPLACE, not INSERT: a repeat reseed is the documented recovery
// path out of an interrupted one, so it has to be callable while the marker is
// already set, and it must leave behind the source it is actually pulling from
// rather than the one that failed.
func (c *Client) BeginReseed(ctx context.Context, source string) error {
	if err := c.execLocal(ctx,
		`INSERT OR REPLACE INTO reseed_in_progress (id, started_at, source) VALUES (1, ?, ?)`,
		c.NowTS(), source); err != nil {
		return fmt.Errorf("mark reseed in progress: %w", err)
	}
	// Bumped for every reseed that STARTS, including a repeat of one that failed,
	// and never reset: a caller holding the old value must be able to see that
	// something happened even if the reseed has since finished.
	if err := c.execLocal(ctx,
		`INSERT INTO reseed_generation (id, generation) VALUES (1, 1)
		 ON CONFLICT(id) DO UPDATE SET generation = reseed_generation.generation + 1`); err != nil {
		return fmt.Errorf("bump reseed generation: %w", err)
	}
	return nil
}

// FinishReseed clears the marker. Only a reseed whose sensitive merge has
// committed may call it.
func (c *Client) FinishReseed(ctx context.Context) error {
	if err := c.execLocal(ctx, `DELETE FROM reseed_in_progress`); err != nil {
		return fmt.Errorf("clear reseed marker: %w", err)
	}
	return nil
}

// ReseedIncomplete reports whether a reseed deleted this node's state and never
// finished restoring it, naming the source it was pulling from.
//
// A read failure is reported, never folded into "no reseed pending". This is the
// same fail-closed rule LocalRealm.Authenticate already applies to the 2FA
// enrollment lookup, and for the same reason: the caller is a login gate, and an
// unreadable marker must not read as permission to serve.
func (c *Client) ReseedIncomplete(ctx context.Context) (bool, string, error) {
	rows, err := c.Query(ctx, `SELECT source FROM reseed_in_progress WHERE id = 1`)
	if err != nil {
		return false, "", fmt.Errorf("read reseed marker: %w", err)
	}
	if len(rows) == 0 {
		return false, "", nil
	}
	return true, rows[0].String("source"), nil
}

// reseedGenerationDDL counts reseeds that have STARTED on this node, and only
// ever increases.
//
// The marker alone cannot close the window a credential check opens. A login
// reads the marker, spends a deliberately-slow bcrypt verifying a password, and
// only then reads user_2fa — so an entire reseed can start AND finish inside one
// request, and re-reading the boolean would find it clear and conclude nothing
// had happened. A caller that captures this number before it reads any
// credential state and re-checks it before granting anything sees the reseed
// either way.
//
// Local-only and framework-created, like the marker beside it: it describes this
// node's own history, costs no schema version, and survives the discard by being
// absent from the replicated table lists that loop walks.
const reseedGenerationDDL = `CREATE TABLE IF NOT EXISTS reseed_generation (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	generation INTEGER NOT NULL
)`

// ReseedFence reports whether a reseed is currently incomplete, the source it
// was pulling from, and the monotone count of reseeds started on this node.
//
// A read failure is reported rather than folded into "no reseed pending": the
// caller is a credential gate, and an unreadable fence must not read as
// permission to serve.
func (c *Client) ReseedFence(ctx context.Context) (incomplete bool, source string, generation int64, err error) {
	incomplete, source, err = c.ReseedIncomplete(ctx)
	if err != nil {
		return false, "", 0, err
	}
	rows, qerr := c.Query(ctx, `SELECT generation FROM reseed_generation WHERE id = 1`)
	if qerr != nil {
		return false, "", 0, fmt.Errorf("read reseed generation: %w", qerr)
	}
	if len(rows) == 0 {
		return incomplete, source, 0, nil
	}
	return incomplete, source, rows[0].Int64("generation"), nil
}
