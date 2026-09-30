package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"
)

// The anti-entropy digest cache (colonelpanik/litevirt#262,
// docs/design/ae-incremental.md).
//
// Every pass used to scan, encode and hash every replicated table, once for
// the pass and once for every peer that asked, whether or not anything had
// changed. The cache keeps each table's digest and bucket digests and hands
// them back until something touches the table.
//
// "Something touched the table" is learned below every Go write path: an
// SQLite pre-update hook on every connection the pool opens bumps the table's
// generation for each row an INSERT, UPDATE, DELETE, UPSERT or REPLACE
// changes (WITHOUT ROWID tables and a DELETE with no WHERE included: a
// registered hook turns the truncate optimisation off). A writer cannot forget
// to invalidate, because it never has to.
//
// What the hook cannot see is bounded rather than trusted:
//   - DDL fires no row hook, so PRAGMA schema_version is part of the key;
//   - digest_v2 changes every encoding, so its flag is part of the key;
//   - a write by another PROCESS (NewLocalClient) or a writer that commits
//     outside Client.mu is covered by digestCacheMaxAge: no entry is served
//     past it. The generation is read under the same read lock the scan
//     holds, and every in-package writer holds the write lock across its
//     commit, so for them the hook and the scan cannot interleave;
//   - the operator's full pass computes its own digests fresh.
//
// Generations are per DATABASE, not per Client: two Clients on one DSN in one
// process (the fleet harness's shared mode, a node reopened while its old
// handle is still closing) see each other's writes.

// digestCacheMaxAge is the longest a cached digest is served without a scan.
// A var so tests can move it.
var digestCacheMaxAge = 10 * time.Minute

// tableGenerations counts, per table, the row changes the pre-update hook has
// seen on one database.
type tableGenerations struct {
	mu  sync.Mutex
	gen map[string]uint64
	// broken is set when a connection could not take the hook: the counts
	// then cannot vouch for that connection's writes, and nothing is cached.
	broken atomic.Bool
	refs   int // guarded by generationRegistry.mu
}

func (g *tableGenerations) bump(table string) {
	g.mu.Lock()
	g.gen[table]++
	g.mu.Unlock()
}

// get returns the table's generation, and false when the counts cannot be
// trusted at all.
func (g *tableGenerations) get(table string) (uint64, bool) {
	if g == nil || g.broken.Load() {
		return 0, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gen[table], true
}

var generationRegistry struct {
	mu   sync.Mutex
	byDB map[string]*tableGenerations
}

func acquireGenerations(dsn string) *tableGenerations {
	generationRegistry.mu.Lock()
	defer generationRegistry.mu.Unlock()
	if generationRegistry.byDB == nil {
		generationRegistry.byDB = make(map[string]*tableGenerations)
	}
	g := generationRegistry.byDB[dsn]
	if g == nil {
		g = &tableGenerations{gen: make(map[string]uint64)}
		generationRegistry.byDB[dsn] = g
	}
	g.refs++
	return g
}

func releaseGenerations(dsn string) {
	generationRegistry.mu.Lock()
	defer generationRegistry.mu.Unlock()
	g := generationRegistry.byDB[dsn]
	if g == nil {
		return
	}
	if g.refs--; g.refs <= 0 {
		delete(generationRegistry.byDB, dsn)
	}
}

// hookedConnector opens connections through modernc's connector and installs
// the pre-update hook on each before database/sql sees it.
type hookedConnector struct {
	driver.Connector
	gens *tableGenerations
}

func (h hookedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := h.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	hr, ok := conn.(sqlite.HookRegisterer)
	if !ok {
		h.gens.broken.Store(true)
		return conn, nil
	}
	gens := h.gens
	hr.RegisterPreUpdateHook(func(d sqlite.SQLitePreUpdateData) {
		gens.bump(d.TableName)
	})
	return conn, nil
}

// openHookedDB opens dsn with every pooled connection reporting its row
// changes to the database's generations.
func openHookedDB(dsn string) (*sql.DB, *tableGenerations, error) {
	base, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite: %w", err)
	}
	gens := acquireGenerations(dsn)
	return sql.OpenDB(hookedConnector{Connector: base, gens: gens}), gens, nil
}

// cachedTableDigest is one table's digest set as of generation gen.
type cachedTableDigest struct {
	set    tableDigestSet
	gen    uint64
	schema int64
	v2     bool
	at     time.Time
}

type digestCache struct {
	mu      sync.Mutex
	entries map[string]cachedTableDigest
	// off disables the cache on this node (anti_entropy_legacy_repair).
	off atomic.Bool
}

// SetDigestCacheEnabled turns this node's digest cache on or off. Off, every
// digest is a scan, as before #262. The daemon turns it off with
// anti_entropy_legacy_repair.
func (c *Client) SetDigestCacheEnabled(on bool) {
	c.digests.off.Store(!on)
	if !on {
		c.digests.mu.Lock()
		c.digests.entries = nil
		c.digests.mu.Unlock()
	}
}

func (c *Client) cachedDigest(table string, schema int64, v2 bool, now time.Time) (tableDigestSet, bool) {
	if c.digests.off.Load() {
		return tableDigestSet{}, false
	}
	gen, ok := c.tableGens.get(table)
	if !ok {
		return tableDigestSet{}, false
	}
	c.digests.mu.Lock()
	e, ok := c.digests.entries[table]
	c.digests.mu.Unlock()
	if !ok || e.gen != gen || e.schema != schema || e.v2 != v2 || now.Sub(e.at) >= digestCacheMaxAge || now.Before(e.at) {
		return tableDigestSet{}, false
	}
	return e.set, true
}

func (c *Client) storeDigest(table string, set tableDigestSet, gen uint64, genOK bool, schema int64, v2 bool, at time.Time) {
	if !genOK || c.digests.off.Load() {
		return
	}
	c.digests.mu.Lock()
	if c.digests.entries == nil {
		c.digests.entries = make(map[string]cachedTableDigest)
	}
	c.digests.entries[table] = cachedTableDigest{set: set, gen: gen, schema: schema, v2: v2, at: at}
	c.digests.mu.Unlock()
}

// schemaVersion reads PRAGMA schema_version, which every DDL statement moves.
func (c *Client) schemaVersion(ctx context.Context) (int64, bool) {
	var v int64
	if err := c.db.QueryRowContext(ctx, `PRAGMA schema_version`).Scan(&v); err != nil {
		return 0, false
	}
	return v, true
}
