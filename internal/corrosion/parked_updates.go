package corrosion

// Parked updates: an LWW UPDATE that met no row, held until the row arrives.
//
// mutation_log carries statements, and a full-PK UPDATE is a PARTIAL write: it
// names a row and a few columns and has nothing to apply to on a replica that
// does not hold the row yet. It is still relayed when it changes nothing here
// (relayStatement), so every peer that holds the row applies it under LWW. The
// replica that lacked the row then receives the row's INSERT, which is OLDER
// than the update, and keeps it. On the WAL lane alone that is permanent: the
// update's entry is already marked seen, nothing sends it again, and the
// replica stays behind its peers until anti-entropy pulls the newer row.
//
// It happens on either end of the link:
//
//   - the ORIGIN, when a node updates a row whose INSERT has not replicated to
//     it yet (the relayed statement lands everywhere but here);
//   - a RECEIVER, when an update reaches it ahead of the row — a leaf's
//     update pushed to a relay the row's creator has not reached yet.
//
// The fix keeps the statement and the wire exactly as they are and gives the
// replica a way to finish the job: an update that met no row because the row is
// ABSENT is parked, in memory, and replayed through the same LWW gate the WAL
// uses the moment a replicated INSERT creates that row. The row's own clock
// decides, as it does everywhere else — a parked update older than the row that
// arrives is skipped, a newer one applies — so the replica reaches the state its
// peers reached by applying the same statements in the order LWW implies.
//
// Deliberately narrow:
//
//   - only DispFullPKUpdate, the plain LWW-gated full-PK UPDATE with a bound
//     updated_at, and its tombstone-guarded twin DispLiveRowUpdate. Bulk updates have no single row to wait for; custom-merge,
//     guarded and no-clock updates carry their own ordering rule and are not
//     LWW-replayable;
//   - only when the row is ABSENT. An update whose extra predicates rejected a
//     row that IS here (a stale epoch, a tombstone) is a decision, not a gap,
//     and is never parked;
//   - replay happens on the WAL apply path, inside the batch that created the
//     row, so a later statement in the same batch applies on top of it and a
//     rolled-back batch leaves the park intact.
//
// What it costs, and what still falls to anti-entropy: the park is in memory,
// bounded (parkedUpdatesMax) and aged out (parkedUpdateTTL), so a restart, an
// overflow, or a row that arrives by an anti-entropy merge instead of the WAL
// leaves the replica exactly where it was before this existed — behind, until
// anti-entropy repairs it. A row that never arrives (an update to a name that
// exists nowhere) just ages out. Nothing about what is sent changes, so a
// mixed-version cluster needs no gate: an older node simply does not park.

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// parkedUpdatesMax bounds the park. Past it the oldest entry is dropped,
	// which costs only what anti-entropy already repairs.
	parkedUpdatesMax = 4096
	// parkedUpdateTTL is how long a row gets to arrive. The WAL lane delivers
	// in seconds; a row later than this is anti-entropy's.
	parkedUpdateTTL = 10 * time.Minute
)

// parkedUpdate is one parked statement.
type parkedUpdate struct {
	seq      uint64 // park order, the identity used to remove it
	table    string
	pkCols   []string
	stmt     Statement
	shape    StmtShape
	hlc      string // the entry HLC, the LWW fallback when the statement binds no updated_at
	parkedAt time.Time
}

// parkedUpdates is the per-client park, keyed by table + primary key.
type parkedUpdates struct {
	mu    sync.Mutex
	next  uint64
	byRow map[string][]parkedUpdate
	count int
	now   func() time.Time // test seam
}

func parkedRowKey(table string, pk []interface{}) string {
	var b strings.Builder
	b.WriteString(table)
	for _, v := range pk {
		b.WriteByte(0)
		b.WriteString(coerceString(v))
	}
	return b.String()
}

func (p *parkedUpdates) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// empty is the lock-light fast path every WAL insert takes.
func (p *parkedUpdates) empty() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count == 0
}

func (p *parkedUpdates) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

// add parks u under key, evicting expired entries and then, if still full, the
// oldest one.
func (p *parkedUpdates) add(key string, u parkedUpdate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byRow == nil {
		p.byRow = make(map[string][]parkedUpdate)
	}
	now := p.clock()
	u.parkedAt = now
	p.next++
	u.seq = p.next
	p.expireLocked(now)
	for p.count >= parkedUpdatesMax && p.count > 0 {
		p.evictOldestLocked()
	}
	p.byRow[key] = append(p.byRow[key], u)
	p.count++
}

func (p *parkedUpdates) expireLocked(now time.Time) {
	for key, list := range p.byRow {
		kept := list[:0]
		for _, u := range list {
			if now.Sub(u.parkedAt) < parkedUpdateTTL {
				kept = append(kept, u)
			}
		}
		p.count -= len(list) - len(kept)
		if len(kept) == 0 {
			delete(p.byRow, key)
		} else {
			p.byRow[key] = kept
		}
	}
}

func (p *parkedUpdates) evictOldestLocked() {
	var oldKey string
	var oldSeq uint64
	for key, list := range p.byRow {
		for _, u := range list {
			if oldSeq == 0 || u.seq < oldSeq {
				oldKey, oldSeq = key, u.seq
			}
		}
	}
	if oldSeq != 0 {
		p.removeLocked(oldKey, map[uint64]bool{oldSeq: true})
	}
}

// pending returns a copy of what is parked under key, unexpired.
func (p *parkedUpdates) pending(key string) []parkedUpdate {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock()
	var out []parkedUpdate
	for _, u := range p.byRow[key] {
		if now.Sub(u.parkedAt) < parkedUpdateTTL {
			out = append(out, u)
		}
	}
	return out
}

func (p *parkedUpdates) remove(key string, seqs map[uint64]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(key, seqs)
}

func (p *parkedUpdates) removeLocked(key string, seqs map[uint64]bool) {
	list := p.byRow[key]
	kept := list[:0]
	for _, u := range list {
		if !seqs[u.seq] {
			kept = append(kept, u)
		}
	}
	p.count -= len(list) - len(kept)
	if len(kept) == 0 {
		delete(p.byRow, key)
	} else {
		p.byRow[key] = kept
	}
}

// ParkedUpdates reports how many updates are waiting for their row.
func (c *Client) ParkedUpdates() int { return c.parked.len() }

// parkableUpdate parses s and reports whether it is a DispFullPKUpdate — the
// only shape parked — returning what a park and a later replay need.
func (c *Client) parkableUpdate(s Statement) (StmtShape, []string, []interface{}, bool) {
	sh, pkCols, err := parseResolved(s.SQL)
	if err != nil || sh.Kind != KindUpdate || !sh.HasFullPKIdentity || sh.UpdatedAtParamIdx < 0 {
		return StmtShape{}, nil, nil, false
	}
	if sh.ValidateParamArity(len(s.Params)) != nil {
		return StmtShape{}, nil, nil, false
	}
	entry, ok := LedgerLookup(stmtFingerprint(sh))
	if !ok {
		return StmtShape{}, nil, nil, false
	}
	disp := entry.Disposition
	if entry.RequiresCapability != "" && entry.DispositionAfter != "" && c.capabilityActive(entry.RequiresCapability) {
		disp = entry.DispositionAfter
	}
	if disp != DispFullPKUpdate && disp != DispLiveRowUpdate && disp != DispHostReadmit {
		return StmtShape{}, nil, nil, false
	}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok || len(pk) != len(pkCols) {
		return StmtShape{}, nil, nil, false
	}
	return sh, pkCols, pk, true
}

// rowPresent reports whether table holds a row (live or tombstoned) with pk.
// table comes from a ledger-registered shape, never from the peer's string.
func rowPresent(ctx context.Context, tx *sql.Tx, table string, pkCols []string, pk []interface{}) (bool, error) {
	where := make([]string, len(pkCols))
	for i, col := range pkCols {
		where[i] = col + " = ?"
	}
	var one int
	err := tx.QueryRowContext(ctx,
		"SELECT 1 FROM "+table+" WHERE "+strings.Join(where, " AND ")+" LIMIT 1", pk...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// parkIfRowAbsent is called, inside tx, for a statement that changed no row.
// When s is a parkable update and its row is absent, it returns the effect that
// parks it — for the caller to run only once tx commits. nil means nothing to
// park. A lookup failure is not the write's failure: the statement has already
// done everything it would have done before parking existed, so it is logged
// and the park skipped, leaving the gap to anti-entropy as before.
func (c *Client) parkIfRowAbsent(ctx context.Context, tx *sql.Tx, s Statement, hlc string) func() {
	sh, pkCols, pk, ok := c.parkableUpdate(s)
	if !ok {
		return nil
	}
	present, err := rowPresent(ctx, tx, sh.Table, pkCols, pk)
	if err != nil {
		slog.Warn("corrosion: could not check for an update's row; not parking it",
			"table", sh.Table, "error", err)
		return nil
	}
	if present {
		return nil
	}
	key := parkedRowKey(sh.Table, pk)
	u := parkedUpdate{table: sh.Table, pkCols: pkCols, stmt: s, shape: sh, hlc: hlc}
	return func() {
		c.parked.add(key, u)
		slog.Debug("corrosion: parked an update whose row has not arrived",
			"table", sh.Table)
	}
}

// replayParked runs, inside the WAL batch's tx, right after statement s applied.
// If s is an INSERT that created a row updates are parked for, each is replayed
// through the LWW gate, oldest clock first, and removed once the batch commits.
func (r *Replicator) replayParked(ctx context.Context, tx *sql.Tx, s Statement) {
	c := r.client
	if c.parked.empty() {
		return
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil || sh.Kind != KindInsert {
		return
	}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok {
		return
	}
	key := parkedRowKey(sh.Table, pk)
	parked := c.parked.pending(key)
	if len(parked) == 0 {
		return
	}
	if present, perr := rowPresent(ctx, tx, sh.Table, parked[0].pkCols, pk); perr != nil || !present {
		if perr != nil {
			slog.Warn("corrosion: could not check a parked update's row; replay deferred",
				"table", sh.Table, "error", perr)
		}
		return // the insert was refused here, or the read failed; keep waiting
	}
	sort.SliceStable(parked, func(i, j int) bool {
		ti, _ := incomingUpdatedAtFromShape(parked[i].shape, parked[i].stmt)
		tj, _ := incomingUpdatedAtFromShape(parked[j].shape, parked[j].stmt)
		return lwwOrder(ti, tj) < 0
	})
	done := make(map[uint64]bool, len(parked))
	for _, u := range parked {
		// A replay that fails is dropped, not propagated: failing the batch
		// would back-pressure the peer's whole stream on a statement it sent
		// long ago and this node already accepted. A failed UPDATE changes
		// nothing (SQLite reverts the statement), so the row is left as it
		// arrived — the pre-park outcome, for anti-entropy to finish.
		// A live-row update replays through its guarded form, as it would
		// have applied had the row been here (live_row_update.go).
		if err := r.applyLWWGated(ctx, tx, appliedForm(u.stmt), u.shape, u.table, u.pkCols, u.hlc); err != nil {
			slog.Warn("corrosion: dropped a parked update that failed to replay",
				"table", u.table, "error", err)
		}
		done[u.seq] = true
	}
	c.deferAfterCommit(tx, func() { c.parked.remove(key, done) })
}
