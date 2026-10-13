package corrosion

// Held (parked) WAL entries: one change a receiver cannot apply no longer stops
// every later change from the same sender — for the natural-key identity
// tables, and only for them.
//
// The WAL apply is fail-closed: any statement that fails rolls the whole push
// back and the sender's watermark stays put, so the sender retries. That is
// right for a fault that clears — a receiver missing a migration, an
// unregistered shape awaiting an upgrade, a busy database. It is wrong for a
// change that can NEVER apply here as it stands: the sender retries the same
// push forever, and every write it makes afterwards waits behind it. Lab 2,
// 2026-10-12 (F-2): a snapshot re-created under a deleted one's name failed
// UNIQUE(vm_name, name) on every peer, and node-3's whole outgoing stream
// stopped at that entry; its later writes reached peers only through
// anti-entropy, minutes late.
//
// SCOPE IS AN ALLOWLIST (parkableTables). Only snapshots and
// container_snapshots qualify: they are the tables whose rows carry a random
// id beside a UNIQUE natural key, so two nodes can hold different rows for one
// name and a refusal is a standing conflict between two rows rather than a
// malformed write. They are the only replicated tables with a secondary
// UNIQUE (TestParkableTables_AreTheIdentityTables pins the list against the
// schema). A table is never holdable by default: a refusal anywhere else —
// and any constraint other than one of these tables' — back-pressures as
// before, and a new table joins only by being added here with its reasons.
//
// An entry is held (entryParkable) when its failure is a constraint refusal
// and every statement is an unguarded LWW row write (plain insert, explicit
// upsert, full-PK update, or per-row-LWW bulk update) to an allowlisted table:
//
//   - the entry is rolled back to its own savepoint and the rest of the batch
//     applies, once; the held entry is recorded seen, acknowledged with the
//     batch, and relayed by a relay exactly as an applied entry is;
//   - it is kept here, and retried on its own — after later pushes
//     (retryParkedSoon) and on a timer (Start) — through the same apply path.
//     Once it applies it is gone from here;
//   - it is LOUD while held: an ERROR line naming the sender, sequence, table
//     and failure when it is held, a WARN on retries (rate-limited),
//     litevirt_replication_parked_entries{origin}, and the
//     replication_entry_parked HA-degraded reason with an event that names it.
//
// What holding does NOT guarantee — the honest limits:
//
//   - applying a held entry late is not always the state applying it in order
//     would have reached on the WAL lane alone. A later full-PK update of the
//     held row from the same sender parks for the row (parked_updates.go), but
//     that park ages out after parkedUpdateTTL (10 minutes) and does not
//     survive a restart; a held entry can wait longer. Anti-entropy then
//     carries the sender's newest row, which is what repairs it;
//   - a later statement keyed by the NATURAL key (a by-name delete) is not
//     held with it: it applies to whatever row holds that name here — in the
//     live-vs-live conflict, this node's own different-id row, which is then
//     tombstoned (not destroyed). That is the existing meaning of a by-name
//     statement;
//   - a later guarded entry is evaluated against this node's rows as they
//     stand. No guard today reads an identity-table row, so a held snapshot
//     row cannot change a guard's answer; a new guard over these tables would
//     have to be judged against holding.
//
// What it does guarantee:
//
//   - nothing is overwritten to make room for a held entry: the row the
//     constraint protects is left exactly as it is;
//   - nothing is lost: the held entry's row is also on its sender, which
//     offers it to every anti-entropy pass, and anti-entropy applies it once
//     the conflict is gone. A restart forgets the held entry, but not the
//     signal: anti-entropy re-derives it from its own refusal of that row
//     (held_refusals.go);
//   - the hold is bounded (parkedEntriesMax). Past it, the next refusal
//     back-pressures as before rather than drop anything.
//
// Rolling upgrade: this is receiver-side only and changes nothing on the
// wire. A sender on any build is held for by an upgraded receiver; an older
// receiver back-pressures as it always did, until it is upgraded — at which
// point the stuck push applies or is held on its next retry, and the stream
// moves again without operator action.

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

var (
	// parkedEntriesMax bounds what one node holds. Past it a refused entry
	// back-pressures, as every refusal did before holding existed.
	parkedEntriesMax = 256
	// parkRetryMinInterval throttles the retry that follows a push, so a busy
	// stream does not re-run the held entries on every write.
	parkRetryMinInterval = 5 * time.Second
	// parkRetryInterval is the timer retry, for a sender that has gone quiet.
	parkRetryInterval = 30 * time.Second
	// parkWarnInterval rate-limits the retry WARN per held entry.
	parkWarnInterval = 5 * time.Minute
)

// parkableEntryError is applyEntry's report that the entry failed in a way
// that may be held rather than back-pressured.
type parkableEntryError struct {
	origin, hlc string
	seq         int64
	table, sql  string
	rowID       string // the refused row's id, when the failing statement names one
	err         error
}

func (e *parkableEntryError) Error() string { return e.err.Error() }
func (e *parkableEntryError) Unwrap() error { return e.err }

// ParkedEntry is one held change, as health, metrics and tests see it. Source
// is "wal" for an entry held here, "ae" for a row anti-entropy refuses
// (held_refusals.go; Seq and HLC are then empty).
type ParkedEntry struct {
	Origin   string
	Seq      int64
	HLC      string
	Table    string
	RowID    string
	Error    string
	HeldAt   time.Time
	Attempts int
	Source   string
}

type parkedEntry struct {
	entry    *pb.MutationEntry
	table    string
	rowID    string
	sql      string
	err      string
	heldAt   time.Time
	attempts int
	warnedAt time.Time
}

// parkState is the Replicator's held set. Its own lock: it is read by the
// health monitor and metrics collector while an apply holds client.mu.
type parkState struct {
	mu        sync.Mutex
	byKey     map[string]*parkedEntry
	lastRetry time.Time
	retrying  bool
}

func parkKey(origin, hlc string) string { return origin + "\x00" + hlc }

// parkableTables is the allowlist of tables whose refused writes may be held
// instead of back-pressured. See the file comment for why these and only
// these; a table is not holdable unless it is named here.
var parkableTables = map[string]bool{
	"snapshots":           true,
	"container_snapshots": true,
}

// entryParkable reports whether an entry that failed with applyErr may be held
// (see the file comment), the table its failure names, and the refused row's
// id when failed carries one.
func (r *Replicator) entryParkable(stmts []Statement, failed Statement, applyErr error) (string, string, bool) {
	if class, _ := classifySQLiteError(applyErr); class != classConstraint {
		return "", "", false
	}
	if isSchemaMissingError(applyErr) || errors.Is(applyErr, ErrInvalidStmt) {
		return "", "", false
	}
	table := ""
	for _, s := range stmts {
		if s.Guard != nil {
			return "", "", false
		}
		if _, legacy := legacyTransformerFor(s.SQL); legacy {
			return "", "", false
		}
		sh, _, err := parseResolved(s.SQL)
		if err != nil || !parkableTables[sh.Table] {
			return "", "", false
		}
		entry, ok := LedgerLookup(stmtFingerprint(sh))
		if !ok {
			return "", "", false
		}
		disp := entry.Disposition
		if entry.RequiresCapability != "" && entry.DispositionAfter != "" && r.client.capabilityActive(entry.RequiresCapability) {
			disp = entry.DispositionAfter
		}
		switch disp {
		case DispPlainInsert, DispExplicitUpsert, DispFullPKUpdate, DispLiveRowUpdate:
		case DispBulkUpdate:
			if entry.Category != CatPerRowLWW {
				return "", "", false
			}
		default:
			return "", "", false
		}
		if table == "" {
			table = sh.Table
		}
	}
	rowID := ""
	if sh, _, err := parseResolved(failed.SQL); err == nil {
		if pk, ok := pkValuesFromShape(sh, failed); ok && len(pk) == 1 {
			rowID = coerceString(pk[0])
		}
	}
	return table, rowID, table != ""
}

func (r *Replicator) parkedLen() int {
	r.park.mu.Lock()
	defer r.park.mu.Unlock()
	return len(r.park.byKey)
}

// parkRoomFor reports whether n more entries may be held.
func (r *Replicator) parkRoomFor(n int) bool {
	return r.parkedLen()+n <= parkedEntriesMax
}

// holdParked records the entries a committed batch acknowledged without
// applying. Called only after the batch committed.
func (r *Replicator) holdParked(entries []*pb.MutationEntry, held map[string]*parkableEntryError) {
	if len(held) == 0 {
		return
	}
	now := time.Now()
	r.park.mu.Lock()
	if r.park.byKey == nil {
		r.park.byKey = make(map[string]*parkedEntry)
	}
	for _, e := range entries {
		pe, ok := held[parkKey(e.Origin, e.Hlc)]
		if !ok {
			continue
		}
		r.park.byKey[parkKey(e.Origin, e.Hlc)] = &parkedEntry{
			entry: e, table: pe.table, rowID: pe.rowID, sql: pe.sql, err: pe.err.Error(), heldAt: now, warnedAt: now,
		}
		r.client.observeMergeRejected(boundedTableLabel(pe.table), string(pathWAL), "held")
		slog.Error("replicator: held a change this node cannot apply; the rest of the sender's stream continues",
			"origin", e.Origin, "seq", e.Seq, "hlc", e.Hlc, "table", pe.table, "sql", pe.sql, "error", pe.err,
			"retry", "automatic; it applies as soon as the conflicting row here allows it",
			"repair", "anti-entropy keeps offering the sender's row; lv doctor divergence shows the table")
	}
	r.park.mu.Unlock()
}

// ParkedEntries reports every change this node holds, oldest first: the WAL
// entries held here, and the identity-table rows anti-entropy refuses
// (held_refusals.go) that no held entry already names.
func (r *Replicator) ParkedEntries() []ParkedEntry {
	r.park.mu.Lock()
	out := make([]ParkedEntry, 0, len(r.park.byKey))
	rows := make(map[string]bool, len(r.park.byKey))
	for _, p := range r.park.byKey {
		out = append(out, ParkedEntry{
			Origin: p.entry.Origin, Seq: p.entry.Seq, HLC: p.entry.Hlc, Table: p.table, RowID: p.rowID,
			Error: p.err, HeldAt: p.heldAt, Attempts: p.attempts, Source: "wal",
		})
		if p.rowID != "" {
			rows[heldRefusalKey(p.table, p.rowID)] = true
		}
	}
	r.park.mu.Unlock()
	for _, h := range r.client.HeldRefusals() {
		if !rows[heldRefusalKey(h.Table, h.RowID)] {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].HeldAt.Equal(out[j].HeldAt) {
			return out[i].HeldAt.Before(out[j].HeldAt)
		}
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].RowID < out[j].RowID
	})
	return out
}

// ParkedCounts is the held count per sender, for
// litevirt_replication_parked_entries.
func (r *Replicator) ParkedCounts() map[string]int {
	out := map[string]int{}
	for _, p := range r.ParkedEntries() {
		out[p.Origin]++
	}
	return out
}

// retryParkedSoon retries the held entries after a push, at most once per
// parkRetryMinInterval and never concurrently with another retry.
func (r *Replicator) retryParkedSoon(ctx context.Context) {
	r.park.mu.Lock()
	due := len(r.park.byKey) > 0 && !r.park.retrying && time.Since(r.park.lastRetry) >= parkRetryMinInterval
	r.park.mu.Unlock()
	if due {
		r.RetryParked(ctx)
	}
}

// RetryParked tries every held entry once, each in its own transaction through
// the same apply path a push takes. One that applies is released; one that
// still cannot is kept with its latest failure.
func (r *Replicator) RetryParked(ctx context.Context) {
	r.park.mu.Lock()
	if r.park.retrying || len(r.park.byKey) == 0 {
		r.park.mu.Unlock()
		return
	}
	r.park.retrying = true
	r.park.lastRetry = time.Now()
	list := make([]*parkedEntry, 0, len(r.park.byKey))
	for _, p := range r.park.byKey {
		list = append(list, p)
	}
	r.park.mu.Unlock()
	defer func() {
		r.park.mu.Lock()
		r.park.retrying = false
		r.park.mu.Unlock()
	}()
	// Oldest first per sender, so a sender's held entries land in its order.
	sort.Slice(list, func(i, j int) bool {
		if list[i].entry.Origin != list[j].entry.Origin {
			return list[i].entry.Origin < list[j].entry.Origin
		}
		return list[i].entry.Seq < list[j].entry.Seq
	})
	for _, p := range list {
		if ctx.Err() != nil {
			return
		}
		err := r.applyHeldEntry(ctx, p.entry)
		key := parkKey(p.entry.Origin, p.entry.Hlc)
		r.park.mu.Lock()
		if err == nil {
			delete(r.park.byKey, key)
			r.park.mu.Unlock()
			if p.rowID != "" {
				r.client.clearHeldRefusal(p.table, p.rowID)
			}
			slog.Info("replicator: a held change applied; it is no longer held",
				"origin", p.entry.Origin, "seq", p.entry.Seq, "table", p.table,
				"held_for", time.Since(p.heldAt).Round(time.Second).String())
			continue
		}
		p.attempts++
		p.err = err.Error()
		warn := time.Since(p.warnedAt) >= parkWarnInterval
		if warn {
			p.warnedAt = time.Now()
		}
		r.park.mu.Unlock()
		if warn {
			slog.Warn("replicator: a held change still cannot apply",
				"origin", p.entry.Origin, "seq", p.entry.Seq, "table", p.table, "attempts", p.attempts,
				"held_for", time.Since(p.heldAt).Round(time.Second).String(), "error", err)
		}
	}
}

// applyHeldEntry applies one held entry in its own transaction. It was
// recorded seen (and relayed) when it was held, so only the apply runs here.
func (r *Replicator) applyHeldEntry(ctx context.Context, entry *pb.MutationEntry) error {
	r.client.mu.Lock()
	defer r.client.mu.Unlock()
	tx, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer r.client.dropDeferredEffects(tx)
	if err := r.applyEntry(ctx, tx, entry, true); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.client.runDeferredEffects(tx)
	return nil
}

// parkRetryLoop retries held entries on a timer, for a sender that has gone
// quiet after its last push.
func (r *Replicator) parkRetryLoop(ctx context.Context) {
	t := time.NewTicker(parkRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-t.C:
			r.RetryParked(ctx)
		}
	}
}
