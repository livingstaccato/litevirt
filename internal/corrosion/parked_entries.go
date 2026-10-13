package corrosion

// Held (parked) WAL entries: one change a receiver cannot apply no longer stops
// every later change from the same sender.
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
// An entry whose failure is a deterministic constraint violation, and whose
// every statement is an unguarded, last-writer-wins row write to a table
// anti-entropy repairs, is HELD instead (entryParkable):
//
//   - the batch is re-applied without it, so the entries before and after it
//     land; it is recorded seen and acknowledged with them, and relayed by a
//     relay exactly as an applied entry is;
//   - it is kept here, and retried on its own — after later pushes
//     (retryParkedSoon) and on a timer (Start) — through the same apply path.
//     Once it applies it is gone from here;
//   - it is LOUD while held: an ERROR line naming the sender, sequence, table
//     and failure when it is held, a WARN on retries (rate-limited),
//     litevirt_replication_parked_entries{origin}, and the
//     replication_entry_parked HA-degraded reason with an event that names it.
//
// Why holding such an entry cannot corrupt anything:
//
//   - nothing is overwritten to make room for it. The row the constraint
//     protects is left exactly as it is; the held entry simply has not
//     happened here yet;
//   - nothing is reordered in a way the data model can see. Every statement in
//     a held entry is an LWW row write, decided by the row's own clock, so
//     applying it later reaches the state applying it in order would have —
//     a later write to the same row from the same sender wins over it either
//     way, and an update that reached the row's absence meanwhile is parked
//     for the row (parked_updates.go) and replayed when the held insert lands.
//     Guarded, custom-merge, append-only and retention statements carry their
//     own ordering rule, and an entry holding any of them still back-pressures;
//   - nothing is lost. The held change is in memory here, and its row is also
//     on the sender, which offers it to every anti-entropy pass: anti-entropy
//     already applies the same rule to the same rows (applyMergeRow keeps
//     local on a constraint and the sender keeps offering the row). A restart
//     forgets what is held here and leaves exactly that repair path — the
//     row's merge_rejected count keeps climbing until it applies;
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
	err         error
}

func (e *parkableEntryError) Error() string { return e.err.Error() }
func (e *parkableEntryError) Unwrap() error { return e.err }

// ParkedEntry is one held entry, as health, metrics and tests see it.
type ParkedEntry struct {
	Origin   string
	Seq      int64
	HLC      string
	Table    string
	Error    string
	HeldAt   time.Time
	Attempts int
}

type parkedEntry struct {
	entry    *pb.MutationEntry
	table    string
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

// parkWALDenyTables are LWW tables whose WAL apply does more than write the
// row (secret and membership absorbs, the admin re-mint floor, the host
// tombstone guard). Their refusals keep back-pressuring.
var parkWALDenyTables = map[string]bool{
	"users":            true,
	"user_credentials": true,
	"hosts":            true,
	"host_membership":  true,
	"host_runtime":     true,
}

var antiEntropyTableSet = func() map[string]bool {
	m := make(map[string]bool, len(tableNames))
	for _, t := range tableNames {
		m[t] = true
	}
	return m
}()

// entryParkable reports whether an entry that failed with applyErr may be held
// (see the file comment), and the table its failure names for the report.
func (r *Replicator) entryParkable(stmts []Statement, applyErr error) (string, bool) {
	if class, _ := classifySQLiteError(applyErr); class != classConstraint {
		return "", false
	}
	if isSchemaMissingError(applyErr) || errors.Is(applyErr, ErrInvalidStmt) {
		return "", false
	}
	table := ""
	for _, s := range stmts {
		if s.Guard != nil {
			return "", false
		}
		if _, legacy := legacyTransformerFor(s.SQL); legacy {
			return "", false
		}
		sh, _, err := parseResolved(s.SQL)
		if err != nil {
			return "", false
		}
		if !antiEntropyTableSet[sh.Table] || parkWALDenyTables[sh.Table] {
			return "", false
		}
		entry, ok := LedgerLookup(stmtFingerprint(sh))
		if !ok {
			return "", false
		}
		disp := entry.Disposition
		if entry.RequiresCapability != "" && entry.DispositionAfter != "" && r.client.capabilityActive(entry.RequiresCapability) {
			disp = entry.DispositionAfter
		}
		switch disp {
		case DispPlainInsert, DispExplicitUpsert, DispFullPKUpdate, DispLiveRowUpdate:
		case DispBulkUpdate:
			if entry.Category != CatPerRowLWW {
				return "", false
			}
			if cleanup, cErr := isClaimedCreateCleanup(s, sh); cErr != nil || cleanup {
				return "", false
			}
		default:
			return "", false
		}
		if table == "" {
			table = sh.Table
		}
	}
	return table, table != ""
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
			entry: e, table: pe.table, sql: pe.sql, err: pe.err.Error(), heldAt: now, warnedAt: now,
		}
		r.client.observeMergeRejected(boundedTableLabel(pe.table), string(pathWAL), "held")
		slog.Error("replicator: held a change this node cannot apply; the rest of the sender's stream continues",
			"origin", e.Origin, "seq", e.Seq, "hlc", e.Hlc, "table", pe.table, "sql", pe.sql, "error", pe.err,
			"retry", "automatic; it applies as soon as the conflicting row here allows it",
			"repair", "anti-entropy keeps offering the sender's row; lv doctor divergence shows the table")
	}
	r.park.mu.Unlock()
}

// ParkedEntries reports what this node holds, oldest first.
func (r *Replicator) ParkedEntries() []ParkedEntry {
	r.park.mu.Lock()
	defer r.park.mu.Unlock()
	out := make([]ParkedEntry, 0, len(r.park.byKey))
	for _, p := range r.park.byKey {
		out = append(out, ParkedEntry{
			Origin: p.entry.Origin, Seq: p.entry.Seq, HLC: p.entry.Hlc, Table: p.table,
			Error: p.err, HeldAt: p.heldAt, Attempts: p.attempts,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].HeldAt.Equal(out[j].HeldAt) {
			return out[i].HeldAt.Before(out[j].HeldAt)
		}
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

// ParkedCounts is the held count per sender, for
// litevirt_replication_parked_entries.
func (r *Replicator) ParkedCounts() map[string]int {
	r.park.mu.Lock()
	defer r.park.mu.Unlock()
	out := make(map[string]int, len(r.park.byKey))
	for _, p := range r.park.byKey {
		out[p.entry.Origin]++
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
	if err := r.applyEntry(ctx, tx, entry); err != nil {
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
