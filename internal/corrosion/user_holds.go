package corrosion

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

// What a receiver does with a write bound to an account's incarnation
// (user_incarnation.go) when it does not hold that incarnation yet.
//
// The rule: anything that grants or loosens is guarded; anything that
// tightens is never dropped.
//
//   - The receiver holds the guard's incarnation: the write applies.
//   - It holds a NEWER incarnation of the name: the write belongs to an
//     account that is gone, and is skipped, whatever it does.
//   - The guard is AHEAD of it — it holds no row for the name, or an older
//     incarnation, as when a write made after a create reaches it before the
//     create does:
//   - a write that tightens (userGuardTighten: a second factor, its active
//     set, a disable, an earlier expiry, a later cut-off) applies at once,
//     so the account never reads as less restricted than it is. A factor's
//     epoch and a lifecycle row's set_by name the incarnation it was for, so
//     if the name then reaches a newer one here, a factor or a lift is taken
//     away again (retireLaggingLifts): it never attaches to a later
//     re-created account;
//   - any other write (a grant, a lift) is held in memory and replayed when
//     the name reaches its incarnation here, or dropped when it reaches a
//     newer one (userHeldWrite).
//
// A lagging node's own writes to an account deleted elsewhere are taken away
// when the re-create reaches it by retireLaggingLifts, which judges from the
// rows alone (their incarnation tags), so a restart does not change it. The
// records only tell newerKnown that a newer incarnation has been heard of.
//
// Both are memory only, bounded and aged out. Losing them (a restart, an
// overflow) is fail-closed: a held grant is missing until anti-entropy
// brings it, and a recorded restriction stays where it is.

var (
	userHoldMax      = 4096
	userHeldTTL      = parkedUpdateTTL
	userTightenTTL   = 24 * time.Hour
	userRecordTables = map[string]bool{"user_2fa": true, "user_2fa_sets": true, "user_lifecycle": true}
)

// userHeldWrite is a grant or lift held until its account's incarnation.
type userHeldWrite struct {
	seq   uint64
	guard MutationGuard
	stmts []Statement // the guarded statement, and an unguarded companion (a token's credential)
	hlc   string
	at    time.Time
}

// userTightenRecord is a restriction-table row written for incarnation inc.
type userTightenRecord struct {
	seq       uint64
	inc       string
	table     string
	pk        []interface{}
	updatedAt string
	at        time.Time
}

type userHolds struct {
	mu      sync.Mutex
	next    uint64
	held    map[string][]userHeldWrite
	records map[string][]userTightenRecord
	count   int
	now     func() time.Time // test seam
}

func (h *userHolds) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

func (h *userHolds) empty() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count == 0
}

// expireLocked drops aged entries, then the oldest while over the bound.
func (h *userHolds) expireLocked() {
	now := h.clock()
	for name, list := range h.held {
		kept := list[:0]
		for _, w := range list {
			if now.Sub(w.at) < userHeldTTL {
				kept = append(kept, w)
			} else {
				warnHeldDropped(name, w, "its account's create or re-create did not reach this node in time")
			}
		}
		h.count -= len(list) - len(kept)
		h.setHeldLocked(name, kept)
	}
	for name, list := range h.records {
		kept := list[:0]
		for _, r := range list {
			if now.Sub(r.at) < userTightenTTL {
				kept = append(kept, r)
			}
		}
		h.count -= len(list) - len(kept)
		h.setRecordsLocked(name, kept)
	}
	for h.count >= userHoldMax && h.count > 0 {
		h.evictOldestLocked()
	}
}

func (h *userHolds) setHeldLocked(name string, list []userHeldWrite) {
	if len(list) == 0 {
		delete(h.held, name)
	} else {
		h.held[name] = list
	}
}

func (h *userHolds) setRecordsLocked(name string, list []userTightenRecord) {
	if len(list) == 0 {
		delete(h.records, name)
	} else {
		h.records[name] = list
	}
}

func (h *userHolds) evictOldestLocked() {
	var name string
	var seq uint64
	held := false
	for n, list := range h.held {
		for _, w := range list {
			if seq == 0 || w.seq < seq {
				name, seq, held = n, w.seq, true
			}
		}
	}
	for n, list := range h.records {
		for _, r := range list {
			if seq == 0 || r.seq < seq {
				name, seq, held = n, r.seq, false
			}
		}
	}
	if seq == 0 {
		return
	}
	if held {
		for _, w := range h.held[name] {
			if w.seq == seq {
				warnHeldDropped(name, w, "the hold is full")
			}
		}
		h.removeHeldLocked(name, map[uint64]bool{seq: true})
	} else {
		h.removeRecordsLocked(name, map[uint64]bool{seq: true})
	}
}

func (h *userHolds) hold(name string, w userHeldWrite) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.held == nil {
		h.held = map[string][]userHeldWrite{}
	}
	h.expireLocked()
	h.next++
	w.seq, w.at = h.next, h.clock()
	h.held[name] = append(h.held[name], w)
	h.count++
}

func (h *userHolds) record(name string, r userTightenRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.records == nil {
		h.records = map[string][]userTightenRecord{}
	}
	h.expireLocked()
	// One record per row: the latest write to it is the one that counts.
	list := h.records[name]
	kept := list[:0]
	for _, old := range list {
		if old.table == r.table && pkKeyEqual(old.pk, r.pk) {
			h.count--
			continue
		}
		kept = append(kept, old)
	}
	h.next++
	r.seq, r.at = h.next, h.clock()
	h.records[name] = append(kept, r)
	h.count++
}

func pkKeyEqual(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if coerceString(a[i]) != coerceString(b[i]) {
			return false
		}
	}
	return true
}

func (h *userHolds) snapshot(name string) ([]userHeldWrite, []userTightenRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]userHeldWrite(nil), h.held[name]...), append([]userTightenRecord(nil), h.records[name]...)
}

func (h *userHolds) removeHeldLocked(name string, seqs map[uint64]bool) {
	list := h.held[name]
	kept := list[:0]
	for _, w := range list {
		if !seqs[w.seq] {
			kept = append(kept, w)
		}
	}
	h.count -= len(list) - len(kept)
	h.setHeldLocked(name, kept)
}

func (h *userHolds) removeRecordsLocked(name string, seqs map[uint64]bool) {
	list := h.records[name]
	kept := list[:0]
	for _, r := range list {
		if !seqs[r.seq] {
			kept = append(kept, r)
		}
	}
	h.count -= len(list) - len(kept)
	h.setRecordsLocked(name, kept)
}

func (h *userHolds) remove(name string, held, records map[uint64]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeHeldLocked(name, held)
	h.removeRecordsLocked(name, records)
}

// newerKnown reports whether this node has heard a write for an incarnation
// of name newer than inc: the name has been re-created elsewhere since.
func (h *userHolds) newerKnown(name, inc string) bool {
	held, records := h.snapshot(name)
	for _, w := range held {
		if incarnationAfter(w.guard.Incarnation, inc) {
			return true
		}
	}
	for _, r := range records {
		if incarnationAfter(r.inc, inc) {
			return true
		}
	}
	return false
}

// UserHolds reports how many user writes are held or recorded here.
func (c *Client) UserHolds() int {
	c.userHolds.mu.Lock()
	defer c.userHolds.mu.Unlock()
	return c.userHolds.count
}

// userGuardVerdict is a receiver's verdict on a user_incarnation_v1 guard.
type userGuardVerdict int

const (
	userVerdictApply userGuardVerdict = iota // the incarnation it holds
	userVerdictSkip                          // an account that is gone here
	userVerdictAhead                         // an incarnation this node has not reached
)

// userGuardVerdictOf judges g against the users row as it stands in tx.
func (c *Client) userGuardVerdictOf(ctx context.Context, tx *sql.Tx, g *MutationGuard) (userGuardVerdict, error) {
	if g.ResourceID == "" || g.Incarnation == "" || !validUserGuardKind(g.ResourceKind) {
		return userVerdictSkip, invalidf("invalid user incarnation guard")
	}
	var created string
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT created_at, deleted_at FROM users WHERE username = ?`, g.ResourceID).
		Scan(&created, &deleted)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return userVerdictSkip, err
	}
	// A grant or lift for an incarnation older than one this node has heard
	// of is an account's that is gone, whatever row it holds yet. A
	// restriction is judged by the row alone: it is never dropped for the
	// incarnation this node still holds.
	if g.ResourceKind != userGuardTighten && c.userHolds.newerKnown(g.ResourceID, g.Incarnation) {
		return userVerdictSkip, nil
	}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return userVerdictAhead, nil
	case created == g.Incarnation:
		isDeleted := deleted.Valid && deleted.String != ""
		switch g.ResourceKind {
		case userGuardLive:
			if isDeleted {
				return userVerdictSkip, nil
			}
		case userGuardDeleted:
			if !isDeleted {
				return userVerdictSkip, nil
			}
		}
		return userVerdictApply, nil
	case incarnationAfter(g.Incarnation, created):
		return userVerdictAhead, nil
	case incarnationAfter(created, g.Incarnation):
		return userVerdictSkip, nil
	}
	// Two stamps neither of which orders: a restriction applies, anything
	// else is not taken.
	if g.ResourceKind == userGuardTighten {
		return userVerdictApply, nil
	}
	return userVerdictSkip, nil
}

// recordUserWrite records, after s applied for incarnation g, a
// restriction-table row s wrote (userTightenRecord).
func (c *Client) recordUserWrite(ctx context.Context, tx *sql.Tx, s Statement, g *MutationGuard, onCommit func(func())) {
	if g == nil || g.Protocol != userIncarnationGuardV1 {
		return
	}
	sh, pkCols, err := parseResolved(s.SQL)
	if err != nil || !userRecordTables[sh.Table] {
		return
	}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok || len(pk) != len(pkCols) {
		return
	}
	ts, ok := userRowUpdatedAt(ctx, tx, sh.Table, pk)
	if !ok {
		return
	}
	// Only a row this write is: one it lost to by clock is another write's.
	if mine, ok := incomingUpdatedAtFromShape(sh, s); !ok || mine != ts {
		return
	}
	r := userTightenRecord{inc: g.Incarnation, table: sh.Table, pk: pk, updatedAt: ts}
	name := g.ResourceID
	onCommit(func() { c.userHolds.record(name, r) })
}

// userRowUpdatedAt reads the updated_at of one restriction-table row.
func userRowUpdatedAt(ctx context.Context, tx *sql.Tx, table string, pk []interface{}) (string, bool) {
	var q string
	switch {
	case table == "user_2fa" && len(pk) == 3:
		q = `SELECT updated_at FROM user_2fa WHERE username = ? AND method = ? AND label = ?`
	case table == "user_2fa_sets" && len(pk) == 1:
		q = `SELECT updated_at FROM user_2fa_sets WHERE username = ?`
	case table == "user_lifecycle" && len(pk) == 2:
		q = `SELECT updated_at FROM user_lifecycle WHERE username = ? AND attribute = ?`
	default:
		return "", false
	}
	var ts string
	if err := tx.QueryRowContext(ctx, q, pk...).Scan(&ts); err != nil {
		return "", false
	}
	return ts, true
}

// settleUserName runs, inside tx, once the users row of name may have moved:
// held writes for the incarnation it now holds are replayed, those for an
// older one dropped. before is the incarnation the row held before it moved
// (userIncarnationHeld, "" for no row). onCommit runs its argument once tx
// commits.
func (c *Client) settleUserName(ctx context.Context, tx *sql.Tx, name, before string, onCommit func(func())) error {
	if name == "" {
		return nil
	}
	local, err := userIncarnationHeld(ctx, tx, name)
	if err != nil || local == "" {
		return err
	}
	// A token says which incarnation it was issued to, so this needs no
	// latch here (token_incarnation.go).
	if local != before {
		if err := retireStaleTokens(ctx, tx, name, local); err != nil {
			return err
		}
	}
	if !c.UserIncarnationOn() {
		return nil
	}
	// Only when the name's incarnation changed here — a re-create, or its
	// first row — what a deleted account's lagging writes left goes, judged
	// by the rows alone, so the answer survives a restart
	// (retireLaggingLifts). An ordinary write to the users row (a password
	// change, an anti-entropy merge of the same account) retires nothing.
	if local != before {
		// Holding an untagged factor set needs an OLDER incarnation replaced
		// here: a name's first row is not one (a node that pulled the factor
		// before the account would otherwise hold every account's factor).
		if err := retireLaggingLifts(ctx, tx, name, local, before != ""); err != nil {
			return err
		}
	}
	held, records := c.userHolds.snapshot(name)
	if len(held) == 0 && len(records) == 0 {
		return nil
	}
	// A record only says a newer incarnation has been heard of (newerKnown);
	// one this node has reached is done with.
	doneRecords := map[uint64]bool{}
	for _, r := range records {
		if !incarnationAfter(r.inc, local) {
			doneRecords[r.seq] = true
		}
	}
	doneHeld := map[uint64]bool{}
	sort.SliceStable(held, func(i, j int) bool { return held[i].seq < held[j].seq })
	replay := c.userHoldReplay.Load()
	for _, w := range held {
		g := w.guard
		v, verr := c.userGuardVerdictOf(ctx, tx, &g)
		if verr != nil {
			return verr
		}
		switch v {
		case userVerdictSkip:
			doneHeld[w.seq] = true
		case userVerdictApply:
			if replay == nil {
				continue // replayed on the WAL path, where the replicator is
			}
			for _, s := range w.stmts {
				if err := (*replay)(ctx, tx, s, w.hlc); err != nil {
					// Dropped, as a parked update that fails to replay is:
					// failing here would refuse an unrelated write.
					slog.Warn("corrosion: dropped a held user write that failed to replay", "error", err)
					break
				}
				c.recordUserWrite(ctx, tx, s, s.Guard, onCommit)
			}
			doneHeld[w.seq] = true
		}
	}
	if len(doneHeld) > 0 || len(doneRecords) > 0 {
		onCommit(func() { c.userHolds.remove(name, doneHeld, doneRecords) })
	}
	return nil
}

// SetUserHoldReplay is wired by the replicator: how a held write is applied
// once its account's incarnation lands.
func (c *Client) setUserHoldReplay(fn func(context.Context, *sql.Tx, Statement, string) error) {
	c.userHoldReplay.Store(&fn)
}

// userIncarnationHeld is the incarnation the users row of name holds in
// tx, or "" when there is no row.
func userIncarnationHeld(ctx context.Context, tx *sql.Tx, name string) (string, error) {
	var created string
	err := tx.QueryRowContext(ctx, `SELECT created_at FROM users WHERE username = ?`, name).Scan(&created)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return created, err
}

// usersStatementName is the account a users-table statement writes, or "".
func usersStatementName(s Statement) string {
	sh, _, err := parseResolved(s.SQL)
	if err != nil || sh.Table != "users" {
		return ""
	}
	if pk, ok := pkValuesFromShape(sh, s); ok && len(pk) == 1 {
		return coerceString(pk[0])
	}
	switch stmtFingerprint(sh) {
	case fpUsersTombstoneIncarnation:
		return coerceString(s.Params[2])
	case fpUsersReactivateIncarnation:
		return coerceString(s.Params[4])
	}
	return ""
}

// tokenCredentialOf finds, after the token insert at stmts[i], the
// credential upsert of the same token in its entry.
func tokenCredentialOf(stmts []Statement, i int) (int, bool) {
	s := stmts[i]
	if len(s.Params) < 1 || !strings.Contains(s.SQL, "INTO tokens") {
		return 0, false
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil {
		return 0, false
	}
	if fp := stmtFingerprint(sh); fp != fpTokensInsert && fp != fpTokensInsertIncarnation {
		return 0, false
	}
	id := coerceString(s.Params[0])
	for j := i + 1; j < len(stmts); j++ {
		t := stmts[j]
		if len(t.Params) < 1 || coerceString(t.Params[0]) != id || !strings.Contains(t.SQL, "token_credentials") {
			continue
		}
		if sh2, _, err := parseResolved(t.SQL); err == nil && stmtFingerprint(sh2) == fpTokenCredentialUpsert {
			return j, true
		}
	}
	return 0, false
}

var (
	fpTokensInsert          = mustFingerprint(tokensInsertSQL)
	fpTokenCredentialUpsert = mustFingerprint(tokenCredentialUpsertSQL)
)

// loosensHere reports whether a lifecycle tightening, judged by its writer
// against the writer's value, would loosen the value this node holds.
func loosensHere(ctx context.Context, tx *sql.Tx, s Statement) (bool, error) {
	if len(s.Params) < 3 || !strings.Contains(s.SQL, "user_lifecycle") {
		return false, nil
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil || stmtFingerprint(sh) != fpUserLifecycleUpsert {
		return false, nil
	}
	tightens, err := statementTightensHere(ctx, tx, s)
	return !tightens, err
}

// warnHeldDropped says that a held grant or lift is given up: until
// anti-entropy brings it (a login session never: it is WAL-only), the account
// lacks it on this node.
func warnHeldDropped(name string, w userHeldWrite, why string) {
	table := ""
	if len(w.stmts) > 0 {
		if sh, _, err := parseResolved(w.stmts[0].SQL); err == nil {
			table = sh.Table
		}
	}
	slog.Warn("corrosion: gave up a user write held for an account this node has not reached; "+
		"anti-entropy repairs it, except a login session, which needs a new login",
		"user", name, "table", table, "incarnation", w.guard.Incarnation, "reason", why)
}
