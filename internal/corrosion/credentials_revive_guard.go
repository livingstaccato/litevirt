package corrosion

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Retirement evidence on host_fence_credentials.
//
// A host's credential row is retired (a tombstone) by its removal or
// re-admission (host_readmit.go), at the admission's own instant T. Only an
// operator legitimately sets a password for the host after that: `lv host
// config --ipmi-pass` (or --clear-ipmi), whose entry always carries the hosts
// write of the password beside the credential upsert. Every other writer of a
// live row — the split passes, and a previous build's split passes mid-roll —
// writes the upsert alone (or beside the empty old-column clear), and on a
// stale node it writes the OLD machine's password under a clock newer than T.
//
// So each row carries the retirement it is ordered after: a tombstone's is its
// own deleted_at, and a live row's is after_retirement — the retirement this
// node held when the operator's write set it, '' when none. Rows are ordered
// by (retirement, updated_at), retirement first. The order is total, so the
// result does not depend on which row a node saw first, on the WAL lane or in
// anti-entropy:
//
//   - a live row set by an operator after T carries T, and beats the
//     tombstone by its newer updated_at;
//   - a live row with no evidence — a split-pass copy, a previous build's
//     revive, a write from before T — never beats the tombstone, however new
//     its clock;
//   - a later retirement beats every row set before it.
//
// THE EVIDENCE IS DERIVED, never sent. A credential upsert's wire shape does
// not change: on the WAL apply path and the local write path, an upsert whose
// entry also writes that host's password in hosts (an operator's write) takes
// the retirement of the row it lands on; any other upsert carries none
// (planCredentialUpsert). Rows carry the column to anti-entropy, where the
// order decides (mergeCredentialOrder). A previous-release row has no column:
// a tombstone's retirement is still its deleted_at, and a live row's is ''.
//
// The cost, stated in docs/migration-failover.md: a live row the migration
// carried over has no evidence, and neither has a password a previous build
// writes, so either loses to a tombstone of a retirement it was in fact set
// after, and to any password this build set after it, until it is written
// again on this build.

var (
	hostCredentialUpsertFingerprint = mustStatementFingerprint(HostFenceCredentialUpsertSQL)
	hostsClearIPMIPassFingerprint   = mustStatementFingerprint(hostsClearIPMIPassSQL)
)

// credentialOrder is a host_fence_credentials row's place in the order.
type credentialOrder struct {
	retirement, updatedAt string
}

// cmpEvidence orders two retirements; the empty one (none) is the lowest.
func cmpEvidence(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}
	return lwwOrder(a, b)
}

// cmp orders o against p: retirement first, then updated_at.
func (o credentialOrder) cmp(p credentialOrder) int {
	if c := cmpEvidence(o.retirement, p.retirement); c != 0 {
		return c
	}
	return lwwOrder(o.updatedAt, p.updatedAt)
}

// rowRetirement is a row's retirement: a tombstone's own deleted_at, a live
// row's after_retirement.
func rowRetirement(deletedAt, afterRetirement string) string {
	if deletedAt != "" {
		return deletedAt
	}
	return afterRetirement
}

// localCredential is this node's row for host, if any.
type localCredential struct {
	exists           bool
	pass, deletedAt  string
	updatedAt, after string
}

func (l localCredential) order() credentialOrder {
	return credentialOrder{retirement: rowRetirement(l.deletedAt, l.after), updatedAt: l.updatedAt}
}

func readLocalCredential(ctx context.Context, tx *sql.Tx, host string) (localCredential, error) {
	var pass, updated, after string
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT ipmi_pass, updated_at, deleted_at, after_retirement FROM host_fence_credentials WHERE host_name = ?`,
		host).Scan(&pass, &updated, &deleted, &after)
	switch {
	case err == sql.ErrNoRows:
		return localCredential{}, nil
	case err != nil:
		return localCredential{}, err
	}
	return localCredential{exists: true, pass: pass, deletedAt: deleted.String, updatedAt: updated, after: after}, nil
}

// credentialUpsertPlan is what one statement does to host_fence_credentials.
type credentialUpsertPlan struct {
	skip  bool   // not applied here
	stamp bool   // applied: set after_retirement to evidence if it landed
	host  string // the row
	pass  string // the statement's password and updated_at, to tell
	ts    string // whether what landed is this statement's
	// evidence is the retirement the row carries if it lands.
	evidence string
}

// planCredentialUpsert decides a HostFenceCredentialUpsertSQL statement on
// this node, on the WAL apply path and the local write path alike.
//
//   - An operator's write (its entry writes the host's password in hosts)
//     takes the retirement of the row it lands on, and is then ordered by its
//     clock as any write is.
//   - Any other upsert carries no retirement, so it is not applied over a row
//     that carries one, unless it is that row's own re-emission (same password
//     and clock: the clear pass hands its row to its stream ahead of the
//     clear).
//
// An operator's write takes the held retirement only when this node's hosts
// row, as it stood before the entry (pre), is the admission that retirement
// belongs to or a later one (admissionAtOrAfter). A node whose hosts row lags
// the re-admission while its credential row already holds the re-admission's
// tombstone (the sensitive anti-entropy pull ran, the public one did not)
// would otherwise hand a lagging operator write from the OLD admission the
// NEW retirement as evidence, and the old machine's password would then win
// everywhere. Such a write is treated as carrying no evidence.
func planCredentialUpsert(ctx context.Context, tx *sql.Tx, s Statement, entry []Statement, pre entryHostRows) (credentialUpsertPlan, error) {
	if !strings.Contains(s.SQL, "host_fence_credentials") {
		return credentialUpsertPlan{}, nil
	}
	if fp, err := FingerprintSQL(s.SQL); err != nil || fp != hostCredentialUpsertFingerprint {
		return credentialUpsertPlan{}, nil
	}
	host, hok := paramString(s.Params, 0)
	pass, pok := paramString(s.Params, 1)
	ts, tok := paramString(s.Params, 2)
	if !hok || !pok || !tok || host == "" {
		return credentialUpsertPlan{}, nil
	}
	local, err := readLocalCredential(ctx, tx, host)
	if err != nil {
		return credentialUpsertPlan{}, err
	}
	plan := credentialUpsertPlan{stamp: true, host: host, pass: pass, ts: ts}
	if !local.exists {
		return plan, nil
	}
	held := local.order().retirement
	if entryWritesHostPassword(entry, host) && (held == "" || pre[host].admissionAtOrAfter(held)) {
		plan.evidence = held
		return plan, nil
	}
	if held == "" {
		return plan, nil
	}
	if local.deletedAt == "" && local.pass == pass && local.updatedAt == ts {
		return credentialUpsertPlan{}, nil // its own re-emission: a no-op here
	}
	noteRetiredCredentialKept(host, "an entry with no operator password write")
	return credentialUpsertPlan{skip: true}, nil
}

// entryHostRow is a host's hosts row as it stood before an entry applied.
type entryHostRow struct {
	found, deleted       bool
	n                    int64
	createdAt, updatedAt string
}

// entryHostRows are the hosts rows of the hosts an entry's credential upserts,
// or its hosts password writes, name, read before any statement of the entry
// runs.
type entryHostRows map[string]entryHostRow

// readEntryHostRows reads, before an entry applies, the hosts row of every
// host one of its credential upserts or hosts password writes names.
func readEntryHostRows(ctx context.Context, tx *sql.Tx, entry []Statement) (entryHostRows, error) {
	var out entryHostRows
	for _, s := range entry {
		host := credentialUpsertHost(s)
		if host == "" {
			if w, ok := secretWriteOf(s); ok && w.col.parent == "hosts" {
				host = w.key
			}
		}
		if host == "" {
			continue
		}
		if _, ok := out[host]; ok {
			continue
		}
		if out == nil {
			out = entryHostRows{}
		}
		var r entryHostRow
		var created, updated, deleted sql.NullString
		err := tx.QueryRowContext(ctx,
			`SELECT incarnation, created_at, updated_at, deleted_at FROM hosts WHERE name = ?`, host).
			Scan(&r.n, &created, &updated, &deleted)
		switch {
		case err == sql.ErrNoRows:
		case err != nil:
			return nil, err
		default:
			r.found = true
			r.createdAt, r.updatedAt = created.String, updated.String
			r.deleted = deleted.Valid && deleted.String != ""
		}
		out[host] = r
	}
	return out, nil
}

// addMissing adds every host of more that r does not hold yet: the row before
// the first entry that named it.
func (r entryHostRows) addMissing(more entryHostRows) entryHostRows {
	for h, row := range more {
		if r == nil {
			r = entryHostRows{}
		}
		if _, ok := r[h]; !ok {
			r[h] = row
		}
	}
	return r
}

// admissionAtOrAfter reports whether the hosts row is the admission that
// retirement held belongs to, or a later one.
//
//   - A re-admission's row starts at the retirement's own instant: a V2
//     re-admission's created_at is ReadmitStamp of its updated_at, and a
//     legacy one's is rewritten to it (stampReadmitIncarnation). So a row
//     created at or after held is that admission or a later one.
//   - At incarnation 0 a row re-admitted by a previous build kept its first
//     created_at; its updated_at, which the re-admission set to held, is then
//     what shows it has seen the retirement. (Not at 1 or higher: every such
//     row was admitted by this build, with its created_at stamped.)
//   - A removed row, or none, is no admission an operator writes for.
func (r entryHostRow) admissionAtOrAfter(held string) bool {
	if !r.found || r.deleted {
		return false
	}
	if notBefore(r.createdAt, held) {
		return true
	}
	return r.n == 0 && notBefore(r.updatedAt, held)
}

// notBefore reports whether ts is at or after held, by instant (a re-admission
// stamps created_at in RFC3339 from an updated_at that may be an HLC).
func notBefore(ts, held string) bool {
	a, aok := tsInstant(ts)
	b, bok := tsInstant(held)
	if aok && bok {
		return cmpInstants(a, b) >= 0
	}
	return lwwOrder(ts, held) >= 0
}

// credentialUpsertHost is the host a HostFenceCredentialUpsertSQL statement
// sets, "" for any other statement.
func credentialUpsertHost(s Statement) string {
	if !strings.Contains(s.SQL, "host_fence_credentials") {
		return ""
	}
	if fp, err := FingerprintSQL(s.SQL); err != nil || fp != hostCredentialUpsertFingerprint {
		return ""
	}
	host, _ := paramString(s.Params, 0)
	return host
}

// apply records the plan's evidence on the row its statement landed.
func (p credentialUpsertPlan) apply(ctx context.Context, tx *sql.Tx) error {
	if !p.stamp {
		return nil
	}
	return stampCredentialEvidence(ctx, tx, p.host, p.pass, p.ts, p.evidence)
}

// stampCredentialEvidence sets after_retirement on host's row if it is live
// and holds pass at updatedAt — the write that just landed, not a newer one.
// Local and never logged, like every derivation of the evidence.
func stampCredentialEvidence(ctx context.Context, tx *sql.Tx, host, pass, updatedAt, evidence string) error {
	_, err := tx.ExecContext(ctx, `UPDATE host_fence_credentials SET after_retirement = ?
		WHERE host_name = ? AND deleted_at IS NULL AND ipmi_pass = ? AND updated_at = ?`,
		evidence, host, pass, updatedAt)
	return err
}

// entryWritesHostPassword reports whether the entry sets host's password in
// hosts.ipmi_pass as an operator write does: any hosts statement that binds
// the password, except the split pass's empty old-column clear.
func entryWritesHostPassword(entry []Statement, host string) bool {
	for _, s := range entry {
		w, ok := secretWriteOf(s)
		if !ok || w.col.parent != "hosts" || w.key != host {
			continue
		}
		if w.value == "" {
			if fp, err := FingerprintSQL(s.SQL); err == nil && fp == hostsClearIPMIPassFingerprint {
				continue
			}
		}
		return true
	}
	return false
}

// Anti-entropy decisions for one incoming host_fence_credentials row.
const (
	credentialMergeDefault   = iota // same retirement: the ordinary LWW merge
	credentialMergeKeepLocal        // the local row is later in the order
	credentialMergeApply            // the incoming row is later in the order
)

// mergeCredentialOrder orders an incoming anti-entropy row against the local
// one when their retirements differ. With the same retirement the ordinary
// merge (LWW and its tie chain) decides, as for any table.
//
// A row the order would apply is first held to the future-skew quarantine the
// ordinary merge applies (skewQuarantinesIncoming), on its clock and on the
// retirement it carries: a clock-corrupt peer's future-dated tombstone, or a
// live row set after a future-dated retirement, would otherwise stand over
// every later operator write until the wall clock passed it.
func (c *Client) mergeCredentialOrder(tx *sql.Tx, table syncTable, row []interface{}, skewGuardOn bool, skewNow time.Time) (int, error) {
	if table.Name != "host_fence_credentials" {
		return credentialMergeDefault, nil
	}
	idx := columnIndexMap(table.Columns)
	host := cellStr(row, idx, "host_name")
	if host == "" {
		return credentialMergeDefault, nil
	}
	in := credentialOrder{
		retirement: rowRetirement(cellStr(row, idx, "deleted_at"), cellStr(row, idx, "after_retirement")),
		updatedAt:  cellStr(row, idx, "updated_at"),
	}
	local, err := readLocalCredential(context.Background(), tx, host)
	if err != nil {
		return credentialMergeDefault, err
	}
	if !local.exists {
		// First seen: the ordinary merge checks the clock; the retirement
		// is checked here, or a row set after a future-dated retirement
		// would outrank every removal until the wall clock passed it.
		if c.skewQuarantinesIncoming(skewGuardOn, "", in.retirement, skewNow) {
			slog.Warn("sync: quarantined future-skewed incoming row (not applied)",
				"table", table.Name, "reason", "future_skew", "first_seen", true)
			return credentialMergeKeepLocal, nil
		}
		return credentialMergeDefault, nil
	}
	held := local.order()
	switch cmpEvidence(in.retirement, held.retirement) {
	case 1:
		if c.skewQuarantinesIncoming(skewGuardOn, held.updatedAt, in.updatedAt, skewNow) ||
			c.skewQuarantinesIncoming(skewGuardOn, held.retirement, in.retirement, skewNow) {
			slog.Warn("sync: quarantined future-skewed incoming row (not applied)",
				"table", table.Name, "reason", "future_skew", "first_seen", false)
			return credentialMergeKeepLocal, nil
		}
		return credentialMergeApply, nil
	case -1:
		noteRetiredCredentialKept(host, "a peer's row set before this node's retirement")
		return credentialMergeKeepLocal, nil
	}
	return credentialMergeDefault, nil
}

// clearTombstoneEvidence leaves every host_fence_credentials tombstone with no
// after_retirement, after an anti-entropy chunk of the table. A tombstone's
// place in the order is its deleted_at; after_retirement means nothing on it,
// and every tombstone this build writes (retireFenceCredential) carries none.
// A previous build's dump has no such column, and the merge upsert updates
// only the columns a dump carries, so its tombstone applied over a live row
// set after an earlier retirement would keep that row's after_retirement. Its
// content would then differ from the same tombstone on every other node, the
// digests would never agree, and the exact-clock tie between the two would be
// unresolved for good (lww_tie_unresolved). Local and never logged.
func clearTombstoneEvidence(tx *sql.Tx) error {
	_, err := tx.ExecContext(context.Background(), `UPDATE host_fence_credentials SET after_retirement = ''
		WHERE COALESCE(deleted_at, '') != '' AND after_retirement != ''`)
	return err
}

// noteRetiredCredentialKept logs, at most once per host per interval, that a
// write lost to a retirement it was not set after.
func noteRetiredCredentialKept(host, what string) {
	retiredKeptLog.mu.Lock()
	defer retiredKeptLog.mu.Unlock()
	now := time.Now()
	if at, ok := retiredKeptLog.at[host]; ok && now.Sub(at) < driftRepeatInterval {
		return
	}
	if retiredKeptLog.at == nil {
		retiredKeptLog.at = map[string]time.Time{}
	}
	retiredKeptLog.at[host] = now
	slog.Warn("a fence credential write lost to a retirement it was not set after; keeping the local row",
		"host", host, "from", what)
}

var retiredKeptLog struct {
	mu sync.Mutex
	at map[string]time.Time
}
