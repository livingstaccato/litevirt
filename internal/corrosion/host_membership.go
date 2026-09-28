package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Host membership on a clock of its own (colonelpanik/litevirt#267).
//
// `hosts` is one row per host with ONE updated_at, and a dozen unrelated
// writers: the daemon reports its own version, schema and resources; operators
// configure fencing, role and region; the failover coordinator and operators
// move the host's state; a healthy peer records its isolation. Replication is
// statement-level with a row-level LWW gate, so two concurrent writes to
// DIFFERENT columns of the same host are not independent. A replica that
// applied the newer one first refuses the older one as stale, and the older
// write is lost there — or, when the two land at the same instant, the resolver
// rightly refuses to coin-flip `state` and the row stays divergent.
//
// This file gives the coordinator-owned columns a second home with a clock of
// their own:
//
//	hosts.state                              -> host_membership.state
//	hosts.isolation_epoch / isolation_reason -> host_membership.isolation_epoch / isolation_reason
//
// isolation_reason travels with the epoch because it is never written without
// it: IsolateHost sets both, ClearHostIsolation clears both. Nothing else about
// a host is written only by these writers, so nothing else moves in this slice;
// the operator-configured and self-reported columns (#267's host_config and
// host_runtime groups) stay on `hosts`. state and the isolation epoch still
// share host_membership's one clock with each other.
//
// THE ROLLING-UPGRADE CONTRACT. Two facts about a previous-release node decide
// the ordering, and both are facts about its binary:
//
//   - it has no ledger entry for any statement on host_membership, so a write
//     to it back-pressures that node's whole replication stream;
//   - it reads state and isolation from `hosts` and nowhere else.
//
// So nothing writes host_membership until host_membership_split_v1 has DURABLY
// latched on this node — a mandatory, ReplicationGated token, so the latch
// cannot form while any host this node replicates to is on the previous build.
// Until then every writer writes the hosts columns exactly as the previous
// release did, and every reader reads them.
//
// Once latched, SplitHostMembership copies every host's current values into
// host_membership, and from the end of this node's first complete pass
// ("live"):
//
//   - every writer of state and isolation writes BOTH homes, in one batch under
//     one updated_at: the hosts columns in their previous-release statement
//     shapes, and host_membership. The hosts copy is what keeps a rollback of
//     one release safe — a node back on the previous build reads hosts.state
//     and nothing else, and it must still see every drain, fence and
//     isolation. Nothing ever clears or freezes the hosts columns in this
//     release; retiring them is a later release's step behind a second token
//     (docs/design/host-membership-retire-old-columns.md).
//   - every reader reads state and isolation from host_membership ONLY,
//     falling back to the hosts columns for a host that has no membership row
//     yet.
//
// The hosts copy still shares the hosts row's clock, so it can still lose a
// concurrent write the way it always could, and on a replica that lost it the
// hosts row can be NEWER than the membership row while holding the OLDER
// state. That is why no reader ever compares the two copies: the membership
// row is the answer.
//
// WRITES MADE ALONE TO THE HOSTS COLUMNS. Latches form per node, so for a few
// seconds after one node latches its neighbour may not have yet, and that
// neighbour's writers write hosts only — as does a node rolled back one
// release. Such a write must reach host_membership, and it is recognised by
// where it came from, never by comparing values: a live writer always puts its
// hosts statement and its host_membership statement in the SAME replicated
// entry, so an entry that writes hosts' state or isolation columns with no
// host_membership statement in it was made by a node that was not writing
// host_membership (entryWritesTable). A latched receiver absorbs such a write
// into its membership row inside the apply transaction, locally and without
// re-emitting it, stamped with the write's own updated_at and only when that
// is newer than the row (absorbUnlatchedMembershipWrite). It does so on the
// WAL apply path and on the local write path, so the node that MADE a
// hosts-only write updates the membership row it holds too; a node whose gate
// is still closed only updates rows it already holds, never creates one. Every
// node computes the same row from the statement alone, so anti-entropy carries
// it to one that missed the entry.
//
// What is not absorbed: a hosts-only write that reached a node only by an
// anti-entropy row merge (a merge carries rows, not entries), unless some
// latched node received the entry itself; and, on a node whose gate was closed,
// a write that arrived before any membership row for that host did — its
// first pass then finds a peer's row and copies nothing, and it serves that
// row until anti-entropy brings the absorbed one.
// None of these can undo a fence: a value reaches host_membership only from a
// live writer, a first copy, or a hosts-only write newer than the row.
//
// TIMESTAMPS. A copied row takes the hosts row's updated_at, never NowTS, for
// the #268 reason: every node copies the same replicated hosts row, so every
// node writes the same membership row and the copies converge instead of
// racing, and a node whose hosts row is behind copies an OLDER timestamp that
// loses to a fresher node's copy.

// hostMembershipLiveFile is the durable half of "this node has completed a
// split pass". NODE-LOCAL: it describes which columns this node's readers
// trust.
const hostMembershipLiveFile = "host_membership_live"

// SetHostMembershipGate injects the predicate that permits WRITING
// host_membership. Wired at daemon start, before the host's first write, to
// the durable host_membership_split_v1 latch marker.
//
// Nil-safe and FAIL CLOSED: an unset gate writes the hosts columns only, which
// is exactly the previous release's behaviour. A wiring omission costs the
// split and never a peer's replication stream. The test constructors leave it
// closed; a test that wants the split opens it itself.
func (c *Client) SetHostMembershipGate(fn func() bool) {
	if fn == nil {
		c.hostMembershipGate.Store(nil)
		return
	}
	c.hostMembershipGate.Store(&fn)
}

// MayWriteHostMembership reports whether this node may write host_membership
// (nil-safe, fail closed).
func (c *Client) MayWriteHostMembership() bool {
	fn := c.hostMembershipGate.Load()
	return fn != nil && (*fn)()
}

// HostMembershipLive reports whether this node has completed a split pass with
// the gate open: its writers write host_membership and its readers read it.
func (c *Client) HostMembershipLive() bool {
	if c.hostMembershipLive.Load() {
		return true
	}
	// The marker only matters for a node that went live in an EARLIER
	// process: in this one, markHostMembershipLive sets the flag. So it is
	// consulted once, not on every read — HostIsolation runs per replication
	// push.
	if c.dataDir == "" || c.hostMembershipLiveChecked.Swap(true) {
		return false
	}
	if _, err := os.Stat(filepath.Join(c.dataDir, hostMembershipLiveFile)); err != nil {
		return false
	}
	c.hostMembershipLive.Store(true)
	return true
}

func (c *Client) markHostMembershipLive() {
	if c.hostMembershipLive.Swap(true) || c.dataDir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(c.dataDir, hostMembershipLiveFile), []byte("1\n"), 0o600); err != nil {
		// In-memory the node is live. After a restart it reads the hosts
		// columns until its first pass — the pre-split behaviour, and safe,
		// because every live write also writes them. The next pass retries.
		c.hostMembershipLive.Store(false)
		slog.Warn("host membership split: could not persist the live marker; retrying next pass", "error", err)
	}
}

// membershipVals are the columns this slice moves.
type membershipVals struct {
	State  string
	Epoch  int64
	Reason string
}

// membershipRow is one host as a reader or the pass sees it: its hosts columns
// and updated_at, and its host_membership row.
type membershipRow struct {
	name       string
	hosts      membershipVals
	hostsTS    string
	memPresent bool
	mem        membershipVals
	memTS      string
}

// resolve is THE read rule: before this node is live, or for a host with no
// membership row, the hosts columns — what the previous release reads.
// Otherwise the membership row, whatever the hosts copy says or however new
// its row is.
func (r membershipRow) resolve(live bool) membershipVals {
	if !live || !r.memPresent {
		return r.hosts
	}
	return r.mem
}

// membershipCols and membershipJoins are the read side of a host's membership,
// for any query over `hosts h`. Qualified and aliased, so they can sit beside
// other hosts columns.
const (
	membershipCols = `h.state AS h_state, h.isolation_epoch AS h_epoch,
		COALESCE(h.isolation_reason, '') AS h_reason, h.updated_at AS h_ts,
		m.host_name AS m_key, m.state AS m_state, m.isolation_epoch AS m_epoch,
		m.isolation_reason AS m_reason, m.updated_at AS m_ts`
	membershipJoins   = ` LEFT JOIN host_membership m ON m.host_name = h.name AND m.deleted_at IS NULL`
	membershipScanSQL = `SELECT h.name AS name, ` + membershipCols + ` FROM hosts h` + membershipJoins
)

func membershipRowFrom(r Row, name string) membershipRow {
	return membershipRow{
		name:       name,
		hosts:      membershipVals{State: r.String("h_state"), Epoch: r.Int64("h_epoch"), Reason: r.String("h_reason")},
		hostsTS:    r.String("h_ts"),
		memPresent: r.String("m_key") != "",
		mem:        membershipVals{State: r.String("m_state"), Epoch: r.Int64("m_epoch"), Reason: r.String("m_reason")},
		memTS:      r.String("m_ts"),
	}
}

func scanMembership(ctx context.Context, c *Client, where string, args ...interface{}) ([]membershipRow, error) {
	rows, err := c.Query(ctx, membershipScanSQL+where, args...)
	if err != nil {
		return nil, err
	}
	out := make([]membershipRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, membershipRowFrom(r, r.String("name")))
	}
	return out, nil
}

// hostMembershipOf resolves one live host's membership, nil when the host has
// no live hosts row.
func hostMembershipOf(ctx context.Context, c *Client, host string) (*membershipVals, error) {
	rows, err := scanMembership(ctx, c, ` WHERE h.name = ? AND h.deleted_at IS NULL`, host)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	v := rows[0].resolve(c.HostMembershipLive())
	return &v, nil
}

// resolvedHostStates is every live host's resolved state, by name.
func resolvedHostStates(ctx context.Context, c *Client) (map[string]string, error) {
	rows, err := scanMembership(ctx, c, ` WHERE h.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	live := c.HostMembershipLive()
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.name] = r.resolve(live).State
	}
	return out, nil
}

// The membership writers. Both upserts are explicit on the primary key, so the
// origin applies them whether or not it holds the row and a receiver LWW-gates
// them on updated_at (DispExplicitUpsert).
const (
	// hostMembershipUpsertSQL writes every column: the pass's copy, and a
	// host created by a live InsertHost.
	hostMembershipUpsertSQL = `INSERT INTO host_membership (host_name, state, isolation_epoch, isolation_reason, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET state = excluded.state,
		   isolation_epoch = excluded.isolation_epoch, isolation_reason = excluded.isolation_reason,
		   updated_at = excluded.updated_at, deleted_at = NULL`
	// hostMembershipStateSQL changes state and nothing else on a row that
	// exists. The isolation values are only used by a receiver that has no row
	// yet, which takes them from the writer's view.
	hostMembershipStateSQL = `INSERT INTO host_membership (host_name, state, isolation_epoch, isolation_reason, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET state = excluded.state,
		   updated_at = excluded.updated_at, deleted_at = NULL`
	// The isolation writers keep hosts' guards: record only over epoch 0,
	// clear only the pinned epoch (isolation.go says why).
	hostMembershipIsolateSQL = `UPDATE host_membership SET isolation_epoch = ?, isolation_reason = ?, updated_at = ?
		 WHERE host_name = ? AND deleted_at IS NULL AND isolation_epoch = 0`
	hostMembershipClearIsolationSQL = `UPDATE host_membership SET isolation_epoch = 0, isolation_reason = '', updated_at = ?
		 WHERE host_name = ? AND deleted_at IS NULL AND isolation_epoch = ?`
)

// membershipEpochIs is the guard of a live isolation write: host has a live
// membership row whose epoch is want. Evaluated inside the write's transaction.
func membershipEpochIs(ctx context.Context, host string, want int64) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var got int64
		err := tx.QueryRowContext(ctx,
			`SELECT isolation_epoch FROM host_membership WHERE host_name = ? AND deleted_at IS NULL`, host).Scan(&got)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return got == want, nil
	}
}

// ── writes made by a node that was not writing host_membership ─────────────

// unlatchedMembershipWrite is what one entry from a node that was not writing
// host_membership wrote to one host's state or isolation columns, and under
// which updated_at. Later statements in the entry override earlier ones.
type unlatchedMembershipWrite struct {
	host, ts string
	hasState bool
	state    string
	hasIso   bool
	epoch    int64
	reason   string
}

// unlatchedMembershipWrites extracts, from one replicated entry, every write to
// hosts' state or isolation columns — nil when the entry also writes
// host_membership (a live node's dual-write, whose membership half is already
// in the entry). Values come from the statement itself, so every receiver
// computes the same result whatever its own hosts row holds. A value the parse
// cannot read exactly (an expression rather than a parameter or a plain
// literal) leaves that column group out.
func unlatchedMembershipWrites(stmts []Statement) []unlatchedMembershipWrite {
	if entryWritesTable(stmts, "host_membership") {
		return nil
	}
	var out []unlatchedMembershipWrite
	byHost := map[string]int{}
	for _, s := range stmts {
		if !strings.Contains(s.SQL, "hosts") {
			continue
		}
		sh, _, err := parseResolved(s.SQL)
		if err != nil || sh.Table != "hosts" || sh.ValidateParamArity(len(s.Params)) != nil {
			continue
		}
		vals := map[string]interface{}{}
		known := map[string]bool{}
		switch sh.Kind {
		case KindUpdate:
			for _, a := range sh.SetAssigns {
				v, ok := assignedValue(a.Expr, s.Params)
				vals[strings.ToLower(a.Column)], known[strings.ToLower(a.Column)] = v, ok
			}
		case KindInsert:
			_, row, ok := insertRowFromShape(sh, s)
			if !ok {
				continue
			}
			for i, col := range sh.InsertCols {
				vals[strings.ToLower(col)], known[strings.ToLower(col)] = row[i], true
			}
		default:
			continue
		}
		_, touchesState := known["state"]
		_, touchesEpoch := known["isolation_epoch"]
		if !touchesState && !touchesEpoch {
			continue
		}
		pk, ok := pkValuesFromShape(sh, s)
		if !ok || len(pk) != 1 {
			continue
		}
		ts, ok := incomingUpdatedAtFromShape(sh, s)
		if !ok || ts == "" {
			continue
		}
		host := coerceString(pk[0])
		i, seen := byHost[host]
		if !seen {
			i = len(out)
			byHost[host] = i
			out = append(out, unlatchedMembershipWrite{host: host})
		}
		w := &out[i]
		if lwwOrder(w.ts, ts) < 0 {
			w.ts = ts
		}
		if known["state"] {
			w.hasState, w.state = true, coerceString(vals["state"])
		}
		if known["isolation_epoch"] {
			epoch, ok := coerceInt64OK(vals["isolation_epoch"])
			if ok && (known["isolation_reason"] || sh.Kind == KindInsert) {
				w.hasIso, w.epoch, w.reason = true, epoch, coerceString(vals["isolation_reason"])
			}
		}
	}
	return out
}

// assignedValue is the exact value an UPDATE assignment writes: its sole bound
// parameter, or a plain integer or string literal in the shape's canonical
// encoding ("n<len>:<digits>", "s<len>:<text>").
func assignedValue(e NormalizedExpr, params []interface{}) (interface{}, bool) {
	if e.SoleParam >= 0 && e.SoleParam < len(params) {
		return params[e.SoleParam], true
	}
	if len(e.ParamIdx) != 0 || len(e.Text) < 3 {
		return nil, false
	}
	colon := strings.IndexByte(e.Text, ':')
	if colon < 2 {
		return nil, false
	}
	var n int
	if _, err := fmt.Sscanf(e.Text[1:colon], "%d", &n); err != nil || colon+1+n != len(e.Text) {
		return nil, false
	}
	body := e.Text[colon+1:]
	switch e.Text[0] {
	case 's':
		return body, true
	case 'n':
		var v int64
		if _, err := fmt.Sscanf(body, "%d", &v); err != nil {
			return nil, false
		}
		return v, true
	}
	return nil, false
}

// Local-only writes of a membership row by absorbUnlatchedMembershipWrite.
// They run inside the write's own transaction and are never logged for
// replication: every node that sees the same entry computes the same row, and
// anti-entropy carries it to one that did not.
const (
	absorbStateSQL = `UPDATE host_membership SET state = ?, updated_at = ? WHERE host_name = ?`
	absorbIsoSQL   = `UPDATE host_membership SET isolation_epoch = ?, isolation_reason = ?, updated_at = ?
		 WHERE host_name = ?`
	absorbBothSQL = `UPDATE host_membership SET state = ?, isolation_epoch = ?, isolation_reason = ?, updated_at = ?
		 WHERE host_name = ?`
	absorbInsertSQL = `INSERT INTO host_membership (host_name, state, isolation_epoch, isolation_reason, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)`
)

// absorbUnlatchedMembershipWrite carries an entry's hosts-only state and
// isolation writes into host_membership, inside the write's own transaction.
// It runs on both paths a write reaches a node by: the WAL apply path (a
// peer's entry) and the local write path (this node's own statements, just
// before they are logged). An entry that writes host_membership itself is a
// live writer's dual-write and is skipped (entryWritesTable).
//
// A write is taken only for a live hosts row, only when its updated_at is
// newer than the membership row's, and the row takes the write's own
// updated_at. mayInsert — this node's host_membership_split_v1 gate is open —
// lets it create a row that does not exist yet, taking the column group the
// write did not set from the hosts row. With the gate closed it only UPDATES a
// row this node already holds: such rows exist only because a latched peer
// wrote them, and updating one keeps this node from serving the value from
// before its own or a neighbour's write once it latches — the stale "active"
// on the very node that fenced.
//
// An error is returned, never swallowed. The caller fails the write: the WAL
// apply path rolls the batch back and back-pressures the sender, the local
// path returns the error to the writer. Swallowing it would commit the hosts
// half, mark the entry seen, and leave this node reading the membership row
// from before a fence with nothing but anti-entropy to correct it. The absorb
// runs in the same transaction and database as the statements that just
// applied, so anything that fails it would fail them too.
func absorbUnlatchedMembershipWrite(ctx context.Context, tx *sql.Tx, stmts []Statement, mayInsert bool) error {
	for _, w := range unlatchedMembershipWrites(stmts) {
		if err := absorbMembershipWrite(ctx, tx, w, w.ts, mayInsert); err != nil {
			return fmt.Errorf("absorb hosts-only membership write for %s: %w", w.host, err)
		}
	}
	return nil
}

// absorbMembershipWrite writes one absorbed write, LWW-gated on updatedAt. It
// takes updatedAt from its caller because an absorbed row carries the WRITE's
// own updated_at, never a fresh clock: every node must compute the same row.
func absorbMembershipWrite(ctx context.Context, tx *sql.Tx, w unlatchedMembershipWrite, updatedAt string, mayInsert bool) error {
	var hState, hReason string
	var hEpoch int64
	err := tx.QueryRowContext(ctx,
		`SELECT state, isolation_epoch, COALESCE(isolation_reason, '') FROM hosts WHERE name = ? AND deleted_at IS NULL`,
		w.host).Scan(&hState, &hEpoch, &hReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // no live host: nothing a live writer would record either
	}
	if err != nil {
		return err
	}
	var memTS string
	err = tx.QueryRowContext(ctx, `SELECT updated_at FROM host_membership WHERE host_name = ?`, w.host).Scan(&memTS)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if !mayInsert {
			return nil
		}
		state, epoch, reason := hState, hEpoch, hReason
		if w.hasState {
			state = w.state
		}
		if w.hasIso {
			epoch, reason = w.epoch, w.reason
		}
		_, err = tx.ExecContext(ctx, absorbInsertSQL, w.host, state, epoch, reason, updatedAt)
		return err
	case err != nil:
		return err
	case lwwOrder(memTS, updatedAt) >= 0:
		return nil // the membership row is as new or newer
	}
	switch {
	case w.hasState && w.hasIso:
		_, err = tx.ExecContext(ctx, absorbBothSQL, w.state, w.epoch, w.reason, updatedAt, w.host)
	case w.hasState:
		_, err = tx.ExecContext(ctx, absorbStateSQL, w.state, updatedAt, w.host)
	case w.hasIso:
		_, err = tx.ExecContext(ctx, absorbIsoSQL, w.epoch, w.reason, updatedAt, w.host)
	}
	return err
}

// MembershipWrite is unlatchedMembershipWrites for the ledger guard in
// scripts/ci/stmtshapecheck, which checks that every registered shape writing
// hosts.state or the isolation columns is one this parser reads. ok is false
// when the statement yields no write.
func MembershipWrite(s Statement) (host, ts string, hasState bool, state string, hasIso bool, epoch int64, reason string, ok bool) {
	ws := unlatchedMembershipWrites([]Statement{s})
	if len(ws) != 1 {
		return "", "", false, "", false, 0, "", false
	}
	w := ws[0]
	return w.host, w.ts, w.hasState, w.state, w.hasIso, w.epoch, w.reason, true
}

// ── the pass ────────────────────────────────────────────────────────────────

// HostMembershipReport is what one SplitHostMembership pass did.
type HostMembershipReport struct {
	// Copied counts hosts given their first membership row.
	Copied int
}

// membershipCopyTS is the updated_at a copied row carries: the hosts row's. See
// TIMESTAMPS above.
func (c *Client) membershipCopyTS(hostsTS string) string {
	if _, ok := tsInstant(hostsTS); ok {
		return hostsTS
	}
	return c.NowTS()
}

// SplitHostMembership gives every host that has no membership row one copied
// from hosts. It never writes the hosts columns and never touches an existing
// membership row. It does nothing unless the host_membership_split_v1 gate is
// open, and it is idempotent. The daemon runs it at start and periodically, and
// every membership writer runs it first. Its replicated writes go out on the
// WAL lane and are repaired by public anti-entropy.
func (c *Client) SplitHostMembership(ctx context.Context) (HostMembershipReport, error) {
	if !c.MayWriteHostMembership() {
		return HostMembershipReport{}, nil
	}
	c.hostMembershipMu.Lock()
	defer c.hostMembershipMu.Unlock()
	return c.splitHostMembershipLocked(ctx)
}

func (c *Client) splitHostMembershipLocked(ctx context.Context) (HostMembershipReport, error) {
	var rep HostMembershipReport
	rows, err := scanMembership(ctx, c, ` WHERE h.deleted_at IS NULL`)
	if err != nil {
		return rep, fmt.Errorf("host membership split: scan: %w", err)
	}
	var firstErr error
	for _, r := range rows {
		if r.memPresent {
			continue
		}
		wrote, err := c.writeMembershipRow(ctx, r.name, r.hosts, c.membershipCopyTS(r.hostsTS))
		if err != nil {
			slog.Warn("host membership split: pass incomplete; retrying next cycle", "host", r.name, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("host membership split: %s: %w", r.name, err)
			}
			continue
		}
		if wrote {
			rep.Copied++
		}
	}
	if firstErr == nil {
		c.markHostMembershipLive()
	}
	return rep, firstErr
}

// writeMembershipRow is the pass's one replicated write: a host's first
// membership row. It takes updatedAt from its caller because the pass stamps
// the hosts row's updated_at, never a fresh clock (see TIMESTAMPS above).
//
// It is guarded, inside its own transaction, on the row still being absent.
// The origin applies an upsert unconditionally, so without the guard a peer's
// newer copy arriving between the pass's scan and this write would be
// overwritten here with an older one — and, the older write being this node's,
// never repaired by the WAL. Found under -race, where the window is wide.
func (c *Client) writeMembershipRow(ctx context.Context, host string, v membershipVals, updatedAt string) (bool, error) {
	return c.ExecuteBatchGuarded(ctx, membershipRowAbsent(ctx, host), []Statement{
		{SQL: hostMembershipUpsertSQL, Params: []interface{}{host, v.State, v.Epoch, v.Reason, updatedAt}},
	})
}

// membershipRowAbsent is writeMembershipRow's guard: host has no membership
// row, live or tombstoned.
func membershipRowAbsent(ctx context.Context, host string) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM host_membership WHERE host_name = ?`, host).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return false, err
	}
}

// withMembershipWrite runs a state or isolation writer. live is true when the
// writer must write host_membership as well as the hosts columns, false when it
// writes the hosts columns only (the gate is closed, or this node has not
// completed a pass yet).
//
// With the gate open it holds hostMembershipMu and runs the split pass first,
// so a node's first write after its latch already goes to both homes.
func (c *Client) withMembershipWrite(ctx context.Context, fn func(live bool) error) error {
	if !c.MayWriteHostMembership() {
		return fn(false)
	}
	c.hostMembershipMu.Lock()
	defer c.hostMembershipMu.Unlock()
	if _, err := c.splitHostMembershipLocked(ctx); err != nil {
		slog.Warn("host membership split: pass before a membership write failed", "error", err)
	}
	return fn(c.HostMembershipLive())
}

// currentIsolation is host's resolved isolation, for a live state writer's
// insert values: a receiver with no membership row for the host yet takes them.
func currentIsolation(ctx context.Context, c *Client, host string) (int64, string, error) {
	cur, err := hostMembershipOf(ctx, c, host)
	if err != nil || cur == nil {
		return 0, "", err
	}
	return cur.Epoch, cur.Reason, nil
}
