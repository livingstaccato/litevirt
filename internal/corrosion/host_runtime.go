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

// Host runtime on a clock of its own (colonelpanik/litevirt#267, the runtime
// half; host_membership.go is the membership half).
//
// `hosts` is one row per host with ONE updated_at. Once host_membership took
// the coordinator's columns away, two writer classes were left on it: the
// operator, who configures the host (address, role, region, fencing, capacity
// overrides, labels), and the host's own daemon, which reports what it is
// running and what it has:
//
//	hosts.version              -> host_runtime.version
//	hosts.schema_version       -> host_runtime.schema_version
//	hosts.cpu_total            -> host_runtime.cpu_total
//	hosts.mem_total            -> host_runtime.mem_total
//	hosts.disk_total           -> host_runtime.disk_total
//	hosts.capacity_policy_hash -> host_runtime.capacity_policy_hash
//
// Replication is statement-level with a row-level LWW gate, so an operator's
// region change on one node and the host's boot report on another are not
// independent: a replica that applied the newer one first refuses the older
// one as stale, and loses it. This file gives the self-reported columns a
// second home with a clock of their own. Identity and operator configuration
// stay on `hosts`, the anchor, as the issue's fix direction says.
//
// THE ROLLING-UPGRADE CONTRACT is host_membership's, for the same two facts
// about a previous-release node's binary: it has no ledger entry for any
// statement on host_runtime (a write to it back-pressures that node's whole
// stream), and it reads the runtime columns from `hosts` and nowhere else. So
// nothing writes host_runtime until host_runtime_split_v1 has DURABLY latched
// on this node — mandatory and ReplicationGated, so the latch cannot form
// while any host this node replicates to is on the previous build. Until then
// every writer writes the hosts columns exactly as the previous release did.
//
// Once latched, SplitHostRuntime copies every host's current values into
// host_runtime, and from the end of this node's first complete pass ("live"):
//
//   - every runtime writer writes BOTH homes, in one batch under one
//     updated_at: the hosts columns in their previous-release statement
//     shapes, and host_runtime. The hosts copy keeps a rollback of one release
//     reading current values. Nothing clears it; host_runtime_retire_v1 stops
//     the pure runtime writers writing it (host_runtime_retire.go).
//   - every reader (scanHost: GetHost, ListHosts, and through them placement,
//     the upgrade gates, `lv host ls`, the UI and MCP host views) reads the
//     runtime columns from a present host_runtime row, whatever the hosts copy
//     says or however new its row is, falling back to the hosts columns only
//     for a host with no live row.
//
// No reader compares the two copies. The hosts copy still shares the hosts
// row's clock, so on a replica that refused the hosts half of a version report
// because a concurrent region change was newer, the hosts row is the NEWER
// row holding the OLDER version.
//
// WRITES MADE ALONE TO THE HOSTS COLUMNS — by a neighbour whose latch has not
// formed yet — are recognised by their ENTRY, never by comparing values or
// against hosts.updated_at (unlatched_origin.go): a live writer always puts its
// host_runtime statement in the same entry as its hosts statement. A receiver
// takes such a write into the host_runtime row it holds, inside the apply
// transaction, locally and never logged, stamped with the write's own
// updated_at and only when that is newer than the row
// (absorbUnlatchedRuntimeWrite). It runs on the WAL apply path and on the
// local write path. A node whose gate is closed only updates a row it already
// holds; one whose gate is open may also create it.
//
// TIMESTAMPS. A copied row takes the hosts row's updated_at moved back by the
// floor shift host_membership uses (membershipCopyTS), never NowTS: every node
// that copies the same replicated hosts row writes the same host_runtime row,
// a node whose hosts row is behind copies an older stamp that loses, and no
// copy ever beats a real report — hosts.updated_at moves on every operator
// write while the runtime columns may be stale.
//
// RE-ADMISSION. A host re-admitted over its tombstone is a new machine; every
// node that applies the re-admission retires the old machine's host_runtime
// row (host_readmit.go, readmitResetTables), and readers fall back to the
// hosts columns — reset to the defaults there — until the new daemon reports.

// hostRuntimeLiveFile is the durable half of "this node has completed a
// runtime split pass". NODE-LOCAL, like hostMembershipLiveFile.
const hostRuntimeLiveFile = "host_runtime_live"

// SetHostRuntimeGate injects the predicate that permits WRITING host_runtime.
// Wired at daemon start, before the host's first write, to the durable
// host_runtime_split_v1 latch marker.
//
// Nil-safe and FAIL CLOSED: an unset gate writes the hosts columns only, which
// is exactly the previous release's behaviour.
func (c *Client) SetHostRuntimeGate(fn func() bool) {
	if fn == nil {
		c.hostRuntimeGate.Store(nil)
		return
	}
	c.hostRuntimeGate.Store(&fn)
}

// MayWriteHostRuntime reports whether this node may write host_runtime
// (nil-safe, fail closed).
func (c *Client) MayWriteHostRuntime() bool {
	fn := c.hostRuntimeGate.Load()
	return fn != nil && (*fn)()
}

// HostRuntimeLive reports whether this node has completed a runtime split pass
// with the gate open: its writers write host_runtime.
func (c *Client) HostRuntimeLive() bool {
	if c.hostRuntimeLive.Load() {
		return true
	}
	if c.dataDir == "" || c.hostRuntimeLiveChecked.Swap(true) {
		return false
	}
	if _, err := os.Stat(filepath.Join(c.dataDir, hostRuntimeLiveFile)); err != nil {
		return false
	}
	c.hostRuntimeLive.Store(true)
	return true
}

func (c *Client) markHostRuntimeLive() {
	if c.hostRuntimeLive.Swap(true) || c.dataDir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(c.dataDir, hostRuntimeLiveFile), []byte("1\n"), 0o600); err != nil {
		// Live in memory. After a restart its writers write hosts only until
		// the first pass, and those writes are absorbed by every node holding
		// the row. The next pass retries.
		c.hostRuntimeLive.Store(false)
		slog.Warn("host runtime split: could not persist the live marker; retrying next pass", "error", err)
	}
}

// runtimeVals are the columns this slice moves. The totals are nullable, as
// on hosts: a host whose resource probe failed has never reported them.
type runtimeVals struct {
	Version       string
	SchemaVersion int64
	CPU           sql.NullInt64
	Mem           sql.NullInt64
	Disk          sql.NullInt64
	PolicyHash    string
}

func nullParam(n sql.NullInt64) interface{} {
	if !n.Valid {
		return nil
	}
	return n.Int64
}

func nullFrom(v interface{}) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	n, ok := coerceInt64OK(v)
	return sql.NullInt64{Int64: n, Valid: ok}
}

func someInt(n int) sql.NullInt64 { return sql.NullInt64{Int64: int64(n), Valid: true} }

// runtimeRow is one host as a reader or the pass sees it: its hosts columns
// and updated_at, and its live host_runtime row.
type runtimeRow struct {
	name    string
	hosts   runtimeVals
	hostsTS string
	present bool
	rt      runtimeVals
}

// resolve is THE read rule: the host_runtime row whenever there is a live one,
// whatever the hosts copy says or however new its row is. Every such row was
// written by a live writer, a copy or an absorb, so it is never less current
// than the hosts copy.
func (r runtimeRow) resolve() runtimeVals {
	if r.present {
		return r.rt
	}
	return r.hosts
}

// runtimeCols and runtimeJoins are the read side of a host's runtime, for any
// query over `hosts h`. Aliased, so they can sit beside the hosts columns.
const (
	runtimeCols = `h.version AS h_version, h.schema_version AS h_schema, h.cpu_total AS h_cpu,
		h.mem_total AS h_mem, h.disk_total AS h_disk, h.capacity_policy_hash AS h_policy,
		rt.host_name AS rt_key, rt.version AS rt_version, rt.schema_version AS rt_schema,
		rt.cpu_total AS rt_cpu, rt.mem_total AS rt_mem, rt.disk_total AS rt_disk,
		rt.capacity_policy_hash AS rt_policy`
	runtimeJoins   = ` LEFT JOIN host_runtime rt ON rt.host_name = h.name AND rt.deleted_at IS NULL`
	runtimeScanSQL = `SELECT h.name AS name, h.updated_at AS h_ts, ` + runtimeCols + ` FROM hosts h` + runtimeJoins
)

func runtimeRowFrom(r Row, name string) runtimeRow {
	return runtimeRow{
		name: name,
		hosts: runtimeVals{Version: r.String("h_version"), SchemaVersion: r.Int64("h_schema"),
			CPU: nullFrom(r.get("h_cpu")), Mem: nullFrom(r.get("h_mem")), Disk: nullFrom(r.get("h_disk")),
			PolicyHash: r.String("h_policy")},
		hostsTS: r.String("h_ts"),
		present: r.String("rt_key") != "",
		rt: runtimeVals{Version: r.String("rt_version"), SchemaVersion: r.Int64("rt_schema"),
			CPU: nullFrom(r.get("rt_cpu")), Mem: nullFrom(r.get("rt_mem")), Disk: nullFrom(r.get("rt_disk")),
			PolicyHash: r.String("rt_policy")},
	}
}

func scanRuntime(ctx context.Context, c *Client, where string, args ...interface{}) ([]runtimeRow, error) {
	rows, err := c.Query(ctx, runtimeScanSQL+where, args...)
	if err != nil {
		return nil, err
	}
	out := make([]runtimeRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, runtimeRowFrom(r, r.String("name")))
	}
	return out, nil
}

// currentRuntime is one live host's runtime row as this node holds it, for a
// live writer: the resolved values (the INSERT half of every upsert, which a
// receiver with no row takes) and whether a live host_runtime row exists.
// ok is false when the host has no live hosts row.
func currentRuntime(ctx context.Context, c *Client, host string) (row runtimeRow, ok bool, err error) {
	rows, err := scanRuntime(ctx, c, ` WHERE h.name = ? AND h.deleted_at IS NULL`, host)
	if err != nil || len(rows) == 0 {
		return runtimeRow{}, false, err
	}
	return rows[0], true, nil
}

// The host_runtime writers. Every one is an explicit upsert on the primary
// key, so the origin applies it whether or not it holds the row and a receiver
// LWW-gates it on updated_at (DispExplicitUpsert). The INSERT half carries
// every column, from the writer's resolved view, for a receiver with no row
// yet; the UPDATE half sets only what the write reports, so a version report
// never carries a stale copy of the totals over a newer resource report.
const (
	// hostRuntimeUpsertSQL writes every column and revives a retired row: the
	// pass's copy, a host created by a live InsertHost, and a live writer
	// whose own row is missing or retired (a re-admitted machine's first
	// report).
	hostRuntimeUpsertSQL = `INSERT INTO host_runtime (host_name, version, schema_version, cpu_total, mem_total, disk_total,
			capacity_policy_hash, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET version = excluded.version, schema_version = excluded.schema_version,
		   cpu_total = excluded.cpu_total, mem_total = excluded.mem_total, disk_total = excluded.disk_total,
		   capacity_policy_hash = excluded.capacity_policy_hash, updated_at = excluded.updated_at, deleted_at = NULL`
	// hostRuntimeReportSQL is the boot report without resources: version and
	// schema version.
	hostRuntimeReportSQL = `INSERT INTO host_runtime (host_name, version, schema_version, cpu_total, mem_total, disk_total,
			capacity_policy_hash, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET version = excluded.version, schema_version = excluded.schema_version,
		   updated_at = excluded.updated_at`
	// hostRuntimeReportResourcesSQL is the boot report with resources.
	hostRuntimeReportResourcesSQL = `INSERT INTO host_runtime (host_name, version, schema_version, cpu_total, mem_total, disk_total,
			capacity_policy_hash, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET version = excluded.version, schema_version = excluded.schema_version,
		   cpu_total = excluded.cpu_total, mem_total = excluded.mem_total, disk_total = excluded.disk_total,
		   updated_at = excluded.updated_at`
	// hostRuntimeVersionSQL is a version report alone (UpdateHostVersion).
	hostRuntimeVersionSQL = `INSERT INTO host_runtime (host_name, version, schema_version, cpu_total, mem_total, disk_total,
			capacity_policy_hash, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at`
	// hostRuntimeResourcesSQL is a resource report alone (UpdateHostResources).
	hostRuntimeResourcesSQL = `INSERT INTO host_runtime (host_name, version, schema_version, cpu_total, mem_total, disk_total,
			capacity_policy_hash, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET cpu_total = excluded.cpu_total, mem_total = excluded.mem_total,
		   disk_total = excluded.disk_total, updated_at = excluded.updated_at`
)

// runtimeParams binds v for host at updatedAt, in the upserts' column order.
func runtimeParams(host string, v runtimeVals, updatedAt string) []interface{} {
	return []interface{}{host, v.Version, v.SchemaVersion, nullParam(v.CPU), nullParam(v.Mem), nullParam(v.Disk),
		v.PolicyHash, updatedAt}
}

// runtimeReport names which partial upsert a live runtime writer emits.
type runtimeReport int

const (
	reportVersion runtimeReport = iota
	reportResources
	reportBoot
	reportBootResources
)

// runtimeStatement is a live runtime writer's host_runtime statement: the
// partial upsert of kind for a host whose live row this node holds, and the
// full one — every column from the resolved view, which already carries the
// report — for a host whose row is missing or retired here, so a re-admitted
// machine's first report brings the whole row back rather than reviving the
// old machine's totals beside its own version. ok is false when the host has
// no live hosts row. Each statement is a literal, so stmtshapecheck can
// enumerate every shape this returns.
func runtimeStatement(ctx context.Context, c *Client, host string, kind runtimeReport, apply func(*runtimeVals), updatedAt string) (Statement, bool, error) {
	cur, ok, err := currentRuntime(ctx, c, host)
	if err != nil || !ok {
		return Statement{}, false, err
	}
	next := cur.resolve()
	apply(&next)
	params := runtimeParams(host, next, updatedAt)
	if !cur.present {
		return Statement{SQL: hostRuntimeUpsertSQL, Params: params}, true, nil
	}
	switch kind {
	case reportVersion:
		return Statement{SQL: hostRuntimeVersionSQL, Params: params}, true, nil
	case reportResources:
		return Statement{SQL: hostRuntimeResourcesSQL, Params: params}, true, nil
	case reportBoot:
		return Statement{SQL: hostRuntimeReportSQL, Params: params}, true, nil
	case reportBootResources:
		return Statement{SQL: hostRuntimeReportResourcesSQL, Params: params}, true, nil
	}
	return Statement{}, false, fmt.Errorf("host runtime: unknown report kind %d", kind)
}

// ── writes made by a node that was not writing host_runtime ────────────────

// runtimeColumns are the hosts columns this slice moves, in a fixed order.
var runtimeColumns = []string{"version", "schema_version", "cpu_total", "mem_total", "disk_total", "capacity_policy_hash"}

func isRuntimeColumn(col string) bool {
	for _, c := range runtimeColumns {
		if c == col {
			return true
		}
	}
	return false
}

// unlatchedRuntimeWrite is what one entry from a node that was not writing
// host_runtime wrote to one host's runtime columns, and under which
// updated_at. Later statements in the entry override earlier ones.
type unlatchedRuntimeWrite struct {
	host, ts string
	// cols maps a runtime column to the value written: a string for version
	// and capacity_policy_hash, an int64 or nil for the integers.
	cols map[string]interface{}
}

// keepVersionExpr is the normalized text of the boot report's version
// assignment (hostStartupSQL): the bound version, unless it is empty, when the
// column keeps its value.
var keepVersionExpr = func() string {
	sh, _, err := parseResolved(`UPDATE hosts SET version = COALESCE(NULLIF(?, ''), version), updated_at = ? WHERE name = ?`)
	if err != nil || len(sh.SetAssigns) == 0 {
		panic("keepVersionExpr does not resolve")
	}
	return sh.SetAssigns[0].Expr.Text
}()

// runtimeAssignedValue is the exact value an UPDATE assignment writes to a
// runtime column. set is false for a value that leaves the column as it was
// (an empty version under the boot report's COALESCE); ok is false for an
// expression the parse cannot read exactly, which leaves the column out.
func runtimeAssignedValue(col string, e NormalizedExpr, params []interface{}) (v interface{}, set, ok bool) {
	if col == "version" && e.Text == keepVersionExpr && len(e.ParamIdx) == 1 && e.ParamIdx[0] < len(params) {
		p := params[e.ParamIdx[0]]
		if p == nil || coerceString(p) == "" {
			return nil, false, true
		}
		return p, true, true
	}
	v, ok = assignedValue(e, params)
	return v, ok, ok
}

// normalizeRuntimeValue converts a statement value to what the column holds:
// a string for the text columns, an int64 or nil for the integers.
func normalizeRuntimeValue(col string, v interface{}) (interface{}, bool) {
	switch col {
	case "version", "capacity_policy_hash":
		return coerceString(v), true
	case "schema_version":
		n, ok := coerceInt64OK(v)
		return n, ok
	default:
		if v == nil {
			return nil, true
		}
		n, ok := coerceInt64OK(v)
		return n, ok
	}
}

// unlatchedRuntimeWrites extracts, from one replicated entry, every write to
// hosts' runtime columns — nil when the entry also writes host_runtime (a live
// node's dual-write, whose host_runtime half is already in the entry). Values
// come from the statement itself, so every receiver computes the same result
// whatever its own hosts row holds.
func unlatchedRuntimeWrites(stmts []Statement) []unlatchedRuntimeWrite {
	if entryWritesTable(stmts, "host_runtime") {
		return nil
	}
	var out []unlatchedRuntimeWrite
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
		switch sh.Kind {
		case KindUpdate:
			for _, a := range sh.SetAssigns {
				col := strings.ToLower(a.Column)
				if !isRuntimeColumn(col) {
					continue
				}
				v, set, ok := runtimeAssignedValue(col, a.Expr, s.Params)
				if !ok || !set {
					continue
				}
				if nv, ok := normalizeRuntimeValue(col, v); ok {
					vals[col] = nv
				}
			}
		case KindInsert:
			_, row, ok := insertRowFromShape(sh, s)
			if !ok {
				continue
			}
			for i, c := range sh.InsertCols {
				col := strings.ToLower(c)
				if !isRuntimeColumn(col) {
					continue
				}
				if nv, ok := normalizeRuntimeValue(col, row[i]); ok {
					vals[col] = nv
				}
			}
		default:
			continue
		}
		if len(vals) == 0 {
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
			out = append(out, unlatchedRuntimeWrite{host: host, cols: map[string]interface{}{}})
		}
		w := &out[i]
		if lwwOrder(w.ts, ts) < 0 {
			w.ts = ts
		}
		for col, v := range vals {
			w.cols[col] = v
		}
	}
	return out
}

// RuntimeWrite is unlatchedRuntimeWrites for the ledger guard in
// scripts/ci/stmtshapecheck, which checks that every registered shape writing
// a hosts runtime column is one this parser reads. cols holds what the
// statement writes (strings for the text columns, int64 or nil for the
// integers); ok is false when the statement yields no write.
func RuntimeWrite(s Statement) (host, ts string, cols map[string]interface{}, ok bool) {
	ws := unlatchedRuntimeWrites([]Statement{s})
	if len(ws) != 1 {
		return "", "", nil, false
	}
	return ws[0].host, ws[0].ts, ws[0].cols, true
}

// absorbUnlatchedRuntimeWrite carries an entry's hosts-only runtime writes
// into host_runtime, inside the write's own transaction, on both the WAL apply
// path and the local write path. An entry that writes host_runtime itself is
// a live writer's dual-write and is skipped (entryWritesTable).
//
// A write is taken only for a live hosts row, only when its updated_at is
// newer than the host_runtime row's, and the row takes the write's own
// updated_at. mayInsert — this node's host_runtime_split_v1 gate is open —
// lets it create a missing row, the columns the write did not set taken from
// the hosts row. With the gate closed it only updates a row this node already
// holds: such rows exist only because a latched peer wrote them, and this
// node's readers read them. A retired row (re-admission) is left alone: its
// readers read the hosts columns, which carry the write.
//
// An error is returned, never swallowed; the caller fails the write, as for
// the membership absorb.
func absorbUnlatchedRuntimeWrite(ctx context.Context, tx *sql.Tx, stmts []Statement, mayInsert bool) error {
	for _, w := range unlatchedRuntimeWrites(stmts) {
		if err := absorbRuntimeWrite(ctx, tx, w, w.ts, mayInsert); err != nil {
			return fmt.Errorf("absorb hosts-only runtime write for %s: %w", w.host, err)
		}
	}
	return nil
}

// absorbRuntimeInsertSQL creates an absorbed row. Local only: run inside the
// write's transaction and never logged, as every node computes the same row
// from the same entry and anti-entropy carries it to one that missed it.
const absorbRuntimeInsertSQL = `INSERT INTO host_runtime (host_name, version, schema_version, cpu_total, mem_total,
		disk_total, capacity_policy_hash, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`

// absorbRuntimeWrite writes one absorbed write, LWW-gated on updatedAt. It
// takes updatedAt from its caller because an absorbed row carries the WRITE's
// own updated_at, never a fresh clock: every node must compute the same row.
func absorbRuntimeWrite(ctx context.Context, tx *sql.Tx, w unlatchedRuntimeWrite, updatedAt string, mayInsert bool) error {
	var hv runtimeVals
	err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(version, ''), schema_version, cpu_total, mem_total, disk_total, capacity_policy_hash
		   FROM hosts WHERE name = ? AND deleted_at IS NULL`,
		w.host).Scan(&hv.Version, &hv.SchemaVersion, &hv.CPU, &hv.Mem, &hv.Disk, &hv.PolicyHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // no live host: nothing a live writer would record either
	}
	if err != nil {
		return err
	}
	var rowTS string
	var rowDeleted sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT updated_at, deleted_at FROM host_runtime WHERE host_name = ?`, w.host).Scan(&rowTS, &rowDeleted)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if !mayInsert {
			return nil
		}
		v := hv
		applyRuntimeCols(&v, w.cols)
		_, err = tx.ExecContext(ctx, absorbRuntimeInsertSQL, runtimeParams(w.host, v, updatedAt)...)
		return err
	case err != nil:
		return err
	case rowDeleted.Valid:
		return nil // retired by a re-admission: readers read the hosts columns
	case lwwOrder(rowTS, updatedAt) >= 0:
		return nil // the host_runtime row is as new or newer
	}
	sets := make([]string, 0, len(w.cols)+1)
	args := make([]interface{}, 0, len(w.cols)+2)
	for _, col := range runtimeColumns { // a fixed order and a closed set of names
		if v, ok := w.cols[col]; ok {
			sets = append(sets, col+" = ?")
			args = append(args, v)
		}
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, updatedAt, w.host)
	_, err = tx.ExecContext(ctx, `UPDATE host_runtime SET `+strings.Join(sets, ", ")+` WHERE host_name = ?`, args...)
	return err
}

// applyRuntimeCols overlays an absorbed write's columns on v.
func applyRuntimeCols(v *runtimeVals, cols map[string]interface{}) {
	for col, x := range cols {
		switch col {
		case "version":
			v.Version = coerceString(x)
		case "schema_version":
			n, _ := coerceInt64OK(x)
			v.SchemaVersion = n
		case "cpu_total":
			v.CPU = nullFrom(x)
		case "mem_total":
			v.Mem = nullFrom(x)
		case "disk_total":
			v.Disk = nullFrom(x)
		case "capacity_policy_hash":
			v.PolicyHash = coerceString(x)
		}
	}
}

// ── the pass ────────────────────────────────────────────────────────────────

// HostRuntimeReport is what one SplitHostRuntime pass did.
type HostRuntimeReport struct {
	// Copied counts hosts given their first host_runtime row.
	Copied int
}

// SplitHostRuntime gives every live host that has no host_runtime row, live or
// retired, one copied from hosts at a floor timestamp (membershipCopyTS). It
// never writes the hosts columns and never touches an existing row. It does
// nothing unless the host_runtime_split_v1 gate is open, and it is idempotent.
// The daemon runs it at start and periodically, and every runtime writer runs
// it first.
func (c *Client) SplitHostRuntime(ctx context.Context) (HostRuntimeReport, error) {
	if !c.MayWriteHostRuntime() {
		return HostRuntimeReport{}, nil
	}
	c.hostRuntimeMu.Lock()
	defer c.hostRuntimeMu.Unlock()
	return c.splitHostRuntimeLocked(ctx)
}

func (c *Client) splitHostRuntimeLocked(ctx context.Context) (HostRuntimeReport, error) {
	var rep HostRuntimeReport
	rows, err := scanRuntime(ctx, c, ` WHERE h.deleted_at IS NULL`)
	if err != nil {
		return rep, fmt.Errorf("host runtime split: scan: %w", err)
	}
	var firstErr error
	for _, r := range rows {
		if r.present {
			continue
		}
		ts, ok := membershipCopyTS(r.hostsTS)
		if !ok {
			slog.Warn("host runtime split: hosts row has no readable updated_at; not copied", "host", r.name)
			continue
		}
		wrote, err := c.writeRuntimeRow(ctx, r.name, r.hosts, ts)
		if err != nil {
			slog.Warn("host runtime split: pass incomplete; retrying next cycle", "host", r.name, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("host runtime split: %s: %w", r.name, err)
			}
			continue
		}
		if wrote {
			rep.Copied++
		}
	}
	if firstErr == nil {
		c.markHostRuntimeLive()
	}
	return rep, firstErr
}

// writeRuntimeRow is the pass's one replicated write: a host's first
// host_runtime row. It takes updatedAt from its caller because the pass stamps
// the floor of the hosts row's updated_at, never a fresh clock.
func (c *Client) writeRuntimeRow(ctx context.Context, host string, v runtimeVals, updatedAt string) (bool, error) {
	return c.ExecuteBatchGuarded(ctx, runtimeRowAbsent(ctx, host), []Statement{
		{SQL: hostRuntimeUpsertSQL, Params: runtimeParams(host, v, updatedAt)},
	})
}

// runtimeRowAbsent guards the pass's copy: host has no host_runtime row, live
// or retired. A retired row is a re-admission's: the hosts columns, reset
// there, are what readers read until the new machine reports, and a copy
// would revive the row ahead of that report. Evaluated inside the copy's own
// transaction, so a peer's row arriving between the scan and the write is
// never overwritten with an older copy (writeMembershipRow's reason).
func runtimeRowAbsent(ctx context.Context, host string) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM host_runtime WHERE host_name = ?`, host).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return false, err
	}
}

// withRuntimeWrite runs a runtime writer. live is true when the writer must
// write host_runtime as well as the hosts columns, false when it writes the
// hosts columns only (the gate is closed, or this node has not completed a
// pass yet). With the gate open it holds hostRuntimeMu and runs the split pass
// first, so a node's first report after its latch already goes to both homes.
func (c *Client) withRuntimeWrite(ctx context.Context, fn func(live bool) error) error {
	if !c.MayWriteHostRuntime() {
		return fn(false)
	}
	c.hostRuntimeMu.Lock()
	defer c.hostRuntimeMu.Unlock()
	if _, err := c.splitHostRuntimeLocked(ctx); err != nil {
		slog.Warn("host runtime split: pass before a runtime write failed", "error", err)
	}
	return fn(c.HostRuntimeLive())
}
