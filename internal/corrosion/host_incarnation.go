package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// THE HOST INCARNATION COUNTER.
//
// A host removed while it was down, and re-added while its data directory
// still held the old database, boots with its own row live there. Every write
// it makes is newer than the re-admission, which it therefore never applies,
// and every other node applies those same writes over the re-admission's
// reset row: one statement, two bases. The rows then differ under one
// updated_at (an unresolved control_plane tie), or anti-entropy hands the
// removed machine's settings back to the whole cluster.
//
// hosts.incarnation numbers a host's admissions. 0 is every row written before
// the feature was first used. A re-admission over a tombstone at N writes N+1
// (readmitHostV2SQL), and nothing else ever raises it. A row's ordering key is
// (incarnation, created_at); at incarnation ≥ 1 created_at is the admission's
// own stamp, bound by the admitter, so every node holds the same key for the
// same admission. Two copies of one admission are ordered by their clock, as
// before: a certificate renewal is an ordinary later write.
//
// Every hosts statement carries the key of the row it was written against
// (Statement.HostIncarnation, stamped centrally just before it runs). A
// receiver refuses a statement written against a lower key, whatever its
// timestamp, refuses one written against a higher key it does not hold yet
// (anti-entropy brings the whole row), and applies the rest by the rules that
// held before. Anti-entropy and the tie chain order rows by the key first. Two
// rows both at incarnation 0 are judged as before, by created_at with the HLC's
// skew as grace (host_incarnation_floor.go): only a re-admission made before
// the feature was used can produce them.
//
// Split tables (host_membership, host_runtime, the credential and Redfish
// rows) carry no key and are never compared with the hosts row.

// HostIncarnation is the ordering key of the hosts row a statement was
// written against. Nil on the wire means incarnation 0.
type HostIncarnation struct {
	N  int64
	At string
}

// readmitHostV2SQL re-admits a host at a new incarnation. Its WHERE is the
// ordering key: it applies over any row of a lower incarnation, live or
// tombstoned, and over a row of the same incarnation whose admission stamp is
// earlier — a duplicate admission. Two copies of one admission (the same
// stamp) are never decided by it: they differ only by later writes, such as a
// certificate renewal, which the clock orders. Applied on the origin and on
// every receiver through its reset form (readmitResetV2SQL), never through the
// timestamp gate: the key is the order.
//
// Params: address, ssh_user, ssh_port, grpc_port, state, cert_serial,
// incarnation, created_at, updated_at, name, incarnation, incarnation,
// created_at.
//
// created_at is bound on the wire (the admitter's stamp), not derived by the
// receiver: every node then holds the stamp the admitter wrote.
const readmitHostV2SQL = `UPDATE hosts SET address = ?, ssh_user = ?, ssh_port = ?, grpc_port = ?,
			state = ?, cert_serial = ?, incarnation = ?, created_at = ?, deleted_at = NULL, updated_at = ?
		 WHERE name = ? AND (incarnation < ? OR (incarnation = ? AND created_at < ?))`

// hostOwnEndpointSQL is a re-admitted host's own correction of the address and
// gRPC port its admission recorded. It is written only by the host itself, and
// only on an own row at incarnation ≥ 1 (the release feature is in use by then).
const hostOwnEndpointSQL = `UPDATE hosts SET address = ?, grpc_port = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`

var (
	readmitV2Fingerprint = mustStatementFingerprint(readmitHostV2SQL)
	readmitResetV2SQL    = buildReadmitResetFor(readmitHostV2SQL)
)

// isReadmitV2 reports whether s is a counter-issuing re-admission.
func isReadmitV2(s Statement) bool {
	if !strings.Contains(s.SQL, "hosts") {
		return false
	}
	fp, err := FingerprintSQL(s.SQL)
	return err == nil && fp == readmitV2Fingerprint
}

// readmitV2Key is the key a V2 re-admission issues, from its parameters.
func readmitV2Key(s Statement) (HostIncarnation, string, bool) {
	if len(s.Params) != 13 {
		return HostIncarnation{}, "", false
	}
	n, nok := paramInt64(s.Params[6])
	at, aok := s.Params[7].(string)
	host, hok := s.Params[9].(string)
	return HostIncarnation{N: n, At: at}, host, nok && aok && hok && n >= 1 && at != "" && host != ""
}

// ReadmitStamp is the admission stamp a re-admission at updatedAt records as
// the row's created_at: its instant, in NowTS's fixed-width form.
func ReadmitStamp(updatedAt string) (string, bool) {
	at, ok := tsInstant(updatedAt)
	if !ok {
		return "", false
	}
	return at.UTC().Format(nowTSLayout), true
}

// readmitV2Params binds readmitHostV2SQL.
func readmitV2Params(h HostRecord, n int64, at, uts string) []interface{} {
	return []interface{}{h.Address, h.SSHUser, h.SSHPort, h.GRPCPort, h.State, h.CertSerial,
		n, at, uts, h.Name, n, n, at}
}

func paramInt64(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64: // JSON-decoded
		if x == float64(int64(x)) {
			return int64(x), true
		}
	}
	return 0, false
}

// hostKey is one hosts row's ordering key.
type hostKey struct {
	n       int64
	at      string
	serial  string
	deleted bool
}

// compareHostKeys orders two rows' keys: > 0 when a is the later admission,
// < 0 when b is, 0 when the key does not decide.
//
//   - a higher incarnation wins;
//   - at the same incarnation (≥ 1), the later admission stamp wins: two
//     admissions issued the same number, and the later one stands;
//   - two copies of the SAME admission (same number, same stamp): a removal
//     stands over a live copy; otherwise the key does not decide, and the
//     clock (LWW, then the tie chain) orders them. The certificate serial
//     orders nothing: a renewal changes it under an unchanged key, and must
//     not be reverted by whichever copy has the larger serial;
//   - two legacy rows at 0: the key does not decide.
//
// serial is kept for diagnostics only.
func compareHostKeys(a, b hostKey) int {
	switch {
	case a.n != b.n:
		if a.n > b.n {
			return 1
		}
		return -1
	case a.n == 0:
		return 0
	case a.at != b.at:
		return strings.Compare(a.at, b.at)
	case a.deleted != b.deleted:
		if a.deleted {
			return 1
		}
		return -1
	default:
		return 0
	}
}

// localHostKey reads name's row key. found is false when there is no row.
func localHostKey(ctx context.Context, tx *sql.Tx, name string) (hostKey, bool, error) {
	var k hostKey
	var created, serial, deleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT incarnation, created_at, cert_serial, deleted_at FROM hosts WHERE name = ?`, name).
		Scan(&k.n, &created, &serial, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return k, false, nil
	}
	if err != nil {
		return k, false, err
	}
	k.at, k.serial, k.deleted = created.String, serial.String, deleted.Valid && deleted.String != ""
	return k, true, nil
}

// statementHostKey is the key a statement was written against: its envelope.
func statementHostKey(s Statement) hostKey {
	if s.HostIncarnation == nil {
		return hostKey{}
	}
	return hostKey{n: s.HostIncarnation.N, at: s.HostIncarnation.At}
}

// Verdicts of the WAL lane's incarnation rule.
const (
	incarnationApply  = ""                              // today's path
	reasonOlderKey    = "older_incarnation"             // written against an earlier incarnation
	reasonNewerKey    = "newer_incarnation_pending"     // written against one this node lacks
	reasonLegacyOver  = "legacy_readmit_over_counter"   // a legacy re-admit over a counted row
	reasonEnvMismatch = "incarnation_envelope_mismatch" // a V2 whose envelope is not its params
)

// hostsIncarnationRefusal decides a replicated hosts statement against the
// local row's key. It returns a non-empty reason when the statement must not
// apply here. A V2 re-admission is never refused for its key: its WHERE is the
// key comparison, so it is applied verbatim (replicator.go, DispHostReadmit).
func hostsIncarnationRefusal(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape) (string, error) {
	if sh.Table != "hosts" {
		return incarnationApply, nil
	}
	if isReadmitV2(s) {
		key, _, ok := readmitV2Key(s)
		if !ok {
			return reasonEnvMismatch, nil
		}
		if s.HostIncarnation != nil && (s.HostIncarnation.N != key.N || s.HostIncarnation.At != key.At) {
			return reasonEnvMismatch, nil
		}
		return incarnationApply, nil
	}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok || len(pk) != 1 {
		return incarnationApply, nil
	}
	name, _ := pk[0].(string)
	local, found, err := localHostKey(ctx, tx, name)
	if err != nil || !found {
		return incarnationApply, err
	}
	if isReadmit(s) {
		if local.n >= 1 {
			return reasonLegacyOver, nil
		}
		return incarnationApply, nil
	}
	in := statementHostKey(s)
	switch {
	case in.n < local.n:
		return reasonOlderKey, nil
	case in.n > local.n:
		return reasonNewerKey, nil
	case in.n == 0 || in.at == local.at:
		return incarnationApply, nil
	case in.at < local.at:
		return reasonOlderKey, nil
	default:
		return reasonNewerKey, nil
	}
}

// noteIncarnationRefusal counts and (rate-limited) logs one refusal.
func (c *Client) noteIncarnationRefusal(tx *sql.Tx, s Statement, reason string) {
	key := reason + "|" + structuralTableLabel(s.SQL)
	c.deferAfterCommit(tx, func() {
		c.observeMergeRejected("hosts", "wal", reason)
		if c.incarnationRefusals.allow(key, time.Now()) {
			slog.Warn("replicator: refused a hosts write against another incarnation of the row",
				"reason", reason, "next_report_after", refusalLogInterval)
		}
	})
}

// hostsAEDecision is anti-entropy's incarnation rule for one incoming hosts
// row: keep the local row, take the incoming one whole (whatever its
// updated_at, and whichever side is a tombstone), or leave the row to the
// rules that held before (0, both 0 or one key).
type hostsAEVerdict int

const (
	aeIncarnationPass hostsAEVerdict = iota
	aeIncarnationKeepLocal
	aeIncarnationTakeIncoming
)

func hostsAEDecision(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (hostsAEVerdict, error) {
	idx := columnIndexMap(table.Columns)
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return aeIncarnationPass, err
	}
	in := rowHostKey(row, idx)
	var local hostKey
	if _, ok := idx["incarnation"]; ok {
		local = rowHostKey(localRow, idx)
	} else {
		// A dump without the column (a previous-build peer): the local key
		// still has to be read in full.
		var lerr error
		local, _, lerr = localHostKey(context.Background(), tx, cellStr(row, idx, "name"))
		if lerr != nil {
			return aeIncarnationPass, lerr
		}
	}
	switch cmp := compareHostKeys(in, local); {
	case cmp > 0:
		return aeIncarnationTakeIncoming, nil
	case cmp < 0:
		return aeIncarnationKeepLocal, nil
	default:
		return aeIncarnationPass, nil
	}
}

// rowHostKey reads a dump row's key. A row without the column is at 0.
func rowHostKey(row []interface{}, idx map[string]int) hostKey {
	n, _ := strconv.ParseInt(cellStr(row, idx, "incarnation"), 10, 64)
	return hostKey{n: n, at: cellStr(row, idx, "created_at"), serial: cellStr(row, idx, "cert_serial"),
		deleted: cellStr(row, idx, "deleted_at") != ""}
}

// ruleIncarnationCounter: two hosts rows with different keys go to the later
// incarnation, whole, ahead of every other rule.
func ruleIncarnationCounter() tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has("incarnation") {
			return pass
		}
		l := rowHostKey(rv.local, rv.colIdx)
		i := rowHostKey(rv.incoming, rv.colIdx)
		switch cmp := compareHostKeys(i, l); {
		case cmp > 0:
			return decideTakeIncoming("incarnation_counter")
		case cmp < 0:
			return decideKeepLocal("incarnation_counter")
		default:
			return pass
		}
	}
}

// stampHostIncarnation sets s's envelope to the key of the hosts row it is
// about to be applied to. It is the ONLY writer of Statement.HostIncarnation
// (host_incarnation_guard_test.go): every hosts statement this node logs is
// stamped here, just before it runs, inside the write's transaction. A V2
// re-admission carries the key it issues; everything else the key of the row as
// it stands. Incarnation 0 leaves the envelope nil, so a statement about a host
// never re-admitted is byte-identical to before.
func stampHostIncarnation(ctx context.Context, tx *sql.Tx, s *Statement) error {
	s.HostIncarnation = nil
	if !strings.Contains(s.SQL, "hosts") {
		return nil
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil || sh.Table != "hosts" {
		return nil
	}
	if isReadmitV2(*s) {
		if key, _, ok := readmitV2Key(*s); ok {
			s.HostIncarnation = &HostIncarnation{N: key.N, At: key.At}
		}
		return nil
	}
	pk, ok := pkValuesFromShape(sh, *s)
	if !ok || len(pk) != 1 {
		return nil
	}
	name, _ := pk[0].(string)
	k, found, err := localHostKey(ctx, tx, name)
	if err != nil || !found || k.n == 0 {
		return err
	}
	s.HostIncarnation = &HostIncarnation{N: k.n, At: k.at}
	return nil
}

// HostIncarnationOf returns name's incarnation and admission stamp as this
// replica holds them, and its serial. found is false when there is no row.
func HostIncarnationOf(ctx context.Context, c *Client, name string) (n int64, at, serial string, deleted, found bool, err error) {
	rows, err := c.Query(ctx, `SELECT incarnation, created_at, cert_serial, deleted_at FROM hosts WHERE name = ?`, name)
	if err != nil || len(rows) == 0 {
		return 0, "", "", false, false, err
	}
	r := rows[0]
	return int64(r.Int("incarnation")), r.String("created_at"), r.String("cert_serial"), r.String("deleted_at") != "", true, nil
}
