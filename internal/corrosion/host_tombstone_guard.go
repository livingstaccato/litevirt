package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// A replicated write that reaches a removed host's TOMBSTONE changes nothing,
// unless it is the removal itself or a re-admission.
//
// `lv host add` of a removed host's name admits the new machine on the node it
// runs on (readmitHostSQL), and the new daemon, on an empty database, registers
// itself (insertHostSQL) and writes its boot state (UpdateHostStartup)
// moments later. Replication relays those writes, and a node can receive the
// daemon's writes before the admission. Name-keyed, they applied to the old
// machine's tombstone there: an INSERT applies as a PK-aware upsert of the
// columns it names, and an UPDATE as a full-PK LWW update, and neither names
// deleted_at. The row stayed deleted under the daemon's newer updated_at; the
// admission, older, then lost the LWW gate; and anti-entropy, where a
// tombstone already wins a tie, carried that tombstone to every node. The new
// host was removed cluster-wide.
//
// So a receiver applies a hosts write over a tombstone only when the write
// sets deleted_at itself — the removal (deleteHostSQL) and the re-admission
// (readmitHostSQL, whose WHERE requires the tombstone). Anything else is
// refused, as DispLiveRowUpdate refuses a VM state write that reaches a
// tombstone (live_row_update.go): the tombstone keeps its updated_at, the
// admission that follows applies, and anti-entropy carries the daemon's newer
// live row to this node from any node that applied it in order. An update
// that meets no row at all still parks as before.
//
// This is a rule about the hosts table on the receiving side, keyed on the
// columns a statement names, not on any fingerprint, so it covers every hosts
// shape a previous release sends, and no wire shape changes.
func hostsTombstoneRefuses(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape) (bool, error) {
	if setsDeletedAt(sh) {
		return false, nil
	}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok || len(pk) != 1 {
		return false, nil
	}
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT deleted_at FROM hosts WHERE name = ?`, pk[0]).Scan(&deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return deleted.Valid && deleted.String != "", nil
}

// setsDeletedAt reports whether the statement writes the deleted_at column.
func setsDeletedAt(sh StmtShape) bool {
	for _, a := range sh.SetAssigns {
		if strings.EqualFold(a.Column, "deleted_at") {
			return true
		}
	}
	for _, c := range sh.InsertCols {
		if strings.EqualFold(c, "deleted_at") {
			return true
		}
	}
	return false
}
