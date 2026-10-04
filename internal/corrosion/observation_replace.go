package corrosion

import "strings"

// replacedObservationApply is how a receiver applies a replicated
// `INSERT OR REPLACE` into host_health, given its PK-aware upsert form
// (insertUpsertRewrite): the same upsert, with deleted_at = NULL as well.
//
// The checker publishes each verdict as INSERT OR REPLACE naming every column
// but deleted_at. On its observer that replaces the whole row, tombstone and
// all. A receiver applies a replicated INSERT as an upsert of the columns it
// names, so it kept deleted_at: once `lv host rm` had tombstoned the rows
// about a host (DeleteHost), the observer's verdicts on the machine `lv host
// add` gave the name to stayed deleted on every other node for good. No
// anti-entropy pass repaired that, since on an updated_at tie the tombstone
// wins (ruleTombstone) and would only delete the observer's own row as well.
// The connectivity view and the dual-run detector's last-alive evidence read
// live rows only, so neither saw the re-added host from any node but the
// observer.
//
// The two other observation tables already clear deleted_at in their own
// upserts. The wire shape is unchanged — the two verdict shapes have gone out
// unchanged since v1.3.0 — so a receiver on the previous release keeps the
// tombstone until it is upgraded, and the observer's next verdict clears it.
// A verdict older than the tombstone is still skipped by the LWW gate before
// it reaches here, so a removal stands against every verdict it superseded.
//
// The failover coordinator reads host_health without a deleted_at filter, and
// that is what kept a re-added host fenceable on a receiver: the verdicts it
// counts were there, only marked deleted. It needs no change, and must not
// gain the filter while a receiver on the previous release can still hand a
// live verdict back as deleted.
func replacedObservationApply(tableName string, sh StmtShape, upsert string) string {
	if tableName != "host_health" || sh.Kind != KindInsert || sh.OnConflict != nil ||
		!strings.EqualFold(sh.LeadingAlgo, "OR REPLACE") || !strings.Contains(upsert, " DO UPDATE SET ") {
		return upsert
	}
	for _, col := range sh.InsertCols {
		if strings.EqualFold(col, "deleted_at") {
			return upsert
		}
	}
	return upsert + ", deleted_at = NULL"
}
