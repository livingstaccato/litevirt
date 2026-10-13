package corrosion

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Natural-key identity resolution (Part H1). Some tables mint a random-UUID PRIMARY KEY but
// carry a UNIQUE natural key, so two nodes can independently create DIFFERENT ids for one
// logical object; the replicated rows then collide on the secondary UNIQUE and the fail-closed
// apply path back-pressures. Under canonical_identity_v1 an upgraded receiver resolves these
// tables by their NATURAL key: for a natural-key group it picks a single deterministic winning id
// and collapses the losing id INTO it — re-keying the surviving row so receiver-only columns are
// preserved (a column-preserving UPDATE, never a whole-row delete+insert).
//
// The winner is chosen conservatively so identity resolution can NEVER silently discard a
// different logical row:
//   - strictly-newer updated_at wins (last-writer-wins by instant); or
//   - on an EXACT-instant tie, the smaller id wins ONLY when the two rows' content is otherwise
//     equivalent (same natural key, equal non-id columns). A tie with DIFFERENT content is an
//     unresolved identity fault: keep local, remain divergent, and surface it — exactly the
//     equal-timestamp/different-content safety fault the program guarantees elsewhere.
//
// Because a losing id is collapsed, any reference to it (a child's parent_id) would be orphaned;
// snapshots.parent_id is provably unused today, so both paths fail CLOSED on a non-null reference
// (incoming) OR an existing child pointing at the losing id, rather than rewrite references.

// tableIdentityKeys maps such a table to the columns of its UNIQUE natural key.
var tableIdentityKeys = map[string][]string{
	"snapshots":           {"vm_name", "name"},
	"container_snapshots": {"host_name", "ct_name", "name"},
}

// identityReferenceColumns maps a table to the columns that reference its OWN primary key. A
// collapse would orphan such a reference (we do not rewrite it), so both paths fail closed on a
// non-null value. snapshots.parent_id points at snapshots.id (a snapshot chain);
// container_snapshots has no self-reference.
var identityReferenceColumns = map[string][]string{
	"snapshots": {"parent_id"},
}

// hasIdentityKey reports whether a table is resolved by natural-key identity.
func hasIdentityKey(table string) bool {
	_, ok := tableIdentityKeys[table]
	return ok
}

// identityDisposition is the resolution decision for one incoming natural-key row against the
// local row (if any) that shares its natural key.
type identityDisposition int

const (
	idApplyNew         identityDisposition = iota // no local row for this natural key → apply incoming
	idKeepLocal                                   // local wins (older/different-id incoming) → no-op, retain any fault
	idAdoptSameID                                 // same id, incoming newer → plain LWW upsert (no collapse)
	idCollapse                                    // different id, incoming wins → re-key local into the winner
	idContentFault                                // exact-instant tie, unproven-equivalent content → keep local, fault
	idAlreadyConverged                            // same id, exact tie, complete-content equivalence → no-op, CLEAR any fault
)

// resolveIdentity decides how to apply an incoming natural-key row given whether a local row
// shares its natural key and, if so, that local row's updated_at/id. contentEqual is consulted
// ONLY on an exact-instant tie (it must report whether the two rows agree on every non-id column);
// it is a func so the caller pays the extra local-row read only when a tie actually occurs.
func resolveIdentity(localExists bool, localTS, localID, incomingTS, incomingID string, contentEqual func() (bool, error)) (identityDisposition, error) {
	if !localExists {
		return idApplyNew, nil
	}
	switch lwwOrder(localTS, incomingTS) {
	case 1:
		return idKeepLocal, nil // local strictly newer
	case -1:
		// Incoming strictly newer. Same id → a plain LWW upsert; different id → collapse.
		if localID == incomingID {
			return idAdoptSameID, nil
		}
		return idCollapse, nil
	}
	// Exact-instant tie: resolve by id ONLY if the content is provably equivalent (a COMPLETE
	// local-schema image), else it is a genuine equal-timestamp/unproven-content safety fault
	// (never silently pick a row).
	equal, err := contentEqual()
	if err != nil {
		return idKeepLocal, err
	}
	if !equal {
		return idContentFault, nil
	}
	// Equivalent, complete-content:
	switch {
	case incomingID == localID:
		// Identical row (same id, equal content, equal instant) — the natural-key group has
		// CONVERGED (e.g. a peer collapsed onto this id and shipped the converged row back). A
		// no-op on the DB, but it must CLEAR any prior fault for this key.
		return idAlreadyConverged, nil
	case incomingID < localID:
		// Deterministic collapse to the smaller id, so every node converges to the same row.
		return idCollapse, nil
	default:
		// Local id is the winner; the peer still holds a larger losing id and will collapse onto
		// us — not yet converged, so keep local and RETAIN any standing fault.
		return idKeepLocal, nil
	}
}

// identityArtifactColumns names, per table, the host column and the on-disk artifact-path column,
// so a collapse can surface a losing-host artifact that may become unreferenced (see
// surfaceIdentityCollapseOrphan). Both identity tables key the physical artifact by host_name.
var identityArtifactColumns = map[string]struct{ host, path string }{
	"snapshots":           {host: "host_name", path: "vmstate_path"},
	"container_snapshots": {host: "host_name", path: "path"},
}

// identityFaultPK is the tracker key for an unresolved identity fault: the natural key, namespaced
// so it can never collide with a physical-PK tracker entry for the same table.
func identityFaultPK(natVals []interface{}) string { return "nk:" + pkKey(natVals) }

// identityCellEqual compares two normalized cells with NULL DISTINCT from empty string (the
// digest-v2 cell contract): nil equals only nil; two present values compare by coerceString. This
// matters for columns like deleted_at, where NULL (live) and "" are semantically different.
func identityCellEqual(a, b interface{}) bool {
	an, bn := a == nil, b == nil
	if an || bn {
		return an && bn
	}
	return coerceString(a) == coerceString(b)
}

// identityContentEquivalent reports whether the incoming row proves the local row equivalent on
// EVERY non-id column of the LOCAL (receiver) schema. It requires a COMPLETE image: every local
// column except id must appear in the incoming projection — otherwise, under schema skew, a
// receiver-only column is uncompared and equivalence is UNPROVEN, so it returns false (the caller
// then treats the tie as an unresolved fault rather than collapsing on an unknown difference).
func identityContentEquivalent(localCols []string, localVals []interface{}, incomingCols []string, incomingVals []interface{}) bool {
	inc := make(map[string]interface{}, len(incomingCols))
	for i, c := range incomingCols {
		if i < len(incomingVals) {
			inc[strings.ToLower(c)] = incomingVals[i]
		}
	}
	for i, c := range localCols {
		lc := strings.ToLower(c)
		if lc == "id" {
			continue
		}
		iv, ok := inc[lc]
		if !ok {
			return false // receiver-only column absent from the incoming image → unproven
		}
		if i >= len(localVals) || !identityCellEqual(localVals[i], iv) {
			return false
		}
	}
	return true
}

// identityIDForeignNaturalKey reports whether the incoming id already exists locally bound to a
// DIFFERENT natural key. If it does, applying/collapsing would re-key or overwrite an UNRELATED
// logical row (a builder-bug / UUID-collision within the stated threat model), destroying two
// records — so the caller must fail closed. Returns false when the id is free or already bound to
// this same natural key (the ordinary same-id case).
func identityIDForeignNaturalKey(tx *sql.Tx, table string, natCols []string, incomingID string, incomingNat []interface{}) (bool, error) {
	dest := make([]sql.NullString, len(natCols))
	ptrs := make([]interface{}, len(natCols))
	for i := range dest {
		ptrs[i] = &dest[i]
	}
	q := "SELECT " + strings.Join(natCols, ", ") + " FROM " + table + " WHERE id = ?"
	if err := tx.QueryRow(q, incomingID).Scan(ptrs...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // id free
		}
		return false, fmt.Errorf("identity id lookup on %s: %w", table, err)
	}
	for i := range natCols {
		local := ""
		if dest[i].Valid {
			local = dest[i].String
		}
		if local != coerceString(incomingNat[i]) {
			return true, nil // id bound to a different natural key
		}
	}
	return false, nil // bound to the same natural key
}

// identityHasChildReference reports whether any local row references losingID through one of the
// table's registered reference columns. Collapsing (re-keying) losingID would orphan such a child;
// since we do NOT rewrite references, the caller fails closed. snapshots.parent_id is unused today
// so this is normally false, but it guards the builder-bug/malformed-entry threat model.
func identityHasChildReference(tx *sql.Tx, table, losingID string) (bool, error) {
	for _, ref := range identityReferenceColumns[table] {
		var one int
		err := tx.QueryRow("SELECT 1 FROM "+table+" WHERE "+ref+" = ? LIMIT 1", losingID).Scan(&one)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("identity reference lookup on %s.%s: %w", table, ref, err)
		}
	}
	return false, nil
}

// identityCollapseUpdate re-keys the losing local row INTO the winning id and overlays the
// sender-supplied columns in ONE atomic UPDATE (… SET <sender cols incl id> = ? … WHERE id =
// losingID). This preserves receiver-only columns (untouched) and is a single statement, so the
// row is never left absent mid-transaction — a post-mutation constraint rejection changes nothing
// and leaves local intact (the caller then keeps local). setCols/setVals are the incoming row's
// columns and values (the id column among them carries the winning id). A deterministic constraint
// violation is reported as rejected=true (keep local); any other error is operational and returned
// so the caller rolls back and back-pressures.
func identityCollapseUpdate(tx *sql.Tx, table string, setCols []string, setVals []interface{}, losingID string) (rejected bool, err error) {
	if len(setCols) != len(setVals) || len(setCols) == 0 {
		return false, fmt.Errorf("identity collapse on %s: malformed row image", table)
	}
	sets := make([]string, len(setCols))
	args := make([]interface{}, 0, len(setVals)+1)
	for i, col := range setCols {
		sets[i] = col + " = ?"
		args = append(args, setVals[i])
	}
	args = append(args, losingID)
	if _, execErr := tx.Exec("UPDATE "+table+" SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); execErr != nil {
		if class, _ := classifySQLiteError(execErr); class == classConstraint {
			return true, nil // keep local
		}
		return false, fmt.Errorf("identity collapse on %s: %w", table, execErr)
	}
	return false, nil
}

// A deleted row gives up its natural key to a newer row.
//
// A snapshot deleted and then re-created under the same name is two rows of
// one natural key: the deleted one, which every peer keeps as a tombstone
// (deletes are soft), and the new one. A build that minted a fresh id for the
// re-create shipped a row that met that tombstone on every peer and failed the
// natural key's UNIQUE, and nothing could ever apply it (lab 2, F-2). Builds
// with the fix re-use the tombstone's id (reuseNaturalKeyRow), but entries the
// older builds already logged are still in their streams, and older senders
// keep producing them through a rolling upgrade.
//
// So a receiver decides a natural-key collision between two DIFFERENT ids, on
// the WAL and on anti-entropy, with or without canonical_identity_v1, whenever
// at least one of the two rows is a tombstone (decideIdentityCollision):
//
//	local         incoming      decision
//	tombstone     newer row     the local tombstone yields (removed; incoming applies)
//	tombstone     older or      the incoming row is superseded: skipped. A delete of
//	              equal live    the name newer than the incoming write is the later
//	                            fact (a delete wins an exact tie: no resurrection)
//	tombstone     tombstone     the newer one stays; an exact tie keeps the smaller
//	                            id, so every node converges on one row
//	live          older         the incoming tombstone is stale: skipped
//	              tombstone
//	anything else               no decision: the apply proceeds as before
//
// Two LIVE rows under one name are canonical_identity's decision, and are
// never touched here. A yield is also refused — the apply then proceeds and,
// if the UNIQUE still refuses it, is held or kept local as before — when the
// tombstone is referenced by a child row, when the incoming id is already
// bound to another natural key, or when the incoming clock is future-skewed
// and the skew guard is on.
//
// A yield's DELETE runs inside a SAVEPOINT with the incoming row's apply, and
// is rolled back unless the incoming row actually lands, so the name is never
// left empty for an older incarnation to take.
//
// canonical_identity_v1's collapse would instead re-key the tombstone into the
// incoming id with a column-preserving UPDATE, and a WAL INSERT does not carry
// deleted_at — so the re-created row would land still deleted, hidden on
// every peer and live only on its origin. Deciding first gives both modes the
// same answer.
//
// No capability gate: the decision reads only this node's row and the
// incoming one, so every upgraded node reaches the same state from the same
// rows, and a node that has not upgraded keeps refusing as before until it
// does. No node relies on a peer making it.

// identityNaturalRow is the row a node holds under one natural key.
type identityNaturalRow struct {
	id, updatedAt string
	deleted       bool
}

func lookupIdentityNaturalRow(tx *sql.Tx, table string, natVals []interface{}) (identityNaturalRow, bool, error) {
	natCols := tableIdentityKeys[table]
	if len(natCols) == 0 || len(natCols) != len(natVals) {
		return identityNaturalRow{}, false, nil
	}
	where := make([]string, len(natCols))
	for i, col := range natCols {
		where[i] = col + " = ?"
	}
	var id, updatedAt, deletedAt sql.NullString
	err := tx.QueryRow("SELECT id, updated_at, deleted_at FROM "+table+" WHERE "+strings.Join(where, " AND "), natVals...).
		Scan(&id, &updatedAt, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identityNaturalRow{}, false, nil
	}
	if err != nil {
		return identityNaturalRow{}, false, fmt.Errorf("identity natural-key lookup on %s: %w", table, err)
	}
	return identityNaturalRow{id: id.String, updatedAt: updatedAt.String, deleted: deletedAt.Valid && deletedAt.String != ""}, true, nil
}

// identityCollision is decideIdentityCollision's answer.
type identityCollision int

const (
	collisionNone         identityCollision = iota // no decision; apply as before
	collisionYieldLocal                            // remove the local tombstone, then apply the incoming row
	collisionSkipIncoming                          // the incoming row is superseded; apply nothing
)

// identityIncoming is the incoming row's side of a collision.
type identityIncoming struct {
	table     string
	natVals   []interface{}
	id, ts    string
	deleted   bool
	skewGuard bool
	now       time.Time
}

// decideIdentityCollision applies the table above. localID names the local
// row a yield removes.
func decideIdentityCollision(tx *sql.Tx, in identityIncoming) (identityCollision, string, error) {
	if in.id == "" || in.ts == "" || !hasIdentityKey(in.table) {
		return collisionNone, "", nil
	}
	local, found, err := lookupIdentityNaturalRow(tx, in.table, in.natVals)
	if err != nil || !found || local.id == in.id || local.updatedAt == "" {
		return collisionNone, "", err
	}
	ord := lwwOrder(local.updatedAt, in.ts) // >0: local newer
	var d identityCollision
	switch {
	case local.deleted && in.deleted:
		switch {
		case ord < 0, ord == 0 && in.id < local.id:
			d = collisionYieldLocal
		default:
			d = collisionSkipIncoming
		}
	case local.deleted:
		if ord < 0 {
			d = collisionYieldLocal
		} else {
			d = collisionSkipIncoming
		}
	case in.deleted:
		if ord > 0 {
			d = collisionSkipIncoming
		}
	}
	if d != collisionYieldLocal {
		return d, "", nil
	}
	if in.skewGuard && tsFutureSkewed(in.ts, in.now) {
		return collisionNone, "", nil
	}
	if foreign, fErr := identityIDForeignNaturalKey(tx, in.table, tableIdentityKeys[in.table], in.id, in.natVals); fErr != nil || foreign {
		return collisionNone, "", fErr
	}
	if child, cErr := identityHasChildReference(tx, in.table, local.id); cErr != nil || child {
		return collisionNone, "", cErr
	}
	return collisionYieldLocal, local.id, nil
}

// identityYieldSavepoint wraps a yield and the incoming row's apply.
const identityYieldSavepoint = "lv_identity_yield"

// yieldThenApply removes the local tombstone localID and runs apply inside a
// savepoint, keeping the removal only if apply reports the incoming row landed.
// An apply error is returned as is (the caller rolls the whole transaction
// back); a row that did not land rolls the removal back with it.
func (c *Client) yieldThenApply(tx *sql.Tx, table, localID string, apply func() (bool, error)) (bool, error) {
	if _, err := tx.Exec("SAVEPOINT " + identityYieldSavepoint); err != nil {
		return false, err
	}
	mark := c.deferredMark(tx)
	if _, err := tx.Exec("DELETE FROM "+table+" WHERE id = ?", localID); err != nil {
		return false, fmt.Errorf("yield stale tombstone on %s: %w", table, err)
	}
	landed, err := apply()
	if err != nil {
		return false, err
	}
	if !landed {
		c.truncateDeferred(tx, mark)
		if _, rbErr := tx.Exec("ROLLBACK TO " + identityYieldSavepoint); rbErr != nil {
			return false, rbErr
		}
	}
	if _, err := tx.Exec("RELEASE " + identityYieldSavepoint); err != nil {
		return false, err
	}
	return landed, nil
}

// identityRowLanded reports whether table holds id under natVals.
func identityRowLanded(tx *sql.Tx, table string, natVals []interface{}, id string) (bool, error) {
	local, found, err := lookupIdentityNaturalRow(tx, table, natVals)
	return found && local.id == id, err
}
