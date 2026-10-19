package corrosion

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// A REMOVAL STANDS OVER ITS OWN ADMISSION.
//
// `lv host rm` on one node while another lags: the lagging node records the
// removed host's state (UpdateHostState, offline) after the removal it has not
// seen. Under last-writer-wins that later write beat the removal twice:
//
//   - over the WAL, a node that applied the state write first skipped the
//     removal as older and kept the host live;
//   - in anti-entropy, that newer live row replaced the tombstone on every
//     node, and the host came back cluster-wide as "offline", listed by
//     GetHost and ListHosts.
//
// The removal ends one admission of the name, and only a re-admission starts
// another. So a live copy of the admission a tombstone ended never replaces
// that tombstone, and a removal of the admission a node holds live applies
// there, whatever either row's clock says. A re-admission is a new admission
// (a higher incarnation, or a new created_at stamp at incarnation 0), so it
// is untouched and still ordered as before.
//
// At incarnation ≥ 1 the key already says which admission a row is
// (compareHostKeys). At 0, sameLegacyAdmission does:
//
//   - a created_at in the stamp's fixed-width form was written by this
//     build's InsertHost or by a re-admission's stamp, and every re-admission
//     a node of this build applies stamps a new one: one created_at, one
//     admission;
//   - an older build's whole-second created_at is kept by that build's
//     re-admission, which stamps nothing. There the certificate serial tells
//     the two apart: a re-admission refuses the removed certificate, and a
//     renewal never issues it again. A renewal that raced the removal leaves
//     the two serials apart, and the clock decides that row as before.
//
// Nothing changes on the wire. A node on a previous build still orders these
// rows by their clock until it is upgraded, and then takes the tombstone.
func sameLegacyAdmission(a, b hostKey) bool {
	if a.n != 0 || b.n != 0 || a.at == "" || a.at != b.at {
		return false
	}
	if isReadmitStamp(a.at) {
		return true
	}
	return a.serial != "" && strings.EqualFold(a.serial, b.serial)
}

// hostRemovalEndsLocalAdmission reports whether s, a replicated host removal
// (deleteHostSQL), ends the admission this node holds live, so it applies
// whatever the local row's clock (applyLWWGated). It runs after the
// incarnation rule, which has already refused a removal written against
// another key.
//
//   - at incarnation ≥ 1 the removal's envelope names the local key;
//   - at 0 the envelope carries nothing, so the row must be stamped
//     (sameLegacyAdmission's first case) and the removal made after that
//     stamp: a removal stamped before a re-admission ended the admission
//     before it. A row in an older build's form is left to the clock here,
//     and anti-entropy decides it by its serial.
//
// A removal stamped implausibly far ahead is left to the clock and its skew
// guard.
func hostRemovalEndsLocalAdmission(ctx context.Context, tx *sql.Tx, s Statement, now time.Time) (bool, error) {
	if !isHostDelete(s) {
		return false, nil
	}
	host, ts, ok := deleteParams(s)
	if !ok || tsFutureSkewed(ts, now) {
		return false, nil
	}
	local, found, err := localHostKey(ctx, tx, host)
	if err != nil || !found || local.deleted {
		return false, err
	}
	in := statementHostKey(s)
	if local.n >= 1 {
		return in.n == local.n && in.at == local.at, nil
	}
	if in.n != 0 || !isReadmitStamp(local.at) {
		return false, nil
	}
	at, err := time.Parse(time.RFC3339, local.at)
	if err != nil {
		return false, nil
	}
	removed, ok := tsInstant(ts)
	return ok && removed.After(at.Truncate(time.Millisecond)), nil
}

// ruleRemovedAdmission settles a tie between two tombstones of one admission
// (one key, one certificate serial) by content-max. A removal applied over a
// later write keeps that write's other columns (hostRemovalEndsLocalAdmission
// applies it verbatim), so two nodes can hold the same removal, under the same
// updated_at, beside a state the other never saw, and the control-plane
// carve-out would leave that tie unresolved for good. A removed row's serial
// is read (a re-admission refuses it), so two tombstones naming different
// certificates still go on to the carve-out.
func ruleRemovedAdmission() tieRule {
	contentMax := ruleContentMax()
	return func(rv rowView) tieDecision {
		if !rv.has("deleted_at") || !rv.has("created_at") || !rv.has("cert_serial") {
			return pass
		}
		l, i := rowHostKey(rv.local, rv.colIdx), rowHostKey(rv.incoming, rv.colIdx)
		if !l.deleted || !i.deleted || l.n != i.n || l.at == "" || l.at != i.at ||
			l.serial == "" || !strings.EqualFold(l.serial, i.serial) {
			return pass
		}
		return contentMax(rv)
	}
}
