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
// (a higher incarnation, or at incarnation 0 a new created_at stamp or a new
// certificate serial), so it is untouched and still ordered as before.
//
// At incarnation ≥ 1 the key already says which admission a row is
// (compareHostKeys). At 0, sameLegacyAdmission does: the same created_at and
// the same certificate serial. The stamp alone is not enough, because v1.9.0
// re-admits without stamping, so its re-add keeps the removed admission's
// created_at, even one this build stamped. The serial tells the two apart: a
// re-admission refuses the removed certificate, and a renewal never issues it
// again. A renewal that raced the removal leaves the two serials apart, and
// the clock decides that row as before.
//
// A node on a previous build still orders these rows by their clock until it
// is upgraded, and then takes the tombstone.
func sameLegacyAdmission(a, b hostKey) bool {
	if a.n != 0 || b.n != 0 || a.at == "" || a.at != b.at {
		return false
	}
	return a.serial != "" && strings.EqualFold(a.serial, b.serial)
}

// hostRemovalEndsLocalAdmission reports whether s, a replicated host removal,
// ends the admission this node holds live, so it applies whatever the local
// row's clock (applyLWWGated). It runs after the incarnation rule.
//
//   - A removal that names its admission's certificate serial
//     (deleteHostAdmissionSQL) ends the local row only while that row holds
//     the same serial, at the key the removal was written against. A removal
//     of serial X never ends a row whose serial is Y: a re-admission refuses
//     the removed certificate, so Y is another admission, even one a v1.9.0
//     node re-admitted without a new created_at. The statement's own WHERE
//     says the same, so the comparison here only saves running it twice:
//     where this declines, the clock applies it to nothing.
//   - A removal in the previous shape (deleteHostSQL) names no admission. At
//     incarnation ≥ 1 its envelope names the key, and the incarnation rule has
//     already refused every other key, so it ends the local admission. At 0 it
//     is left to the clock, as before, and anti-entropy then decides the row
//     by created_at and serial (sameLegacyAdmission). A previous-release node
//     writes only this shape, and so does this build until the host_incarnation
//     release feature is granted.
//
// A removal stamped implausibly far ahead is left to the clock and its skew
// guard.
func hostRemovalEndsLocalAdmission(ctx context.Context, tx *sql.Tx, s Statement, now time.Time) (bool, error) {
	if !isHostDelete(s) {
		return false, nil
	}
	host, ts, serial, ok := deleteParams(s)
	if !ok || tsFutureSkewed(ts, now) {
		return false, nil
	}
	local, found, err := localHostKey(ctx, tx, host)
	if err != nil || !found || local.deleted {
		return false, err
	}
	in := statementHostKey(s)
	if in.n != local.n || (local.n >= 1 && in.at != local.at) {
		return false, nil
	}
	if serial != "" {
		return strings.EqualFold(local.serial, serial), nil
	}
	return local.n >= 1, nil
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
