package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// DispHostReadmit: re-admitting a host over its tombstone starts the row over.
//
// `lv host add` of a name that `lv host rm` removed admits a NEW machine under
// the old name (AdmitHost). Its statement, readmitHostSQL, sets the identity
// columns and nothing else, and every node that still held the old row kept
// the old machine's per-host settings under the new identity: its IPMI target,
// user and password, fence strategy, watchdog, role, region, capacity
// overrides and labels. Two things followed on the kvm003-f3 lab, 2026-10-03:
//
//   - the new machine would have been fenced with the OLD machine's BMC
//     credentials. Its host_fence_credentials row was never retired either, so
//     every node, the rebuilt ones included (sensitive-lane anti-entropy
//     copied it to them), served the old password as the new machine's;
//   - nodes rebuilt after the re-admission had no old row to keep, and held
//     the schema defaults. The new machine's boot write sets none of those
//     columns, so the two groups held different content under one updated_at:
//     a tie the hosts chain refuses to settle (resolver.go), permanently.
//
// The fresh daemon's own InsertHost cannot repair it either: a replicated
// INSERT applies as a PK-aware upsert of the columns it names, and it names
// none of the IPMI columns, labels or region.
//
// WHY THE WIRE SHAPE DOES NOT CHANGE. Widening readmitHostSQL would mint a
// fingerprint a receiver on the previous release does not know, and an unknown
// shape back-pressures: that receiver stops applying the sender's whole stream
// until it is upgraded. So, as for DispLiveRowUpdate, the reset travels with
// the FINGERPRINT. Every node that knows the fingerprint as DispHostReadmit
// applies it through its reset form (readmitResetSQL), which binds the same
// parameters and also returns each per-host setting column to the value a host
// row nobody configured holds: the schema default. That is what a node that
// never had the old row holds after the new daemon's InsertHost, so the two
// agree. A receiver on the previous release applies the narrow statement as
// before, and keeps the old values until an operator writes them.
//
// What is not reset, deliberately:
//   - created_at: a record of the row, not a setting, and a receiver has no
//     deterministic value to put there; the new daemon's InsertHost carries its
//     own;
//   - isolation_epoch and isolation_reason: a quarantine, kept across
//     re-admission as AdmitHost's membership write keeps it, and monotone by
//     contract (isolation.go). host_membership carries nothing else.
//
// THE CREDENTIAL ROW. Readers take host_fence_credentials whenever a live row
// exists (credentials_split.go), so clearing hosts.ipmi_pass alone would leave
// the old password in force. Each node that applies a re-admission therefore
// also retires the host's credential row, LOCALLY and never logged, as the
// unlatched-secret absorb does (credentials_absorb.go): a tombstone with an
// empty secret, stamped with the admission's own updated_at as both deleted_at
// and updated_at, and only over a row older than that. Every node derives the
// same tombstone from the same statement, sensitive-lane anti-entropy carries
// it to a node that missed the entry, and a password set for the new machine
// after its admission is newer and stands. A node whose credential gate is
// closed retires the row as well: such a row exists only because a latched
// peer wrote it, and that node's own reader would serve it.
const readmitResetColumns = `fence_strategy = 'best-effort', ipmi_address = NULL, ipmi_user = NULL,
			ipmi_pass = NULL, watchdog_dev = NULL, labels = NULL, role = 'worker', region = 'default',
			cpu_overcommit = 0, mem_overcommit = 0, cpu_reserve = -1, mem_reserve_mib = -1,
			capacity_policy_hash = '', version = '', schema_version = 0,
			cpu_total = NULL, mem_total = NULL, disk_total = NULL, `

// readmitResetSQL is readmitHostSQL with every per-host setting column reset.
// Built from the wire form, so the two cannot drift apart.
var readmitResetSQL = buildReadmitReset()

// readmitFingerprint is the wire fingerprint applied through readmitResetSQL.
var readmitFingerprint = mustStatementFingerprint(readmitHostSQL)

func buildReadmitReset() string {
	const anchor = "deleted_at = NULL,"
	if strings.Count(readmitHostSQL, anchor) != 1 {
		panic("readmitHostSQL must clear deleted_at exactly once: " + readmitHostSQL)
	}
	reset := strings.Replace(readmitHostSQL, anchor, readmitResetColumns+anchor, 1)
	// The reset form binds exactly the wire form's parameters, in the same
	// order: a receiver executes it with the INCOMING params.
	wire, _, err := parseResolved(readmitHostSQL)
	if err != nil {
		panic("readmitHostSQL does not resolve: " + err.Error())
	}
	r, _, err := parseResolved(reset)
	if err != nil {
		panic("readmit reset SQL does not resolve: " + reset + ": " + err.Error())
	}
	if wire.Kind != KindUpdate || !wire.HasFullPKIdentity || wire.UpdatedAtParamIdx < 0 {
		panic("readmitHostSQL must be a full-PK UPDATE binding updated_at")
	}
	if r.ValidateParamArity(wire.ParamCount) != nil || r.UpdatedAtParamIdx != wire.UpdatedAtParamIdx {
		panic("readmit reset form must bind the wire form's parameters")
	}
	return reset
}

// isReadmit reports whether s is a host re-admission, by fingerprint.
func isReadmit(s Statement) bool {
	if !strings.Contains(s.SQL, "hosts") {
		return false
	}
	fp, err := FingerprintSQL(s.SQL)
	return err == nil && fp == readmitFingerprint
}

// readmitParams are the host name and updated_at a re-admission binds.
func readmitParams(s Statement) (host, ts string, ok bool) {
	// address, ssh_user, ssh_port, grpc_port, state, cert_serial, updated_at,
	// name, cert_serial — readmitHostSQL's order.
	if len(s.Params) != 9 {
		return "", "", false
	}
	ts, tok := s.Params[6].(string)
	host, hok := s.Params[7].(string)
	return host, ts, tok && hok && host != "" && ts != ""
}

// deleteFingerprint is the wire fingerprint of the host removal (DeleteHost).
var deleteFingerprint = mustStatementFingerprint(deleteHostSQL)

// isHostDelete reports whether s is a host removal, by fingerprint.
func isHostDelete(s Statement) bool {
	if !strings.Contains(s.SQL, "hosts") {
		return false
	}
	fp, err := FingerprintSQL(s.SQL)
	return err == nil && fp == deleteFingerprint
}

// deleteParams are the host name and updated_at a removal binds:
// deleted_at, updated_at, name — deleteHostSQL's order.
func deleteParams(s Statement) (host, ts string, ok bool) {
	if len(s.Params) != 3 {
		return "", "", false
	}
	ts, tok := s.Params[1].(string)
	host, hok := s.Params[2].(string)
	return host, ts, tok && hok && host != "" && ts != ""
}

// retireReadmittedCredentials retires the fence credential row of every host
// the statements re-admit or remove. See THE CREDENTIAL ROW above.
//
// A removal retires it as a re-admission does, for the same reason and in the
// same way. `lv host rm` used to leave the row live: the removed machine's BMC
// password went on being served for the name on every node, and stayed on the
// sensitive lane until a re-admission retired it, and only on the nodes that
// applied one. The removal keeps its wire shape and its DispFullPKUpdate
// disposition. The retirement is local and never logged, stamped with the
// removal's own updated_at so every node derives the same tombstone, and only
// over a row older than that, so a credential set for a machine admitted under
// the name since stands.
func retireReadmittedCredentials(ctx context.Context, tx *sql.Tx, stmts []Statement) error {
	for _, s := range stmts {
		var host, ts string
		var ok bool
		switch {
		case isReadmit(s):
			host, ts, ok = readmitParams(s)
		case isHostDelete(s):
			host, ts, ok = deleteParams(s)
		}
		if !ok {
			continue
		}
		if err := retireFenceCredential(ctx, tx, host, ts); err != nil {
			return fmt.Errorf("retire %s's fence credential: %w", host, err)
		}
	}
	return nil
}

// retireFenceCredential stamps the tombstone with updatedAt, the admission's
// own updated_at (which its origin took from NowTS), never a clock of this
// node's: every node must derive the same row from the same statement.
func retireFenceCredential(ctx context.Context, tx *sql.Tx, host, updatedAt string) error {
	var cur string
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT updated_at, deleted_at FROM host_fence_credentials WHERE host_name = ?`, host).Scan(&cur, &deleted)
	switch {
	case err == sql.ErrNoRows:
		return nil
	case err != nil:
		return err
	case deleted.Valid && deleted.String != "":
		return nil // already retired
	case lwwOrder(cur, updatedAt) >= 0:
		return nil // set after the admission: the new machine's
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE host_fence_credentials SET ipmi_pass = '', deleted_at = ?, updated_at = ? WHERE host_name = ?`,
		updatedAt, updatedAt, host)
	return err
}
