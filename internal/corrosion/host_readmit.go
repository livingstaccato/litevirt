package corrosion

import (
	"context"
	"database/sql"
	"errors"
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
//   - created_at is not reset to a default: it becomes the re-admission's
//     own instant, the row's new incarnation (THE INCARNATION, below);
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

func buildReadmitReset() string { return buildReadmitResetFor(readmitHostSQL) }

// buildReadmitResetFor inserts the reset columns into a re-admission's wire
// form (readmitHostSQL, readmitHostV2SQL). The reset form binds exactly the
// wire form's parameters, in the same order: a receiver executes it with the
// INCOMING params.
func buildReadmitResetFor(wireSQL string) string {
	const anchor = "deleted_at = NULL,"
	if strings.Count(wireSQL, anchor) != 1 {
		panic("a re-admission must clear deleted_at exactly once: " + wireSQL)
	}
	reset := strings.Replace(wireSQL, anchor, readmitResetColumns+anchor, 1)
	wire, _, err := parseResolved(wireSQL)
	if err != nil {
		panic("re-admission SQL does not resolve: " + err.Error())
	}
	r, _, err := parseResolved(reset)
	if err != nil {
		panic("readmit reset SQL does not resolve: " + reset + ": " + err.Error())
	}
	if wire.Kind != KindUpdate || !wire.HasFullPKIdentity || wire.UpdatedAtParamIdx < 0 {
		panic("a re-admission must be a full-PK UPDATE binding updated_at")
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

// The wire fingerprints of the host removal: DeleteHost's, and
// DeleteHostAdmissionIf's, which also names the removed admission's serial.
var (
	deleteFingerprint          = mustStatementFingerprint(deleteHostSQL)
	deleteAdmissionFingerprint = mustStatementFingerprint(deleteHostAdmissionSQL)
)

// isHostDelete reports whether s is a host removal, in either shape, by
// fingerprint.
func isHostDelete(s Statement) bool {
	if !strings.Contains(s.SQL, "hosts") {
		return false
	}
	fp, err := FingerprintSQL(s.SQL)
	return err == nil && (fp == deleteFingerprint || fp == deleteAdmissionFingerprint)
}

// deleteParams are the host name and updated_at a removal binds, and the
// serial it names ("" for deleteHostSQL): deleted_at, updated_at, name and,
// for deleteHostAdmissionSQL, cert_serial.
func deleteParams(s Statement) (host, ts, serial string, ok bool) {
	if len(s.Params) != 3 && len(s.Params) != 4 {
		return "", "", "", false
	}
	ts, tok := s.Params[1].(string)
	host, hok := s.Params[2].(string)
	sok := true
	if len(s.Params) == 4 {
		serial, sok = s.Params[3].(string)
		sok = sok && serial != ""
	}
	return host, ts, serial, tok && hok && sok && host != "" && ts != ""
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
		case isReadmitV2(s):
			if len(s.Params) == 13 {
				ts, _ = s.Params[8].(string)
				host, _ = s.Params[9].(string)
				ok = host != "" && ts != ""
			}
			if ok {
				if err := retireHostOwnedRows(ctx, tx, host, ts); err != nil {
					return fmt.Errorf("reset %s's per-host rows on re-admission: %w", host, err)
				}
				// A counted re-admission retires the credential even where
				// this node holds none, so a lagging node's live row from the
				// earlier admission meets a retirement here on the sensitive
				// merge, not an empty slot it would fill.
				if err := ensureCredentialRow(ctx, tx, host, ts); err != nil {
					return fmt.Errorf("retire %s's fence credential: %w", host, err)
				}
			}
		case isReadmit(s):
			host, ts, ok = readmitParams(s)
			if ok {
				if err := retireHostOwnedRows(ctx, tx, host, ts); err != nil {
					return fmt.Errorf("reset %s's per-host rows on re-admission: %w", host, err)
				}
				if err := stampReadmitIncarnation(ctx, tx, s, host, ts); err != nil {
					return fmt.Errorf("stamp %s's re-admission: %w", host, err)
				}
			}
		case isHostDelete(s):
			var serial string
			host, ts, serial, ok = deleteParams(s)
			if ok && serial != "" {
				// A removal that names its admission retires the credential
				// only where the row is that admission: a row under another
				// serial is a re-admission, whose credential is not this
				// removal's (host_removal_stands.go).
				var cur sql.NullString
				err := tx.QueryRowContext(ctx, `SELECT cert_serial FROM hosts WHERE name = ?`, host).Scan(&cur)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return fmt.Errorf("read %s's serial: %w", host, err)
				}
				ok = err == nil && strings.EqualFold(cur.String, serial)
			}
		}
		if !ok {
			continue
		}
		if err := retireFenceCredential(ctx, tx, host, ts); err != nil {
			return fmt.Errorf("retire %s's fence credential: %w", host, err)
		}
		if err := retireFenceRedfish(ctx, tx, host, ts); err != nil {
			return fmt.Errorf("retire %s's Redfish settings: %w", host, err)
		}
		// The removed or re-admitted machine's fence key and host keys: its
		// key leaves every peer's authorized_keys, and a re-admitted machine
		// publishes its own (host_fence_ssh.go).
		if err := retireFenceSSH(ctx, tx, host, ts); err != nil {
			return fmt.Errorf("retire %s's fence SSH keys: %w", host, err)
		}
	}
	return nil
}

// retireFenceCredential stamps the tombstone with updatedAt, the admission's
// own updated_at (which its origin took from NowTS), never a clock of this
// node's: every node must derive the same row from the same statement.
//
// It retires every row that comes before the tombstone in the credential
// order (credentials_revive_guard.go): a row set after an EARLIER retirement,
// or after none, is retired however new its clock — that is the stale copy
// the order exists to stop. Only a row an operator set after this retirement
// (or a later one) stands.
func retireFenceCredential(ctx context.Context, tx *sql.Tx, host, updatedAt string) error {
	local, err := readLocalCredential(ctx, tx, host)
	if err != nil || !local.exists {
		return err
	}
	if local.order().cmp(credentialOrder{retirement: updatedAt, updatedAt: updatedAt}) >= 0 {
		return nil // already retired at it, or set after it
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE host_fence_credentials SET ipmi_pass = '', deleted_at = ?, updated_at = ?, after_retirement = ''
		 WHERE host_name = ?`,
		updatedAt, updatedAt, host)
	return err
}

// ensureCredentialRow inserts host's credential tombstone at updatedAt when
// this node holds no credential row for it; retireFenceCredential then finds
// it already retired at that instant. Every node derives the same row from the
// same statement.
func ensureCredentialRow(ctx context.Context, tx *sql.Tx, host, updatedAt string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO host_fence_credentials (host_name, ipmi_pass, updated_at, deleted_at, after_retirement)
		 VALUES (?, '', ?, ?, '') ON CONFLICT(host_name) DO NOTHING`,
		host, updatedAt, updatedAt)
	return err
}

// retireAdoptedAdmissionCredential is the credential half of a counted
// re-admission for a node that adopts its hosts row by anti-entropy (a later
// key than the local row's) rather than applying its entry: such a node runs
// no retireReadmittedCredentials, and would otherwise hold no retirement for
// the new admission, so a lagging node's live row from the earlier one would
// fill the slot on the sensitive merge. It retires the credential at the
// admission's created_at, the instant of the re-admission's own updated_at
// (ReadmitStamp): not after a password written for the new admission, which
// carries that updated_at as its retirement, and after the earlier
// admission's retirement (the re-admission is stamped after it). A removal
// adopted this way, and a row at incarnation 0, retire nothing here.
func retireAdoptedAdmissionCredential(ctx context.Context, tx *sql.Tx, table syncTable, row []interface{}) error {
	idx := columnIndexMap(table.Columns)
	if _, ok := idx["incarnation"]; !ok {
		return nil
	}
	in := rowHostKey(row, idx)
	host := cellStr(row, idx, "name")
	if in.n < 1 || in.deleted || in.at == "" || host == "" {
		return nil
	}
	if err := ensureCredentialRow(ctx, tx, host, in.at); err != nil {
		return fmt.Errorf("retire %s's fence credential: %w", host, err)
	}
	if err := retireFenceCredential(ctx, tx, host, in.at); err != nil {
		return fmt.Errorf("retire %s's fence credential: %w", host, err)
	}
	return nil
}

// THE HOST'S OTHER ROWS. Four more tables are keyed by the host's name, and a
// re-admission decides each one, as it decides each hosts column:
//
//   - host_networks is RESET. Its rows are wiring confirmed on the old
//     machine's NICs: member interface names, static addresses, and a state
//     of `applied` with a generation. For the new machine `lv host network
//     ls` would report wiring it does not have, and its next `lv host network
//     apply` would render every one of them, old NIC names and the old
//     machine's addresses included, onto hardware they were never planned
//     for; the apply's self-cutoff check guards only the cluster-LAN
//     interface. ("A host that lost its DB re-learns its intent from peers"
//     is about a host that keeps its identity; `lv host rm` ends it.)
//   - netbox_host_config is RESET. It is the host's own publication of the
//     NetBox cluster name its daemon resolves, and the mirror refuses to run
//     while a live host has published none (netbox_cluster_uniformity.go).
//     The old machine's row would stand in for a new machine that never
//     publishes (NetBox disabled there), which is exactly the host that check
//     exists to catch. A new machine that does publish writes after its
//     admission, so its row is newer and stands.
//   - host_runtime is RESET. It is the old machine's own report of its
//     version, schema version and resource totals (host_runtime.go), and
//     readers take it ahead of the hosts columns this re-admission resets.
//     Retired, readers fall back to those reset columns until the new
//     machine's first report, which brings the row back whole.
//   - host_firewall_rules is KEPT. They are the host_overrides tier of the
//     FORWARD chain: the operator's policy for guest traffic through the
//     host of that name, not a fact about its hardware, and never the host's
//     own ingress, so they cannot cut the new machine off. Dropping them
//     would silently relax that policy for every guest placed there, and a
//     row with a stack_name belongs to its stack, not to the machine.
//
// Each reset row becomes a tombstone the way the credential row does: locally
// and never logged, stamped with the admission's own updated_at as deleted_at
// and updated_at, and only over a row older than that.
var readmitResetTables = []struct{ table, key string }{
	{"host_networks", "host_name"},
	{"netbox_host_config", "host_name"},
	{"host_runtime", "host_name"},
}

func retireHostOwnedRows(ctx context.Context, tx *sql.Tx, host, updatedAt string) error {
	for _, t := range readmitResetTables {
		rows, err := tx.QueryContext(ctx,
			`SELECT rowid, updated_at FROM `+t.table+` WHERE `+t.key+` = ? AND deleted_at IS NULL`, host)
		if err != nil {
			return fmt.Errorf("%s: %w", t.table, err)
		}
		var older []int64
		for rows.Next() {
			var id int64
			var cur string
			if err := rows.Scan(&id, &cur); err != nil {
				rows.Close()
				return fmt.Errorf("%s: %w", t.table, err)
			}
			if lwwOrder(cur, updatedAt) < 0 {
				older = append(older, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("%s: %w", t.table, err)
		}
		for _, id := range older {
			if _, err := tx.ExecContext(ctx,
				`UPDATE `+t.table+` SET deleted_at = ?, updated_at = ? WHERE rowid = ?`,
				updatedAt, updatedAt, id); err != nil {
				return fmt.Errorf("%s: %w", t.table, err)
			}
		}
	}
	return nil
}

// THE INCARNATION. A re-admission starts the row over, so the row's created_at
// becomes the admission's own instant: its updated_at, read as wall time and
// written in NowTS's fixed-width RFC3339Nano form, so a re-admission within
// the same second as the row's first insert still orders after it. Like the
// credential tombstone, it is written locally and never logged, by every node
// that applies the re-admission, the origin included, and every node derives
// the same value from the same statement. It is written only where the
// re-admission itself applied: the row is live, carries the admitted serial
// and is stamped with the admission's updated_at.
//
// It is what lets the hosts tie chain (resolver.go) tell the re-admitted row
// from the machine's previous incarnation. A host removed while it was down
// and re-added while its data directory still held the OLD database boots
// with its own row live there: RegisterHost re-records the new serial instead
// of re-admitting, and that write, like every later one, is newer than the
// re-admission, which the machine therefore never applies (its row is live,
// and newer). Every other node applies the same writes over the re-admission's
// reset row. Both sides then hold different content under one updated_at, and
// with grpc_port, role or the fence settings among the differences the chain
// used to leave the tie unresolved for good: the machine kept the old
// machine's labels, region, role and fence settings, and nothing but another
// re-admission could settle it. The two rows now differ in created_at too, and
// the later one wins whole: the re-admitted row, which also carries every
// write the machine made since, because every node applied them over it.
//
// Nothing changes on the wire. Mid-roll, an older build does not stamp, and
// what it does with a stamped row depends on which build it is:
//   - a build that carries the re-admission reset (f3126912) but not the stamp
//     holds, after the re-admission and every write since, the same row as a
//     stamping node except for created_at — unless it pulled the stale row
//     whole (it has no merge floor), in which case control-plane columns
//     differ and its chain leaves the tie unresolved until it is upgraded.
//     Where the rows otherwise agree, its chain reaches content-max over the
//     two and picks the stamped row: the canonical encoding length-prefixes
//     each value, and the stamp's 30 characters order after the 20 of an
//     older build's InsertHost (whole-second RFC3339), while two fixed-width
//     values order as time does;
//   - a build without the reset (v1.9.0 and earlier) applies the narrow
//     re-admission and keeps the old machine's settings, so control-plane
//     columns still differ and its chain leaves the tie unresolved, as before.
//
// Where no node that applied the re-admission stamped, both sides keep the old
// created_at and the tie stays as it was. A stamp can also be erased: a whole
// row pulled from an older-build survivor that holds a newer write replaces
// the stamped row on a node that has no merge floor (an older build). A node
// on this build keeps its stamp against such a row (host_incarnation_floor.go),
// so stamping on one node is necessary for convergence, not sufficient.
//
// The comparison is between two wall clocks: the old row's created_at was
// written by whichever node first inserted it, the stamp is the admitting
// node's (HLC physical time where HLC is on). If the old row's created_at is
// LATER than the stamp — a skew larger than the host's whole first membership —
// the tie rule hands every node the stale row, whole: the removed machine's
// labels, role, fence settings and grpc_port come back cluster-wide, where
// before this rule only the machine itself kept them. The merge floor does not
// help there either, since it too judges by the stamp being later.
func stampReadmitIncarnation(ctx context.Context, tx *sql.Tx, s Statement, host, updatedAt string) error {
	serial, ok := s.Params[5].(string)
	if !ok || serial == "" {
		return nil
	}
	at, ok := tsInstant(updatedAt)
	if !ok {
		return nil
	}
	_, err := tx.ExecContext(ctx,
		`UPDATE hosts SET created_at = ? WHERE name = ? AND updated_at = ? AND deleted_at IS NULL
			AND lower(cert_serial) = lower(?)`,
		at.UTC().Format(nowTSLayout), host, updatedAt, serial)
	return err
}
