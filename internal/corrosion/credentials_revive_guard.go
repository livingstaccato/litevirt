package corrosion

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
)

// Refusing an unpaired revive of a retired host credential.
//
// A host's credential row is retired (a tombstone) by its removal or
// re-admission (host_readmit.go). Only an operator legitimately brings it back:
// `lv host config --ipmi-pass` (or --clear-ipmi), whose entry always carries
// the hosts write of the password beside the credential upsert. The split
// passes write the upsert alone, or beside the old-column clear, and on a
// stale node they write the OLD machine's password, stamped with a hosts row
// newer than the tombstone, so it would win LWW everywhere.
//
// This build's passes never revive a tombstone (credentials_split.go), but a
// node still on the previous build does, mid-roll, and its writer cannot be
// fixed. So, as with the unlatched-origin absorbs, the entry decides: a
// credential upsert over a LOCAL tombstone whose entry carries no other hosts
// write of that host's password is not applied here. It is checked on the WAL
// apply path and on the local write path alike, and every node on this build
// keeps the same tombstone.
//
// THE SENSITIVE LANE. The origin of such a revive holds the live row itself,
// and anti-entropy would carry it to every node as a ROW, newer than the
// tombstone, with no entry to judge. A row cannot say whether an operator
// wrote it, so a row merge never turns a retired host credential live
// (mergeKeepsRetiredCredential). The operator's write still reaches every node
// by its entry. What a row merge cannot deliver is an operator revive that a
// node missed on the WAL lane altogether; that node keeps the credential
// retired, fences that host with "no IPMI password" until the password is set
// again, and its digest for host_fence_credentials differs from its peers'
// until then. That is the fail-closed side, chosen over letting any previous
// build's stale copy back in.

var (
	hostCredentialUpsertFingerprint = mustStatementFingerprint(HostFenceCredentialUpsertSQL)
	hostsClearIPMIPassFingerprint   = mustStatementFingerprint(hostsClearIPMIPassSQL)
)

// refuseUnpairedCredentialRevive reports whether s is a host credential upsert
// that would turn this node's retired row live without an operator's password
// write in the same entry.
func refuseUnpairedCredentialRevive(ctx context.Context, tx *sql.Tx, s Statement, entry []Statement) (bool, error) {
	if !strings.Contains(s.SQL, "host_fence_credentials") {
		return false, nil
	}
	if fp, err := FingerprintSQL(s.SQL); err != nil || fp != hostCredentialUpsertFingerprint {
		return false, nil
	}
	host, ok := paramString(s.Params, 0)
	if !ok || host == "" || entryWritesHostPassword(entry, host) {
		return false, nil
	}
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT deleted_at FROM host_fence_credentials WHERE host_name = ?`, host).Scan(&deleted)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}
	if !deleted.Valid || deleted.String == "" {
		return false, nil
	}
	slog.Warn("not reviving a retired fence credential from an entry with no operator password write",
		"host", host)
	return true, nil
}

// entryWritesHostPassword reports whether the entry sets host's password in
// hosts.ipmi_pass as an operator write does: any hosts statement that binds
// the password, except the split pass's empty old-column clear.
func entryWritesHostPassword(entry []Statement, host string) bool {
	for _, s := range entry {
		w, ok := secretWriteOf(s)
		if !ok || w.col.parent != "hosts" || w.key != host {
			continue
		}
		if w.value == "" {
			if fp, err := FingerprintSQL(s.SQL); err == nil && fp == hostsClearIPMIPassFingerprint {
				continue
			}
		}
		return true
	}
	return false
}

// mergeKeepsRetiredCredential reports whether an anti-entropy row for
// host_fence_credentials would turn a credential retired on this node live.
// It is refused whatever its updated_at: see THE SENSITIVE LANE above. A
// retired incoming row, or one for a host with no local row or a live one,
// merges as usual.
func mergeKeepsRetiredCredential(tx *sql.Tx, table syncTable, row []interface{}) (bool, error) {
	if table.Name != "host_fence_credentials" {
		return false, nil
	}
	hi, di := indexOf(table.Columns, "host_name"), indexOf(table.Columns, "deleted_at")
	if hi < 0 || di < 0 || hi >= len(row) || di >= len(row) || coerceString(row[di]) != "" {
		return false, nil
	}
	host := coerceString(row[hi])
	var deleted sql.NullString
	err := tx.QueryRow(`SELECT deleted_at FROM host_fence_credentials WHERE host_name = ?`, host).Scan(&deleted)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}
	if !deleted.Valid || deleted.String == "" {
		return false, nil
	}
	slog.Warn("anti-entropy: not reviving a retired fence credential from a peer's row", "host", host)
	return true, nil
}
