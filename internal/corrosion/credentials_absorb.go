package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Absorbing a secret written by a node that had not latched credentials_split_v1.
//
// Readers take the credential row whenever one exists (credentials_split.go),
// so a secret that reaches a latched node ONLY in its old column would never be
// served. That happens in one routine window: latches form per node, and a
// new-build neighbour that has not latched yet writes the old column alone.
//
// The parent row's updated_at cannot tell such a write from a stale one. It is
// bumped by every unrelated write to the row (a version report, a role change),
// and when one of those reaches a replica ahead of a latched rotation, the LWW
// gate refuses the rotation's parent half there: the replica then holds the
// OLD secret on a NEWER parent row (the colonelpanik/litevirt#267 race).
//
// The entry itself can. A latched writer always emits the credential upsert in
// the SAME entry as the parent write; there is no latched path that writes a
// secret column without it. So an entry that sets a secret column and carries
// no statement on that secret's credential table came, by construction, from a
// node that had not latched. No record of the origin's latch is needed, and
// none exists.
//
// absorbUnlatchedSecretWrite runs inside the write's own transaction, on both
// paths a write reaches a node by: the WAL apply path (a peer's entry) and the
// local write path (this node's own write, with the statements it is about to
// log). For each such secret it writes the credential row LOCALLY — it is never
// logged or re-emitted — stamped with the write's own updated_at, and only when
// that is newer than the credential row it replaces. Every node computes the
// same row from the same write, so the replicas agree, and sensitive-lane
// anti-entropy repairs one that missed the entry from any that did not. Empty
// values (the clears the first credentials_split_v1 build emitted) are never
// absorbed.
//
// A node whose own gate is open may create the row (insert). A node whose gate
// is still closed only UPDATES a row it already holds: such rows exist only
// because a latched peer wrote them, so updating one adds nothing a peer could
// not already see, and it keeps this node's own reader — which takes the
// credential row whenever one exists — from serving the value from before its
// own write. That matters most on the unlatched node the rotation was made
// through, and after it latches.

// secretColumn names one secret column and the credential table that holds it.
type secretColumn struct {
	parent, parentPK, column string
	credTable, credPK        string
}

var secretColumns = []secretColumn{
	{"hosts", "name", "ipmi_pass", "host_fence_credentials", "host_name"},
	{"users", "username", "password_hash", "user_credentials", "username"},
	{"tokens", "id", "token_hash", "token_credentials", "token_id"},
}

// secretWrite is one secret an entry's statement sets.
type secretWrite struct {
	col            secretColumn
	key, value, ts string
}

// absorbUnlatchedSecretWrite absorbs every secret the entry sets without a
// paired credential statement. See the block comment above.
func absorbUnlatchedSecretWrite(ctx context.Context, tx *sql.Tx, stmts []Statement, mayInsert bool) error {
	paired := map[string]bool{}
	for _, s := range stmts {
		for _, sc := range secretColumns {
			if statementTable(s.SQL) == sc.credTable {
				paired[sc.credTable] = true
			}
		}
	}
	for _, s := range stmts {
		w, ok := secretWriteOf(s)
		if !ok || paired[w.col.credTable] || w.value == "" || w.ts == "" || w.key == "" {
			continue
		}
		if err := absorbSecret(ctx, tx, w.col, w.key, w.value, w.ts, mayInsert); err != nil {
			return fmt.Errorf("absorb %s.%s: %w", w.col.parent, w.col.column, err)
		}
	}
	return nil
}

// absorbSecret writes one absorbed credential row, LWW-gated on updatedAt;
// with mayInsert false it only updates a row that already exists. The parent
// must exist and be live: absorbing a deleted user's or revoked token's hash
// would give it a credential no latched writer would.
func absorbSecret(ctx context.Context, tx *sql.Tx, col secretColumn, key, value, updatedAt string, mayInsert bool) error {
	var live int
	err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM `+col.parent+` WHERE `+col.parentPK+` = ? AND deleted_at IS NULL`, key).Scan(&live)
	if err != nil || live == 0 {
		return err
	}
	var cur sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT updated_at FROM `+col.credTable+` WHERE `+col.credPK+` = ?`, key).Scan(&cur)
	switch {
	case err == sql.ErrNoRows:
		if !mayInsert {
			return nil
		}
	case err != nil:
		return err
	case cur.Valid && lwwOrder(cur.String, updatedAt) >= 0:
		return nil // the credential row is as new or newer
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO `+col.credTable+` (`+col.credPK+`, `+col.column+`, updated_at, deleted_at)
		 VALUES (?, ?, ?, NULL)
		 ON CONFLICT(`+col.credPK+`) DO UPDATE SET `+col.column+` = excluded.`+col.column+`,
		   updated_at = excluded.updated_at, deleted_at = NULL`, key, value, updatedAt)
	return err
}

// statementTable is the table an INSERT or UPDATE names ("" otherwise).
func statementTable(sqlText string) string {
	f := strings.Fields(sqlText)
	switch {
	case len(f) >= 2 && strings.EqualFold(f[0], "UPDATE"):
		return f[1]
	case len(f) >= 3 && strings.EqualFold(f[0], "INSERT"):
		for i := 1; i+1 < len(f); i++ {
			if strings.EqualFold(f[i], "INTO") {
				return strings.SplitN(f[i+1], "(", 2)[0]
			}
		}
	}
	return ""
}

// secretWriteOf reports the secret a statement sets, if it sets one: the
// parent key, the value and the statement's own updated_at, read from its
// bound parameters. It understands the two shapes every secret writer uses —
// an INSERT whose VALUES are all placeholders, and an UPDATE whose SET binds
// the secret (directly or through COALESCE(?, col)) and whose WHERE binds the
// key — so a prior release's ConfigureHost subsets resolve the same way.
func secretWriteOf(s Statement) (secretWrite, bool) {
	sqlText := strings.Join(strings.Fields(s.SQL), " ")
	table := statementTable(sqlText)
	for _, sc := range secretColumns {
		if table != sc.parent {
			continue
		}
		var vi, ti, ki int
		var ok bool
		if strings.HasPrefix(strings.ToUpper(sqlText), "UPDATE") {
			vi, ti, ki, ok = updateParamIndexes(sqlText, sc)
		} else {
			vi, ti, ki, ok = insertParamIndexes(sqlText, sc)
		}
		if !ok {
			return secretWrite{}, false
		}
		val, vok := paramString(s.Params, vi)
		ts, tok := paramString(s.Params, ti)
		key, kok := paramString(s.Params, ki)
		if !vok || !tok || !kok {
			return secretWrite{}, false
		}
		return secretWrite{col: sc, key: key, value: val, ts: ts}, true
	}
	return secretWrite{}, false
}

func paramString(params []interface{}, i int) (string, bool) {
	if i < 0 || i >= len(params) {
		return "", false
	}
	s, ok := params[i].(string)
	return s, ok
}

// updateParamIndexes finds the placeholder indexes of the secret, updated_at
// and the key in `UPDATE t SET ... secret = ?|COALESCE(?, ...) ... WHERE pk = ?`.
func updateParamIndexes(sqlText string, sc secretColumn) (val, ts, key int, ok bool) {
	where := strings.Index(sqlText, " WHERE ")
	if where < 0 {
		return 0, 0, 0, false
	}
	set := sqlText[:where]
	at := func(s string, within string, base int) int {
		i := strings.Index(within, s)
		if i < 0 {
			return -1
		}
		return strings.Count(sqlText[:base+i], "?")
	}
	val = -1
	for _, form := range []string{" " + sc.column + " = ?", " " + sc.column + " = COALESCE(?"} {
		if v := at(form, set, 0); v >= 0 {
			val = v
			break
		}
	}
	ts = at(" updated_at = ?", set, 0)
	key = at(" WHERE "+sc.parentPK+" = ?", sqlText[where:], where)
	return val, ts, key, val >= 0 && ts >= 0 && key >= 0
}

// insertParamIndexes maps column names to placeholder indexes in
// `INSERT INTO t (c1, c2, ...) VALUES (?, ?, ...)`.
func insertParamIndexes(sqlText string, sc secretColumn) (val, ts, key int, ok bool) {
	open := strings.Index(sqlText, "(")
	closeCols := strings.Index(sqlText, ")")
	vals := strings.Index(strings.ToUpper(sqlText), "VALUES (")
	if open < 0 || closeCols < open || vals < closeCols {
		return 0, 0, 0, false
	}
	rest := sqlText[vals+len("VALUES ("):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return 0, 0, 0, false
	}
	cols := strings.Split(sqlText[open+1:closeCols], ",")
	placeholders := strings.Split(rest[:end], ",")
	if len(cols) != len(placeholders) {
		return 0, 0, 0, false
	}
	idx := map[string]int{}
	n := 0
	for i, c := range cols {
		if strings.TrimSpace(placeholders[i]) != "?" {
			continue
		}
		idx[strings.TrimSpace(c)] = n
		n++
	}
	val, vok := idx[sc.column]
	ts, tok := idx["updated_at"]
	key, kok := idx[sc.parentPK]
	return val, ts, key, vok && tok && kok
}

// SecretWrite is secretWriteOf for the ledger guard in scripts/ci/stmtshapecheck,
// which checks that every registered shape naming a secret column is one this
// parser reads: the parent table, and the key, value and updated_at it binds.
func SecretWrite(s Statement) (table, key, value, updatedAt string, ok bool) {
	w, ok := secretWriteOf(s)
	return w.col.parent, w.key, w.value, w.ts, ok
}
