package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func decodeStmts(t *testing.T, raw string) []Statement {
	t.Helper()
	var stmts []Statement
	if err := json.Unmarshal([]byte(raw), &stmts); err != nil {
		t.Fatalf("decode logged statements: %v", err)
	}
	return stmts
}

func specConflictOn(c *Client) { c.SetSpecConflictGate(func() bool { return true }) }

// loggedSQL is the statement text of every mutation c has logged, in order.
func loggedSQL(t *testing.T, c *Client) []string {
	t.Helper()
	var out []string
	for _, e := range walEntries(t, c, "x") {
		for _, s := range decodeStmts(t, e.Stmts) {
			out = append(out, s.SQL)
		}
	}
	return out
}

// An out-of-band spec edit keeps the previous release's shape until
// spec_conflict_v1 has latched — a previous-release peer has no ledger entry
// for the epoch-carrying one — and carries the owner epoch after.
func TestMutateDesiredSpec_CarriesTheOwnerEpochOnlyOnceLatched(t *testing.T) {
	ctx := context.Background()
	for _, latched := range []bool{false, true} {
		c := testClient(t)
		if latched {
			specConflictOn(c)
		}
		seedVM(t, c, "vm1", `{"cpu":2}`)
		if applied, gen, err := MutateDesiredSpec(ctx, c, "vm1", func(string) (string, error) { return `{"cpu":4}`, nil }); err != nil || !applied || gen != 1 {
			t.Fatalf("latched=%v: applied=%v gen=%d err=%v", latched, applied, gen, err)
		}
		var edit string
		for _, sql := range loggedSQL(t, c) {
			if strings.Contains(sql, "spec_generation = spec_generation + 1") {
				edit = sql
			}
		}
		want, _ := FingerprintSQL(vmSpecMutateSQL)
		if latched {
			want, _ = FingerprintSQL(vmSpecMutateAtEpochSQL)
		}
		if got, err := FingerprintSQL(edit); err != nil || got != want {
			t.Errorf("latched=%v: logged edit %q is not the expected shape", latched, edit)
		}
		if _, ok := LedgerLookup(want); !ok {
			t.Errorf("latched=%v: the emitted shape is not in the ledger", latched)
		}
	}
}
