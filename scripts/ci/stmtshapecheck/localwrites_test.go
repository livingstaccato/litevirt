package main

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestLocalWriteGaps: a LocalTx.Exec onto a node-local claim table passes, one
// onto a replicated table and one with non-constant SQL are gaps.
//
// Mutation: make localWriteGaps skip the table check — the replicated write
// stops being reported.
func TestLocalWriteGaps(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
	}
	pkgs, err := packages.Load(cfg, "./testdata/localwrites")
	if err != nil || packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("load fixture: %v", err)
	}
	gaps := localWriteGaps(pkgs)
	if len(gaps) != 2 {
		t.Fatalf("want 2 gaps (the replicated write and the dynamic one), got %d:\n%s", len(gaps), strings.Join(gaps, "\n"))
	}
	if !strings.Contains(strings.Join(gaps, "\n"), `writes "hosts"`) {
		t.Fatalf("the replicated write was not named:\n%s", strings.Join(gaps, "\n"))
	}
}

// TestLocalWriteGaps_TreeIsClean: the real tree has no LocalTx.Exec gap.
func TestLocalWriteGaps_TreeIsClean(t *testing.T) {
	pkgs, _, err := scanTree("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if gaps := localWriteGaps(pkgs); len(gaps) != 0 {
		t.Fatalf("ExecuteLocal write gaps in the tree:\n%s", strings.Join(gaps, "\n"))
	}
}
