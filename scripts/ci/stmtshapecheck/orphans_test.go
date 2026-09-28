package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// repoRoot is the module root, relative to this package's directory.
var repoRoot = filepath.Join("..", "..", "..")

// ledgerFileKeys returns the fingerprint keys of the map literal assigned to varName in a
// checked-in ledger file. It reads the FILE rather than the compiled corrosion maps on purpose:
// the question is what `-emit-ledger` would drop from the file on disk.
func ledgerFileKeys(t *testing.T, path, varName string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	keys := map[string]bool{}
	found := false
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if name.Name != varName || i >= len(vs.Values) {
					continue
				}
				cl, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					t.Fatalf("%s: %s is not a composite literal", path, varName)
				}
				found = true
				for _, elt := range cl.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					lit, ok := kv.Key.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: %s has a non-literal key", path, varName)
					}
					k, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("%s: unquote %s: %v", path, lit.Value, err)
					}
					keys[k] = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("%s: no `var %s = ...` map literal", path, varName)
	}
	return keys
}

// orphanedLedgerEntries returns the generated-ledger fingerprints that the current tree does not
// emit and the historical ledger does not hold. Each one is recognised today only because nobody
// has regenerated the ledger since its emitter went away: the next `-emit-ledger` drops it
// silently, and a peer still sending that shape has its replication stream refused.
func orphanedLedgerEntries(generated, emitted, historical map[string]bool) []string {
	var out []string
	for fp := range generated {
		if !emitted[fp] && !historical[fp] {
			out = append(out, fp)
		}
	}
	sort.Strings(out)
	return out
}

func TestOrphanedLedgerEntries(t *testing.T) {
	gen := map[string]bool{"live": true, "moved": true, "orphan": true}
	emitted := map[string]bool{"live": true, "new-not-yet-generated": true}
	hist := map[string]bool{"moved": true, "old": true}
	got := orphanedLedgerEntries(gen, emitted, hist)
	if len(got) != 1 || got[0] != "orphan" {
		t.Fatalf("orphanedLedgerEntries = %v, want [orphan]", got)
	}
}

// TestGeneratedLedgerHasNoOrphans is the drift guard for the checked-in generated ledger: every
// entry in stmtledger_generated.go must be either emitted by a builder in the CURRENT tree or
// also held in stmtledger_historical.go. An entry that is neither survives only until someone
// runs `-emit-ledger`, which regenerates from the tree and drops it without a word — and the
// ledger-drift check cannot see that coming, because it compares ledgers, not the tree.
//
// The fix for a failure here is never to delete the entry. Either the shape is still emitted
// and the scanner cannot see the call (make the call direct), or its emitter is gone and a
// supported peer may still send it (add it as a family in stmthistorical.go and regenerate
// with -emit-historical).
func TestGeneratedLedgerHasNoOrphans(t *testing.T) {
	_, findings, err := scanTree(repoRoot)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	emitted := map[string]bool{}
	for _, f := range findings {
		if f.fp != "" {
			emitted[f.fp] = true
		}
	}
	if len(emitted) == 0 {
		t.Fatal("scan found no replicated statements; the scan itself is broken")
	}
	dir := filepath.Join(repoRoot, "internal", "corrosion")
	gen := ledgerFileKeys(t, filepath.Join(dir, "stmtledger_generated.go"), "stmtLedger")
	hist := ledgerFileKeys(t, filepath.Join(dir, "stmtledger_historical.go"), "historicalLedger")
	for _, fp := range orphanedLedgerEntries(gen, emitted, hist) {
		t.Errorf("stmtledger_generated.go holds %s, which no builder in the current tree emits and "+
			"stmtledger_historical.go does not hold — the next -emit-ledger drops it silently", fp)
	}
}

// TestHistoricalLedgerFileMatchesGenerator is the same drift guard for stmtledger_historical.go,
// in both directions. A checked-in historical entry the generator no longer produces is dropped
// by the next `-emit-historical`: harmless when the current ledger already holds that
// fingerprint (a builder started emitting the shape again, so it is a stale duplicate), and a
// stream-stalling removal when nothing else does (no family generates it any more). An entry the
// generator produces that the file lacks is a shape the receiver refuses until someone
// regenerates. Either way the fix is to regenerate — and, for the second kind, to restore the
// family first.
func TestHistoricalLedgerFileMatchesGenerator(t *testing.T) {
	want, _, err := historicalEntries()
	if err != nil {
		t.Fatalf("historicalEntries: %v", err)
	}
	have := ledgerFileKeys(t, filepath.Join(repoRoot, "internal", "corrosion", "stmtledger_historical.go"), "historicalLedger")
	var stale, missing []string
	for fp := range have {
		if _, ok := want[fp]; !ok {
			stale = append(stale, fp)
		}
	}
	for fp := range want {
		if !have[fp] {
			missing = append(missing, fp)
		}
	}
	sort.Strings(stale)
	sort.Strings(missing)
	for _, fp := range stale {
		if corrosion.CurrentLedgerHas(fp) {
			t.Errorf("stmtledger_historical.go holds %s, which the current ledger also holds; "+
				"-emit-historical drops the duplicate — regenerate it", fp)
		} else {
			t.Errorf("stmtledger_historical.go holds %s, which no family in stmthistorical.go generates "+
				"and the current ledger does not hold — the next -emit-historical drops it silently", fp)
		}
	}
	for _, fp := range missing {
		t.Errorf("stmthistorical.go generates %s but stmtledger_historical.go lacks it — regenerate with -emit-historical", fp)
	}
}
