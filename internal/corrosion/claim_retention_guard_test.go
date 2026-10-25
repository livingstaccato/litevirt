package corrosion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The new-voter certified-prefix import (automation_import.go) is safe only
// because chosen automation values survive as claim rows that every ordinary
// adopter merges from a sealed majority: automation claim rows are never
// pruned. This guard pins that, statically, over every non-test Go file:
//
//   - no DELETE, REPLACE, DROP, ALTER/RENAME, TRUNCATE of local_recovery_claims
//     except a DELETE passed ClaimKindLeaseTerm and scoped by target_kind
//     (pruneLeaseTermClaimsTx);
//   - none at all of local_incarnation_claims or local_automation_history;
//   - no DELETE/REPLACE/DROP/ALTER whose table name is computed, outside the
//     functions listed in claimRetentionDynamicOK.
//
// UPDATE counts too: clearing a value or acceptance column is a compaction.
// A printf format string is SQL with a computed part, like a concatenation;
// a computed part anywhere in the table name ("local_%s_claims") is computed.
// Package-level declarations are allowlisted by constant name, never by file.
//
// Known limits (a reviewer must still catch these): an upsert
// (INSERT ... ON CONFLICT DO UPDATE) that writes LOWER ballots or empty
// values keeps the row and is not flagged; SQL assembled through
// strings.Builder, bytes.Buffer, strings.Join, or a whole statement passed
// through a variable, is not folded; and SQL outside Go source is not scanned.
//
// A change that needs one of these must first show the import stays safe
// without the rows (docs: task5g design §2), then change this guard.

var claimRetentionTables = `(local_recovery_claims|local_incarnation_claims|local_automation_history)`

var claimRetentionVerb = `(update|delete\s+from|replace\s+into|insert\s+or\s+replace\s+into|drop\s+table(\s+if\s+exists)?|alter\s+table|truncate(\s+table)?|rename\s+to)`

var claimRetentionStatic = regexp.MustCompile(claimRetentionVerb + `\s+["` + "`" + `]?` + claimRetentionTables + `\b`)

// dynamicMark stands for a non-constant operand in a folded string.
const dynamicMark = "\x00dyn\x00"

var claimRetentionDynamic = regexp.MustCompile(`(` + claimRetentionVerb + `\s+["` + "`" + `]?[a-z0-9_]*` + regexp.QuoteMeta(dynamicMark) + `)`)

// claimRetentionDynamicUpdate: a computed table in an UPDATE statement (SQL
// shape "update <name> set"), not the word in prose.
var claimRetentionDynamicUpdate = regexp.MustCompile(`update\s+["` + "`" + `]?[a-z0-9_]*` + regexp.QuoteMeta(dynamicMark) + `[a-z0-9_"` + "`" + `]*\s+set\b`)

// printfVerb is one printf directive in a format string.
var printfVerb = regexp.MustCompile(`%[-+# 0-9.*\[\]]*[a-zA-Z%]`)

// isPrintf: fmt.Sprintf and its kin, whose first argument is a format.
func isPrintf(call *ast.CallExpr) bool {
	var name string
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		name = f.Sel.Name
	case *ast.Ident:
		name = f.Name
	}
	return name == "Sprintf" || name == "Fprintf" || name == "Appendf" || name == "Printf"
}

// claimRetentionDynamicOK are the functions allowed to delete, drop or
// rename a computed table, with why none of them can reach the three tables.
var claimRetentionDynamicOK = map[string]string{
	"internal/corrosion/identity.go:yieldThenApply":                                        "replicated identity tables keyed by id; the guarded tables are node-local claim/history tables without an id column",
	"internal/corrosion/testing.go:RefoundTableForTest":                                    "test-only table rebuild that copies every row",
	"internal/corrosion/isolation.go:DiscardReplicatedStateForReseed":                      "walks the replicated tables only; the test asserts the guarded tables are not replicated",
	"internal/corrosion/schema.go:rebuildClusterCRLStatements":                             "rebuilds cluster_crl under a constant name",
	"internal/corrosion/schema_automation_custody.go:automationCustodyDropOriginal":        "drops the custody recipient table after copying it to its replacement",
	"internal/corrosion/schema_automation_custody.go:automationCustodyRenameReplacement":   "renames the custody replacement table into place",
	"internal/corrosion/anti_entropy_authority.go:antiEntropySweepDeletedWorkloadChildren": "UPDATE over a constant list of replicated VM child tables",
	"internal/corrosion/host_readmit.go:retireHostOwnedRows":                               "soft delete (deleted_at) of replicated host-owned tables",
	"internal/corrosion/identity.go:identityCollapseUpdate":                                "replicated identity tables keyed by id",
	"internal/corrosion/identity.go:tombstoneLocalInPlace":                                 "replicated identity tables keyed by id, soft delete",
	"internal/corrosion/recovery_claims_proof.go:updateProofClaimCertificateLocal":         "sets claim_certificate on replicated proof rows during replication apply",
	"internal/corrosion/replicator.go:applyBulkPerRow":                                     "replication apply; reaches replicated tables only (asserted above)",
	"internal/corrosion/stmthistorical.go:HistoricalShapes":                                "statement-shape ledger entries over a constant list of replicated firewall tables",
	"internal/corrosion/sync.go:updateProofStepState":                                      "sets step_state on replicated proof rows during replication apply",
	"internal/health/superseded_bound.go:renameSetAside":                                   "an os.Rename log label, not SQL",
}

func TestClaimRetentionNeverPrunesAutomationState(t *testing.T) {
	// The reseed discard walks every replicated table with a computed
	// DELETE; it cannot reach a table that is not one.
	for _, table := range []string{"local_recovery_claims", "local_incarnation_claims", "local_automation_history"} {
		if IsReplicatedTable(table) {
			t.Errorf("%s is replicated: a reseed discards it", table)
		}
	}
	root := filepath.Join("..", "..")
	var findings []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "gen" || name == "vendor" || name == "node_modules" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		findings = append(findings, claimRetentionFindings(t, path, filepath.ToSlash(rel))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// claimRetentionFindings reports every forbidden statement in one file.
func claimRetentionFindings(t *testing.T, path, rel string) []string {
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return claimRetentionScan(t, rel, src)
}

// claimRetentionScan reports every forbidden statement in one file's source.
func claimRetentionScan(t *testing.T, rel string, src []byte) []string {
	if !strings.Contains(strings.ToLower(string(src)), "delete") && !strings.Contains(strings.ToLower(string(src)), "update") && !strings.Contains(strings.ToLower(string(src)), "replace") &&
		!strings.Contains(strings.ToLower(string(src)), "drop") && !strings.Contains(strings.ToLower(string(src)), "alter") &&
		!strings.Contains(strings.ToLower(string(src)), "truncate") && !strings.Contains(strings.ToLower(string(src)), "rename") {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	var out []string
	check := func(fn string, e ast.Expr, call *ast.CallExpr) {
		folded := foldString(e)
		if call != nil && isPrintf(call) && len(call.Args) > 0 && call.Args[0] == e {
			folded = printfVerb.ReplaceAllString(folded, dynamicMark)
		}
		s := strings.ToLower(strings.Join(strings.Fields(folded), " "))
		if s == "" {
			return
		}
		at := fset.Position(e.Pos())
		for _, ix := range claimRetentionStatic.FindAllStringSubmatchIndex(s, -1) {
			stmt, table := s[ix[0]:ix[1]], s[ix[len(ix)-2]:ix[len(ix)-1]]
			if table == "local_recovery_claims" && strings.HasPrefix(stmt, "delete") && leaseTermScoped(s, call) {
				continue
			}
			// Adding a column keeps every row.
			if strings.HasPrefix(stmt, "alter") && strings.HasPrefix(strings.TrimSpace(s[ix[1]:]), "add ") {
				continue
			}
			out = append(out, rel+":"+strconv.Itoa(at.Line)+": "+stmt+" prunes automation-carrying state (claim_retention_guard_test.go)")
		}
		dynamic := false
		for _, m := range claimRetentionDynamic.FindAllString(s, -1) {
			if !strings.HasPrefix(m, "update") {
				dynamic = true
			}
		}
		if dynamic || claimRetentionDynamicUpdate.MatchString(s) {
			if _, ok := claimRetentionDynamicOK[rel+":"+fn]; !ok {
				out = append(out, rel+":"+strconv.Itoa(at.Line)+": "+fn+" deletes, drops or renames a computed table; prove it cannot reach the claim/history tables and list it in claimRetentionDynamicOK")
			}
		}
	}
	type unit struct {
		fn   string
		node ast.Node
	}
	var units []unit
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			units = append(units, unit{d.Name.Name, d})
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				name := ""
				if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
					name = vs.Names[0].Name
				}
				units = append(units, unit{name, spec})
			}
		}
	}
	for _, u := range units {
		fn := u.fn
		// Maximal string expressions, each checked once, with the call they
		// are an argument of (for the lease-term scope).
		var walk func(n ast.Node, call *ast.CallExpr) bool
		walk = func(n ast.Node, call *ast.CallExpr) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				ast.Inspect(x.Fun, func(m ast.Node) bool { return m == nil || walk(m, nil) })
				for _, a := range x.Args {
					a := a
					ast.Inspect(a, func(m ast.Node) bool { return m == nil || walk(m, x) })
				}
				return false
			case *ast.BinaryExpr:
				if x.Op == token.ADD && isStringish(x) {
					check(fn, x, call)
					return false
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					check(fn, x, call)
				}
			}
			return true
		}
		ast.Inspect(u.node, func(n ast.Node) bool { return n == nil || walk(n, nil) })
	}
	return out
}

// isStringish: a + chain with at least one string literal operand.
func isStringish(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.BinaryExpr:
		return x.Op == token.ADD && (isStringish(x.X) || isStringish(x.Y))
	case *ast.ParenExpr:
		return isStringish(x.X)
	}
	return false
}

// foldString concatenates a string expression, with dynamicMark for every
// operand that is not a literal.
func foldString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return dynamicMark
		}
		v, err := strconv.Unquote(x.Value)
		if err != nil {
			return ""
		}
		return v
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return foldString(x.X) + foldString(x.Y)
		}
	case *ast.ParenExpr:
		return foldString(x.X)
	}
	return dynamicMark
}

// leaseTermScoped: the DELETE is scoped by target_kind and the call binds
// ClaimKindLeaseTerm.
func leaseTermScoped(sql string, call *ast.CallExpr) bool {
	if call == nil || !regexp.MustCompile(`where\s+target_kind\s*=\s*\?`).MatchString(sql) {
		return false
	}
	for _, a := range call.Args {
		switch x := a.(type) {
		case *ast.Ident:
			if x.Name == "ClaimKindLeaseTerm" {
				return true
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "ClaimKindLeaseTerm" {
				return true
			}
		}
	}
	return false
}

// Each probe is a way a later change could prune or clear automation-carrying
// state; each must be caught. The controls must not be.
func TestClaimRetentionGuardCatchesProbes(t *testing.T) {
	const head = "package corrosion\n\nimport \"fmt\"\n\nvar _ = fmt.Sprintf\n\n"
	for _, p := range []struct {
		name, rel, body string
		caught          bool
	}{
		{"update clears claim values", "internal/corrosion/probe.go",
			"func p(ctx context.Context, tx *LocalTx) { tx.Exec(ctx, `UPDATE local_recovery_claims SET value_json = NULL WHERE target_kind = ?`, ClaimKindAutomation) }", true},
		{"update clears history", "internal/corrosion/probe.go",
			"func p(ctx context.Context, tx *LocalTx) { tx.Exec(ctx, \"UPDATE local_automation_history SET value_json = ''\") }", true},
		{"update of incarnation claims", "internal/corrosion/probe.go",
			"const q = `update local_incarnation_claims set accept_json = ''`", true},
		{"sprintf computed table", "internal/corrosion/probe.go",
			"func p(table string) string { return fmt.Sprintf(\"DELETE FROM %s WHERE x = 1\", table) }", true},
		{"sprintf partial table name", "internal/corrosion/probe.go",
			"func p(kind string) string { return fmt.Sprintf(\"DELETE FROM local_%s_claims\", kind) }", true},
		{"concatenated partial table name", "internal/corrosion/probe.go",
			"func p(kind string) string { return \"DELETE FROM local_\" + kind + \"_claims\" }", true},
		{"new computed drop in the custody file", "internal/corrosion/schema_automation_custody.go",
			"const sneaky = \"DROP TABLE \" + otherTable", true},
		{"control: the custody drop constant", "internal/corrosion/schema_automation_custody.go",
			"const automationCustodyDropOriginal = \"DROP TABLE \" + automationCustodyRecipientTable", false},
		{"control: lease-term prune", "internal/corrosion/probe.go",
			"func p(ctx context.Context, tx *LocalTx) { tx.Exec(ctx, `DELETE FROM local_recovery_claims WHERE target_kind = ? AND owner_epoch < ?`, ClaimKindLeaseTerm, 1) }", false},
		{"control: upsert keeps the row", "internal/corrosion/probe.go",
			"const q = `INSERT INTO local_recovery_claims (a) VALUES (?) ON CONFLICT DO UPDATE SET a = excluded.a`", false},
	} {
		got := claimRetentionScan(t, p.rel, []byte(head+p.body+"\n"))
		if (len(got) > 0) != p.caught {
			t.Errorf("%s: findings %q, want caught=%v", p.name, got, p.caught)
		}
	}
}
