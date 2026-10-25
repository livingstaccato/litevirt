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
// A change that needs one of these must first show the import stays safe
// without the rows (docs: task5g design §2), then change this guard.

var claimRetentionTables = `(local_recovery_claims|local_incarnation_claims|local_automation_history)`

var claimRetentionVerb = `(delete\s+from|replace\s+into|insert\s+or\s+replace\s+into|drop\s+table(\s+if\s+exists)?|alter\s+table|truncate(\s+table)?|rename\s+to)`

var claimRetentionStatic = regexp.MustCompile(claimRetentionVerb + `\s+["` + "`" + `]?` + claimRetentionTables + `\b`)

// dynamicMark stands for a non-constant operand in a folded string.
const dynamicMark = "\x00dyn\x00"

var claimRetentionDynamic = regexp.MustCompile(`(delete\s+from|replace\s+into|insert\s+or\s+replace\s+into|drop\s+table(\s+if\s+exists)?|alter\s+table|truncate(\s+table)?|rename\s+to)\s+` + regexp.QuoteMeta(dynamicMark))

// claimRetentionDynamicOK are the functions allowed to delete, drop or
// rename a computed table, with why none of them can reach the three tables.
var claimRetentionDynamicOK = map[string]string{
	"internal/corrosion/identity.go:yieldThenApply":                   "replicated identity tables keyed by id; the guarded tables are node-local claim/history tables without an id column",
	"internal/corrosion/testing.go:RefoundTableForTest":               "test-only table rebuild that copies every row",
	"internal/corrosion/isolation.go:DiscardReplicatedStateForReseed": "walks the replicated tables only; the test asserts the guarded tables are not replicated",
	"internal/corrosion/schema.go:rebuildClusterCRLStatements":        "rebuilds cluster_crl under a constant name",
	"internal/corrosion/schema_automation_custody.go:":                "package constants naming the custody recipient tables",
	"internal/health/superseded_bound.go:renameSetAside":              "an os.Rename log label, not SQL",
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
	if !strings.Contains(strings.ToLower(string(src)), "delete") && !strings.Contains(strings.ToLower(string(src)), "replace") &&
		!strings.Contains(strings.ToLower(string(src)), "drop") && !strings.Contains(strings.ToLower(string(src)), "alter") &&
		!strings.Contains(strings.ToLower(string(src)), "truncate") && !strings.Contains(strings.ToLower(string(src)), "rename") {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	var out []string
	check := func(fn string, e ast.Expr, call *ast.CallExpr) {
		s := strings.ToLower(strings.Join(strings.Fields(foldString(e)), " "))
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
		if claimRetentionDynamic.MatchString(s) {
			if _, ok := claimRetentionDynamicOK[rel+":"+fn]; !ok {
				out = append(out, rel+":"+strconv.Itoa(at.Line)+": "+fn+" deletes, drops or renames a computed table; prove it cannot reach the claim/history tables and list it in claimRetentionDynamicOK")
			}
		}
	}
	for _, decl := range f.Decls {
		fn := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
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
		ast.Inspect(decl, func(n ast.Node) bool { return n == nil || walk(n, nil) })
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
