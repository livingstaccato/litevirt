package corrosion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// auditWriters is every production function that calls InsertAuditLog, keyed
// "pkg.Func" or "pkg.(*Type).Method", with the test that proves the rows it
// writes come out SIGNED — and that verify counts them as signed — when its
// client carries a signing keyring.
//
// InsertAuditLog is where signing happens, so a writer is signed exactly when it
// goes through InsertAuditLog on the daemon's client: the one wireAuditKeyring
// installed the keyring on. A writer with its own client, or its own INSERT,
// would write unsigned rows that a host under a signing contract cannot
// legitimately produce, and every node would report them as tampering.
var auditWriters = map[string]struct{ dir, test string }{
	"grpcapi.(*Server).auditAs":             {"internal/grpcapi", "TestAuditWriter_RPCRowsAreSigned"},
	"corrosion.FoldPendingAudit":            {"internal/corrosion", "TestFoldPendingAudit_OneSignedRowAtTheTimeItHappened"},
	"failover.(*Coordinator).audit":         {"internal/failover", "TestAuditWriter_CoordinatorRowsAreSigned"},
	"health.(*Reconciler).auditOwnerAssert": {"internal/health", "TestAuditWriter_OwnerAssertRowsAreSigned"},
	"health.(*ContainerChecker).auditRekey": {"internal/health", "TestAuditWriter_OwnerAssertRowsAreSigned"},
	"health.auditSettle":                    {"internal/health", "TestAuditWriter_SettleRowsAreSigned"},
	"daemon.(*Daemon).checkAdminFloor":      {"internal/daemon", "TestAuditWriter_AdminFloorRowsAreSigned"},
}

// rawAuditInserts are the only non-test files allowed to spell an INSERT into
// audit_log: InsertAuditLog itself, and the historical-shape ledger that names
// the v44 statement so a receiver can recognise it.
var rawAuditInserts = map[string]bool{
	"internal/corrosion/audit.go":          true,
	"internal/corrosion/stmthistorical.go": true,
}

// TestAuditWriters_EveryCallSiteIsCovered fails on a new audit write path until
// it is listed in auditWriters with a test proving its rows are signed, and on
// any audit_log INSERT written outside InsertAuditLog.
func TestAuditWriters_EveryCallSiteIsCovered(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root not found at %s: %v", root, err)
	}
	rawInsert := regexp.MustCompile(`(?i)INSERT\s+(OR\s+\w+\s+)?INTO\s+audit_log\b`)

	found := map[string][]string{} // writer → call sites
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || rel == "gen" || d.Name() == "vendor" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := f.Name.Name + "." + fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				name = f.Name.Name + ".(" + recvType(fn.Recv.List[0].Type) + ")." + fn.Name.Name
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					if calleeName(n.Fun) == "InsertAuditLog" {
						found[name] = append(found[name], fset.Position(n.Pos()).String())
					}
				case *ast.BasicLit:
					if n.Kind == token.STRING && rawInsert.MatchString(n.Value) && !rawAuditInserts[filepath.ToSlash(rel)] {
						t.Errorf("%s: an INSERT into audit_log outside InsertAuditLog — that row is never "+
							"signed, so under a signing contract every node reports it as tampering. "+
							"Write through corrosion.InsertAuditLog on the daemon's client instead",
							fset.Position(n.Pos()))
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	var names []string
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "corrosion.InsertAuditLog" {
			continue
		}
		if _, ok := auditWriters[name]; !ok {
			t.Errorf("%s writes audit rows (%s) and is not in auditWriters. Add it, with a test "+
				"that wires a signing keyring (SignAuditRowsForTest) and asserts its rows are "+
				"signed (AssertAuditRowsSignedForTest). Better still, route it through an "+
				"existing writer", name, strings.Join(found[name], ", "))
		}
	}
	for name, w := range auditWriters {
		if _, ok := found[name]; !ok {
			t.Errorf("auditWriters lists %s, which no longer calls InsertAuditLog; remove it", name)
		}
		if !testDeclared(t, filepath.Join(root, w.dir), w.test) {
			t.Errorf("auditWriters says %s is covered by %s in %s, and no such test exists", name, w.test, w.dir)
		}
	}
}

func recvType(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return "*" + recvType(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return recvType(e.X)
	}
	return "?"
}

func calleeName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

func testDeclared(t *testing.T, dir, name string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	decl := "func " + name + "(t *testing.T)"
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), decl) {
			return true
		}
	}
	return false
}
