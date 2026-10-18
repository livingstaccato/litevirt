package corrosion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test 11 (I2): nothing but stampHostIncarnation sets a statement's
// HostIncarnation. A writer that set it itself could claim any incarnation, and
// one that forgot it would be refused everywhere once its host is re-admitted;
// the central stamp is what makes "every hosts write carries the key" true. The
// guard covers the whole module's non-test Go code.
func TestHostIncarnation_OnlyTheCentralStampSetsIt(t *testing.T) {
	root := filepath.Join("..", "..")
	var bad []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "gen", ".claude", ".worktrees":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		bad = append(bad, noncentralHostIncarnationWrites(fset, f, path)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Errorf("HostIncarnation is set outside stampHostIncarnation: %v", bad)
	}
}

// RecipientBinding's scalar historical admission observation is a distinct
// field from Statement.HostIncarnation. Resolve its explicit import alias;
// keep checking assignments and all nested expressions conservatively.
func noncentralHostIncarnationWrites(fset *token.FileSet, f *ast.File, path string) []string {
	var bad []string
	contractAlias := ""
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, "\"") == "github.com/litevirt/litevirt/internal/automation/contract" {
			contractAlias = "contract"
			if imp.Name != nil {
				contractAlias = imp.Name.Name
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		central := fn.Name.Name == "stampHostIncarnation" && strings.HasSuffix(path, "host_incarnation.go")
		ast.Inspect(fn, func(m ast.Node) bool {
			switch x := m.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "HostIncarnation" && !central {
						bad = append(bad, fset.Position(x.Pos()).String())
					}
				}
			case *ast.CompositeLit:
				recipient := false
				if typ, ok := x.Type.(*ast.SelectorExpr); ok && typ.Sel.Name == "RecipientBinding" {
					if pkg, ok := typ.X.(*ast.Ident); ok && contractAlias != "" && pkg.Name == contractAlias {
						recipient = true
					}
				}
				for _, elt := range x.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "HostIncarnation" && !central && !recipient {
							bad = append(bad, fset.Position(kv.Pos()).String())
						}
					}
				}
			}
			return true
		})
		return false
	})
	return bad
}

func TestHostIncarnation_GuardDistinguishesRecipientObservation(t *testing.T) {
	src := `package sample
import binding "github.com/litevirt/litevirt/internal/automation/contract"
func f() {
 _ = binding.RecipientBinding{HostIncarnation: 1}
 _ = Statement{HostIncarnation: nil}
 stmt.HostIncarnation = nil
 _ = unrelated.RecipientBinding{HostIncarnation: 1}
 _ = binding.RecipientBinding{KeyID: func() string { _ = Statement{HostIncarnation: nil}; return "" }()}
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	bad := noncentralHostIncarnationWrites(fset, f, "sample.go")
	if len(bad) != 4 {
		t.Fatalf("guard must allow only historical RecipientBinding field and reject four statement/unrelated/nested writes: %v", bad)
	}
}

// And the stamp sets it on hosts statements only.
func TestHostIncarnation_StampedOnHostsStatementsOnly(t *testing.T) {
	c := newTestDB(t)
	tx, err := c.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO hosts (name, address, ssh_user, state, cert_serial, created_at, updated_at, incarnation)
		VALUES ('h', '10.0.0.1', 'root', 'active', '01', 'x', 'x', 3)`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql   string
		hosts bool
	}{
		{`UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`, true},
		{`UPDATE host_labels SET value = ?, updated_at = ? WHERE host_name = ? AND key = ?`, false},
		{`UPDATE image_hosts SET status = ?, updated_at = ? WHERE image_name = ? AND host_name = ?`, false},
	} {
		s := Statement{SQL: q.sql, Params: []interface{}{"r", "t", "h", "k"}}
		s.Params = s.Params[:strings.Count(q.sql, "?")]
		if err := stampHostIncarnation(t.Context(), tx, &s); err != nil {
			t.Fatal(err)
		}
		if (s.HostIncarnation != nil) != q.hosts {
			t.Errorf("%q stamped %+v", q.sql, s.HostIncarnation)
		}
	}
}
