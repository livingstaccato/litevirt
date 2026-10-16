package corrosion

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLeaseKeys_EveryAcquiredKeyIsListed derives the keys the tree acquires from
// its source and requires each to be in leaseKeys.
//
// shared_lun_detector was acquired for a release without being listed. Every
// peer then refused GetLeaseTermHighWater for it, the mint clearance never
// reached a quorum, and once the term-1 holder restarted no node could take
// the lease: the scan stopped and `lv health` stayed DEGRADED.
//
// The scan reads every non-test .go file under internal/ and cmd/, finds each
// call to AcquireLeaseWithTerm and resolves its key argument: a string literal,
// a package constant (followed through corrosion.LeaseKey* aliases), or a
// struct field, resolved through every value the field is assigned in that
// package. A key it cannot resolve fails the test: an acquire site it cannot
// read is one it cannot vouch for.
//
// Mutation: drop LeaseKeySharedLUN from leaseKeys and this fails naming
// internal/grpcapi/shared_lun_health.go.
func TestLeaseKeys_EveryAcquiredKeyIsListed(t *testing.T) {
	root := leaseKeyModuleRoot(t)
	pkgs := map[string][]*ast.File{} // dir → parsed non-test files
	paths := map[*ast.File]string{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if perr != nil {
				return perr
			}
			pkgs[filepath.Dir(path)] = append(pkgs[filepath.Dir(path)], f)
			paths[f], _ = filepath.Rel(root, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	corrosionDir := filepath.Join(root, "internal", "corrosion")

	type site struct{ where, expr string }
	var sites []site
	acquired := map[string][]string{} // key → sites
	for dir, files := range pkgs {
		r := leaseKeyResolver{pkgs: pkgs, dir: dir, corrosionDir: corrosionDir}
		for _, f := range files {
			// AcquireLeaseWithTerm taken as a VALUE (acquire :=
			// corrosion.AcquireLeaseWithTerm) would be called under another
			// name this scan cannot see. Every reference must be a call's
			// callee, or the declaration itself.
			callee := map[ast.Node]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					callee[x.Fun] = true
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						callee[sel.Sel] = true
					}
				case *ast.FuncDecl:
					callee[x.Name] = true
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == "AcquireLeaseWithTerm" && !callee[id] {
					t.Errorf("%s: AcquireLeaseWithTerm is referenced other than as a call; "+
						"this scan can only vouch for direct calls", paths[f])
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || calleeName(call.Fun) != "AcquireLeaseWithTerm" || len(call.Args) < 3 {
					return true
				}
				where := paths[f]
				sites = append(sites, site{where: where, expr: leaseKeyExprText(call.Args[2])})
				vals, ok := r.resolve(call.Args[2], 0)
				if !ok || len(vals) == 0 {
					t.Errorf("%s: AcquireLeaseWithTerm key %s cannot be resolved to a constant; "+
						"spell it as a corrosion.LeaseKey* constant or teach this test to read it",
						where, leaseKeyExprText(call.Args[2]))
					return true
				}
				for _, v := range vals {
					acquired[v] = append(acquired[v], where)
				}
				return true
			})
		}
	}
	if len(sites) < 4 {
		t.Fatalf("found %d AcquireLeaseWithTerm sites (%v); the failover coordinator, the rebalancer, "+
			"the dual-run detector and the shared_lun scan all acquire one, so the scan is broken", len(sites), sites)
	}
	var keys []string
	for k := range acquired {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !ValidLeaseKey(k) {
			t.Errorf("lease key %q is acquired at %v but is not in leaseKeys: every peer refuses its "+
				"high-water read, so once its first holder goes no node can take it over", k, acquired[k])
		}
	}
	for _, want := range []string{LeaseKeyFailover, LeaseKeyRebalancer, LeaseKeyDualRun, LeaseKeySharedLUN} {
		if _, ok := acquired[want]; !ok {
			t.Errorf("no acquire site resolved to %q (resolved %v); the scan missed a known consumer", want, keys)
		}
	}
}

// TestAcquireLeaseWithTerm_RefusesAnUnlistedKey: the guard that makes an
// unlisted key fail on its first acquire instead of on its first takeover.
//
// Mutation: drop the ValidLeaseKey check from AcquireLeaseWithTerm and this
// mints term 1 for a key no peer will answer for.
func TestAcquireLeaseWithTerm_RefusesAnUnlistedKey(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	held, term, err := AcquireLeaseWithTerm(ctx, c, "not_a_lease", "host-a", time.Minute, time.Now())
	if err == nil || held || term != 0 {
		t.Fatalf("held=%v term=%d err=%v; want an error and no lease for an unlisted key", held, term, err)
	}
	if n, err := countLeaseTerms(ctx, c, "not_a_lease"); err != nil || n != 0 {
		t.Fatalf("an unlisted key left %d term rows (err %v)", n, err)
	}
}

func countLeaseTerms(ctx context.Context, c *Client, key string) (int, error) {
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM leader_lease_terms WHERE key = ?`, key)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	return int(rows[0].Int("n")), nil
}

// leaseKeyResolver resolves a key expression in package dir to string values.
type leaseKeyResolver struct {
	pkgs         map[string][]*ast.File
	dir          string
	corrosionDir string
}

func (r leaseKeyResolver) resolve(e ast.Expr, depth int) ([]string, bool) {
	if depth > 8 {
		return nil, false
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return nil, false
		}
		s, err := strconv.Unquote(x.Value)
		return []string{s}, err == nil
	case *ast.Ident:
		if v := leaseKeyConstValue(r.pkgs[r.dir], x.Name); v != nil {
			return r.resolve(v, depth+1)
		}
		// Not a constant: a parameter or a variable.
		return nil, false
	case *ast.SelectorExpr:
		if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "corrosion" {
			v := leaseKeyConstValue(r.pkgs[r.corrosionDir], x.Sel.Name)
			if v == nil {
				return nil, false
			}
			return leaseKeyResolver{pkgs: r.pkgs, dir: r.corrosionDir, corrosionDir: r.corrosionDir}.resolve(v, depth+1)
		}
		// A struct field: every value this package assigns it.
		var out []string
		for _, v := range leaseKeyFieldAssignments(r.pkgs[r.dir], x.Sel.Name) {
			vals, ok := r.resolve(v, depth+1)
			if !ok {
				return nil, false
			}
			out = append(out, vals...)
		}
		return out, len(out) > 0
	}
	return nil, false
}

// constValue returns the expression a package-level constant name is declared
// with, or nil.
func leaseKeyConstValue(files []*ast.File, name string) ast.Expr {
	for _, f := range files {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, s := range g.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if n.Name == name && i < len(vs.Values) {
						return vs.Values[i]
					}
				}
			}
		}
	}
	return nil
}

// fieldAssignments collects every expression assigned to a field named name in
// these files: `Name: v` in a composite literal and `x.Name = v`.
func leaseKeyFieldAssignments(files []*ast.File, name string) []ast.Expr {
	var out []ast.Expr
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok && id.Name == name {
					out = append(out, x.Value)
				}
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == name && i < len(x.Rhs) {
						out = append(out, x.Rhs[i])
					}
				}
			}
			return true
		})
	}
	return out
}

func leaseKeyExprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.BasicLit:
		return x.Value
	case *ast.SelectorExpr:
		return leaseKeyExprText(x.X) + "." + x.Sel.Name
	}
	return "<expr>"
}

// moduleRoot walks up from the test's working directory to the module root.
func leaseKeyModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test's working directory")
		}
		dir = parent
	}
}
