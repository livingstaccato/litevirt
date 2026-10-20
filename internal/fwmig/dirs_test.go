package fwmig

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every string constant named *Dir in this package is in Dirs(), so a record
// directory added later is on the storage deny list too (D2-13 re-review 2
// m-5; the storage guard iterates Dirs()).
//
// Mutation: leave a *Dir constant out of Dirs() — red.
func TestDirs_EveryDirConstant(t *testing.T) {
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != token.CONST {
					continue
				}
				for _, sp := range g.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if !strings.HasSuffix(n.Name, "Dir") || i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						found++
						if !slices.Contains(Dirs(), v) {
							t.Errorf("record directory %s (%q) is not in Dirs()", n.Name, v)
						}
					}
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no *Dir constant found; the scan is broken")
	}
}
