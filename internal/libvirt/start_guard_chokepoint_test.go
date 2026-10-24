package libvirt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Every way this package brings a domain to life goes through the start
// guard (SetStartGuard): the daemon's guard (grpcapi.NICStartGuard) is the one
// place a guest's NIC firewall goes in force and its NICs' VLANs go on its
// taps before it runs, so a start that skipped it would run an access-VLAN
// guest on VLAN 1, its bridge's untagged segment.
//
// So: libvirt's domain-creating calls (DomainCreate*, DomainRestore*) appear
// only in startDomainGuarded and restoreWithRetry, and those run the guard
// (guardedStart; the guard's before and afterPaused). A new start path in this
// package either goes through one of them or fails here.
//
// Mutation: a DomainCreate call in another function — red; restoreWithRetry
// not calling the guard — red.
func TestEveryDomainStartGoesThroughTheStartGuard(t *testing.T) {
	creates := map[string]bool{
		"DomainCreate": true, "DomainCreateWithFlags": true, "DomainCreateXML": true,
		"DomainCreateXMLWithFiles": true, "DomainCreateWithFiles": true,
		"DomainRestore": true, "DomainRestoreFlags": true,
	}
	guarded := map[string][]string{
		"startDomainGuarded": {"guardedStart"},
		"restoreWithRetry":   {"before", "afterPaused"},
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				calls := map[string]bool{}
				var created []token.Pos
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					name := ""
					switch fn := call.Fun.(type) {
					case *ast.SelectorExpr:
						name = fn.Sel.Name
					case *ast.Ident:
						name = fn.Name
					}
					calls[name] = true
					if creates[name] {
						created = append(created, call.Pos())
					}
					return true
				})
				if len(created) == 0 {
					continue
				}
				// A method of the same name (an interface's declaration
				// has no body) is not a start path.
				want, ok := guarded[fd.Name.Name]
				if !ok || fd.Recv != nil {
					for _, at := range created {
						t.Errorf("%s creates a domain at %s outside the start guard: route it through startDomainGuarded or restoreWithRetry",
							fd.Name.Name, fset.Position(at))
					}
					continue
				}
				seen[fd.Name.Name] = true
				for _, w := range want {
					if !calls[w] {
						t.Errorf("%s creates a domain but does not call %s: the start guard does not run", fd.Name.Name, w)
					}
				}
			}
		}
	}
	for name := range guarded {
		if !seen[name] {
			t.Errorf("%s creates no domain any more: the scan is out of date", name)
		}
	}
}
