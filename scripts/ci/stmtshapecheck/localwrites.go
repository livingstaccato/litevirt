package main

import (
	"fmt"
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/packages"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ExecuteLocal WRITES NOTHING A PEER WILL EVER SEE.
//
// corrosion.Client.ExecuteLocal is the non-relaying write path the voter side
// of recovery claims uses (docs/design/recovery-claims.md §3.7): a promise must
// never be relayed, so it is written in a local transaction that produces no
// mutation_log row. The same property makes it dangerous anywhere else — a
// replicated table written there diverges from every peer, silently and
// permanently, because nothing will ever carry the write.
//
// LocalTx.Exec refuses such a write at runtime. This makes "local" a property
// the tooling checks as well: every LocalTx.Exec call site must carry
// compile-time constant SQL whose target is a registered node-local claim table
// and is in neither replicated table list.

// localWriteGaps reports every LocalTx.Exec call whose target is not provably a
// node-local claim table.
func localWriteGaps(pkgs []*packages.Package) []string {
	var gaps []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Exec" {
					return true
				}
				selection := pkg.TypesInfo.Selections[sel]
				if selection == nil || selection.Kind() != types.MethodVal || !isCorrosionNamed(selection.Recv(), "LocalTx") {
					return true
				}
				pos := pkg.Fset.Position(call.Pos())
				if len(call.Args) < 2 {
					gaps = append(gaps, fmt.Sprintf("%s: LocalTx.Exec without a SQL argument", loc(pos)))
					return true
				}
				s, ok := constString(pkg, call.Args[1])
				if !ok {
					gaps = append(gaps, fmt.Sprintf("%s: LocalTx.Exec with non-constant SQL: ExecuteLocal writes "+
						"are never relayed, so the target table must be provable here", loc(pos)))
					return true
				}
				table, err := corrosion.StatementTable(s)
				if err != nil {
					gaps = append(gaps, fmt.Sprintf("%s: LocalTx.Exec SQL does not parse: %v", loc(pos), err))
					return true
				}
				if !corrosion.IsNodeLocalClaimTable(table) || corrosion.IsReplicatedTable(table) {
					gaps = append(gaps, fmt.Sprintf("%s: LocalTx.Exec writes %q, which is not a node-local claim "+
						"table. ExecuteLocal is never relayed, so a write to a replicated table here diverges "+
						"from every peer; use Execute", loc(pos), table))
				}
				return true
			})
		}
	}
	return gaps
}
