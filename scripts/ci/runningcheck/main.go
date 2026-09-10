// Command runningcheck enforces litevirt's marker chokepoint: a VM row must
// never say "running" without a marker naming the ownership generation that
// runtime belongs to.
//
// A row that says running while no marker names its generation is a workload
// nobody can prove. That window is what the dual-run detector's newborn grace
// exists to tolerate, so closing it everywhere is what eventually makes that
// grace deletable — and a new unrouted call site would silently reopen it.
//
// There are two publish orderings, and using the wrong one is as much a defect
// as using neither:
//
//   - NON-MINTING writers (UpdateVMState and friends) leave the generation
//     unchanged, so the marker value is already known. Mark first, then commit.
//   - MINTING writers (TransferVMOwner*, CompleteVMStartProof) set
//     state='running' AND advance vm_owner_epoch in one statement, so the
//     correct value does not EXIST until the commit lands. Commit, read back,
//     then mark. Routing one of these through the non-minting helper stamps the
//     generation the row is about to LEAVE — the exact marker/row disagreement
//     the detector reports.
//
// The rules, all AST-checked:
//
//  1. A non-minting primitive whose state argument is a string literal other
//     than "running" is exempt — it cannot publish a running VM. Any other
//     state argument (literal "running", or a value only known at runtime) must
//     be inside a closure handed to a publish helper.
//  2. A minting primitive must always be inside such a closure, and it must be a
//     MINTED helper. There is no state argument to exempt it by.
//  3. A closure assigned to a variable and handed to a publish helper may ALSO
//     be invoked directly, but only inside a branch that has proven the state is
//     not "running" — otherwise the routing is decorative and the direct call
//     publishes unmarked.
//  4. A corrosion.VMRecord literal born at "running" — or at a state only known
//     at runtime — must be graduated by an assignOwnerEpochAtCreate call in the
//     same function. An insert lands at the vm_owner_epoch column default of 0,
//     convergence early-returns on zero, and the backfill that would graduate it
//     is gated behind enforcement.owner_epoch, which is off by default.
//
// A site that genuinely cannot be routed opts out with a trailing
// `//runningcheck:allow <reason>` comment on any line the statement spans. The
// four ownership HANDOFFS use this: they commit a row that names a DIFFERENT
// host while running on the host giving the VM away, whose domain libvirt has
// already undefined. Marking there would stamp a runtime that is going away, and
// for the post-cutover commit it would refuse the commit outright on every
// successful migration.
//
// Usage:
//
//	runningcheck -root .        # walk <root> for production .go files; exit 1 on any violation
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// nonMinting are corrosion writers that can set state='running' while leaving
// vm_owner_epoch alone. stateArg is the zero-based index of the state parameter,
// or -1 where the state travels inside a VMRecord (rule 4 covers those).
var nonMinting = map[string]int{
	"UpdateVMState":            3,
	"UpdateVMStateStrict":      3,
	"UpdateVMStateAtEpoch":     3,
	"UpdateVMHost":             -1,
	"CommitMigrationOwnership": 5,
	"InsertVM":                 -1,
	"InsertVMWithHardware":     -1,
}

// minting are writers whose statement sets state='running' AND advances
// vm_owner_epoch together. The value is the zero-based index of the state
// parameter, or -1 for a writer that always publishes running and so can never
// be exempted by a literal.
var minting = map[string]int{
	"TransferVMOwner":      4,
	"TransferVMOwnerFresh": 4,
	"CompleteVMStartProof": -1,
}

// mintedHelpers take the commit-then-mark ordering; plainHelpers the
// mark-then-commit one. A minting primitive routed through a plain helper is a
// family mismatch, not a pass.
var mintedHelpers = map[string]bool{
	"publishRunningMinted":   true,
	"PublishVMRunningMinted": true,
}

var plainHelpers = map[string]bool{
	"publishRunning":    true,
	"PublishVMRunning":  true,
	"PublishRunningVia": true,
}

type violation struct {
	file string
	line int
	msg  string
}

func main() {
	root := flag.String("root", ".", "repository root to scan for production .go files")
	flag.Parse()

	var violations []violation
	err := filepath.WalkDir(*root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "gen":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		vs, perr := scanFile(path)
		if perr != nil {
			return perr
		}
		violations = append(violations, vs...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "runningcheck: %v\n", err)
		os.Exit(2)
	}

	if len(violations) == 0 {
		fmt.Println("runningcheck: every running publish is routed through the marker chokepoint; OK")
		return
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].file != violations[j].file {
			return violations[i].file < violations[j].file
		}
		return violations[i].line < violations[j].line
	})
	fmt.Fprintf(os.Stderr, "runningcheck: FAIL — %d unrouted or misrouted running publish(es):\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  %s:%d: %s\n", v.file, v.line, v.msg)
	}
	fmt.Fprintf(os.Stderr,
		"\nA row that says \"running\" with no marker naming its generation is a workload\n"+
			"nobody can prove. Route the write through the chokepoint:\n"+
			"    s.publishRunning(ctx, name, state, func(ctx context.Context) error { ... })\n"+
			"or, when the statement ALSO advances vm_owner_epoch:\n"+
			"    s.publishRunningMinted(ctx, name, func(ctx context.Context) error { ... })\n"+
			"If the site genuinely cannot be routed — an ownership handoff marks the host\n"+
			"that is giving the VM away — add a trailing `//runningcheck:allow <reason>`.\n")
	os.Exit(1)
}

// fileScan carries the per-file state the rules share.
type fileScan struct {
	path  string
	fset  *token.FileSet
	allow map[int]bool
	out   []violation
}

func scanFile(path string) ([]violation, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s := &fileScan{path: path, fset: fset, allow: map[int]bool{}}
	// A directive is honored on any line the statement spans (the trailing form
	// writecheck uses) AND on the line immediately after a comment block that
	// carries it — these reasons run to several lines, and a block sitting
	// directly above the call reads far better than a trailing fragment.
	for _, cg := range file.Comments {
		carries := false
		for _, c := range cg.List {
			if strings.Contains(c.Text, "runningcheck:allow") {
				carries = true
				s.allow[fset.Position(c.Slash).Line] = true
			}
		}
		if carries {
			s.allow[fset.Position(cg.End()).Line+1] = true
		}
	}
	// Rules are per-function: routing evidence (which closures reach a helper,
	// whether the function graduates its insert) is function-scoped.
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil {
				s.checkFunc(fn.Body)
			}
		}
		return true
	})
	return s.out, nil
}

// report anchors at the statement's first line but honors an allow directive on
// ANY line it spans — a routed call is usually multi-line, and the natural place
// for the directive is the closing line.
func (s *fileScan) report(n ast.Node, msg string) {
	start := s.fset.Position(n.Pos()).Line
	end := s.fset.Position(n.End()).Line
	for ln := start; ln <= end; ln++ {
		if s.allow[ln] {
			return
		}
	}
	s.out = append(s.out, violation{file: s.path, line: start, msg: msg})
}

func (s *fileScan) checkFunc(body *ast.BlockStmt) {
	routed := collectRouting(body, s.fset)
	graduates := callsGraduation(body)

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := corrosionCall(call)
		switch {
		case hasKey(minting, name):
			if idx := minting[name]; idx >= 0 && idx < len(call.Args) {
				if lit, ok := stringLit(call.Args[idx]); ok && lit != "running" {
					return true // a transfer that hands over a STOPPED VM publishes no runtime
				}
			}
			switch routed.family(call, s.fset) {
			case familyMinted:
				// Correct.
			case familyPlain:
				s.report(call, fmt.Sprintf("corrosion.%s(...) is a MINTING write routed through the "+
					"mark-then-commit helper; it would stamp the generation the row is about to leave "+
					"— use publishRunningMinted", name))
			default:
				s.report(call, fmt.Sprintf("corrosion.%s(...) publishes a running VM at a NEW generation "+
					"but is not routed through publishRunningMinted", name))
			}
		case hasKey(nonMinting, name):
			idx := nonMinting[name]
			if idx >= 0 && idx < len(call.Args) {
				if lit, ok := stringLit(call.Args[idx]); ok && lit != "running" {
					return true // cannot publish a running VM
				}
			}
			if idx < 0 {
				return true // state travels in a VMRecord; rule 4 covers it
			}
			if routed.family(call, s.fset) == familyNone {
				s.report(call, fmt.Sprintf("corrosion.%s(...) can publish a running VM but is not routed "+
					"through publishRunning", name))
			}
		}
		return true
	})

	// Rule 3: a routed closure variable may be invoked directly only under a
	// proven non-running branch.
	for _, use := range routed.directCalls(body, s.fset) {
		s.report(use.call, fmt.Sprintf("the routed closure %q is also invoked directly outside a branch "+
			"that proves the state is not \"running\"; that invocation publishes unmarked", use.name))
	}

	// Rule 4: born-running inserts must graduate.
	if graduates {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || !isVMRecord(cl) {
			return true
		}
		st, found := stateField(cl)
		if !found {
			return true
		}
		if lit, ok := stringLit(st); ok && lit != "running" {
			return true
		}
		s.report(cl, "a corrosion.VMRecord is inserted at a running (or runtime-determined) state "+
			"without an assignOwnerEpochAtCreate call in the same function; it would be born at "+
			"epoch 0, which convergence never repairs and the default-off backfill never graduates")
		return true
	})
}

func hasKey(m map[string]int, k string) bool { _, ok := m[k]; return ok }

// corrosionCall returns the function name for a corrosion.<Fn>(...) call, else "".
func corrosionCall(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "corrosion" {
		return ""
	}
	return sel.Sel.Name
}

// helperName returns the publish-helper name a call targets, else "".
func helperName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

type family int

const (
	familyNone family = iota
	familyPlain
	familyMinted
)

// routing records, per function, the source spans of closures handed to a
// publish helper — plus, for closures reached through a variable, that
// variable's name.
type routing struct {
	spans []span
	vars  map[string]family
}

type span struct {
	start, end int
	fam        family
}

func (r routing) family(n ast.Node, fset *token.FileSet) family {
	line := fset.Position(n.Pos()).Line
	best := familyNone
	for _, sp := range r.spans {
		if line >= sp.start && line <= sp.end {
			// A minted span wins: it is the stricter classification, and a
			// primitive inside one is being published with that ordering.
			if sp.fam == familyMinted {
				return familyMinted
			}
			best = sp.fam
		}
	}
	return best
}

// collectRouting finds every closure handed to a publish helper — inline, or
// reached through a variable — and records the source span it covers, so a
// primitive can be tested for "is lexically inside a routed closure".
func collectRouting(body *ast.BlockStmt, fset *token.FileSet) routing {
	r := routing{vars: map[string]family{}}

	// Pass 1: which arguments reach a helper, and with which ordering.
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fam := helperFamily(helperName(call))
		if fam == familyNone {
			return true
		}
		for _, arg := range call.Args {
			switch a := arg.(type) {
			case *ast.FuncLit:
				// Written inline at the call.
				r.spans = append(r.spans, span{
					start: fset.Position(a.Body.Pos()).Line,
					end:   fset.Position(a.Body.End()).Line,
					fam:   fam,
				})
			case *ast.Ident:
				// Reached through a variable; its closure body is found below.
				r.vars[a.Name] = fam
			}
		}
		return true
	})

	// Pass 2: the bodies of the closures those variables hold.
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		fam, routed := r.vars[id.Name]
		if !routed {
			return true
		}
		if fl, ok := assign.Rhs[0].(*ast.FuncLit); ok {
			r.spans = append(r.spans, span{
				start: fset.Position(fl.Body.Pos()).Line,
				end:   fset.Position(fl.Body.End()).Line,
				fam:   fam,
			})
		}
		return true
	})
	return r
}

func helperFamily(name string) family {
	switch {
	case mintedHelpers[name]:
		return familyMinted
	case plainHelpers[name]:
		return familyPlain
	}
	return familyNone
}

// directUse names a direct invocation of a routed closure variable.
type directUse struct {
	name string
	call *ast.CallExpr
}

func (r routing) directCalls(body *ast.BlockStmt, fset *token.FileSet) []directUse {
	// Collect the source ranges of `if` statements whose condition proves the
	// state is not "running"; a direct invocation inside one is legitimate.
	var proven []span
	ast.Inspect(body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Cond == nil || !provesNotRunning(ifs.Cond) {
			return true
		}
		proven = append(proven, span{
			start: fset.Position(ifs.Body.Pos()).Line,
			end:   fset.Position(ifs.Body.End()).Line,
		})
		return true
	})

	var out []directUse
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if _, routedVar := r.vars[id.Name]; !routedVar {
			return true
		}
		line := fset.Position(call.Pos()).Line
		for _, sp := range proven {
			if line >= sp.start && line <= sp.end {
				return true
			}
		}
		out = append(out, directUse{name: id.Name, call: call})
		return true
	})
	return out
}

// provesNotRunning reports whether a condition establishes that the state is
// something other than "running" — `state != "running"`, or a disjunction of
// such comparisons.
func provesNotRunning(e ast.Expr) bool {
	switch b := e.(type) {
	case *ast.ParenExpr:
		return provesNotRunning(b.X)
	case *ast.BinaryExpr:
		switch b.Op {
		case token.NEQ:
			if lit, ok := stringLit(b.Y); ok && lit == "running" {
				return true
			}
			if lit, ok := stringLit(b.X); ok && lit == "running" {
				return true
			}
		case token.LAND, token.LOR:
			return provesNotRunning(b.X) || provesNotRunning(b.Y)
		}
	}
	return false
}

func callsGraduation(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if helperName(call) == "assignOwnerEpochAtCreate" {
			found = true
		}
		return true
	})
	return found
}

func isVMRecord(cl *ast.CompositeLit) bool {
	sel, ok := cl.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "corrosion" && sel.Sel.Name == "VMRecord"
}

func stateField(cl *ast.CompositeLit) (ast.Expr, bool) {
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "State" {
			return kv.Value, true
		}
	}
	return nil, false
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(bl.Value, "`\""), true
}
