package capabilities

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The release-feature guard. A release feature's data may be written only
// through health.Checker.WithFeature, which records the feature's use — the
// bit a rolled-back node decides its quarantine on — before it hands the write
// a FeatureGrant. Two shortcuts compile, pass a branch's own tests, and leave
// no used bit:
//
//   - gating on the release token's latch directly (Latched, Enforced,
//     DurablyLatched, CapabilityActive… with the release token), the way every
//     per-feature token was gated before;
//   - minting a FeatureGrant anywhere but the gate.
//
// This test fails the build on either, in non-test code outside the files that
// implement the gate and the status report.

var releaseLatchReaders = map[string]bool{
	"Latched": true, "Enforced": true, "DurablyLatched": true, "CapabilityActive": true,
	"CapabilityActiveForHealth": true, "PeerSupports": true, "PeerSupportsFresh": true,
}

// releaseGuardAllowed are the files that may read the release token's latch.
var releaseGuardAllowed = map[string]bool{
	"internal/health/release_feature.go": true, // the gate itself
	"internal/grpcapi/upgrade_status.go": true, // the status report and the peer-refusal check
}

// mintAllowed are the files that may claim the grant minter: the gate.
var mintAllowed = map[string]bool{
	"internal/health/release_feature.go": true,
}

// variableTokenAllowed are the places that may read a latch with a token held
// in a VARIABLE rather than named as a capabilities constant (N11), each for a
// reason that has nothing to do with gating a feature's write. A key is
// "<file>:<function>" — the exemption covers that function, not its file
// (m-R2-5) — or "<file>:*" for the latch implementation and the gate. Anywhere
// else a non-constant token is refused: info.Token, a loop variable or a
// helper's result is how a release token would reach a latch read unseen.
var variableTokenAllowed = map[string]string{
	"internal/health/capability.go:*":                           "the latch implementation itself",
	"internal/health/release_feature.go:*":                      "the release-feature gate",
	"internal/grpcapi/upgrade_status.go:GetUpgradeStatus":       "the status report iterates every known token",
	"internal/grpcapi/upgrade_status.go:usedReleaseTokens":      "the push-path judge over every used release token",
	"internal/grpcapi/upgrade_status.go:releaseLagging":         "the rollout summary over this build's release token",
	"internal/grpcapi/upgrade_status.go:evaluateReleaseRollout": "the rollout condition over this build's release token",
	"internal/grpcapi/ha_health.go:RunHAHealthMonitor":          "per-token metrics over Supported()",
	"internal/grpcapi/ha_health.go:retryLatchedMarkers":         "retries the marker write of every latched token",
	"internal/grpcapi/ha_health.go:activateOneUnlatched":        "the latch driver walks every supported token",
	"internal/grpcapi/ha_health.go:checkOneCapabilityHealth":    "the post-latch freshness check over every token",
	"internal/grpcapi/ha_health.go:evaluateHADegraded":          "the degraded evaluation over every supported token",
	"internal/grpcapi/host.go:withheldStandDowns":               "walks a fixed list of two flag tokens",
}

// variableTokenOK reports whether rel's function fn is exempt.
func variableTokenOK(rel, fn string) bool {
	return variableTokenAllowed[rel+":*"] != "" || variableTokenAllowed[rel+":"+fn] != ""
}

// constantToken reports whether e names a capabilities constant directly
// (capabilities.SplitBrainGateV1), which a reader can see at the call site.
func constantToken(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "capabilities" && ast.IsExported(sel.Sel.Name)
}

func isReleaseTokenExpr(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == "ReleaseToken" || strings.HasPrefix(v.Sel.Name, "Release20")
	case *ast.Ident:
		return v.Name == "ReleaseToken" || strings.HasPrefix(v.Name, "Release20")
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			return err == nil && strings.HasPrefix(s, "release_")
		}
	}
	return false
}

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// releaseGuardViolations lists the guard's findings in one parsed file.
func releaseGuardViolations(fset *token.FileSet, f *ast.File, rel string) []string {
	var out []string
	check := func(fn string, root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				// Every mention, called or taken as a value (m-R2-5).
				if v.Sel.Name == "GrantForTest" {
					out = append(out, fset.Position(v.Pos()).String()+": GrantForTest outside a test")
				}
			case *ast.CallExpr:
				name := calleeName(v)
				pos := fset.Position(v.Pos()).String()
				if name == "ClaimGrantMinter" && !mintAllowed[rel] {
					out = append(out, pos+": ClaimGrantMinter outside the release-feature gate")
				}
				if releaseLatchReaders[name] && len(v.Args) > 0 {
					last := v.Args[len(v.Args)-1]
					switch {
					case isReleaseTokenExpr(last):
						if !releaseGuardAllowed[rel] {
							out = append(out, pos+": "+name+" on a release token; gate the write with health.Checker.WithFeature")
						}
					case !constantToken(last) && !variableTokenOK(rel, fn):
						out = append(out, pos+": "+name+" in "+fn+" with a token that is not a named capabilities constant; "+
							"name the token, or add \""+rel+":"+fn+"\" to variableTokenAllowed with a reason")
					}
				}
			}
			return true
		})
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			check(fd.Name.Name, fd)
			continue
		}
		check("", d)
	}
	return out
}

func TestReleaseFeatureGuard_NoLatchShortcutsInTheTree(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var violations []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "gen" || rel == ".git" || strings.HasPrefix(rel, ".claude") || rel == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		violations = append(violations, releaseGuardViolations(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// The guard has teeth: each shortcut in a file outside the allowlist is found.
func TestReleaseFeatureGuard_FindsEachShortcut(t *testing.T) {
	src := `package x
func f() {
	_ = gate.Enforced(ctx, capabilities.ReleaseToken)
	_ = gate.DurablyLatched(capabilities.Release202611V1)
	_ = gate.Latched("release_2026_11_v1")
	_ = capabilities.ClaimGrantMinter()
	_ = gate.Latched(capabilities.SplitBrainGateV1)
	_ = gate.Enforced(ctx, info.Token)
	_ = gate.Latched(tok)
	_ = gate.PeerSupportsFresh(ctx, peer, featureToken(f))
	_ = capabilities.GrantForTest(t, "widgets")
	g := capabilities.GrantForTest
	_ = g
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := releaseGuardViolations(fset, f, "internal/grpcapi/vm.go"); len(got) != 9 {
		t.Fatalf("violations = %v, want the nine shortcuts and not the split-brain read", got)
	}
	// An exemption covers a named function, not its whole file: the same
	// variable-token reads in an allowlisted FILE but another function are found.
	if got := releaseGuardViolations(fset, f, "internal/grpcapi/ha_health.go"); len(got) != 9 {
		t.Fatalf("in ha_health.go, function f: violations = %v, want all nine", got)
	}
	// The gate's own file may read the token and claim the minter; GrantForTest
	// is refused everywhere outside tests, called or not.
	if got := releaseGuardViolations(fset, f, "internal/health/release_feature.go"); len(got) != 2 ||
		!strings.Contains(got[0], "GrantForTest") || !strings.Contains(got[1], "GrantForTest") {
		t.Fatalf("the gate's own file: %v, want only the two GrantForTest findings", got)
	}
}

// TestReleaseFeatureWriters_TakeAGrant: every function a declared feature lists
// as a writer of its data takes a capabilities.FeatureGrant, so it cannot be
// called without passing the gate.
//
// writersPending are the features declared ahead of the branch that writes
// their data (release_2026_11_v1 is declared in full before its feature
// branches land, because its set is frozen). Each may list no writer, and must
// not: the branch that adds its Writers deletes it from here in the same
// change, after which the feature must list them.
var writersPending = map[Feature]bool{
	FeatureAutomationStream: true,
}

// TestReleaseFeatureWriters_TakeAGrant: a writer listed under several
// features (review I-4) must Check each of them; one Check on any grant does
// not cover the others.
func TestReleaseFeatureWriters_TakeAGrant(t *testing.T) {
	root := filepath.Join("..", "..")
	consts, err := featureConstants(filepath.Join(root, "internal", "capabilities"))
	if err != nil {
		t.Fatal(err)
	}
	for f := range writersPending {
		if _, ok := LookupFeature(f); !ok {
			t.Errorf("writersPending names %q, which is not a declared feature", f)
		}
	}
	listedUnder := map[string][]Feature{}
	for _, f := range Features() {
		info, _ := LookupFeature(f)
		switch {
		case writersPending[f] && len(info.Writers) > 0:
			t.Errorf("feature %q lists writers but is still in writersPending: delete it from there", f)
		case !writersPending[f] && len(info.Writers) == 0:
			t.Errorf("feature %q lists no writer of its data", f)
		}
		for _, w := range info.Writers {
			listedUnder[w] = append(listedUnder[w], f)
		}
	}
	for w, fs := range listedUnder {
		if err := writerTakesGrant(root, w, fs, consts); err != nil {
			t.Errorf("features %v writer %s: %v", fs, w, err)
		}
	}
}

// TestReleaseFeatureWriters_PendingFeatureIsNotWritten (m4): a feature still in
// writersPending is one no code writes yet. A branch that switches to it — any
// non-test reference to its constant outside this package, a
// WithReleaseFeature call or a FeatureAvailable check — must list its Writers
// and delete it from writersPending in the same change; otherwise those
// writers are never checked for a grant. This makes that step a test rather
// than a checklist line.
func TestReleaseFeatureWriters_PendingFeatureIsNotWritten(t *testing.T) {
	root := filepath.Join("..", "..")
	consts, err := featureConstants(filepath.Join(root, "internal", "capabilities"))
	if err != nil {
		t.Fatal(err)
	}
	if len(consts) != len(Features()) {
		t.Fatalf("found %d feature constants %v, want one per declared feature (%d)", len(consts), consts, len(Features()))
	}
	refs, err := pendingFeatureRefs(root, consts, writersPending)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		t.Error(r)
	}
}

// The pending-feature check has teeth: a reference outside the package is
// found, one in a test file or in internal/capabilities is not, and a feature
// no longer pending may be referenced anywhere.
func TestReleaseFeatureWriters_PendingCheckFindsAReference(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/x/x.go", `package x
import "github.com/litevirt/litevirt/internal/capabilities"
var _ = capabilities.FeatureWidgets
var _ = capabilities.FeatureGadgets
`)
	write("internal/x/x_test.go", `package x
import "github.com/litevirt/litevirt/internal/capabilities"
var _ = capabilities.FeatureWidgets
`)
	write("internal/capabilities/c.go", `package capabilities
var _ = capabilities.FeatureWidgets
`)
	consts := map[string]Feature{"FeatureWidgets": "widgets", "FeatureGadgets": "gadgets"}
	refs, err := pendingFeatureRefs(dir, consts, map[Feature]bool{"widgets": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || !strings.Contains(refs[0], "x.go") || !strings.Contains(refs[0], `"widgets"`) {
		t.Fatalf("references = %v, want exactly the one to widgets in internal/x/x.go", refs)
	}
}

// featureConstants maps each Feature constant declared in dir to its value.
func featureConstants(dir string) (map[string]Feature, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]Feature{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Feature" {
					continue
				}
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil {
							out[n.Name] = Feature(v)
						}
					}
				}
			}
		}
	}
	return out, nil
}

// pendingFeatureRefs lists every non-test reference, outside
// internal/capabilities, to the constant of a feature still in pending.
func pendingFeatureRefs(root string, consts map[string]Feature, pending map[Feature]bool) ([]string, error) {
	fset := token.NewFileSet()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "gen" || rel == ".git" || strings.HasPrefix(rel, ".claude") || rel == "vendor" ||
				rel == "internal/capabilities" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "capabilities" {
				return true
			}
			if feat, ok := consts[sel.Sel.Name]; ok && pending[feat] {
				out = append(out, fmt.Sprintf("%s: capabilities.%s (feature %q) is used here but is still in "+
					"writersPending: list its Writers and delete it from writersPending in the same change",
					fset.Position(sel.Pos()), sel.Sel.Name, feat))
			}
			return true
		})
		return nil
	})
	return out, err
}

// The writer check has teeth.
func TestReleaseFeatureWriters_CheckFindsAMissingGrant(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "internal", "x")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package x
import "github.com/litevirt/litevirt/internal/capabilities"
func Good(g capabilities.FeatureGrant, n int) error { return g.Check("widgets") }
func Bad(n int) error { return nil }
func NoCheck(g capabilities.FeatureGrant) error { return nil }
type T struct{}
func (T) Method(ctx int, g capabilities.FeatureGrant) error { return g.Check("widgets") }
func Both(g, h capabilities.FeatureGrant) error {
	if err := g.Check("widgets"); err != nil {
		return err
	}
	return h.Check(capabilities.FeatureGadgets)
}
func OnlyOne(g, h capabilities.FeatureGrant) error { return g.Check("widgets") }
func Crossed(g capabilities.FeatureGrant) error { return g.Check(capabilities.FeatureGadgets) }
`
	if err := os.WriteFile(filepath.Join(pkg, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	widgets := []Feature{"widgets"}
	consts := map[string]Feature{"FeatureWidgets": "widgets", "FeatureGadgets": "gadgets"}
	if err := writerTakesGrant(dir, "internal/x.Good", widgets, consts); err != nil {
		t.Errorf("Good: %v", err)
	}
	if err := writerTakesGrant(dir, "internal/x.T.Method", widgets, consts); err != nil {
		t.Errorf("T.Method: %v", err)
	}
	if writerTakesGrant(dir, "internal/x.Bad", widgets, consts) == nil {
		t.Error("Bad takes no grant, and passed")
	}
	if writerTakesGrant(dir, "internal/x.NoCheck", widgets, consts) == nil {
		t.Error("NoCheck takes a grant and never checks it, and passed")
	}
	if writerTakesGrant(dir, "internal/x.Missing", widgets, consts) == nil {
		t.Error("a writer that does not exist passed")
	}
	// A writer listed under two features must Check both (review I-4).
	both := []Feature{"widgets", "gadgets"}
	if err := writerTakesGrant(dir, "internal/x.Both", both, consts); err != nil {
		t.Errorf("Both: %v", err)
	}
	if writerTakesGrant(dir, "internal/x.OnlyOne", both, consts) == nil {
		t.Error("OnlyOne is listed under widgets and gadgets and checks only widgets, and passed")
	}
	if err := writerTakesGrant(dir, "internal/x.OnlyOne", widgets, consts); err != nil {
		t.Errorf("OnlyOne listed under widgets alone: %v", err)
	}
	if writerTakesGrant(dir, "internal/x.Crossed", widgets, consts) == nil {
		t.Error("Crossed is listed under widgets and checks only gadgets, and passed")
	}
}

// writerTakesGrant finds writer — "<package dir>.<Func>" or
// "<package dir>.<Type>.<Method>" — under root and checks it has a parameter of
// type FeatureGrant (capabilities.FeatureGrant, or FeatureGrant in-package)
// and, for each of features (those it is listed under), calls Check with that
// feature on one of its grant parameters. consts maps each Feature constant's
// name to its value, so a Check(capabilities.FeatureX) argument resolves.
func writerTakesGrant(root, writer string, features []Feature, consts map[string]Feature) error {
	dot := strings.Index(writer, ".")
	if dot < 0 {
		return fmt.Errorf("malformed writer %q", writer)
	}
	dir, name := writer[:dot], writer[dot+1:]
	recv, fn := "", name
	if i := strings.Index(name, "."); i >= 0 {
		recv, fn = name[:i], name[i+1:]
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(root, dir, e.Name()), nil, 0)
		if err != nil {
			return err
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != fn || recvName(fd) != recv {
				continue
			}
			var grants []string
			for _, field := range fd.Type.Params.List {
				if isGrantType(field.Type) {
					for _, pn := range field.Names {
						grants = append(grants, pn.Name)
					}
				}
			}
			if len(grants) == 0 {
				return fmt.Errorf("%s takes no capabilities.FeatureGrant", writer)
			}
			checked := checkedFeatures(fd.Body, grants, consts)
			if len(checked) == 0 {
				return fmt.Errorf("%s takes a capabilities.FeatureGrant but never calls its Check", writer)
			}
			for _, feat := range features {
				if !checked[feat] {
					return fmt.Errorf("%s is listed under %q but never calls Check(%q) on one of its grants", writer, feat, feat)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("%s not found", writer)
}

func recvName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func isGrantType(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == "FeatureGrant"
	case *ast.Ident:
		return v.Name == "FeatureGrant"
	}
	return false
}

// checkedFeatures returns the features body passes to <grant>.Check(...) for
// any of grants. An argument resolves through consts (capabilities.FeatureX
// or an in-package FeatureX) or is a string literal; any other argument
// counts as a Check of the empty feature, which no listing names.
//
// It cannot tell WHICH grant a Check is made on: a writer that checks one
// feature on another feature's grant parameter satisfies it. Slot correctness
// is the writers' behavioural tests' job (for the rule writers,
// corrosion TestFirewallRuleWriters_EachFeatureNeedsItsOwnGrant).
func checkedFeatures(body *ast.BlockStmt, grants []string, consts map[string]Feature) map[Feature]bool {
	out := map[Feature]bool{}
	if body == nil {
		return out
	}
	isGrant := map[string]bool{}
	for _, g := range grants {
		isGrant[g] = true
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Check" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || !isGrant[id.Name] {
			return true
		}
		var feat Feature
		if len(call.Args) == 1 {
			switch a := call.Args[0].(type) {
			case *ast.SelectorExpr:
				feat = consts[a.Sel.Name]
			case *ast.Ident:
				feat = consts[a.Name]
			case *ast.BasicLit:
				if v, err := strconv.Unquote(a.Value); err == nil {
					feat = Feature(v)
				}
			}
		}
		out[feat] = true
		return true
	})
	return out
}
