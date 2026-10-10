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

// variableTokenAllowed are the files that may read a latch with a token held in
// a VARIABLE rather than named as a capabilities constant (N11), each for a
// reason that has nothing to do with gating a feature's write. Anywhere else a
// non-constant token is refused: info.Token, a loop variable or a helper's
// result is how a release token would reach a latch read unseen.
var variableTokenAllowed = map[string]string{
	"internal/health/capability.go":      "the latch implementation itself",
	"internal/health/release_feature.go": "the release-feature gate",
	"internal/grpcapi/upgrade_status.go": "the status report iterates every known token",
	"internal/grpcapi/ha_health.go":      "the HA monitor drives and checks every supported token",
	"internal/grpcapi/host.go":           "withheldStandDowns walks a fixed list of two flag tokens",
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
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call)
		pos := fset.Position(call.Pos()).String()
		if name == "ClaimGrantMinter" && !mintAllowed[rel] {
			out = append(out, pos+": ClaimGrantMinter outside the release-feature gate")
		}
		if name == "GrantForTest" {
			out = append(out, pos+": GrantForTest outside a test")
		}
		if releaseLatchReaders[name] && len(call.Args) > 0 {
			last := call.Args[len(call.Args)-1]
			switch {
			case isReleaseTokenExpr(last):
				if !releaseGuardAllowed[rel] {
					out = append(out, pos+": "+name+" on a release token; gate the write with health.Checker.WithFeature")
				}
			case !constantToken(last) && variableTokenAllowed[rel] == "":
				out = append(out, pos+": "+name+" with a token that is not a named capabilities constant; "+
					"name the token, or add this file to variableTokenAllowed with a reason")
			}
		}
		return true
	})
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
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := releaseGuardViolations(fset, f, "internal/grpcapi/vm.go"); len(got) != 8 {
		t.Fatalf("violations = %v, want the eight shortcuts and not the split-brain read", got)
	}
	// The gate's own file may read the token and claim the minter; GrantForTest
	// is refused everywhere outside tests.
	if got := releaseGuardViolations(fset, f, "internal/health/release_feature.go"); len(got) != 1 ||
		!strings.Contains(got[0], "GrantForTest") {
		t.Fatalf("the gate's own file: %v, want only the GrantForTest finding", got)
	}
}

// TestReleaseFeatureWriters_TakeAGrant: every function a declared feature lists
// as a writer of its data takes a capabilities.FeatureGrant, so it cannot be
// called without passing the gate.
func TestReleaseFeatureWriters_TakeAGrant(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, f := range Features() {
		info, _ := LookupFeature(f)
		if len(info.Writers) == 0 {
			t.Errorf("feature %q lists no writer of its data", f)
		}
		for _, w := range info.Writers {
			if err := writerTakesGrant(root, w); err != nil {
				t.Errorf("feature %q writer %s: %v", f, w, err)
			}
		}
	}
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
type T struct{}
func (T) Method(ctx int, g capabilities.FeatureGrant) error { return nil }
`
	if err := os.WriteFile(filepath.Join(pkg, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writerTakesGrant(dir, "internal/x.Good"); err != nil {
		t.Errorf("Good: %v", err)
	}
	if err := writerTakesGrant(dir, "internal/x.T.Method"); err != nil {
		t.Errorf("T.Method: %v", err)
	}
	if writerTakesGrant(dir, "internal/x.Bad") == nil {
		t.Error("Bad takes no grant, and passed")
	}
	if writerTakesGrant(dir, "internal/x.Missing") == nil {
		t.Error("a writer that does not exist passed")
	}
}

// writerTakesGrant finds writer — "<package dir>.<Func>" or
// "<package dir>.<Type>.<Method>" — under root and checks it has a parameter of
// type FeatureGrant (capabilities.FeatureGrant, or FeatureGrant in-package).
func writerTakesGrant(root, writer string) error {
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
			for _, field := range fd.Type.Params.List {
				if isGrantType(field.Type) {
					return nil
				}
			}
			return fmt.Errorf("%s takes no capabilities.FeatureGrant", writer)
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
